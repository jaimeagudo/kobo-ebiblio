#!/usr/bin/env python3
import os
import re
import sys
import json
import shutil
import argparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KEY_FILE = os.path.join(BASE_DIR, "adobe_signing_key.json")

COMUNIDADES = [
    ("andalucia", "Andalucía", "https://andalucia.ebiblio.es"),
    ("aragon", "Aragón", "https://aragon.ebiblio.es"),
    ("asturias", "Asturias", "https://asturias.ebiblio.es"),
    ("baleares", "Illes Balears", "https://baleares.ebiblio.es"),
    ("canarias", "Canarias", "https://canarias.ebiblio.es"),
    ("cantabria", "Cantabria", "https://cantabria.ebiblio.es"),
    ("castillalamancha", "Castilla-La Mancha", "https://castillalamancha.ebiblio.es"),
    ("castillayleon", "Castilla y León", "https://castillayleon.ebiblio.es"),
    ("catalunya", "Cataluña", "https://catalunya.ebiblio.es"),
    ("ceuta", "Ceuta", "https://ceuta.ebiblio.es"),
    ("extremadura", "Extremadura", "https://extremadura.ebiblio.es"),
    ("galicia", "Galicia", "https://galicia.ebiblio.es"),
    ("larioja", "La Rioja", "https://larioja.ebiblio.es"),
    ("madrid", "Comunidad de Madrid", "https://madrid.ebiblio.es"),
    ("melilla", "Melilla", "https://melilla.ebiblio.es"),
    ("murcia", "Región de Murcia", "https://murcia.ebiblio.es"),
    ("navarra", "Navarra", "https://navarra.ebiblio.es"),
    ("euskadi", "País Vasco / Euskadi", "https://euskadi.ebiblio.es"),
    ("valencia", "Comunitat Valenciana", "https://valencia.ebiblio.es"),
]


def find_kobo_drive(explicit_path=None):
    if explicit_path:
        expanded = os.path.expanduser(explicit_path)
        if os.path.exists(os.path.join(expanded, ".kobo", "version")):
            return expanded
        raise RuntimeError(f"La ruta indicada no parece un Kobo válido: {expanded}")

    if os.path.exists("/Volumes"):
        for entry in sorted(os.listdir("/Volumes")):
            candidate = os.path.join("/Volumes", entry)
            if os.path.exists(os.path.join(candidate, ".kobo", "version")):
                return candidate

    raise RuntimeError(
        "No se detectó el Kobo conectado por USB en /Volumes.\n"
        "Conecta el Kobo por cable de datos y pulsa 'Conectar' en la pantalla del dispositivo."
    )


def _normalize_hex(val):
    if not isinstance(val, str):
        return ""
    s = val.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return re.sub(r"\s+", "", s)


def _normalize_cert(val):
    if not isinstance(val, str):
        return ""
    return val.strip()


def resolve_signing_key(key_file=None):
    candidate = os.path.expanduser(key_file) if key_file else DEFAULT_KEY_FILE
    if not os.path.exists(candidate):
        raise RuntimeError(
            f"No se encontró el archivo de clave en '{candidate}'.\n"
            "En macOS, la extracción automática desde Windows Registry/DPAPI no está disponible.\n"
            "Coloca un 'adobe_signing_key.json' válido (con 'n', 'd' y 'cert') en la carpeta del proyecto "
            "o pásalo con --key-file /ruta/a/adobe_signing_key.json."
        )

    try:
        with open(candidate, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise RuntimeError(f"No se pudo leer '{candidate}' como JSON válido: {exc}")

    if not isinstance(data, dict):
        raise RuntimeError(f"El archivo '{candidate}' debe contener un objeto JSON.")

    n_val = _normalize_hex(data.get("n"))
    d_val = _normalize_hex(data.get("d"))
    cert_val = _normalize_cert(data.get("cert"))

    missing = []
    if not n_val:
        missing.append("n")
    if not d_val:
        missing.append("d")
    if not cert_val:
        missing.append("cert")

    if missing:
        raise RuntimeError(
            f"El archivo '{candidate}' no tiene los campos obligatorios completos (faltan: {', '.join(missing)})."
        )

    # Validar que n y d sean hexadecimales válidos
    try:
        int(n_val, 16)
        int(d_val, 16)
    except ValueError as exc:
        raise RuntimeError(f"Los campos 'n' y 'd' en '{candidate}' deben ser hexadecimales válidos: {exc}")

    # Normalizar en un archivo limpio si hubo espacios/prefijos extra
    normalized_obj = {
        "n": n_val,
        "d": d_val,
        "cert": cert_val,
    }
    if data != normalized_obj:
        clean_path = os.path.join(BASE_DIR, ".adobe_signing_key.normalized.json")
        with open(clean_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(normalized_obj, f, indent=2, ensure_ascii=False)
        return clean_path

    return candidate


def ensure_config_json():
    cfg_path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = {}

        if existing.get("ebiblio_user"):
            com_name = next((c[1] for c in COMUNIDADES if c[0] == existing.get("comunidad")), existing.get("comunidad"))
            print(f"[INFO] Cuenta eBiblio actual: {existing.get('ebiblio_user')} ({com_name})")
            try:
                ans = input("Pulsa [Enter] para mantener esta cuenta, o escribe 'c' para cambiarla: ").strip().lower()
            except EOFError:
                ans = ""
            if ans != "c" and existing.get("ebiblio_pass"):
                return existing

    print("\n--- Configuración de tu cuenta de eBiblio ---")
    for idx, (_k, name, url) in enumerate(COMUNIDADES, 1):
        print(f"  {idx:2d}. {name} ({url})")
    choice = input("\nElige el número de tu Comunidad Autónoma [1 para Andalucía]: ").strip()
    idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(COMUNIDADES) else 0
    com_key = COMUNIDADES[idx][0]
    user = input("Tu correo/usuario de eBiblio: ").strip()
    pwd = input("Tu contraseña de eBiblio: ").strip()

    cfg = {"comunidad": com_key, "ebiblio_user": user, "ebiblio_pass": pwd}
    with open(cfg_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.chmod(cfg_path, 0o600)
    print(f"[OK] Guardada configuración en {cfg_path}\n")
    return cfg


def configure_kobo_adobe_page_numbers(kobo):
    conf_path = os.path.join(kobo, ".kobo", "Kobo", "Kobo eReader.conf")
    if not os.path.exists(conf_path):
        return
    with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    if "showAdobePageNumbers=" in content:
        content = re.sub(r"showAdobePageNumbers=\w+", "showAdobePageNumbers=false", content)
    elif "[Reading]" in content:
        content = content.replace("[Reading]", "[Reading]\nshowAdobePageNumbers=false", 1)
    else:
        content += "\n[Reading]\nshowAdobePageNumbers=false\n"
    with open(conf_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    print("[OK] Desactivados números de página diminutos en el margen derecho (showAdobePageNumbers=false)")


def write_lf_file(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def install(kobo_path=None, key_file=None):
    kobo = find_kobo_drive(kobo_path)
    print(f"[OK] Kobo detectado en {kobo}")

    act_xml = os.path.join(kobo, ".adobe-digital-editions", "activation.xml")
    if not os.path.exists(act_xml):
        raise RuntimeError(
            f"El Kobo aún no tiene el archivo {act_xml}.\n"
            "Paso previo necesario (solo 1 vez):\n"
            "  1. Abre Adobe Digital Editions en tu ordenador.\n"
            "  2. Inicia sesión con tu cuenta de Adobe (Ayuda -> Autorizar equipo).\n"
            "  3. Haz clic en el engranaje junto a 'KOBOeReader' -> 'Autorizar dispositivo'."
        )

    binary_src = os.path.join(BASE_DIR, "ebiblio-kobo")
    if not os.path.exists(binary_src):
        raise RuntimeError(
            f"No se encontró el binario ARM '{binary_src}'.\n"
            "Compílalo para Linux ARM antes de instalar (ej. GOOS=linux GOARCH=arm go build -o ebiblio-kobo ./cmd/ebiblio-kobo)."
        )

    signing_key_path = resolve_signing_key(key_file)
    cfg = ensure_config_json()
    com_info = next((c for c in COMUNIDADES if c[0] == cfg.get("comunidad")), COMUNIDADES[0])

    ebiblio_dir = os.path.join(kobo, ".adds", "ebiblio")
    nm_dir = os.path.join(kobo, ".adds", "nm")
    nm_already_installed = os.path.exists(os.path.join(nm_dir, "ebiblio")) and not os.path.exists(os.path.join(nm_dir, "uninstall"))
    os.makedirs(ebiblio_dir, exist_ok=True)
    os.makedirs(nm_dir, exist_ok=True)

    uninstall_flag = os.path.join(nm_dir, "uninstall")
    if os.path.exists(uninstall_flag):
        os.remove(uninstall_flag)

    # 1. Copy ARM binary, config.json, and adobe_signing_key.json
    binary_dst = os.path.join(ebiblio_dir, "ebiblio-kobo")
    shutil.copy2(binary_src, binary_dst)
    try:
        os.chmod(binary_dst, 0o755)
    except OSError:
        pass

    shutil.copy2(os.path.join(BASE_DIR, "config.json"), os.path.join(ebiblio_dir, "config.json"))
    shutil.copy2(signing_key_path, os.path.join(ebiblio_dir, "adobe_signing_key.json"))
    print(f"[OK] Copiados binario ARM y configuración a {ebiblio_dir}")

    # 2. Write sync.sh and start_ui.sh with strict Unix LF (\n) line endings
    sync_sh = (
        "#!/bin/sh\n"
        "mount -o remount,exec /tmp 2>/dev/null\n"
        "if ! cmp -s /mnt/onboard/.adds/ebiblio/ebiblio-kobo /tmp/ebiblio-kobo 2>/dev/null; then\n"
        "    cp -f /mnt/onboard/.adds/ebiblio/ebiblio-kobo /tmp/ebiblio-kobo\n"
        "    chmod +x /tmp/ebiblio-kobo\n"
        "fi\n"
        "/tmp/ebiblio-kobo --sync >/dev/null 2>&1\n"
        "/bin/sync\n"
        "exit 0\n"
    )
    write_lf_file(os.path.join(ebiblio_dir, "sync.sh"), sync_sh)

    start_ui_sh = (
        "#!/bin/sh\n"
        "LOG=/mnt/onboard/.adds/ebiblio/ui.log\n"
        "ifconfig lo 127.0.0.1 up 2>/dev/null\n"
        "mount -o remount,exec /tmp 2>/dev/null\n"
        "if ! cmp -s /mnt/onboard/.adds/ebiblio/ebiblio-kobo /tmp/ebiblio-kobo 2>/dev/null; then\n"
        "    killall ebiblio-kobo 2>/dev/null\n"
        "    cp -f /mnt/onboard/.adds/ebiblio/ebiblio-kobo /tmp/ebiblio-kobo\n"
        "    chmod +x