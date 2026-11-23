import base64
import ctypes
import glob
import json
import os
import re
import winreg
from ctypes import wintypes


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def dpapi_decrypt(encrypted_bytes: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    if not encrypted_bytes:
        raise ValueError("Empty input passed to dpapi_decrypt")

    buf_in = ctypes.create_string_buffer(encrypted_bytes)
    in_blob = DATA_BLOB(
        len(encrypted_bytes),
        ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_byte)),
    )
    out_blob = DATA_BLOB()

    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        err = ctypes.GetLastError()
        raise RuntimeError(f"CryptUnprotectData failed (Win32 error {err})")

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def try_decrypt_candidate(raw_val) -> bytes | None:
    candidates = []
    if isinstance(raw_val, bytes):
        candidates.append(raw_val)
    elif isinstance(raw_val, str):
        s = raw_val.strip()
        if not s:
            return None
        # Try base64 if it looks like base64
        if re.fullmatch(r"[A-Za-z0-9+/=]+", s) and len(s) >= 24:
            try:
                candidates.append(base64.b64decode(s, validate=True))
            except Exception:
                pass
        # Try hex if it looks like hex
        hex_clean = re.sub(r"\s+", "", s.removeprefix("0x"))
        if re.fullmatch(r"[0-9A-Fa-f]+", hex_clean) and len(hex_clean) >= 24 and len(hex_clean) % 2 == 0:
            try:
                candidates.append(bytes.fromhex(hex_clean))
            except Exception:
                pass
        candidates.append(s.encode("utf-8", errors="ignore"))

    for blob in candidates:
        # DPAPI blobs typically start with bytes 01 00 00 00 (version 1)
        if len(blob) >= 16:
            try:
                return dpapi_decrypt(blob)
            except Exception:
                continue
    return None


def scan_registry():
    decrypted_items = []
    roots = [
        ("HKCU", winreg.HKEY_CURRENT_USER),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE),
    ]
    paths = [
        r"Software\Adobe\Adept",
        r"Software\Adobe\Digital Editions",
    ]
    for root_name, root_key in roots:
        for subkey in paths:
            try:
                with winreg.OpenKey(root_key, subkey) as k:
                    idx = 0
                    while True:
                        try:
                            name, val, reg_type = winreg.EnumValue(k, idx)
                        except OSError:
                            break
                        idx += 1
                        dec = try_decrypt_candidate(val)
                        if dec is not None:
                            print(f"[DPAPI OK] {root_name}\\{subkey} -> {name} ({len(dec)} bytes)")
                            decrypted_items.append((f"reg:{root_name}\\{subkey}\\{name}", dec))
                        else:
                            print(f"[SKIP]     {root_name}\\{subkey} -> {name} (type={reg_type})")
            except FileNotFoundError:
                pass
            except OSError as exc:
                print(f"[ERR]      {root_name}\\{subkey}: {exc}")
    return decrypted_items


def scan_ade_files():
    decrypted_items = []
    search_roots = [
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("APPDATA", ""),
        os.path.expanduser("~\\Documents"),
    ]
    for base in search_roots:
        if not base or not os.path.isdir(base):
            continue
        for pat in ("**/*activation*", "**/*adept*", "**/*.dat", "**/*.xml"):
            for path in glob.glob(os.path.join(base, pat), recursive=True):
                if not os.path.isfile(path):
                    continue
                low = path.lower()
                if "adobe" not in low and "digital editions" not in low and "adept" not in low:
                    continue
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                dec = try_decrypt_candidate(data)
                if dec is not None:
                    print(f"[DPAPI OK] file:{path} ({len(dec)} bytes)")
                    decrypted_items.append((f"file:{path}", dec))
    return decrypted_items


def main():
    print("Buscando y descifrando datos DPAPI de Adobe Digital Editions...")
    items = scan_registry() + scan_ade_files()
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dpapi_dumps")
    os.makedirs(out_dir, exist_ok=True)

    for i, (source, blob) in enumerate(items, 1):
        out_path = os.path.join(out_dir, f"dump_{i:02d}.bin")
        with open(out_path, "wb") as f:
            f.write(blob)
        print(f"  -> Guardado {out_path} desde {source}")

    if not items:
        print("No se pudo descifrar ningún bloque con DPAPI.")
        print("Asegúrate de haber autorizado Adobe Digital Editions en este mismo usuario de Windows.")
    else:
        print(f"\nListo: {len(items)} bloque(s) descifrado(s) en '{out_dir}'.")
        print("Revisa esos volcados para mapear los campos 'n', 'd' y 'cert' a adobe_signing_key.json.")


if __name__ == "__main__":
    main()