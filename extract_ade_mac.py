import os
import re
import json
import base64
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ACT_PATH = os.path.expanduser("~/Library/Application Support/Adobe/Digital Editions/activation.dat")

# 1. Get Mac hardware serial number & username (used by ADE on macOS to derive the key)
ioreg_out = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]).decode("utf-8", errors="ignore")
m_serial = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', ioreg_out)
serial = m_serial.group(1).encode("utf-8")
username = os.environ.get("USER", "").encode("utf-8")

# 2. Parse encrypted device key and pkcs12 from activation.dat
tree = ET.parse(ACT_PATH)
root = tree.getroot()
ns = {"adept": "http://ns.adobe.com/adept"}

enc_key_b64 = root.findtext(".//adept:credentials/adept:user/adept:key", namespaces=ns) or root.findtext(".//{http://ns.adobe.com/adept}key")
p12_b64 = root.findtext(".//adept:credentials/adept:user/adept:pkcs12", namespaces=ns) or root.findtext(".//{http://ns.adobe.com/adept}pkcs12")

# 3. Derive macOS ADE AES-128 key & decrypt device key
aes_key = hashlib.sha256(serial + username).digest()[:16]
enc_key = base64.b64decode(enc_key_b64)
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b"\x00" * 16))
decryptor = cipher.decryptor()
raw_key = decryptor.update(enc_key) + decryptor.finalize()
pad = raw_key[-1]
if 1 <= pad <= 16:
     raw_key = raw_key[:-pad]
pass_b64 = base64.b64encode(raw_key).decode("ascii")

# 4. Extract cert + RSA modulus (n) & privateExponent (d) via OpenSSL
p12_tmp = os.path.join(BASE_DIR, "_temp_ade.p12")
pem_tmp = os.path.join(BASE_DIR, "_temp_ade.pem")
with open(p12_tmp, "wb") as f:
    f.write(base64.b64decode(p12_b64))

try:
    subprocess.run(["openssl", "pkcs12", "-in", p12_tmp, "-passin", f"pass:{pass_b64}", "-nodes", "-out", pem_tmp], check=True)
except subprocess.CalledProcessError:
    # OpenSSL 3+ on Homebrew often needs -legacy for older RC2/3DES PKCS12 files
    subprocess.run(["openssl", "pkcs12", "-in", p12_tmp, "-passin", f"pass:{pass_b64}", "-nodes", "-legacy", "-out", pem_tmp], check=True)

with open(pem_tmp, "r", encoding="utf-8", errors="ignore") as f:
    pem_content = f.read()

m_cert = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem_content, re.S)
cert_b64 = re.sub(r"\s+", "", m_cert.group(1))
out_txt = subprocess.check_output(["openssl", "rsa", "-in", pem_tmp, "-text", "-noout"]).decode("utf-8")

os.remove(p12_tmp)
os.remove(pem_tmp)

def get_hex(label):
    m = re.search(label + r":\s+((?:[0-9a-fA-F]{2}:?\s*)+)", out_txt)
    return hex(int(re.sub(r"[^0-9a-fA-F]", "", m.group(1)), 16))

out_path = os.path.join(BASE_DIR, "adobe_signing_key.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"n": get_hex("modulus"), "d": get_hex("privateExponent"), "cert": cert_b64}, f, indent=2)

print(f"[OK] Creado {out_path}")