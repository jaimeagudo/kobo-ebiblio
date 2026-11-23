import base64
import ctypes
import json
import os
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
    buf_in = ctypes.create_string_buffer(encrypted_bytes)
    in_blob = DATA_BLOB(len(encrypted_bytes), ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError(f"CryptUnprotectData failed: error {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def read_adept_values():
    out = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Adobe\Adept\Device") as k:
        dev_key, _ = winreg.QueryValueEx(k, "key")
        out["device_key_dpapi_decrypted_len"] = len(dpapi_decrypt(dev_key))
        out["device_key_dpapi_decrypted_hex"] = dpapi_decrypt(dev_key).hex()

    base = r"Software\Adobe\Adept\Activation\0001"
    for sub, val_name in [("0001", "value"), ("0002", "value"), ("0003", "value")]:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{base}\\{sub}") as sk:
            default_label, _ = winreg.QueryValueEx(sk, "")
            val, _ = winreg.QueryValueEx(sk, val_name)
            out[default_label] = val
    return out


def main():
    data = read_adept_values()
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "adept_extracted_raw.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Saved raw extracted fields to: {out_path}")
    print("Keys found:", list(data.keys()))


if __name__ == "__main__":
    main()