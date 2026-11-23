import ctypes
import json
import os
import winreg
from ctypes import wintypes


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.c_void_p),
    ]


def dpapi_decrypt(encrypted_bytes: bytes) -> bytes:
    if not isinstance(encrypted_bytes, (bytes, bytearray)) or len(encrypted_bytes) == 0:
        raise ValueError("Expected non-empty bytes for DPAPI decryption")

    try:
        import win32crypt  # type: ignore

        _, decrypted = win32crypt.CryptUnprotectData(bytes(encrypted_bytes), None, None, None, 0)
        return decrypted
    except ImportError:
        pass

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_wchar_p,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    raw = bytes(encrypted_bytes)
    in_buf = ctypes.create_string_buffer(raw, len(raw))
    in_blob = DATA_BLOB(len(raw), ctypes.cast(in_buf, ctypes.c_void_p).value)
    out_blob = DATA_BLOB(0, None)

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        err = ctypes.GetLastError()
        raise RuntimeError(f"CryptUnprotectData failed: error {err}")

    try:
        size = int(out_blob.cbData)
        out_buf = ctypes.create_string_buffer(size)
        if size > 0 and out_blob.pbData:
            ctypes.memmove(out_buf, out_blob.pbData, size)
        return out_buf.raw
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)


def read_adept_values():
    out = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Adobe\Adept\Device") as k:
        dev_key, reg_type = winreg.QueryValueEx(k, "key")
        if reg_type != winreg.REG_BINARY:
            raise RuntimeError(f"Unexpected registry type for Device\\key: {reg_type}")
        decrypted = dpapi_decrypt(dev_key)
        out["device_key_dpapi_decrypted_len"] = len(decrypted)
        out["device_key_dpapi_decrypted_hex"] = decrypted.hex()

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