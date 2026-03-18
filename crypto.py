import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SymmetricKey:
    def __init__(self, raw: bytes):
        if len(raw) != 64:
            raise ValueError(f"Expected 64 bytes, got {len(raw)}")
        self.raw = raw
        self.enc_key = raw[:32]
        self.mac_key = raw[32:]

    def to_b64(self) -> str:
        return base64.b64encode(self.raw).decode()

    @classmethod
    def from_b64(cls, b64: str) -> "SymmetricKey":
        return cls(base64.b64decode(b64))

    @classmethod
    def generate(cls) -> "SymmetricKey":
        return cls(os.urandom(64))


def enc_string_encrypt(plaintext: str, key: SymmetricKey) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key.enc_key), modes.CBC(iv))
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(key.mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{base64.b64encode(iv).decode()}|{base64.b64encode(ct).decode()}|{base64.b64encode(mac).decode()}"


def enc_string_decrypt(enc_str: str, key: SymmetricKey) -> str:
    t, rest = enc_str.split(".", 1)
    if t != "2":
        raise ValueError(f"Unsupported type {t}")
    parts = rest.split("|")
    iv = base64.b64decode(parts[0])
    ct = base64.b64decode(parts[1])
    mac_got = base64.b64decode(parts[2])
    if not hmac.compare_digest(mac_got, hmac.new(key.mac_key, iv + ct, hashlib.sha256).digest()):
        raise ValueError("MAC mismatch")
    dec = Cipher(algorithms.AES(key.enc_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def enc_string_decrypt_bytes(enc_str: str, key: SymmetricKey) -> bytes:
    t, rest = enc_str.split(".", 1)
    parts = rest.split("|")
    iv = base64.b64decode(parts[0])
    ct = base64.b64decode(parts[1])
    mac_got = base64.b64decode(parts[2]) if len(parts) > 2 else None
    if mac_got and not hmac.compare_digest(mac_got, hmac.new(key.mac_key, iv + ct, hashlib.sha256).digest()):
        raise ValueError("MAC mismatch")
    dec = Cipher(algorithms.AES(key.enc_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def enc_string_to_dict(enc_str: str) -> dict:
    t, rest = enc_str.split(".", 1)
    parts = rest.split("|")
    d = {"encryptionType": int(t), "encryptedString": enc_str}
    if len(parts) >= 1: d["iv"] = parts[0]
    if len(parts) >= 2: d["data"] = parts[1]
    if len(parts) >= 3: d["mac"] = parts[2]
    return d


def dict_to_enc_string(d: dict) -> str:
    if d.get("encryptedString"):
        return d["encryptedString"]
    return f"{d.get('encryptionType', 2)}.{d.get('iv', '')}|{d.get('data', '')}|{d.get('mac', '')}"
