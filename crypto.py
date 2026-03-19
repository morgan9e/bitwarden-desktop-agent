import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from secmem import SecureBuffer, wipe


class SymmetricKey:
    def __init__(self, raw: bytes | bytearray):
        if len(raw) != 64:
            raise ValueError(f"expected 64 bytes, got {len(raw)}")
        self._secure = SecureBuffer(raw)
        if isinstance(raw, bytearray):
            wipe(raw)

    @property
    def raw(self) -> bytearray:
        return self._secure.raw

    @property
    def enc_key(self) -> bytearray:
        return self._secure.raw[:32]

    @property
    def mac_key(self) -> bytearray:
        return self._secure.raw[32:]

    def to_b64(self) -> str:
        return base64.b64encode(bytes(self._secure)).decode()

    def close(self):
        self._secure.close()

    @classmethod
    def from_b64(cls, b64: str) -> "SymmetricKey":
        return cls(base64.b64decode(b64))

    @classmethod
    def generate(cls) -> "SymmetricKey":
        return cls(os.urandom(64))


def _decrypt_raw(enc_str: str, key: SymmetricKey) -> bytearray:
    t, rest = enc_str.split(".", 1)
    parts = rest.split("|")
    iv = base64.b64decode(parts[0])
    ct = base64.b64decode(parts[1])
    if len(parts) > 2:
        mac_got = base64.b64decode(parts[2])
        expected = hmac.new(bytes(key.mac_key), iv + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_got, expected):
            raise ValueError("MAC mismatch")
    dec = Cipher(algorithms.AES(bytes(key.enc_key)), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return bytearray(unpadder.update(padded) + unpadder.finalize())


def enc_string_encrypt(plaintext: str, key: SymmetricKey) -> str:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    ct = Cipher(algorithms.AES(bytes(key.enc_key)), modes.CBC(iv)).encryptor()
    encrypted = ct.update(padded) + ct.finalize()
    mac = hmac.new(bytes(key.mac_key), iv + encrypted, hashlib.sha256).digest()
    iv_b64 = base64.b64encode(iv).decode()
    ct_b64 = base64.b64encode(encrypted).decode()
    mac_b64 = base64.b64encode(mac).decode()
    return f"2.{iv_b64}|{ct_b64}|{mac_b64}"


def enc_string_decrypt(enc_str: str, key: SymmetricKey) -> str:
    raw = _decrypt_raw(enc_str, key)
    result = raw.decode()
    wipe(raw)
    return result


def enc_string_decrypt_bytes(enc_str: str, key: SymmetricKey) -> bytearray:
    return _decrypt_raw(enc_str, key)


def enc_string_to_dict(enc_str: str) -> dict:
    t, rest = enc_str.split(".", 1)
    parts = rest.split("|")
    d = {"encryptionType": int(t), "encryptedString": enc_str}
    if len(parts) >= 1:
        d["iv"] = parts[0]
    if len(parts) >= 2:
        d["data"] = parts[1]
    if len(parts) >= 3:
        d["mac"] = parts[2]
    return d


def dict_to_enc_string(d: dict) -> str:
    if s := d.get("encryptedString"):
        return s
    t = d.get("encryptionType", 2)
    return f"{t}.{d.get('iv', '')}|{d.get('data', '')}|{d.get('mac', '')}"
