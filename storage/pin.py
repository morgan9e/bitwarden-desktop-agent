import base64
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import KeyStore

STORE_DIR = Path.home() / ".cache" / "com.bitwarden.desktop" / "keys"


class PinKeyStore(KeyStore):
    def __init__(self, store_dir: Path = STORE_DIR):
        self._dir = store_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self._dir), 0o700)

    @property
    def name(self) -> str:
        return "pin"

    def _path(self, uid: str) -> Path:
        return self._dir / f"{uid}.enc"

    def is_available(self) -> bool:
        return True

    def has_key(self, uid: str) -> bool:
        return self._path(uid).exists()

    def store(self, uid: str, data: bytes, auth: str):
        salt = os.urandom(32)
        enc_key, mac_key = _derive(auth, salt)
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        ct = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
        encrypted = ct.update(padded) + ct.finalize()
        mac = hmac.new(mac_key, salt + iv + encrypted, hashlib.sha256).digest()
        blob = salt + iv + mac + encrypted
        self._path(uid).write_bytes(blob)
        os.chmod(str(self._path(uid)), 0o600)

    def load(self, uid: str, auth: str) -> bytes:
        blob = self._path(uid).read_bytes()
        salt, iv, mac_stored, ct = blob[:32], blob[32:48], blob[48:80], blob[80:]
        enc_key, mac_key = _derive(auth, salt)
        mac_check = hmac.new(mac_key, salt + iv + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_stored, mac_check):
            raise ValueError("Wrong PIN or corrupted data")
        dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def remove(self, uid: str):
        p = self._path(uid)
        if p.exists():
            p.unlink()


def _derive(password: str, salt: bytes) -> tuple[bytes, bytes]:
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, dklen=64)
    return raw[:32], raw[32:]
