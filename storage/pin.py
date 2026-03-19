import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import KeyStore

VERSION = 1
STORE_DIR = Path.home() / ".cache" / "com.bitwarden.desktop" / "keys"

SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024


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
        key = _derive(auth, salt)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, data, salt)
        blob = bytes([VERSION]) + salt + nonce + ct
        self._path(uid).write_bytes(blob)
        os.chmod(str(self._path(uid)), 0o600)

    def load(self, uid: str, auth: str) -> bytes:
        blob = self._path(uid).read_bytes()
        _ver, salt, nonce, ct = blob[0], blob[1:33], blob[33:45], blob[45:]
        key = _derive(auth, salt)
        try:
            return AESGCM(key).decrypt(nonce, ct, salt)
        except Exception:
            raise ValueError("wrong password or corrupted data")

    def remove(self, uid: str):
        p = self._path(uid)
        if p.exists():
            p.unlink()


def _derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode(), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=SCRYPT_MAXMEM,
    )
