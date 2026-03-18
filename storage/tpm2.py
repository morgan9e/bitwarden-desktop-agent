import os
import subprocess
import tempfile
from pathlib import Path

from . import KeyStore

STORE_DIR = Path.home() / ".cache" / "com.bitwarden.desktop" / "tpm2"


class TPM2KeyStore(KeyStore):
    def __init__(self, store_dir: Path = STORE_DIR):
        self._dir = store_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self._dir), 0o700)

    @property
    def name(self) -> str:
        return "tpm2"

    def _pub(self, uid: str) -> Path:
        return self._dir / f"{uid}.pub"

    def _priv(self, uid: str) -> Path:
        return self._dir / f"{uid}.priv"

    def is_available(self) -> bool:
        try:
            return subprocess.run(
                ["tpm2_getcap", "properties-fixed"],
                capture_output=True, timeout=5,
            ).returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def has_key(self, uid: str) -> bool:
        return self._pub(uid).exists() and self._priv(uid).exists()

    def store(self, uid: str, data: bytes, auth: str):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            ctx = t / "primary.ctx"
            dat = t / "data.bin"
            dat.write_bytes(data)
            os.chmod(str(dat), 0o600)

            _run(["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "aes256cfb", "-c", str(ctx)])
            _run(["tpm2_create", "-C", str(ctx), "-i", str(dat),
                  "-u", str(self._pub(uid)), "-r", str(self._priv(uid)), "-p", auth])
            dat.write_bytes(b"\x00" * len(data))

        os.chmod(str(self._pub(uid)), 0o600)
        os.chmod(str(self._priv(uid)), 0o600)

    def load(self, uid: str, auth: str) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            ctx = t / "primary.ctx"
            loaded = t / "loaded.ctx"

            _run(["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "aes256cfb", "-c", str(ctx)])
            _run(["tpm2_load", "-C", str(ctx),
                  "-u", str(self._pub(uid)), "-r", str(self._priv(uid)), "-c", str(loaded)])
            return _run(["tpm2_unseal", "-c", str(loaded), "-p", auth]).stdout

    def remove(self, uid: str):
        for p in (self._pub(uid), self._priv(uid)):
            if p.exists():
                p.unlink()


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors="replace").strip())
    return r
