from abc import ABC, abstractmethod


class KeyStore(ABC):
    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def has_key(self, user_id: str) -> bool: ...

    @abstractmethod
    def store(self, user_id: str, data: bytes, auth: str) -> None: ...

    @abstractmethod
    def load(self, user_id: str, auth: str) -> bytes: ...

    @abstractmethod
    def remove(self, user_id: str) -> None: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


def get_backend(preferred: str | None = None) -> KeyStore:
    from .tpm2 import TPM2KeyStore
    from .pin import PinKeyStore

    if preferred == "pin":
        return PinKeyStore()
    if preferred == "tpm2":
        store = TPM2KeyStore()
        if not store.is_available():
            raise RuntimeError("TPM2 not available")
        return store

    tpm = TPM2KeyStore()
    if tpm.is_available():
        return tpm
    return PinKeyStore()
