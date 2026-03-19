import base64
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

import log
from askpass import Prompter
from crypto import SymmetricKey, enc_string_encrypt, enc_string_decrypt, enc_string_to_dict, dict_to_enc_string
from secmem import wipe
from storage import KeyStore


class BiometricBridge:
    def __init__(self, store: KeyStore, user_id: str, prompter: Prompter):
        self._store = store
        self._uid = user_id
        self._prompt = prompter
        self._sessions: dict[str, SymmetricKey] = {}

    def __call__(self, msg: dict) -> dict | None:
        app_id = msg.get("appId", "")
        message = msg.get("message")
        if message is None:
            return None

        if isinstance(message, dict) and message.get("command") == "setupEncryption":
            return self._handshake(app_id, message)

        if isinstance(message, dict) and ("encryptedString" in message or "encryptionType" in message):
            return self._encrypted(app_id, message)

        if isinstance(message, str) and message.startswith("2."):
            return self._encrypted(app_id, {"encryptedString": message})

        return None

    def _handshake(self, app_id: str, msg: dict) -> dict:
        pub_bytes = base64.b64decode(msg.get("publicKey", ""))
        pub_key = serialization.load_der_public_key(pub_bytes)

        shared = SymmetricKey.generate()
        self._sessions[app_id] = shared

        encrypted = pub_key.encrypt(
            bytes(shared.raw),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(), label=None,
            ),
        )

        log.info(f"handshake complete, app={app_id[:12]}")
        return {
            "appId": app_id,
            "command": "setupEncryption",
            "messageId": -1,
            "sharedSecret": base64.b64encode(encrypted).decode(),
        }

    def _encrypted(self, app_id: str, enc_msg: dict) -> dict | None:
        if app_id not in self._sessions:
            log.warn(f"no session for app={app_id[:12]}")
            return {"appId": app_id, "command": "invalidateEncryption"}

        key = self._sessions[app_id]
        try:
            plaintext = enc_string_decrypt(dict_to_enc_string(enc_msg), key)
        except Exception:
            log.error("message decryption failed")
            return {"appId": app_id, "command": "invalidateEncryption"}

        data = json.loads(plaintext)
        cmd = data.get("command", "")
        mid = data.get("messageId", 0)

        log.info(f"<- {cmd} (msg={mid})")
        resp = self._dispatch(cmd, mid)
        if resp is None:
            log.warn(f"unhandled command: {cmd}")
            return None

        encrypted = enc_string_encrypt(json.dumps(resp), key)
        return {"appId": app_id, "messageId": mid, "message": enc_string_to_dict(encrypted)}

    def _reply(self, cmd: str, mid: int, **kwargs) -> dict:
        return {"command": cmd, "messageId": mid, "timestamp": int(time.time() * 1000), **kwargs}

    def _dispatch(self, cmd: str, mid: int) -> dict | None:
        handlers = {
            "unlockWithBiometricsForUser": self._handle_unlock,
            "getBiometricsStatus": self._handle_status,
            "getBiometricsStatusForUser": self._handle_status,
            "authenticateWithBiometrics": self._handle_auth,
        }
        handler = handlers.get(cmd)
        if handler is None:
            return None
        return handler(cmd, mid)

    def _handle_unlock(self, cmd: str, mid: int) -> dict:
        key_b64 = self._unseal_key()
        if key_b64 is None:
            log.warn("unlock denied or failed")
            return self._reply(cmd, mid, response=False)
        log.info("-> unlock granted")
        resp = self._reply(cmd, mid, response=True, userKeyB64=key_b64)
        key_b64 = None
        return resp

    def _handle_status(self, cmd: str, mid: int) -> dict:
        log.info("-> biometrics available")
        return self._reply(cmd, mid, response=0)

    def _handle_auth(self, cmd: str, mid: int) -> dict:
        log.info("-> authenticated")
        return self._reply(cmd, mid, response=True)

    def _unseal_key(self) -> str | None:
        pw = self._prompt(f"Enter {self._store.name} password:")
        if pw is None:
            log.info("cancelled")
            return None
        try:
            raw = self._store.load(self._uid, pw)
            pw = None
            b64 = base64.b64encode(bytes(raw)).decode()
            if isinstance(raw, bytearray):
                wipe(raw)
            log.info(f"unsealed {len(raw)}B from {self._store.name}")
            return b64
        except Exception as e:
            log.error(f"unseal failed: {e}")
            return None
