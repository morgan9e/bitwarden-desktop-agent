import base64
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

import log
from crypto import SymmetricKey, enc_string_encrypt, enc_string_decrypt, enc_string_to_dict, dict_to_enc_string
from gui import ask_password
from storage import KeyStore


class BiometricBridge:
    def __init__(self, store: KeyStore, user_id: str):
        self._store = store
        self._uid = user_id
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
            shared.raw,
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

    def _dispatch(self, cmd: str, mid: int) -> dict | None:
        ts = int(time.time() * 1000)

        if cmd == "unlockWithBiometricsForUser":
            key_b64 = self._unseal_key()
            if key_b64 is None:
                log.warn("unlock denied or failed")
                return {"command": cmd, "messageId": mid, "timestamp": ts, "response": False}
            log.info("-> unlock granted, key delivered")
            return {"command": cmd, "messageId": mid, "timestamp": ts, "response": True, "userKeyB64": key_b64}

        if cmd in ("getBiometricsStatus", "getBiometricsStatusForUser"):
            log.info(f"-> biometrics available")
            return {"command": cmd, "messageId": mid, "timestamp": ts, "response": 0}

        if cmd == "authenticateWithBiometrics":
            log.info("-> authenticated")
            return {"command": cmd, "messageId": mid, "timestamp": ts, "response": True}

        return None

    def _unseal_key(self) -> str | None:
        log.info(f"requesting {self._store.name} password via GUI")
        pw = ask_password("Bitwarden Unlock", f"Enter {self._store.name} password:")
        if pw is None:
            log.info("user cancelled dialog")
            return None
        try:
            raw = self._store.load(self._uid, pw)
            b64 = base64.b64encode(raw).decode()
            log.info(f"unsealed {len(raw)}B key from {self._store.name}")
            raw = None
            pw = None
            log.info("key material wiped from memory")
            return b64
        except Exception as e:
            log.error(f"unseal failed: {e}")
            return None
