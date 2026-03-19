import base64
import hashlib
import hmac
import json
import urllib.parse
import urllib.request
import uuid

import log
from askpass import Prompter
from crypto import SymmetricKey, enc_string_decrypt_bytes
from secmem import wipe


def login(email: str, password: str, server: str, prompt: Prompter) -> tuple[bytearray, str]:
    base = server.rstrip("/")
    if "bitwarden.com" in base or "bitwarden.eu" in base:
        api = base.replace("vault.", "api.")
        identity = base.replace("vault.", "identity.")
    else:
        api, identity = base + "/api", base + "/identity"

    log.info(f"prelogin {api}/accounts/prelogin")
    prelogin = _json_post(f"{api}/accounts/prelogin", {"email": email})
    kdf_type = _get(prelogin, "kdf", 0)
    kdf_iter = _get(prelogin, "kdfIterations", 600000)
    kdf_mem = _get(prelogin, "kdfMemory", 64)
    kdf_par = _get(prelogin, "kdfParallelism", 4)
    log.info(f"kdf: {'pbkdf2' if kdf_type == 0 else 'argon2id'} iterations={kdf_iter}")

    log.info("deriving master key...")
    master_key = bytearray(_derive_master_key(password, email, kdf_type, kdf_iter, kdf_mem, kdf_par))
    pw_hash = base64.b64encode(
        hashlib.pbkdf2_hmac("sha256", bytes(master_key), password.encode(), 1, dklen=32)
    ).decode()

    form = {
        "grant_type": "password", "username": email, "password": pw_hash,
        "scope": "api offline_access", "client_id": "connector",
        "deviceType": "8", "deviceIdentifier": str(uuid.uuid4()), "deviceName": "bw-bridge",
    }

    log.info(f"token {identity}/connect/token")
    token_resp = _try_login(f"{identity}/connect/token", form, prompt)

    enc_user_key = _extract_encrypted_user_key(token_resp)
    log.info("decrypting user key...")
    stretched = _stretch(master_key)
    wipe(master_key)
    user_key = enc_string_decrypt_bytes(enc_user_key, stretched)
    stretched.close()
    user_id = _extract_user_id(token_resp.get("access_token", ""))
    log.info(f"user key decrypted ({len(user_key)}B)")

    return user_key, user_id


def _get(d: dict, key: str, default=None):
    return d.get(key, d.get(key[0].upper() + key[1:], default))


def _try_login(url: str, form: dict, prompt: Prompter) -> dict:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "application/json", "Device-Type": "8",
    }
    try:
        return _form_post(url, form, headers)
    except _HttpError as e:
        if "TwoFactor" not in e.body:
            log.fatal(f"login failed: {e.body[:200]}")

        body = json.loads(e.body)
        providers = _get(body, "twoFactorProviders2", {})

        if "0" not in providers and 0 not in providers:
            log.fatal("2FA required but TOTP not available")

        log.info("TOTP required")
        code = prompt("TOTP code:")
        if code is None:
            log.fatal("no TOTP code provided")
        form["twoFactorToken"] = code.strip()
        form["twoFactorProvider"] = "0"
        return _form_post(url, form, headers)


def _extract_encrypted_user_key(resp: dict) -> str:
    udo = _get(resp, "userDecryptionOptions")
    if udo:
        mpu = _get(udo, "masterPasswordUnlock")
        if mpu:
            k = _get(mpu, "masterKeyEncryptedUserKey")
            if k:
                return k
    k = _get(resp, "key")
    if k:
        return k
    log.fatal("no encrypted user key in server response")


def _extract_user_id(token: str) -> str:
    try:
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("sub", "unknown")
    except Exception:
        return "unknown"


def _derive_master_key(pw: str, email: str, kdf: int, iters: int, mem: int, par: int) -> bytes:
    salt = email.lower().strip().encode()
    if kdf == 0:
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters, dklen=32)
    if kdf == 1:
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(
            secret=pw.encode(), salt=salt, time_cost=iters,
            memory_cost=mem * 1024, parallelism=par, hash_len=32, type=Type.ID,
        )
    log.fatal(f"unsupported kdf type: {kdf}")


def _stretch(master_key: bytearray) -> SymmetricKey:
    enc = hmac.new(bytes(master_key), b"enc\x01", hashlib.sha256).digest()
    mac = hmac.new(bytes(master_key), b"mac\x01", hashlib.sha256).digest()
    return SymmetricKey(bytearray(enc + mac))


class _HttpError(Exception):
    def __init__(self, code: int, body: str):
        self.code, self.body = code, body
        super().__init__(f"HTTP {code}")


def _json_post(url: str, data: dict) -> dict:
    req = urllib.request.Request(url, json.dumps(data).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def _form_post(url: str, form: dict, headers: dict) -> dict:
    req = urllib.request.Request(url, urllib.parse.urlencode(form).encode(), headers)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise _HttpError(e.code, e.read().decode()) from e
