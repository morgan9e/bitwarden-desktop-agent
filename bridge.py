#!/usr/bin/env python3
import argparse
import hashlib

import log
from askpass import get_prompter, available
from auth import login
from ipc import get_socket_path, serve
from native_messaging import BiometricBridge
from secmem import wipe
from storage import get_backend


def user_hash(email: str) -> str:
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()[:16]


def main():
    p = argparse.ArgumentParser(description="Bitwarden desktop bridge agent")
    p.add_argument("--email", required=True)
    p.add_argument("--password")
    p.add_argument("--server", default="https://vault.bitwarden.com")
    p.add_argument("--backend", choices=["tpm2", "pin"])
    p.add_argument("--askpass", choices=available())
    p.add_argument("--enroll", action="store_true")
    p.add_argument("--remove", action="store_true")
    args = p.parse_args()

    uid = user_hash(args.email)
    store = get_backend(args.backend)
    prompt = get_prompter(args.askpass)
    log.info(f"backend: {store.name}")

    if args.remove:
        if store.has_key(uid):
            store.remove(uid)
            log.info(f"key removed for {args.email}")
        else:
            log.info(f"no key found for {args.email}")
        return

    if not store.has_key(uid) or args.enroll:
        log.info("enrolling" if not store.has_key(uid) else "re-enrolling")
        pw = args.password or prompt("master password:")
        if pw is None:
            log.fatal("no password provided")
        log.info(f"logging in as {args.email}")
        key_bytes, server_uid = login(args.email, pw, args.server, prompt)
        pw = None
        log.info(f"authenticated, uid={server_uid}")

        auth = prompt(f"choose {store.name} password:")
        if auth is None:
            log.fatal("no password provided")
        auth2 = prompt(f"confirm {store.name} password:")
        if auth != auth2:
            log.fatal("passwords don't match")
        store.store(uid, bytes(key_bytes), auth)
        wipe(key_bytes)
        auth = None
        auth2 = None
        log.info(f"key sealed via {store.name}")
    else:
        log.info(f"key ready for {args.email}")

    bridge = BiometricBridge(store, uid, prompt)
    sock = get_socket_path()
    log.info(f"listening on {sock}")
    serve(sock, bridge)


if __name__ == "__main__":
    main()
