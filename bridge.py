#!/usr/bin/env python3
import argparse
import getpass
import hashlib

import log
from auth import login
from ipc import get_socket_path, serve
from native_messaging import BiometricBridge
from storage import get_backend


def user_hash(email: str) -> str:
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()[:16]


def main():
    p = argparse.ArgumentParser(description="Bitwarden desktop bridge agent")
    p.add_argument("--email", required=True)
    p.add_argument("--password")
    p.add_argument("--server", default="https://vault.bitwarden.com")
    p.add_argument("--backend", choices=["tpm2", "pin"])
    p.add_argument("--enroll", action="store_true", help="re-login and re-seal key")
    args = p.parse_args()

    uid = user_hash(args.email)
    store = get_backend(args.backend)
    log.info(f"storage backend: {store.name}")

    if not store.has_key(uid) or args.enroll:
        if not store.has_key(uid):
            log.info(f"no sealed key found, need to enroll")
        else:
            log.info(f"re-enrolling (--enroll)")

        pw = args.password or getpass.getpass("master password: ")
        log.info(f"logging in as {args.email} ...")
        key_bytes, server_uid = login(args.email, pw, args.server)
        log.info(f"authenticated, user_id={server_uid}")

        auth = getpass.getpass(f"choose {store.name} password: ")
        auth2 = getpass.getpass(f"confirm: ")
        if auth != auth2:
            log.fatal("passwords don't match")
        store.store(uid, key_bytes, auth)
        log.info(f"user key sealed via {store.name}")
    else:
        log.info(f"sealed key ready for {args.email}")

    bridge = BiometricBridge(store, uid)
    sock = get_socket_path()
    log.info(f"listening on {sock}")
    serve(sock, bridge)


if __name__ == "__main__":
    main()
