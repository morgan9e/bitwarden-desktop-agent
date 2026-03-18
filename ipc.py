import json
import os
import socket
import struct
from pathlib import Path

import log


def get_socket_path() -> Path:
    cache = Path.home() / ".cache" / "com.bitwarden.desktop"
    cache.mkdir(parents=True, exist_ok=True)
    return cache / "s.bw"


def recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_message(conn: socket.socket) -> dict | None:
    header = recv_exact(conn, 4)
    if not header:
        return None
    length = struct.unpack("=I", header)[0]
    if length == 0 or length > 1024 * 1024:
        return None
    data = recv_exact(conn, length)
    if not data:
        return None
    return json.loads(data)


def send_message(conn: socket.socket, msg: dict):
    data = json.dumps(msg).encode()
    conn.sendall(struct.pack("=I", len(data)) + data)


def serve(sock_path: Path, handler):
    if sock_path.exists():
        sock_path.unlink()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    srv.listen(5)
    os.chmod(str(sock_path), 0o600)

    try:
        while True:
            conn, _ = srv.accept()
            log.info("client connected")
            _handle_conn(conn, handler)
            log.info("client disconnected")
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        srv.close()
        if sock_path.exists():
            sock_path.unlink()


def _handle_conn(conn: socket.socket, handler):
    try:
        while True:
            msg = read_message(conn)
            if msg is None:
                break
            if "command" in msg and "appId" not in msg:
                log.info(f"proxy: {msg.get('command')}")
                continue
            resp = handler(msg)
            if resp is not None:
                send_message(conn, resp)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()
