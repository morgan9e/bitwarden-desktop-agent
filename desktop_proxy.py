#!/usr/bin/env python3
import os
import socket
import struct
import sys
import threading
from pathlib import Path


def ipc_socket_path() -> str:
    return str(Path.home() / ".librewolf" / "s.bw")


def read_stdin_message() -> bytes | None:
    header = sys.stdin.buffer.read(4)
    if len(header) < 4:
        return None
    length = struct.unpack("=I", header)[0]
    if length == 0 or length > 1024 * 1024:
        return None
    data = sys.stdin.buffer.read(length)
    if len(data) < length:
        return None
    return data


def write_stdout_message(data: bytes):
    header = struct.pack("=I", len(data))
    sys.stdout.buffer.write(header + data)
    sys.stdout.buffer.flush()


def read_ipc_message(sock: socket.socket) -> bytes | None:
    header = recv_exact(sock, 4)
    if header is None:
        return None
    length = struct.unpack("=I", header)[0]
    if length == 0 or length > 1024 * 1024:
        return None
    return recv_exact(sock, length)


def send_ipc_message(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("=I", len(data)) + data)


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def ipc_to_stdout(sock: socket.socket):
    try:
        while True:
            msg = read_ipc_message(sock)
            if msg is None:
                break
            write_stdout_message(msg)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass


def main():
    path = ipc_socket_path()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except (FileNotFoundError, ConnectionRefusedError):
        sys.exit(1)

    send_ipc_message(sock, b'{"command":"connected"}')

    reader = threading.Thread(target=ipc_to_stdout, args=(sock,), daemon=True)
    reader.start()

    try:
        while True:
            msg = read_stdin_message()
            if msg is None:
                break
            send_ipc_message(sock, msg)
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            send_ipc_message(sock, b'{"command":"disconnected"}')
        except OSError:
            pass
        sock.close()


if __name__ == "__main__":
    main()
