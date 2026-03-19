#!/opt/homebrew/bin/python3
import socket
import struct
import sys
import threading
from pathlib import Path

MAX_MSG = 1024 * 1024


def ipc_socket_path() -> str:
    return str(Path.home() / ".cache" / "com.bitwarden.desktop" / "s.bw")


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_stdin() -> bytes | None:
    header = sys.stdin.buffer.read(4)
    if len(header) < 4:
        return None
    length = struct.unpack("=I", header)[0]
    if length == 0 or length > MAX_MSG:
        return None
    data = sys.stdin.buffer.read(length)
    return data if len(data) == length else None


def write_stdout(data: bytes):
    sys.stdout.buffer.write(struct.pack("=I", len(data)) + data)
    sys.stdout.buffer.flush()


def read_ipc(sock: socket.socket) -> bytes | None:
    header = recv_exact(sock, 4)
    if header is None:
        return None
    length = struct.unpack("=I", header)[0]
    if length == 0 or length > MAX_MSG:
        return None
    return recv_exact(sock, length)


def send_ipc(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("=I", len(data)) + data)


def ipc_to_stdout(sock: socket.socket):
    try:
        while True:
            msg = read_ipc(sock)
            if msg is None:
                break
            write_stdout(msg)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass


def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(ipc_socket_path())
    except (FileNotFoundError, ConnectionRefusedError):
        sys.exit(1)

    send_ipc(sock, b'{"command":"connected"}')
    threading.Thread(target=ipc_to_stdout, args=(sock,), daemon=True).start()

    try:
        while True:
            msg = read_stdin()
            if msg is None:
                break
            send_ipc(sock, msg)
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            send_ipc(sock, b'{"command":"disconnected"}')
        except OSError:
            pass
        sock.close()


if __name__ == "__main__":
    main()
