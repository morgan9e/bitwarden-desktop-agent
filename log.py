import sys
import time

_start = time.monotonic()

def _ts() -> str:
    elapsed = time.monotonic() - _start
    return f"{elapsed:8.3f}"

def info(msg: str):
    print(f"[{_ts()}] {msg}", file=sys.stderr, flush=True)

def warn(msg: str):
    print(f"[{_ts()}] WARN {msg}", file=sys.stderr, flush=True)

def error(msg: str):
    print(f"[{_ts()}] ERROR {msg}", file=sys.stderr, flush=True)

def fatal(msg: str):
    error(msg)
    sys.exit(1)
