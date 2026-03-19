import ctypes
import ctypes.util
import sys

if sys.platform == "darwin":
    _libc = ctypes.CDLL("libSystem.B.dylib")
else:
    _libc = ctypes.CDLL(ctypes.util.find_library("c"))

_mlock = _libc.mlock
_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_mlock.restype = ctypes.c_int

_munlock = _libc.munlock
_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_munlock.restype = ctypes.c_int


def _addr(buf: bytearray) -> int:
    return ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))


def mlock(buf: bytearray):
    if len(buf) > 0:
        _mlock(_addr(buf), len(buf))


def munlock(buf: bytearray):
    if len(buf) > 0:
        _munlock(_addr(buf), len(buf))


def wipe(buf: bytearray):
    for i in range(len(buf)):
        buf[i] = 0


class SecureBuffer:
    __slots__ = ("_buf",)

    def __init__(self, data: bytes | bytearray):
        self._buf = bytearray(data)
        mlock(self._buf)

    @property
    def raw(self) -> bytearray:
        return self._buf

    def __len__(self):
        return len(self._buf)

    def __bytes__(self):
        return bytes(self._buf)

    def __del__(self):
        self.close()

    def close(self):
        if self._buf:
            wipe(self._buf)
            munlock(self._buf)
