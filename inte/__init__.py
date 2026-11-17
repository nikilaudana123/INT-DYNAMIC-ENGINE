import ctypes
import os
import subprocess
import hashlib
import struct
from pathlib import Path


def _resolve_library(custom_path: str | None = None) -> str:
    if custom_path and os.path.exists(custom_path):
        return os.path.abspath(custom_path)

    pkg_dir = Path(__file__).resolve().parent
    bundled_so = pkg_dir / "_native" / "libinte.so"
    if bundled_so.exists():
        return str(bundled_so)

    system_so = Path("/usr/local/lib/libinte.so")
    if system_so.exists():
        return str(system_so)

    cache_dir = Path.home() / ".cache" / "int-dynamic-engine"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached_so = cache_dir / "libinte.so"

    if not cached_so.exists():
        cpp_src = pkg_dir / "_native" / "inte_core.cpp"
        cmd = [
            "g++", "-O3", "-shared", "-fPIC", "-std=c++17",
            str(cpp_src), "-o", str(cached_so),
            "-lssl", "-lcrypto", "-lpthread"
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except FileNotFoundError:
            raise RuntimeError("g++ compiler not found. Install g++ and libssl-dev (e.g., sudo apt install g++ libssl-dev).")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to compile C++ core:\n{e.stderr}")

    return str(cached_so)


class IntDynamicEngine:
    def __init__(self, storage_dir: str, max_ram_mb: float = 16.0, secret_key: str = "inttech-default-key", lib_path: str | None = None):
        so_path = _resolve_library(lib_path)
        self.lib = ctypes.CDLL(so_path)

        self.lib.inte_init.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8)]
        self.lib.inte_init.restype = ctypes.c_void_p

        self.lib.inte_put.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
        self.lib.inte_put.restype = ctypes.c_int

        self.lib.inte_get.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t)]
        self.lib.inte_get.restype = ctypes.c_int

        self.lib.inte_free_buf.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
        self.lib.inte_free_buf.restype = None

        self.lib.inte_delete.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.inte_delete.restype = ctypes.c_int

        self.lib.inte_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
        self.lib.inte_stats.restype = None

        self.lib.inte_close.argtypes = [ctypes.c_void_p]
        self.lib.inte_close.restype = None

        self.lib.inte_disk_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
        self.lib.inte_disk_stats.restype = None

        self.lib.inte_compact.argtypes = [ctypes.c_void_p]
        self.lib.inte_compact.restype = ctypes.c_int

        self.SCAN_CB_TYPE = ctypes.CFUNCTYPE(
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.c_void_p
        )

        self.lib.inte_scan_prefix.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
            self.SCAN_CB_TYPE, ctypes.c_void_p
        ]
        self.lib.inte_scan_prefix.restype = ctypes.c_int

        self.lib.inte_aggregate_double_prefix.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_double),
            ctypes.POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double)
        ]
        self.lib.inte_aggregate_double_prefix.restype = ctypes.c_int

        key_bytes = hashlib.sha256(secret_key.encode("utf-8")).digest()
        key_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key_bytes)

        max_ram_bytes = int(max_ram_mb * 1024 * 1024)
        self.handle = self.lib.inte_init(storage_dir.encode("utf-8"), max_ram_bytes, key_buf)
        if not self.handle:
            raise RuntimeError("Failed to initialize libinte engine")

    def put(self, key: str, data: bytes | str):
        if isinstance(data, str):
            data = data.encode("utf-8")
        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        res = self.lib.inte_put(self.handle, key.encode("utf-8"), buf, len(data))
        if res != 0:
            raise RuntimeError(f"inte_put failed with code {res}")

    def get(self, key: str) -> bytes | None:
        out_ptr = ctypes.POINTER(ctypes.c_uint8)()
        out_len = ctypes.c_size_t()
        res = self.lib.inte_get(self.handle, key.encode("utf-8"), ctypes.byref(out_ptr), ctypes.byref(out_len))
        if res == 1:
            return None
        if res != 0:
            raise RuntimeError(f"inte_get failed with code {res}")
        try:
            return ctypes.string_at(out_ptr, out_len.value)
        finally:
            self.lib.inte_free_buf(out_ptr)

    def delete(self, key: str) -> bool:
        return self.lib.inte_delete(self.handle, key.encode("utf-8")) == 0

    def stats(self) -> dict:
        ram_used = ctypes.c_size_t()
        ram_items = ctypes.c_size_t()
        disk_items = ctypes.c_size_t()
        self.lib.inte_stats(self.handle, ctypes.byref(ram_used), ctypes.byref(ram_items), ctypes.byref(disk_items))
        return {
            "ram_used_kb": round(ram_used.value / 1024, 2),
            "ram_items": ram_items.value,
            "disk_items": disk_items.value
        }

    def disk_stats(self) -> dict:
        active = ctypes.c_size_t()
        total = ctypes.c_size_t()
        self.lib.inte_disk_stats(self.handle, ctypes.byref(active), ctypes.byref(total))
        dead = max(0, total.value - active.value)
        return {
            "active_kb": round(active.value / 1024, 2),
            "file_size_kb": round(total.value / 1024, 2),
            "dead_space_kb": round(dead / 1024, 2)
        }

    def compact(self):
        res = self.lib.inte_compact(self.handle)
        if res != 0:
            raise RuntimeError(f"inte_compact failed with code {res}")

    def scan_prefix(self, prefix: str, callback, contains_filter: str | None = None) -> int:
        def _c_wrapper(key_ptr, data_ptr, length, _user_data):
            k = key_ptr.decode("utf-8")
            raw = ctypes.string_at(data_ptr, length)
            res = callback(k, raw)
            return 0 if res is None or res is True else 1

        c_cb = self.SCAN_CB_TYPE(_c_wrapper)
        flt = contains_filter.encode("utf-8") if contains_filter else None
        return self.lib.inte_scan_prefix(self.handle, prefix.encode("utf-8"), flt, c_cb, None)

    def aggregate_double_prefix(self, prefix: str, value_offset: int = 0) -> dict:
        cnt = ctypes.c_size_t()
        total = ctypes.c_double()
        mn = ctypes.c_double()
        mx = ctypes.c_double()
        res = self.lib.inte_aggregate_double_prefix(
            self.handle, prefix.encode("utf-8"), value_offset,
            ctypes.byref(cnt), ctypes.byref(total), ctypes.byref(mn), ctypes.byref(mx)
        )
        if res != 0:
            raise RuntimeError(f"inte_aggregate_double_prefix failed: {res}")
        return {
            "count": cnt.value,
            "sum": round(total.value, 4),
            "avg": round(total.value / cnt.value, 4) if cnt.value > 0 else 0.0,
            "min": round(mn.value, 4),
            "max": round(mx.value, 4)
        }

    def close(self):
        if self.handle:
            self.lib.inte_close(self.handle)
            self.handle = None


INTEngine = IntDynamicEngine
__version__ = "3.0.0"
__all__ = ["IntDynamicEngine", "INTEngine"]
