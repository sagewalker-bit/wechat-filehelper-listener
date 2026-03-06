
from __future__ import annotations

from dataclasses import dataclass
import csv
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import io
from pathlib import Path
import re
import sqlite3
import subprocess
import time
from typing import Any, Iterable, Optional

from app.config import WatcherConfig
from app.wechat_ui import MessageSnapshot, Rect


class DBUnavailable(RuntimeError):
    pass


# WeChat 4.x key-info decrypt constants.
SALT_PREFIX = "TencentWeChat"
KEY_PREFIX = bytes([0x02, 0x1A])

# Key-material regexes captured from WeChat process memory.
_KEY_MATERIAL_PATTERNS = [
    re.compile(
        b"\\x18((\\d{15})|([a-z0-9A-Z_-]{6,28}))((....)(.{4,48})\\x1a(.{4,48})\\x20)",
        re.DOTALL,
    ),
    re.compile(
        b"\\x18((\\d{15})|([a-z0-9A-Z_-]{6,28}))((....)(.{4,48})\\x1a)",
        re.DOTALL,
    ),
]
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HEX32_BYTES_RE = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
_HEX64_BYTES_RE = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_VERIFY_CTX_CACHE: dict[str, tuple[tuple[int, int, int], list[tuple[int, bytes, bytes]]]] = {}
_GLOBAL_VERIFY_AES: _BCryptAes | None = None


def _expand_key_material_candidates(raw: bytes) -> set[bytes]:
    out: set[bytes] = set()
    if not raw:
        return out
    out.add(raw)
    out.add(raw.strip(b"\x00"))
    if len(raw) >= 2:
        out.add(raw[1:])
        out.add(raw[2:])

    # Direct fixed-size slices.
    for n in (16, 24, 32):
        if len(raw) == n:
            out.add(raw)
        elif len(raw) > n and len(raw) <= 96:
            for i in range(0, len(raw) - n + 1):
                out.add(raw[i : i + n])

    # Keep only plausible AES key-material lengths.
    cleaned: set[bytes] = set()
    for c in out:
        if len(c) in {16, 24, 32}:
            cleaned.add(c)
    return cleaned


def _sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _derive_wechat_db_keys(db_password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    # WeChat DB uses SQLCipher-style key derivation:
    # 1) aes_key = PBKDF2(password, salt, 64000, 32)
    # 2) mac_key = PBKDF2(aes_key, salt^0x3A, 2, 32)
    aes_key = hashlib.pbkdf2_hmac(
        "sha1",
        db_password,
        salt,
        64000,
        dklen=32,
    )
    mac_salt = bytes(b ^ 58 for b in salt)
    mac_key = hashlib.pbkdf2_hmac(
        "sha1",
        aes_key,
        mac_salt,
        2,
        dklen=32,
    )
    return aes_key, mac_key


def _normalize_target_chat(name: str) -> str:
    low = (name or "").strip().lower()
    if low in {"filehelper", "文件传输助手"}:
        return "filehelper"
    return low


def _parse_page_size(db_bytes: bytes) -> int:
    if len(db_bytes) < 18:
        return 4096
    page_size = int.from_bytes(db_bytes[16:18], byteorder="big")
    if page_size in {0, 1}:
        return 65536
    if page_size < 512 or page_size > 65536:
        return 4096
    return page_size


def _parse_wal_page_size(wal_path: Path) -> int | None:
    if not wal_path.exists():
        return None
    try:
        header = wal_path.read_bytes()[:32]
    except Exception:
        return None
    if len(header) < 12:
        return None

    magic_be = int.from_bytes(header[0:4], byteorder="big")
    magic_le = int.from_bytes(header[0:4], byteorder="little")
    if magic_be == 0x377F0682:
        endian = "big"
    elif magic_le == 0x377F0682:
        endian = "little"
    else:
        return None

    page_size = int.from_bytes(header[8:12], byteorder=endian)
    if page_size == 0:
        page_size = 65536
    if page_size < 512 or page_size > 65536:
        return None
    return page_size


def _candidate_page_sizes(db_path: Path, db_bytes: bytes) -> list[int]:
    wal_ps = _parse_wal_page_size(db_path.with_suffix(".db-wal"))
    if wal_ps is not None and len(db_bytes) >= wal_ps and (len(db_bytes) % wal_ps) == 0:
        # WAL header carries the most reliable page-size signal for encrypted DB.
        return [wal_ps]

    out: list[int] = []
    seen: set[int] = set()

    def add(v: int | None) -> None:
        if v is None:
            return
        if v < 512 or v > 65536:
            return
        # SQLite page size is power-of-two from 512..65536.
        if (v & (v - 1)) != 0:
            return
        if v not in seen:
            out.append(v)
            seen.add(v)

    add(_parse_wal_page_size(db_path.with_suffix(".db-wal")))
    add(_parse_page_size(db_bytes))
    for v in (4096, 8192, 16384, 32768, 65536, 2048, 1024, 512):
        add(v)

    file_len = len(db_bytes)
    return [v for v in out if file_len >= v and (file_len % v == 0)]


def _is_plausible_sqlite_header_tail(header_tail: bytes, expected_page_size: int) -> bool:
    if len(header_tail) < 16:
        return False

    page_size = int.from_bytes(header_tail[0:2], byteorder="big")
    if page_size in {0, 1}:
        page_size = 65536
    if page_size != expected_page_size:
        return False

    write_ver = header_tail[2]
    read_ver = header_tail[3]
    reserved = header_tail[4]
    max_payload = header_tail[5]
    min_payload = header_tail[6]
    leaf_payload = header_tail[7]

    if write_ver not in {1, 2}:
        return False
    if read_ver not in {1, 2}:
        return False
    if reserved > 64:
        return False
    if (max_payload, min_payload, leaf_payload) != (64, 32, 32):
        return False
    return True


def _get_verify_context(db_path: Path) -> list[tuple[int, bytes, bytes]]:
    try:
        st = db_path.stat()
    except Exception:
        return []
    wal = db_path.with_suffix(".db-wal")
    wal_mtime_ns = 0
    try:
        wal_mtime_ns = wal.stat().st_mtime_ns
    except Exception:
        wal_mtime_ns = 0

    sig = (int(st.st_size), int(st.st_mtime_ns), int(wal_mtime_ns))
    cache_key = str(db_path.resolve())
    cached = _VERIFY_CTX_CACHE.get(cache_key)
    if cached is not None and cached[0] == sig:
        return cached[1]

    if st.st_size < 64:
        _VERIFY_CTX_CACHE[cache_key] = (sig, [])
        return []

    max_prefix = min(65536, int(st.st_size))
    try:
        with db_path.open("rb") as f:
            prefix = f.read(max_prefix)
    except Exception:
        _VERIFY_CTX_CACHE[cache_key] = (sig, [])
        return []

    candidate_sizes: list[int] = []
    seen: set[int] = set()

    def add(ps: int | None) -> None:
        if ps is None:
            return
        if ps < 512 or ps > 65536:
            return
        if (ps & (ps - 1)) != 0:
            return
        if ps > len(prefix) or ps > st.st_size:
            return
        if ps not in seen:
            candidate_sizes.append(ps)
            seen.add(ps)

    # WAL page-size is the most reliable signal.
    wal_ps = _parse_wal_page_size(wal)
    add(wal_ps)
    # Fallback candidates.
    for ps in (4096, 8192, 16384, 32768, 65536, 2048, 1024, 512):
        add(ps)

    out: list[tuple[int, bytes, bytes]] = []
    for ps in candidate_sizes:
        if st.st_size % ps != 0:
            continue
        page = prefix[:ps]
        if len(page) < 64:
            continue
        out.append((ps, page[:16], page[16:ps]))

    _VERIFY_CTX_CACHE[cache_key] = (sig, out)
    return out


def _parse_key(key: str | bytes) -> bytes:
    if isinstance(key, bytes):
        b = key
    else:
        s = str(key).strip()
        if not s:
            raise ValueError("Empty db key")
        if len(s) % 2 != 0:
            raise ValueError("DB key hex length must be even")
        b = bytes.fromhex(s)
    if b.startswith(KEY_PREFIX):
        b = b[len(KEY_PREFIX) :]
    if len(b) not in {16, 24, 32}:
        raise ValueError(f"DB key must be 16/24/32 bytes, got {len(b)}")
    return b


class _BCryptAes:
    _CHAINING_MODE = "ChainingMode"
    _CHAIN_CBC = "ChainingModeCBC"
    _CHAIN_ECB = "ChainingModeECB"

    def __init__(self) -> None:
        self._bcrypt = ctypes.WinDLL("bcrypt", use_last_error=True)
        self._alg = ctypes.c_void_p()
        self._configure_prototypes()
        self._open()

    def _configure_prototypes(self) -> None:
        b = self._bcrypt
        b.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        ]
        b.BCryptOpenAlgorithmProvider.restype = wintypes.LONG
        b.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        b.BCryptCloseAlgorithmProvider.restype = wintypes.LONG
        b.BCryptSetProperty.argtypes = [
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.ULONG,
            wintypes.DWORD,
        ]
        b.BCryptSetProperty.restype = wintypes.LONG
        b.BCryptGetProperty.argtypes = [
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.DWORD,
        ]
        b.BCryptGetProperty.restype = wintypes.LONG
        b.BCryptGenerateSymmetricKey.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.ULONG,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.ULONG,
            wintypes.DWORD,
        ]
        b.BCryptGenerateSymmetricKey.restype = wintypes.LONG
        b.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
        b.BCryptDestroyKey.restype = wintypes.LONG
        b.BCryptDecrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.ULONG,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.DWORD,
        ]
        b.BCryptDecrypt.restype = wintypes.LONG

    def _open(self) -> None:
        status = self._bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(self._alg), "AES", None, 0
        )
        if status != 0:
            raise DBUnavailable(f"BCryptOpenAlgorithmProvider failed: {status}")

    def close(self) -> None:
        if self._alg:
            self._bcrypt.BCryptCloseAlgorithmProvider(self._alg, 0)
            self._alg = ctypes.c_void_p()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _set_mode(self, mode: str) -> None:
        raw = (mode + "\\x00").encode("utf-16le")
        value = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        status = self._bcrypt.BCryptSetProperty(
            self._alg,
            self._CHAINING_MODE,
            value,
            len(raw),
            0,
        )
        if status != 0:
            raise DBUnavailable(f"BCryptSetProperty({mode}) failed: {status}")

    def _get_u32_property(self, prop_name: str) -> int:
        out = (ctypes.c_ubyte * 4)()
        ret = wintypes.ULONG()
        status = self._bcrypt.BCryptGetProperty(
            self._alg,
            prop_name,
            out,
            4,
            ctypes.byref(ret),
            0,
        )
        if status != 0:
            raise DBUnavailable(f"BCryptGetProperty({prop_name}) failed: {status}")
        return int.from_bytes(bytes(out), byteorder="little")

    def _decrypt_raw(self, mode: str, key: bytes, data: bytes, iv: bytes | None) -> bytes:
        if not data:
            return b""
        if len(data) % 16 != 0:
            raise DBUnavailable("AES input must be 16-byte aligned")

        self._set_mode(mode)

        obj_len = self._get_u32_property("ObjectLength")
        key_obj = (ctypes.c_ubyte * obj_len)()
        hkey = ctypes.c_void_p()
        key_buf = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)

        status = self._bcrypt.BCryptGenerateSymmetricKey(
            self._alg,
            ctypes.byref(hkey),
            key_obj,
            obj_len,
            key_buf,
            len(key),
            0,
        )
        if status != 0:
            raise DBUnavailable(f"BCryptGenerateSymmetricKey failed: {status}")

        try:
            in_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            out_buf = (ctypes.c_ubyte * len(data))()
            out_len = wintypes.ULONG(0)

            iv_buf: Optional[ctypes.Array[Any]] = None
            iv_ptr = None
            iv_len = 0
            if iv is not None:
                iv_buf = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv)
                iv_ptr = iv_buf
                iv_len = len(iv)

            status = self._bcrypt.BCryptDecrypt(
                hkey,
                in_buf,
                len(data),
                None,
                iv_ptr,
                iv_len,
                out_buf,
                len(data),
                ctypes.byref(out_len),
                0,
            )
            if status != 0:
                raise DBUnavailable(f"BCryptDecrypt failed: {status}")
            return bytes(out_buf)[: out_len.value]
        finally:
            self._bcrypt.BCryptDestroyKey(hkey)

    def decrypt_cbc(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        return self._decrypt_raw(self._CHAIN_CBC, key, data, iv)

    def decrypt_ecb(self, key: bytes, data: bytes) -> bytes:
        return self._decrypt_raw(self._CHAIN_ECB, key, data, None)


def _decrypt_page(
    encrypted_page: bytes, aes_key: bytes, mac_key: bytes, page_index: int, aes: _BCryptAes
) -> bytes | None:
    if len(encrypted_page) <= 48:
        return None

    body = encrypted_page[:-48]
    iv = encrypted_page[-48:-32]
    mac = encrypted_page[-32:-12]

    check = hmac.new(
        mac_key,
        body + iv + int(page_index).to_bytes(4, byteorder="little"),
        digestmod=hashlib.sha1,
    ).digest()
    if check[:20] != mac:
        return None

    plain = aes.decrypt_cbc(aes_key, iv, body)
    return plain + encrypted_page[-48:]


def _get_global_verify_aes() -> _BCryptAes:
    global _GLOBAL_VERIFY_AES
    if _GLOBAL_VERIFY_AES is None:
        _GLOBAL_VERIFY_AES = _BCryptAes()
    return _GLOBAL_VERIFY_AES


def verify_db_key(db_path: Path, key_hex: str, aes: _BCryptAes | None = None) -> bool:
    if not db_path.exists():
        return False
    try:
        key = _parse_key(key_hex)
    except Exception:
        return False
    verify_pages = _get_verify_context(db_path)
    if not verify_pages:
        return False

    aes_obj = aes or _get_global_verify_aes()
    try:
        for page_size, salt, enc_first in verify_pages:
            aes_key, mac_key = _derive_wechat_db_keys(key, salt)
            out = _decrypt_page(enc_first, aes_key, mac_key, 1, aes_obj)
            if out is None:
                continue
            if _is_plausible_sqlite_header_tail(out[:16], page_size):
                return True
        return False
    finally:
        pass


def decrypt_db_bytes(db_path: Path, key_hex: str) -> bytes:
    raw = db_path.read_bytes()
    db_password = _parse_key(key_hex)
    page_sizes = _candidate_page_sizes(db_path, raw)
    if not page_sizes:
        raise DBUnavailable("Encrypted DB page size invalid")

    last_error = "decrypt_failed"
    for page_size in page_sizes:
        aes = _BCryptAes()
        try:
            pages: list[bytes] = []
            page_count = len(raw) // page_size
            if page_count <= 0:
                continue

            for i in range(page_count):
                page_index = i + 1
                page = raw[i * page_size : (i + 1) * page_size]
                if page_index == 1:
                    salt = page[:16]
                    aes_key, mac_key = _derive_wechat_db_keys(db_password, salt)
                    dec = _decrypt_page(page[16:], aes_key, mac_key, page_index, aes)
                    if dec is None:
                        raise DBUnavailable("DB key verify failed while decrypting first page")
                    if not _is_plausible_sqlite_header_tail(dec[:16], page_size):
                        raise DBUnavailable("First page tail does not look like SQLite header")
                    pages.append(b"SQLite format 3\\x00" + dec[:16] + dec[16:])
                else:
                    dec = _decrypt_page(page, aes_key, mac_key, page_index, aes)
                    if dec is None:
                        raise DBUnavailable(f"Failed to decrypt page {page_index}")
                    pages.append(dec)
            return b"".join(pages)
        except Exception as exc:
            last_error = str(exc)
            continue
        finally:
            aes.close()

    raise DBUnavailable(f"Failed to decrypt DB with all candidate page sizes: {last_error}")


def apply_wal_to_plain_db(plain_db: bytes, wal_path: Path, key_hex: str, salt: bytes) -> bytes:
    if not wal_path.exists():
        return plain_db
    wal = wal_path.read_bytes()
    if len(wal) < 32:
        return plain_db

    magic_be = int.from_bytes(wal[0:4], byteorder="big")
    magic_le = int.from_bytes(wal[0:4], byteorder="little")
    if magic_be == 0x377F0682:
        endian = "big"
    elif magic_le == 0x377F0682:
        endian = "little"
    else:
        return plain_db

    page_size = int.from_bytes(wal[8:12], byteorder=endian)
    if page_size == 0:
        page_size = 65536
    if page_size <= 0:
        return plain_db

    frame_size = 24 + page_size
    frame_count = (len(wal) - 32) // frame_size
    if frame_count <= 0:
        return plain_db

    db_password = _parse_key(key_hex)
    aes_key, mac_key = _derive_wechat_db_keys(db_password, salt)
    aes = _BCryptAes()
    out = bytearray(plain_db)
    committed_pages = 0

    try:
        off = 32
        for _ in range(frame_count):
            hdr = wal[off : off + 24]
            frame = wal[off + 24 : off + 24 + page_size]
            off += frame_size
            if len(hdr) < 24 or len(frame) < page_size:
                continue

            page_no = int.from_bytes(hdr[0:4], byteorder=endian)
            db_size_pages = int.from_bytes(hdr[4:8], byteorder=endian)
            if page_no <= 0:
                continue

            dec = _decrypt_page(frame, aes_key, mac_key, page_no, aes)
            if dec is None:
                continue

            start = (page_no - 1) * page_size
            end = start + page_size
            if end > len(out):
                out.extend(b"\\x00" * (end - len(out)))
            out[start:end] = dec

            if db_size_pages > 0:
                committed_pages = db_size_pages
    finally:
        aes.close()

    if committed_pages > 0:
        trunc = committed_pages * page_size
        if trunc <= len(out):
            out = out[:trunc]
    return bytes(out)


def _decrypt_key_info(key_info_data: bytes, key_material: bytes, account_id: str) -> bytes | None:
    if not key_info_data or len(key_info_data) <= 16:
        return None
    if len(key_material) not in {16, 24, 32}:
        return None

    master = hashlib.md5((account_id + SALT_PREFIX).encode("utf-8")).digest()
    views: list[bytes] = [key_info_data]

    # A common container layout is: 0A <varint_len> <payload>.
    try:
        if key_info_data and key_info_data[0] == 0x0A:
            i = 1
            shift = 0
            ln = 0
            while i < len(key_info_data):
                b = key_info_data[i]
                i += 1
                ln |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
                if shift > 28:
                    break
            if 0 < ln <= len(key_info_data) - i:
                views.append(key_info_data[i : i + ln])
    except Exception:
        pass

    for data in views:
        data_len = len(data)
        max_start = min(32, max(1, data_len - 32))
        for start in range(0, max_start):
            for tail_trim in (0, 4, 8, 12, 16, 20, 24, 28, 32):
                end = data_len - tail_trim
                if end - start <= 32:
                    continue
                salt = data[start : start + 16]
                encrypted_data = data[start + 16 : end]
                if len(encrypted_data) == 0 or (len(encrypted_data) % 16) != 0:
                    continue

                aes = _BCryptAes()
                try:
                    raw = aes.decrypt_ecb(key_material, encrypted_data)
                except Exception:
                    raw = b""
                finally:
                    aes.close()
                if not raw:
                    continue

                unmasked = bytes(raw[i] ^ master[i % len(master)] for i in range(len(raw)))
                pad = int(unmasked[-1])
                if pad <= 0 or pad > 16 or len(unmasked) <= pad:
                    continue
                unmasked = unmasked[:-pad]
                if len(unmasked) <= 16:
                    continue

                md5_data = unmasked[:16]
                key_data = unmasked[16:]
                if hashlib.md5(key_data + salt).digest() != md5_data:
                    continue
                return key_data
    return None

def _find_wechat_pids() -> list[int]:
    try:
        output = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            text=True,
            encoding="utf-8",
            errors="ignore",
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []

    out: list[int] = []
    rows = csv.reader(io.StringIO(output))
    for row in rows:
        if len(row) < 2:
            continue
        name = row[0].strip().lower()
        if name not in {"wechat.exe", "weixin.exe"}:
            continue
        try:
            out.append(int(row[1]))
        except Exception:
            continue
    return sorted(set(out))


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def _read_process_key_materials(
    pid: int,
    max_scan_seconds: float = 3.0,
    max_regions: int = 1200,
    relaxed: bool = False,
) -> list[tuple[str, bytes]]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100

    if relaxed:
        readable = {
            0x02,
            0x04,
            0x08,
            0x20,
            0x40,
            0x80,
        }
    else:
        # Fast path: key materials are usually in writable regions.
        readable = {
            0x04,
            0x08,
            0x40,
            0x80,
        }

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return []

    hits: set[tuple[str, bytes]] = set()
    max_pattern_len = 96
    max_addr = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
    addr = 0

    start_at = time.monotonic()
    region_count = 0
    try:
        while addr < max_addr:
            if (time.monotonic() - start_at) >= max_scan_seconds:
                break
            if region_count >= max_regions:
                break
            mbi = _MEMORY_BASIC_INFORMATION()
            ret = kernel32.VirtualQueryEx(
                h,
                ctypes.c_void_p(addr),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if ret == 0:
                break

            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize or 0)
            region_count += 1
            if size <= 0:
                addr = base + 0x1000
                continue

            prot = int(mbi.Protect or 0)
            is_readable = (
                int(mbi.State) == MEM_COMMIT
                and (prot & PAGE_GUARD) == 0
                and (prot & PAGE_NOACCESS) == 0
                and (prot & 0xFF) in readable
            )
            if not is_readable:
                addr = base + size
                continue

            chunk = 0x80000
            tail = b""
            offset = 0
            while offset < size:
                want = min(chunk, size - offset)
                buf = (ctypes.c_ubyte * want)()
                got = ctypes.c_size_t(0)
                ok = kernel32.ReadProcessMemory(
                    h,
                    ctypes.c_void_p(base + offset),
                    ctypes.byref(buf),
                    want,
                    ctypes.byref(got),
                )
                if not ok and got.value == 0:
                    offset += want
                    tail = b""
                    continue
                data = bytes(buf[: got.value])
                blob = tail + data

                for pat in _KEY_MATERIAL_PATTERNS:
                    for m in pat.finditer(blob):
                        try:
                            account_id = m.group(1).decode("utf-8", errors="ignore")
                        except Exception:
                            continue
                        if not account_id:
                            continue

                        raw_parts: list[bytes] = []
                        for idx in (4, 5, 6, 7):
                            try:
                                part = m.group(idx)
                            except Exception:
                                part = None
                            if isinstance(part, (bytes, bytearray)) and len(part) > 0:
                                raw_parts.append(bytes(part))
                        try:
                            g6 = m.group(6)
                            g7 = m.group(7)
                            if isinstance(g6, (bytes, bytearray)) and isinstance(
                                g7, (bytes, bytearray)
                            ):
                                raw_parts.append(bytes(g6) + bytes(g7))
                                raw_parts.append(bytes(g7) + bytes(g6))
                        except Exception:
                            pass

                        for part in raw_parts:
                            for km in _expand_key_material_candidates(part):
                                hits.add((account_id, km))

                tail = blob[-max_pattern_len:]
                offset += want

            addr = base + size
    finally:
        kernel32.CloseHandle(h)

    return sorted(hits, key=lambda x: (x[0], x[1]))


def _read_process_hex_key_candidates(
    pid: int,
    max_scan_seconds: float = 1.2,
    max_regions: int = 700,
    max_hits: int = 50000,
) -> list[str]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100

    readable = {
        0x02,
        0x04,
        0x08,
        0x20,
        0x40,
        0x80,
    }

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return []

    out: set[str] = set()
    max_addr = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
    addr = 0
    start_at = time.monotonic()
    region_count = 0
    max_pattern_len = 96

    try:
        while addr < max_addr:
            if (time.monotonic() - start_at) >= max_scan_seconds:
                break
            if region_count >= max_regions:
                break
            if len(out) >= max_hits:
                break

            mbi = _MEMORY_BASIC_INFORMATION()
            ret = kernel32.VirtualQueryEx(
                h,
                ctypes.c_void_p(addr),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if ret == 0:
                break

            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize or 0)
            region_count += 1
            if size <= 0:
                addr = base + 0x1000
                continue

            prot = int(mbi.Protect or 0)
            is_readable = (
                int(mbi.State) == MEM_COMMIT
                and (prot & PAGE_GUARD) == 0
                and (prot & PAGE_NOACCESS) == 0
                and (prot & 0xFF) in readable
            )
            if not is_readable:
                addr = base + size
                continue

            chunk = 0x60000
            tail = b""
            offset = 0
            while offset < size:
                if (time.monotonic() - start_at) >= max_scan_seconds:
                    break
                if len(out) >= max_hits:
                    break
                want = min(chunk, size - offset)
                buf = (ctypes.c_ubyte * want)()
                got = ctypes.c_size_t(0)
                ok = kernel32.ReadProcessMemory(
                    h,
                    ctypes.c_void_p(base + offset),
                    ctypes.byref(buf),
                    want,
                    ctypes.byref(got),
                )
                if not ok and got.value == 0:
                    offset += want
                    tail = b""
                    continue
                data = bytes(buf[: got.value])
                blob = tail + data

                for pat in (_HEX32_BYTES_RE, _HEX64_BYTES_RE):
                    for m in pat.finditer(blob):
                        try:
                            s = m.group(0).decode("ascii").lower()
                        except Exception:
                            continue
                        out.add(s)
                        if len(out) >= max_hits:
                            break

                tail = blob[-max_pattern_len:]
                offset += want

            addr = base + size
    finally:
        kernel32.CloseHandle(h)

    return sorted(out)


def _open_process_for_read(pid: int):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    return kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)


def _get_process_module_span(
    process_handle,
    module_name_contains: str,
    max_scan_seconds: float = 3.0,
    max_regions: int = 6000,
) -> tuple[int, int] | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    psapi.GetMappedFileNameW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    psapi.GetMappedFileNameW.restype = wintypes.DWORD

    target = module_name_contains.lower()
    max_addr = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
    addr = 0
    start_at = time.monotonic()
    region_count = 0
    span_begin: int | None = None
    span_end: int | None = None

    while addr < max_addr:
        if (time.monotonic() - start_at) >= max_scan_seconds:
            break
        if region_count >= max_regions:
            break

        mbi = _MEMORY_BASIC_INFORMATION()
        ret = kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(addr),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if ret == 0:
            break

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)
        region_count += 1
        if size <= 0:
            addr = base + 0x1000
            continue

        name_buf = ctypes.create_unicode_buffer(512)
        got = psapi.GetMappedFileNameW(
            process_handle,
            ctypes.c_void_p(base),
            name_buf,
            512,
        )
        if got > 0:
            mapped = str(name_buf.value or "").lower()
            if target in mapped:
                if span_begin is None or base < span_begin:
                    span_begin = base
                end = base + size
                if span_end is None or end > span_end:
                    span_end = end

        addr = base + size

    if span_begin is None or span_end is None or span_end <= span_begin:
        return None
    return span_begin, span_end


def _search_process_pattern_addresses(
    process_handle,
    patterns: list[bytes],
    max_scan_seconds: float = 3.5,
    max_regions: int = 1400,
    max_hits_per_pattern: int = 8,
    begin_addr: int = 0,
    end_addr: int | None = None,
) -> list[int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100

    readable = {
        0x02,
        0x04,
        0x08,
        0x20,
        0x40,
        0x80,
    }

    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    compiled = [(p, re.compile(re.escape(p))) for p in patterns]
    hit_count: dict[bytes, int] = {p: 0 for p in patterns}
    out: set[int] = set()
    start_at = time.monotonic()
    max_addr = (
        end_addr
        if (isinstance(end_addr, int) and end_addr > 0)
        else (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
    )
    addr = max(0, int(begin_addr))
    region_count = 0
    tail_keep = max(len(p) for p in patterns) + 8 if patterns else 64

    while addr < max_addr:
        if (time.monotonic() - start_at) >= max_scan_seconds:
            break
        if region_count >= max_regions:
            break
        if all(hit_count[p] >= max_hits_per_pattern for p in hit_count):
            break

        mbi = _MEMORY_BASIC_INFORMATION()
        ret = kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(addr),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if ret == 0:
            break

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)
        region_count += 1
        if size <= 0:
            addr = base + 0x1000
            continue
        if base + size <= addr:
            addr = base + size
            continue

        prot = int(mbi.Protect or 0)
        is_readable = (
            int(mbi.State) == MEM_COMMIT
            and (prot & PAGE_GUARD) == 0
            and (prot & PAGE_NOACCESS) == 0
            and (prot & 0xFF) in readable
        )
        if not is_readable:
            addr = base + size
            continue

        chunk = 0x70000
        offset = 0
        tail = b""
        while offset < size:
            if (time.monotonic() - start_at) >= max_scan_seconds:
                break
            want = min(chunk, size - offset)
            buf = (ctypes.c_ubyte * want)()
            got = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                process_handle,
                ctypes.c_void_p(base + offset),
                ctypes.byref(buf),
                want,
                ctypes.byref(got),
            )
            if not ok and got.value == 0:
                offset += want
                tail = b""
                continue

            data = bytes(buf[: got.value])
            blob = tail + data
            blob_base = base + offset - len(tail)

            for pat, cre in compiled:
                if hit_count[pat] >= max_hits_per_pattern:
                    continue
                for m in cre.finditer(blob):
                    out.add(blob_base + m.start())
                    hit_count[pat] += 1
                    if hit_count[pat] >= max_hits_per_pattern:
                        break

            tail = blob[-tail_keep:]
            offset += want

        addr = base + size

    return sorted(out)


def _read_process_bytes(process_handle, address: int, size: int) -> bytes | None:
    if address <= 0 or size <= 0:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    buf = (ctypes.c_ubyte * size)()
    got = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.byref(buf),
        size,
        ctypes.byref(got),
    )
    if not ok or got.value != size:
        return None
    return bytes(buf)


def _read_process_indirect_bytes(
    process_handle,
    address: int,
    size: int = 32,
    ptr_size: int = 8,
) -> bytes | None:
    raw_ptr = _read_process_bytes(process_handle, address, ptr_size)
    if not raw_ptr:
        return None
    ptr_val = int.from_bytes(raw_ptr, byteorder="little", signed=False)
    if ptr_val <= 0:
        return None
    return _read_process_bytes(process_handle, ptr_val, size)


def _find_db_key_by_anchor_scan(
    pid: int,
    db_path: Path,
    verify_cache: dict[str, bool],
    verify_aes: _BCryptAes,
) -> str | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    process = _open_process_for_read(pid)
    if not process:
        return None
    try:
        start_at = time.monotonic()
        verify_start = len(verify_cache)
        span = _get_process_module_span(process, "wechatwin.dll", max_scan_seconds=2.5, max_regions=4500)
        if span is None:
            return None
        begin_addr, end_addr = span

        anchors = _search_process_pattern_addresses(
            process,
            patterns=[b"iphone\x00", b"android\x00", b"ipad\x00"],
            max_scan_seconds=2.8,
            max_regions=2200,
            max_hits_per_pattern=2,
            begin_addr=begin_addr,
            end_addr=end_addr,
        )
        if not anchors:
            return None
        anchors = sorted(set(anchors))

        for anchor in reversed(anchors):
            for ptr_size in (8, 4):
                for pos in range(anchor, max(anchor - 2000, 0), -ptr_size):
                    if (time.monotonic() - start_at) >= 6.0:
                        return None
                    if (len(verify_cache) - verify_start) >= 12:
                        return None
                    maybe_key = _read_process_indirect_bytes(
                        process,
                        pos,
                        size=32,
                        ptr_size=ptr_size,
                    )
                    if not maybe_key:
                        continue
                    if maybe_key == (b"\x00" * 32) or maybe_key == (b"\xff" * 32):
                        continue
                    if maybe_key.count(0) > 8:
                        continue
                    cand = maybe_key.hex()
                    if _verify_key_candidate(db_path, cand, verify_cache, aes=verify_aes):
                        return cand
        return None
    finally:
        kernel32.CloseHandle(process)


def _discover_profiles(data_root: Path) -> list[Path]:
    if not data_root.exists():
        return []
    out: list[Path] = []
    for p in data_root.iterdir():
        if not p.is_dir():
            continue
        if not p.name.startswith("wxid_"):
            continue
        msg_db = p / "db_storage" / "message" / "message_0.db"
        if msg_db.exists():
            out.append(p)
    out.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return out


def _candidate_account_ids(profile: Path) -> list[str]:
    name = profile.name
    out = {name}
    m = re.match(r"^(wxid_[a-zA-Z0-9]+)_([a-z0-9]{4,8})$", name)
    if m:
        out.add(m.group(1))
    return sorted(out)


def _normalize_hex_candidate(raw: str) -> str | None:
    s = str(raw or "").strip().lower()
    if not s:
        return None
    if len(s) % 2 != 0:
        return None
    if not _HEX_RE.fullmatch(s):
        return None
    return s


def _verify_key_candidate(
    db_path: Path,
    candidate_hex: str,
    cache: dict[str, bool],
    aes: _BCryptAes | None = None,
) -> bool:
    cand = _normalize_hex_candidate(candidate_hex)
    if cand is None:
        return False
    if cand in cache:
        return cache[cand]
    ok = verify_db_key(db_path, cand, aes=aes)
    cache[cand] = ok
    return ok


def _resolve_db_key(profile: Path, db_path: Path, key_info_db: Path) -> tuple[str, str, bytes]:
    scan_started_at = time.monotonic()

    if not key_info_db.exists():
        raise DBUnavailable(f"key_info.db not found: {key_info_db}")

    try:
        con = sqlite3.connect(key_info_db)
        rows = con.execute(
            "SELECT user_name_md5, key_md5, key_info_md5, key_info_data FROM LoginKeyInfoTable"
        ).fetchall()
    except Exception as exc:
        raise DBUnavailable(f"Failed reading key_info.db: {exc}") from exc
    finally:
        try:
            con.close()
        except Exception:
            pass

    verify_cache: dict[str, bool] = {}

    # Stage 0: quick direct candidates from key_info rows.
    row_user_md5_values = sorted(
        {
            str(r[0] or "").strip().lower()
            for r in rows
            if str(r[0] or "").strip()
        }
    )
    direct_candidates: set[str] = set()
    for row_user_md5, key_md5, key_info_md5, _key_info_data in rows:
        for raw in (row_user_md5, key_md5, key_info_md5):
            cand = _normalize_hex_candidate(str(raw or ""))
            if cand:
                direct_candidates.add(cand)
        row_u = str(row_user_md5 or "").strip().lower()
        row_k = str(key_info_md5 or "").strip().lower()
        if _normalize_hex_candidate(row_u) and _normalize_hex_candidate(row_k):
            direct_candidates.add(row_u + row_k)
            direct_candidates.add(row_k + row_u)

    for cand in sorted(direct_candidates):
        if _verify_key_candidate(db_path, cand, verify_cache):
            return cand, "direct_key_info", b""

    wal_page_size = _parse_wal_page_size(db_path.with_suffix(".db-wal"))
    page_size_candidates = [wal_page_size] if wal_page_size else []

    pids = _find_wechat_pids()
    if not pids:
        raise DBUnavailable("WeChat process not found. Keep WeChat running, then retry.")

    verify_aes = _get_global_verify_aes()
    # Anchor scan is expensive because each verification uses PBKDF2(64000).
    # Probe a small number of WeChat processes first to keep doctor responsive.
    for pid in pids[:2]:
        anchor_key = _find_db_key_by_anchor_scan(
            pid=pid,
            db_path=db_path,
            verify_cache=verify_cache,
            verify_aes=verify_aes,
        )
        if anchor_key:
            return anchor_key, f"anchor_scan_pid_{pid}", b""

    key_material_hits: list[tuple[str, bytes]] = []
    for pid in pids:
        key_material_hits.extend(
            _read_process_key_materials(
                pid,
                max_scan_seconds=1.8,
                max_regions=900,
                relaxed=False,
            )
        )
        if len(key_material_hits) >= 80:
            break

    # Fallback: broaden readable memory classes if fast scan found nothing.
    if not key_material_hits:
        for pid in pids:
            key_material_hits.extend(
                _read_process_key_materials(
                    pid,
                    max_scan_seconds=2.5,
                    max_regions=1200,
                    relaxed=True,
                )
            )
            if len(key_material_hits) >= 80:
                break
    key_material_hits = sorted(set(key_material_hits), key=lambda x: (x[0], x[1]))
    if not key_material_hits:
        raise DBUnavailable(
            "Failed to extract key materials from WeChat process memory. "
            f"pids={pids}. Try running PowerShell as Administrator and keep WeChat unlocked in foreground."
        )

    memory_hex_candidates: set[str] = set()
    for pid in pids:
        for cand in _read_process_hex_key_candidates(
            pid,
            max_scan_seconds=1.1,
            max_regions=650,
            max_hits=25000,
        ):
            memory_hex_candidates.add(cand)
            if len(memory_hex_candidates) >= 25000:
                break
        if len(memory_hex_candidates) >= 25000:
            break

    len_dist: dict[int, int] = {}
    for _acc, km in key_material_hits:
        len_dist[len(km)] = len_dist.get(len(km), 0) + 1
    len_summary = ",".join(f"{k}:{v}" for k, v in sorted(len_dist.items()))

    account_candidates = set(_candidate_account_ids(profile))
    for account_id, _ in key_material_hits:
        account_id = str(account_id or "").strip()
        if not account_id:
            continue
        # Keep likely account ids only; memory scan can contain noisy numeric ids.
        if account_id.startswith("wxid_"):
            account_candidates.add(account_id)

    # Budget starts after memory scan, so scan cost does not consume derive time.
    resolve_started_at = time.monotonic()
    resolve_budget_s = 14.0
    verify_limit = 90
    quick_verify_limit = 22
    quick_verify_start = len(verify_cache)
    deep_decrypt_ok = 0
    deep_key_md5_ok = 0

    def _time_exceeded() -> bool:
        return (time.monotonic() - resolve_started_at) >= resolve_budget_s

    def _try_verify(cand: str) -> bool:
        if _time_exceeded():
            return False
        norm = _normalize_hex_candidate(cand)
        if norm is None:
            return False
        if norm not in verify_cache and len(verify_cache) >= verify_limit:
            return False
        return _verify_key_candidate(db_path, norm, verify_cache, aes=verify_aes)

    # Stage 0.5: try raw hex-like key candidates found directly in process memory.
    mem_verified_start = len(verify_cache)
    for cand in memory_hex_candidates:
        if _time_exceeded():
            break
        if (len(verify_cache) - mem_verified_start) >= 24:
            break
        if _try_verify(cand):
            return cand, "memory_hex", b""
        if len(cand) in {32, 64}:
            if _try_verify("021a" + cand):
                return "021a" + cand, "memory_hex_prefixed", b""

    key_materials = sorted({km for _acc, km in key_material_hits})
    prioritized_key_materials: list[bytes] = []
    seen_quick_km: set[bytes] = set()
    for account_id, km in key_material_hits:
        if account_id in account_candidates and km not in seen_quick_km:
            prioritized_key_materials.append(km)
            seen_quick_km.add(km)
    for km in key_materials:
        if km not in seen_quick_km:
            prioritized_key_materials.append(km)
            seen_quick_km.add(km)

    # Stage 1: quick key derivation directly from key-material candidates.
    for key_material in prioritized_key_materials[:18]:
        if _time_exceeded():
            break
        if (len(verify_cache) - quick_verify_start) >= quick_verify_limit:
            break
        quick_candidates: set[str] = {
            key_material.hex(),
            (KEY_PREFIX + key_material).hex(),
            _md5_hex(key_material),
            _sha256_hex(key_material),
        }
        for account_id in account_candidates:
            aid = account_id.encode("utf-8", errors="ignore")
            quick_candidates.update(
                {
                    _md5_hex(aid + key_material),
                    _md5_hex(key_material + aid),
                }
            )
        for row_user_md5 in row_user_md5_values:
            uid = row_user_md5.encode("utf-8", errors="ignore")
            quick_candidates.update(
                {
                    _md5_hex(uid + key_material),
                    _md5_hex(key_material + uid),
                }
            )
        for cand in quick_candidates:
            if _try_verify(cand):
                return cand, "quick_key_material", key_material

    preferred_key_materials: list[bytes] = []
    seen_km: set[bytes] = set()
    for account_id, km in key_material_hits:
        if account_id in account_candidates and km not in seen_km:
            preferred_key_materials.append(km)
            seen_km.add(km)
    for km in key_materials:
        if km not in seen_km:
            preferred_key_materials.append(km)
            seen_km.add(km)

    # Limit deep decrypt attempts to keep doctor responsive.
    deep_key_materials = preferred_key_materials[:40]

    for key_material in deep_key_materials:
        if _time_exceeded():
            break
        for account_id in account_candidates:
            if _time_exceeded():
                break
            user_name_md5 = _md5_hex(account_id.encode("utf-8"))
            for row_user_md5, _key_md5, key_info_md5, key_info_data in rows:
                if _time_exceeded():
                    break
                if row_user_md5 and str(row_user_md5).strip().lower() != user_name_md5:
                    continue
                if not isinstance(key_info_data, (bytes, bytearray)):
                    continue

                account_key = _decrypt_key_info(bytes(key_info_data), key_material, account_id)
                if not account_key:
                    continue
                deep_decrypt_ok += 1

                account_key_variants: set[bytes] = set()
                account_key_variants.add(account_key)
                if len(account_key) > 16:
                    account_key_variants.add(account_key[16:])
                if len(account_key) > 32:
                    account_key_variants.add(account_key[:32])
                    account_key_variants.add(account_key[-32:])

                # Sliding fixed-size windows can recover true key bytes from wrapped blobs.
                if len(account_key) <= 128:
                    for n in (16, 24, 32):
                        if len(account_key) >= n:
                            for i in range(0, len(account_key) - n + 1):
                                account_key_variants.add(account_key[i : i + n])

                try:
                    ascii_key = account_key.decode("utf-8", errors="ignore").strip()
                except Exception:
                    ascii_key = ""
                if re.fullmatch(r"[0-9a-fA-F]{32,68}", ascii_key or "") and (len(ascii_key) % 2 == 0):
                    try:
                        account_key_variants.add(bytes.fromhex(ascii_key))
                    except Exception:
                        pass

                key_info_md5_norm = _normalize_hex_candidate(str(key_info_md5 or ""))
                if key_info_md5_norm:
                    md5_matched = [ak for ak in account_key_variants if _md5_hex(ak) == key_info_md5_norm]
                    if md5_matched:
                        deep_key_md5_ok += len(md5_matched)
                        variants_to_try = md5_matched
                    else:
                        # Keep only a tiny sample when md5 doesn't match, to avoid exploding noise.
                        variants_to_try = list(account_key_variants)[:2]
                else:
                    variants_to_try = list(account_key_variants)[:6]

                for ak in variants_to_try:
                    if _time_exceeded():
                        break
                    if len(ak) not in {16, 24, 32}:
                        continue
                    candidate_hexes: set[str] = {
                        ak.hex(),
                        (KEY_PREFIX + ak).hex(),
                    }

                    aid = account_id.encode("utf-8", errors="ignore")
                    uid = str(row_user_md5 or "").strip().lower().encode("utf-8", errors="ignore")
                    parts_pool = [
                        (aid, key_material, ak),
                        (aid, ak, key_material),
                        (key_material, aid, ak),
                        (key_material, ak, aid),
                        (ak, aid, key_material),
                        (ak, key_material, aid),
                        (key_material, ak),
                        (ak, key_material),
                        (aid, ak),
                        (ak, aid),
                    ]
                    if uid:
                        parts_pool.extend(
                            [
                                (uid, key_material, ak),
                                (uid, ak, key_material),
                                (key_material, uid, ak),
                                (ak, key_material, uid),
                                (uid, ak),
                                (ak, uid),
                            ]
                        )

                    for parts in parts_pool:
                        blob = b"".join(parts)
                        candidate_hexes.add(_md5_hex(blob))
                        candidate_hexes.add(_sha256_hex(blob))

                    if key_info_md5:
                        kmd5 = str(key_info_md5).strip().lower()
                        if _normalize_hex_candidate(kmd5):
                            candidate_hexes.add(kmd5)
                            candidate_hexes.add(kmd5 + ak.hex())
                            candidate_hexes.add(ak.hex() + kmd5)

                    for cand in candidate_hexes:
                        if _try_verify(cand):
                            return cand, account_id, key_material

    raise DBUnavailable(
        "Unable to resolve DB key from key_info + memory materials. "
        f"profiles={profile.name}, pids={pids}, key_info_rows={len(rows)}, key_material_hits={len(key_material_hits)}. "
        f"wal_page_size={wal_page_size}, page_size_candidates={page_size_candidates}. "
        f"key_material_len_dist={len_summary}, memory_hex_candidates={len(memory_hex_candidates)}, "
        f"verified_candidates={len(verify_cache)}, "
        f"quick_verified={len(verify_cache)-quick_verify_start}, deep_decrypt_ok={deep_decrypt_ok}, deep_key_md5_ok={deep_key_md5_ok}, "
        f"resolve_timeout={_time_exceeded()}, resolve_budget_s={resolve_budget_s}, "
        f"scan_elapsed_s={round(resolve_started_at - scan_started_at, 3)}. "
        "This usually means current WeChat build changed key layout."
    )


@dataclass(frozen=True)
class _MessageModel:
    table_name: str
    id_expr: str
    ts_expr: str
    talker_expr: str
    content_expr: str
    sender_expr: str
    type_expr: str
    type_col_present: bool


@dataclass(frozen=True)
class _MessageRow:
    msg_id: str
    timestamp: int
    direction: str
    text: str


def _q(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _pick(columns: dict[str, str], names: Iterable[str]) -> str | None:
    for n in names:
        if n.lower() in columns:
            return columns[n.lower()]
    return None


def _detect_message_model(conn: sqlite3.Connection) -> _MessageModel:
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    best: tuple[int, _MessageModel] | None = None

    for (table_name,) in tables:
        try:
            cols = conn.execute(f"PRAGMA table_info({_q(table_name)})").fetchall()
        except Exception:
            continue
        if not cols:
            continue

        col_map = {str(c[1]).lower(): str(c[1]) for c in cols}
        talker = _pick(col_map, ["StrTalker", "talker", "username", "chat_id"])
        content = _pick(col_map, ["StrContent", "content", "msg_content", "text"])
        sender = _pick(col_map, ["IsSender", "is_sender", "sender", "isSend", "from_me"])
        mtype = _pick(col_map, ["Type", "type", "MsgType", "msg_type"])
        ts = _pick(
            col_map,
            ["CreateTime", "create_time", "msgsvrid", "MsgSvrID", "local_id", "id"],
        )
        mid = _pick(col_map, ["MsgSvrID", "msgsvrid", "local_id", "id"])

        if not talker or not content:
            continue

        score = 0
        score += 5
        if sender:
            score += 2
        if mtype:
            score += 2
        if ts:
            score += 2
        if mid:
            score += 1
        if table_name.lower().startswith("message") or table_name.lower() == "msg":
            score += 2

        model = _MessageModel(
            table_name=table_name,
            id_expr=_q(mid) if mid else "rowid",
            ts_expr=_q(ts) if ts else (_q(mid) if mid else "rowid"),
            talker_expr=_q(talker),
            content_expr=_q(content),
            sender_expr=_q(sender) if sender else "0",
            type_expr=_q(mtype) if mtype else "1",
            type_col_present=bool(mtype),
        )
        if best is None or score > best[0]:
            best = (score, model)

    if best is None:
        raise DBUnavailable("No usable message table found in decrypted DB.")
    return best[1]


def _normalize_text(text: str) -> str:
    text = str(text).replace("\\r", "\\n")
    text = "\\n".join(line.rstrip() for line in text.split("\\n"))
    text = re.sub(r"\\n{3,}", "\\n\\n", text)
    return text.strip()

class WeChatDBAutomation:
    def __init__(self, target_chat: str, config: WatcherConfig) -> None:
        if _normalize_target_chat(target_chat) != "filehelper":
            raise DBUnavailable("DB backend only supports 文件传输助手(filehelper).")

        self.target_chat = target_chat
        self.config = config
        self.bound = False
        self.profile_dir: Path | None = None
        self.db_path: Path | None = None
        self.wal_path: Path | None = None
        self.key_info_db: Path | None = None
        self.db_key: str | None = None
        self.account_id: str | None = None
        self.key_material: bytes | None = None
        self.last_error: str = ""
        self.snapshot_path = (
            Path(__file__).resolve().parent.parent
            / "runtime"
            / "decrypted"
            / "message_0.plain.db"
        )
        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        self.model: _MessageModel | None = None

        self._plain_bytes: bytes | None = None
        self._plain_salt: bytes | None = None
        self._src_db_mtime: float = 0.0
        self._src_wal_mtime: float = 0.0
        self._last_refresh_at = 0.0
        self._refresh_interval_s = max(0.2, float(config.poll_ms) / 1000.0)

    def is_bound(self) -> bool:
        return self.bound

    def unbind(self) -> None:
        self.bound = False
        self._plain_bytes = None
        self.model = None

    def bind_window(self) -> bool:
        if self.bound:
            return True
        try:
            self._bind()
            self.last_error = ""
            return True
        except Exception as exc:
            self.last_error = str(exc)
            self.unbind()
            return False

    def _bind(self) -> None:
        data_root = Path.home() / "Documents" / "xwechat_files"
        profiles = _discover_profiles(data_root)
        if not profiles:
            raise DBUnavailable(f"No WeChat profile found under: {data_root}")

        profile = profiles[0]
        db_path = profile / "db_storage" / "message" / "message_0.db"
        wal_path = db_path.with_suffix(".db-wal")
        account_candidates = _candidate_account_ids(profile)
        key_info_db = None
        for account_id in account_candidates:
            p = data_root / "all_users" / "login" / account_id / "key_info.db"
            if p.exists():
                key_info_db = p
                break
        if key_info_db is None:
            all_key_infos = list((data_root / "all_users" / "login").glob("*/key_info.db"))
            if not all_key_infos:
                raise DBUnavailable("Cannot find key_info.db for current account.")
            key_info_db = all_key_infos[0]

        db_key, account_id, key_material = _resolve_db_key(profile, db_path, key_info_db)

        self.profile_dir = profile
        self.db_path = db_path
        self.wal_path = wal_path
        self.key_info_db = key_info_db
        self.db_key = db_key
        self.account_id = account_id
        self.key_material = key_material

        self._refresh_snapshot(force=True)
        with sqlite3.connect(self.snapshot_path) as conn:
            self.model = _detect_message_model(conn)

        self.bound = True

    def get_window_title(self) -> str:
        if not self.bound or self.profile_dir is None:
            return ""
        return f"wechat-db:{self.profile_dir.name}"

    def is_target_chat_active(self) -> bool:
        return self.bound

    def fetch_visible_text_messages(self) -> list[MessageSnapshot]:
        if not self.bound:
            return []
        self._refresh_snapshot(force=False)
        rows = self._query_filehelper_rows(limit=240)

        out: list[MessageSnapshot] = []
        for idx, row in enumerate(rows):
            rect = Rect(left=0, top=idx, right=1, bottom=idx + 1)
            runtime_id = row.msg_id
            payload = (
                f"{row.msg_id}|{row.timestamp}|{row.direction}|{row.text}"
            ).encode("utf-8", errors="ignore")
            fingerprint = _sha1_hex(payload)
            out.append(
                MessageSnapshot(
                    text=row.text,
                    direction=row.direction,
                    runtime_id=runtime_id,
                    rect=rect,
                    fingerprint=fingerprint,
                )
            )
        return out

    def doctor(self) -> dict[str, Any]:
        if not self.bound:
            return {
                "window_found": False,
                "target_active": False,
                "visible_message_count": 0,
                "backend": "db",
                "reason": "db_not_bound",
            }
        rows = self._query_filehelper_rows(limit=10)
        return {
            "window_found": True,
            "window_title": self.get_window_title(),
            "target_active": True,
            "visible_message_count": len(rows),
            "sample_texts": [r.text for r in rows[-3:]],
            "profile_dir": str(self.profile_dir) if self.profile_dir else "",
            "db_path": str(self.db_path) if self.db_path else "",
            "backend": "db",
        }

    def _refresh_snapshot(self, force: bool) -> None:
        if self.db_path is None or self.db_key is None:
            raise DBUnavailable("DB backend is not initialized.")

        now = time.monotonic()
        if not force and now - self._last_refresh_at < self._refresh_interval_s:
            return
        self._last_refresh_at = now

        db_mtime = self.db_path.stat().st_mtime
        wal_mtime = 0.0
        if self.wal_path and self.wal_path.exists():
            wal_mtime = self.wal_path.stat().st_mtime

        needs_full = force or self._plain_bytes is None or db_mtime != self._src_db_mtime
        needs_wal = needs_full or (wal_mtime != self._src_wal_mtime)
        if not needs_full and not needs_wal:
            return

        if needs_full:
            plain = decrypt_db_bytes(self.db_path, self.db_key)
            self._plain_salt = self.db_path.read_bytes()[:16]
        else:
            if self._plain_bytes is None:
                plain = decrypt_db_bytes(self.db_path, self.db_key)
                self._plain_salt = self.db_path.read_bytes()[:16]
            else:
                plain = self._plain_bytes

        if self.wal_path and self.wal_path.exists() and self._plain_salt is not None:
            plain = apply_wal_to_plain_db(
                plain, self.wal_path, self.db_key, self._plain_salt
            )

        self._plain_bytes = plain
        self._src_db_mtime = db_mtime
        self._src_wal_mtime = wal_mtime
        tmp = self.snapshot_path.with_suffix(".tmp")
        tmp.write_bytes(plain)
        tmp.replace(self.snapshot_path)

    def _query_filehelper_rows(self, limit: int) -> list[_MessageRow]:
        if self.model is None:
            return []
        sql = (
            "SELECT "
            f"{self.model.id_expr} AS _id, "
            f"{self.model.ts_expr} AS _ts, "
            f"{self.model.talker_expr} AS _talker, "
            f"{self.model.content_expr} AS _content, "
            f"{self.model.sender_expr} AS _sender, "
            f"{self.model.type_expr} AS _type "
            f"FROM {_q(self.model.table_name)} "
            f"WHERE lower(CAST({self.model.talker_expr} AS TEXT)) = 'filehelper' "
            f"ORDER BY {self.model.ts_expr} DESC "
            "LIMIT ?"
        )

        out: list[_MessageRow] = []
        with sqlite3.connect(self.snapshot_path) as conn:
            rows = conn.execute(sql, (int(limit),)).fetchall()

        for row in reversed(rows):
            msg_id = str(row[0])
            try:
                ts = int(row[1])
            except Exception:
                ts = 0
            talker = str(row[2] or "").strip().lower()
            if talker != "filehelper":
                continue

            text = _normalize_text(str(row[3] or ""))
            if not text:
                continue

            try:
                sender = int(row[4])
            except Exception:
                sender = 0
            direction = "outgoing" if sender else "incoming"

            if self.model.type_col_present:
                try:
                    msg_type = int(row[5])
                except Exception:
                    msg_type = 0
                if msg_type != 1:
                    continue

            out.append(
                _MessageRow(
                    msg_id=msg_id,
                    timestamp=ts,
                    direction=direction,
                    text=text,
                )
            )
        return out
