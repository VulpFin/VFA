# Copyright (C) 2025 TG11
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#!/usr/bin/env python3
"""
vfa_extract - the one VFA1 reader, shared by vfa.py, the SFX/SFI stubs and the viewer.

A "container" is any file that ends with a VFA archive (stub + archive).
Optionally an SFI manifest sits immediately before the archive:

    [stub][manifest JSON][u32 manifest_len]["/VFIM1"][VFA1 archive ... footer]

Rules this reader enforces (see VFA1.md):
  - header version must be 1 and every header flag bit must be known, otherwise refuse;
  - the TOC must parse exactly (no layout guessing, no trailing bytes) - an optional
    TOC extension ("VTX1", flag F_TOCX) carries per-block offsets, sizes and CRC32s;
  - every block is length-checked, and CRC-checked when the archive records CRCs;
  - decompression output is capped at the size the TOC claims (no decompression bombs);
  - nothing is written outside the destination directory (safe_join()).
"""

import sys, os, io, struct, getpass, hashlib, zlib, lzma, bz2, json, stat, tempfile, unicodedata, shutil
from datetime import datetime
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

# ---------------- Logging ----------------

LOG_COL_PIPE = 48
class VLog:
    LEVELS = {"quiet": 0, "error": 1, "warning": 2, "info": 3, "debug": 4, "trace": 5}
    def __init__(self, level="warning", tag="VFA", sink=None):
        self.level = self.LEVELS.get(level, 2)
        self.tag = tag
        self.sink = sink  # optional callable(str) e.g. file writer / GUI
    def _fmt(self, name, msg):
        ts = datetime.now().strftime("%m/%d/%Y %H:%M:%S.%f")[:-1]
        prefix = f"[{self.tag} {name.upper():<7}] {ts}"
        pad = max(1, LOG_COL_PIPE - len(prefix) - 1)
        return f"{prefix}{' ' * pad}| {msg}"
    def _emit(self, lvl, name, msg):
        if self.level >= lvl:
            line = self._fmt(name, msg)
            if sys.stdout is not None:
                try: print(line, flush=True)
                except Exception: pass
            if self.sink:
                try: self.sink(line)
                except Exception: pass
    def error(self, msg):   self._emit(1, "ERROR", msg)
    def warning(self, msg): self._emit(2, "WARNING", msg)
    def info(self, msg):    self._emit(3, "INFO", msg)
    def debug(self, msg):   self._emit(4, "DEBUG", msg)
    def trace(self, msg):   self._emit(5, "TRACE", msg)

LOGGER = VLog("warning")

def set_logger(lg: VLog):
    global LOGGER
    LOGGER = lg

class VFAError(Exception):
    """Fatal, user-presentable error (bad archive, wrong password, ...)."""
    def __init__(self, msg, code=1):
        super().__init__(msg); self.code = code

# ---------------- VFA constants ----------------

MAGIC = b"VFA1"
END_MAGIC = b"/VFA1"
MANIFEST_MAGIC = b"/VFIM1"       # trailer of the SFI manifest blob
MANIFEST_RESERVED_PREFIX = "__vfi__/"
SUPPORTED_VERSION = 1

AEAD_NONE = 0; AEAD_AESGCM = 1
KDF_NONE = 0;  KDF_ARGON2ID = 1; KDF_SCRYPT = 2

M_NONE = 0; M_ZLIB = 1; M_LZMA = 2; M_BROTLI = 3; M_ZSTD = 4; M_XZ = 5; M_BZ2 = 6; M_LZ4 = 7
METHOD_NAMES = {M_NONE: "none", M_ZLIB: "zlib", M_LZMA: "lzma", M_BROTLI: "brotli",
                M_ZSTD: "zstd", M_XZ: "xz", M_BZ2: "bz2", M_LZ4: "lz4"}
F_ENCRYPTED = 1 << 0
F_SOLID = 1 << 1
F_TOCX = 1 << 2                  # TOC ends with a "VTX1" extension (block table with CRCs)
KNOWN_FLAGS = F_ENCRYPTED | F_SOLID | F_TOCX
H_NONE = 0; H_SHA256 = 1; H_BLAKE3 = 2; H_XXH64 = 3
HASH_NAMES = {H_NONE: "none", H_SHA256: "sha256", H_BLAKE3: "blake3", H_XXH64: "xxh64"}
ET_FILE = 0; ET_DIR = 1; ET_SYMLINK = 2; ET_HARDLINK = 3
ET_NAMES = ["file", "dir", "symlink", "hardlink"]

HEADER_LEN = 4 + 2 + 4 + 1 + 1 + 1 + 2 + 4 + 1 + 4 + 4 + 1 + 16 + 1 + 12 + 16   # 74
FOOTER_LEN = 8 + 4 + 1 + 32 + 5  # toc_off u64, toc_sz u32, hash_kind u8, digest[32], END_MAGIC[5]
FRAME_HDR = 5                    # u32 payload_len, u8 method
MAX_BLOCK = 1 << 30              # writers never put more than this in one block

# TOC extension: [b"VTX1"][u32 nrec] then nrec * ([u16 type][u16 rflags][u32 len][data])
TOCX_MAGIC = b"VTX1"
TX_BLOCKS = 1                    # data: u32 n, then n * BLOCK_REC
TX_TOCCRC = 2                    # data: u32 crc32 of the TOC bytes before "VTX1" (entries)
TXF_CRITICAL = 1                 # a reader that does not know this record type must refuse
BLOCK_REC = struct.Struct("<QIIBBI")   # frame_off (from archive start), csz, usz, method, bflags, crc32
BF_CRC = 1                       # crc32 field is valid

TOC_NONCE_BASE = 0xFFFFFFFFFFFFFFFF
def toc_nonce_index(gen: int) -> int:
    """AEAD index for the TOC. gen (header reserved[0:4]) is bumped on every encrypted append,
    so a rewritten TOC never reuses a nonce. gen=0 is what every archive before VFA 1.1 used."""
    return TOC_NONCE_BASE - gen

def pack_tocx(blocks: List[Tuple[int, int, int, int, Optional[int]]], toc_entries: bytes) -> bytes:
    """blocks: (frame_off, csz, usz, method, crc32 or None) in frame order; toc_entries: the TOC bytes before it."""
    body = bytearray(struct.pack("<I", len(blocks)))
    for off, csz, usz, meth, crc in blocks:
        body += BLOCK_REC.pack(off, csz, usz, meth, BF_CRC if crc is not None else 0, crc or 0)
    crc_rec = struct.pack("<I", crc32(toc_entries))
    return (TOCX_MAGIC + struct.pack("<I", 2)
            + struct.pack("<HHI", TX_TOCCRC, TXF_CRITICAL, len(crc_rec)) + crc_rec
            + struct.pack("<HHI", TX_BLOCKS, TXF_CRITICAL, len(body)) + bytes(body))

def crc32(data) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

# ---------------- Optional deps ----------------

try:
    import brotli; HAVE_BROTLI = True
except Exception:
    HAVE_BROTLI = False
try:
    import zstandard as zstd; HAVE_ZSTD = True
except Exception:
    HAVE_ZSTD = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAVE_AESGCM = True
except Exception:
    AESGCM = None; Scrypt = None; HAVE_AESGCM = False
try:
    import argon2.low_level as argon2ll
    HAVE_ARGON2 = True
except Exception:
    argon2ll = None; HAVE_ARGON2 = False
try:
    import lz4.frame as lz4f; HAVE_LZ4 = True
except Exception:
    HAVE_LZ4 = False
try:
    import xxhash; HAVE_XXH = True
except Exception:
    HAVE_XXH = False
try:
    import blake3 as _blake3; HAVE_BLAKE3 = True
except Exception:
    HAVE_BLAKE3 = False

# ---------------- Crypto / codec helpers ----------------

def _nonce_from(prefix12: bytes, index: int) -> bytes:
    m = hashlib.sha256(); m.update(prefix12); m.update(struct.pack("<Q", index)); m.update(b"vfa-nonce")
    return m.digest()[:12]

def _aead_decrypt(key, aead_id, nonce_prefix, index, ciphertext, aad=b""):
    if aead_id != AEAD_AESGCM or not HAVE_AESGCM:
        raise VFAError("Cannot decrypt: AES-GCM support unavailable (install 'cryptography').")
    try:
        return AESGCM(key).decrypt(_nonce_from(nonce_prefix, index), ciphertext, aad)
    except Exception:
        raise VFAError("Decryption failed (wrong password or corrupted data).", code=5)

def _kdf(password: bytes, kdf_id, t, m, p, salt) -> bytes:
    # The header chooses the KDF cost, so cap it: a damaged or hostile header must not be able to ask for
    # terabytes of RAM or hours of CPU. Writers default to Argon2id t=3, m=256 MiB, p=4 / scrypt n=2^15, r=8.
    if kdf_id == KDF_ARGON2ID and not (t <= 64 and m <= 4 * 1024 * 1024 and 1 <= (p or 4) <= 64):
        raise VFAError(f"Argon2 parameters out of range (t={t}, m={m} KiB, p={p}); refusing (corrupted header?).")
    if kdf_id == KDF_SCRYPT and not ((t or 1 << 15) <= 1 << 24 and (m or 8) <= 64 and (p or 1) <= 64
                                     and (t or 1 << 15) * (m or 8) * 128 <= 4 << 30):
        raise VFAError(f"scrypt parameters out of range (n={t}, r={m}, p={p}); refusing (corrupted header?).")
    if kdf_id == KDF_ARGON2ID:
        if not HAVE_ARGON2: raise VFAError("Argon2 KDF requested but argon2-cffi not installed.")
        return argon2ll.hash_secret_raw(secret=password, salt=salt, time_cost=t or 3,
                                        memory_cost=m or (256 * 1024), parallelism=p or 4,
                                        hash_len=32, type=argon2ll.Type.ID, version=argon2ll.ARGON2_VERSION)
    if kdf_id == KDF_SCRYPT:
        if Scrypt is None: raise VFAError("Scrypt KDF requested but 'cryptography' not installed.")
        return Scrypt(salt=salt, length=32, n=t or (1 << 15), r=m or 8, p=p or 1).derive(password)
    raise VFAError("Archive has no KDF but decryption was requested.")

def _drain(read, limit: int) -> bytes:
    """Read from a stream-like read(n) until EOF or limit+1 bytes."""
    out = bytearray()
    while len(out) <= limit:
        b = read(min(1 << 20, limit + 1 - len(out)))
        if not b: break
        out += b
    return out          # bytearray: no extra copy of a possibly large block

def _decompress(method: int, data: bytes, limit: int) -> bytes:
    """Decompress one block, never producing more than limit+1 bytes (callers then reject > limit).
    Raises VFAError on any codec error, truncated stream or unknown method."""
    name = METHOD_NAMES.get(method, f"#{method}")
    try:
        if method == M_NONE:
            return data[:limit + 1]
        if method == M_ZLIB:
            d = zlib.decompressobj(); out = d.decompress(data, limit + 1)
            if len(out) <= limit and not d.eof: raise VFAError("zlib stream truncated")
            return out
        if method in (M_LZMA, M_XZ):
            d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE if method == M_LZMA else lzma.FORMAT_XZ)
            out = d.decompress(data, max_length=limit + 1)
            if len(out) <= limit and not d.eof: raise VFAError(f"{name} stream truncated")
            return out
        if method == M_BZ2:
            d = bz2.BZ2Decompressor(); out = d.decompress(data, max_length=limit + 1)
            if len(out) <= limit and not d.eof: raise VFAError("bz2 stream truncated")
            return out
        if method == M_LZ4:
            if not HAVE_LZ4: raise VFAError("This archive needs lz4, which this build does not include.")
            d = lz4f.LZ4FrameDecompressor(); out = d.decompress(data, max_length=limit + 1)
            if len(out) <= limit and not d.eof: raise VFAError("lz4 stream truncated")
            return out
        if method == M_BROTLI:
            if not HAVE_BROTLI: raise VFAError("This archive needs brotli, which this build does not include.")
            d = brotli.Decompressor(); out = d.process(data)   # brotli has no output cap in its Python API
            if len(out) <= limit and not d.is_finished(): raise VFAError("brotli stream truncated")
            return out
        if method == M_ZSTD:
            if not HAVE_ZSTD: raise VFAError("This archive needs zstandard, which this build does not include.")
            with zstd.ZstdDecompressor().stream_reader(io.BytesIO(data), read_across_frames=False) as r:
                return _drain(r.read, limit)
    except VFAError:
        raise
    except Exception as e:
        raise VFAError(f"Corrupt {name} block: {e}")
    raise VFAError(f"Unknown compression method {method}; this archive needs a newer VFA.")

def _make_hasher(kind: int):
    if kind == H_SHA256: return hashlib.sha256()
    if kind == H_XXH64 and HAVE_XXH: return xxhash.xxh64()
    if kind == H_BLAKE3 and HAVE_BLAKE3: return _blake3.blake3()
    return None

# ---------------- Path safety ----------------

_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
                 *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}

def _check_rel(rel: str) -> List[str]:
    if "\x00" in rel:
        raise VFAError(f"Unsafe path in archive (NUL byte): {rel!r}")
    norm = rel.replace("\\", "/")
    if norm.startswith("/") or (len(norm) > 1 and norm[1] == ":"):
        raise VFAError(f"Unsafe absolute path in archive: {rel!r}")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise VFAError(f"Unsafe path traversal in archive: {rel!r}")
    if not parts:
        raise VFAError(f"Empty path in archive: {rel!r}")
    if os.name == "nt":
        for p in parts:
            if ":" in p:
                raise VFAError(f"Unsafe path in archive (':' / alternate data stream): {rel!r}")
            if any(c in '<>"|?*' or ord(c) < 32 for c in p) or p[-1] in " .":
                raise VFAError(f"Path in archive is not a valid Windows file name: {rel!r}")
            if p.split(".")[0].upper().rstrip(" ") in _WIN_RESERVED:
                raise VFAError(f"Unsafe path in archive (reserved device name): {rel!r}")
    return parts

def _inside(real_dest: str, real_full: str) -> bool:
    return real_full == real_dest or real_full.startswith(real_dest.rstrip(os.sep) + os.sep)

def safe_join(dest: str, rel: str, follow_last: bool = True) -> str:
    """Join an archive-relative path onto dest, refusing anything that could escape it
    (absolute paths, drive letters, '..', NUL, device names, or symlinks pointing out of dest).
    follow_last=False checks only the parent chain (for creating/replacing a link itself)."""
    parts = _check_rel(rel)
    full = os.path.join(dest, *parts)
    real_dest = os.path.realpath(dest)
    probe = full if follow_last else os.path.dirname(full)
    if not _inside(real_dest, os.path.realpath(probe)):
        raise VFAError(f"Path escapes destination: {rel!r}")
    return full

def _is_root(rel: str) -> bool:
    return all(p in ("", ".") for p in rel.replace("\\", "/").split("/"))

def _norm(rel: str) -> str:
    return "/".join(p for p in rel.replace("\\", "/").split("/") if p not in ("", "."))

# ---------------- Parsing ----------------

class _Reader:
    def __init__(self, data, what):
        self.mv = memoryview(data); self.pos = 0; self.what = what
    def need(self, n, field):
        if n < 0 or self.pos + n > len(self.mv):
            raise VFAError(f"{self.what} truncated reading {field}.")
        b = self.mv[self.pos:self.pos + n]; self.pos += n
        return b
    def u(self, fmt, field):
        s = struct.calcsize(fmt)
        return struct.unpack(fmt, self.need(s, field))[0]
    @property
    def left(self): return len(self.mv) - self.pos

def parse_header(data: bytes) -> dict:
    r = _Reader(data, "Header")
    if bytes(r.need(4, "magic")) != MAGIC: raise VFAError("Bad VFA header magic.")
    version = r.u("<H", "version")
    flags = r.u("<I", "flags")
    if version != SUPPORTED_VERSION:
        raise VFAError(f"Archive format version {version} is not supported by this reader (supports {SUPPORTED_VERSION}). "
                       "Use a newer VFA.")
    if flags & ~KNOWN_FLAGS:
        raise VFAError(f"Archive uses feature flags 0x{flags & ~KNOWN_FLAGS:x} this reader does not understand. Use a newer VFA.")
    dm, dl, be = struct.unpack("<BBB", r.need(3, "method/level/block"))
    th = r.u("<H", "threads"); rm = r.u("<I", "ram")
    kid = r.u("<B", "kdf id"); kt, km = struct.unpack("<II", r.need(8, "kdf params")); kp = r.u("<B", "kdf p")
    salt = bytes(r.need(16, "salt")); aid = r.u("<B", "aead id"); nprefix = bytes(r.need(12, "nonce prefix"))
    reserved = bytes(r.need(16, "reserved"))
    toc_gen = struct.unpack("<I", reserved[:4])[0]
    if flags & F_ENCRYPTED and aid != AEAD_AESGCM:
        raise VFAError(f"Unknown encryption id {aid}; this archive needs a newer VFA.")
    return {"version": version, "flags": flags, "default_method": dm, "default_level": dl,
            "block_exp": be, "threads": th, "ram_mib": rm, "kdf_id": kid, "kdf_t": kt,
            "kdf_m": km, "kdf_p": kp, "salt": salt, "aead_id": aid, "nonce_prefix": nprefix,
            "reserved": reserved, "toc_gen": toc_gen, "header_len": HEADER_LEN}

def parse_toc(data: bytes, solid: bool, has_tocx: bool) -> Tuple[List[dict], Optional[list]]:
    """Returns (entries, block_records or None). Every byte of the TOC must be accounted for."""
    r = _Reader(data, "TOC")
    n = r.u("<I", "count")
    entries = []
    for _ in range(n):
        plen = r.u("<H", "path length")
        try: path = bytes(r.need(plen, "path")).decode("utf-8")
        except UnicodeDecodeError: raise VFAError("TOC contains a path that is not valid UTF-8.")
        mode = r.u("<I", "mode"); mtime = r.u("<Q", "mtime"); size = r.u("<Q", "size"); nb = r.u("<I", "block count")
        entry_type = r.u("<B", "entry type")
        if entry_type > ET_HARDLINK: raise VFAError(f"Unknown entry type {entry_type} for {path!r}; this archive needs a newer VFA.")
        mlen = r.u("<I", "meta length")
        meta = bytes(r.need(mlen, "meta")) if mlen else b""
        blocks = []; start_off = 0
        if solid:
            start_off = r.u("<Q", "solid offset")
        else:
            if nb * 17 > r.left: raise VFAError("TOC truncated reading block tuples.")
            for _ in range(nb):
                idx, usz, csz, meth = struct.unpack("<QIIB", r.need(17, "block tuple"))
                blocks.append((idx, usz, csz, meth))
        if entry_type != ET_FILE and (blocks or size):
            raise VFAError(f"TOC entry {path!r} ({ET_NAMES[entry_type]}) claims file data.")
        if not solid and entry_type == ET_FILE and sum(b[1] for b in blocks) != size:
            raise VFAError(f"TOC entry {path!r}: block sizes do not add up to the file size.")
        entries.append({"path": path, "mode": mode, "mtime": mtime, "size": size, "blocks": blocks,
                        "start_off": start_off, "entry_type": entry_type, "meta": meta})
    recs = None
    if has_tocx:
        entries_end = r.pos
        if bytes(r.need(4, "extension magic")) != TOCX_MAGIC: raise VFAError("TOC extension magic missing.")
        toc_crc_ok = False
        for _ in range(r.u("<I", "extension count")):
            rtype, rflags, rlen = struct.unpack("<HHI", r.need(8, "extension record header"))
            body = bytes(r.need(rlen, "extension record"))
            if rtype == TX_BLOCKS:
                br = _Reader(body, "Block table")
                cnt = br.u("<I", "block count")
                if cnt * BLOCK_REC.size != br.left: raise VFAError("Block table size mismatch.")
                recs = [BLOCK_REC.unpack(br.need(BLOCK_REC.size, "block record")) for _ in range(cnt)]
            elif rtype == TX_TOCCRC:
                if len(body) != 4 or struct.unpack("<I", body)[0] != crc32(bytes(r.mv[:entries_end])):
                    raise VFAError("TOC failed its CRC32 check (corrupted archive).")
                toc_crc_ok = True
            elif rflags & TXF_CRITICAL:
                raise VFAError(f"Archive uses TOC extension type {rtype} this reader does not understand. Use a newer VFA.")
            else:
                LOGGER.debug(f"Ignoring optional TOC extension type {rtype}")
        if recs is None or not toc_crc_ok: raise VFAError("Archive is flagged with a block table but it is incomplete.")
    if r.left:
        raise VFAError(f"TOC has {r.left} unexpected trailing bytes (corrupted, or written by a newer VFA).")
    return entries, recs

# ---------------- Container ----------------

ProgressCB = Callable[[int, int, int, int, str], None]  # files_done, files_total, bytes_done, bytes_total, name

class Block:
    __slots__ = ("off", "csz", "usz", "method", "crc")
    def __init__(self, off, csz, usz, method, crc):
        self.off, self.csz, self.usz, self.method, self.crc = off, csz, usz, method, crc

class _FileView:
    """bytes-like window onto an open file: view[a:b] -> bytes, view[i] -> int. Positioned reads instead of mmap,
    so reading a large archive does not pin it into this process's working set (mmap'd pages count as RSS)."""
    def __init__(self, f, base: int, length: int):
        self._f, self._base, self._len = f, base, length
    def __len__(self): return self._len
    def __getitem__(self, k):
        if isinstance(k, slice):
            a, b, _ = k.indices(self._len)
            if b <= a: return b""
            self._f.seek(self._base + a); return self._f.read(b - a)
        if k < 0: k += self._len
        if not 0 <= k < self._len: raise IndexError(k)
        self._f.seek(self._base + k); return self._f.read(1)[0]
    def release(self): pass

def effective_end(buf, size: int) -> int:
    """Where the archive's footer ends. Normally the end of the file - but `signtool sign` on a stub+archive
    appends an Authenticode certificate table after it (recorded in the PE security directory, padded to 8 bytes).
    Then the footer ends where that table starts, minus up to 7 zero padding bytes."""
    try:
        if size < 0x40 or bytes(buf[0:2]) != b"MZ": return size
        pe, = struct.unpack("<I", buf[0x3C:0x40])
        if pe + 24 + 2 > size or bytes(buf[pe:pe + 4]) != b"PE\0\0": return size
        opt = pe + 24
        magic, = struct.unpack("<H", buf[opt:opt + 2])
        dd = opt + (96 if magic == 0x10B else 112 if magic == 0x20B else -1 << 40)
        if dd < 0 or dd + 5 * 8 > size: return size
        cert_off, cert_len = struct.unpack("<II", buf[dd + 4 * 8:dd + 5 * 8])
        if not cert_off or cert_off + cert_len != size: return size
        end = cert_off
        for _ in range(7):                      # signtool's alignment padding
            if bytes(buf[end - 5:end - 1]) == b"/VFA" or buf[end - 1] != 0: break
            end -= 1
        LOGGER.debug(f"Authenticode certificate table at {cert_off}; archive ends at {end}")
        return end
    except Exception:
        return size

def find_manifest(buf, arc_start: int) -> Tuple[Optional[dict], int]:
    """Optional SFI manifest right before the archive: [manifest JSON][u32 len]["/VFIM1"]. Returns (manifest, stub_end)."""
    mt = len(MANIFEST_MAGIC)
    if arc_start >= mt + 4 and bytes(buf[arc_start - mt:arc_start]) == MANIFEST_MAGIC:
        (mlen,) = struct.unpack("<I", buf[arc_start - mt - 4:arc_start - mt])
        mstart = arc_start - mt - 4 - mlen
        if mstart >= 0:
            try:
                return json.loads(bytes(buf[mstart:mstart + mlen]).decode("utf-8")), mstart
            except Exception as e:
                LOGGER.warning(f"Manifest present but unreadable: {e}")
    return None, arc_start

def open_container(path: str):
    """Open a VFA1 or VFA2 archive (plain, SFX, SFI, signed or not); the format is chosen by the end magic."""
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        end = effective_end(_FileView(f, 0, size), size)
        f.seek(max(0, end - 5)); tail = f.read(5)
    if tail == b"/VFA2":
        import vfa2
        return vfa2.Archive2(path)
    return Container(path)

def _case_insensitive(dest: str) -> bool:
    """Does the filesystem at dest treat names case-insensitively? Probed with a temporary file."""
    try:
        fd, probe = tempfile.mkstemp(prefix=".vfacase-", dir=dest); os.close(fd)
    except OSError:
        return os.name == "nt" or sys.platform == "darwin"     # cannot probe: assume the platform default
    try:
        return os.path.exists(os.path.join(os.path.dirname(probe), os.path.basename(probe).upper()))
    finally:
        try: os.remove(probe)
        except OSError: pass

def _broad_key(p: str) -> str:
    """Folds at least as much as any volume we know (case, NFC/NFD, Windows separators): equal keys MAY be one file."""
    return unicodedata.normalize("NFC", os.path.normcase(p)).casefold()


def _same_on_volume(dest: str, a: str, b: str) -> bool:
    """Ask the destination volume whether relative paths a and b name one file: create a in a scratch directory
    at dest and look for b. The volume's own rules decide (NTFS upcase table, APFS normalization, ...)."""
    probe = tempfile.mkdtemp(prefix=".vfaprobe-", dir=dest)
    try:
        pa = os.path.join(probe, a); os.makedirs(os.path.dirname(pa), exist_ok=True)
        open(pa, "wb").close()
        return os.path.exists(os.path.join(probe, b))
    finally:
        shutil.rmtree(probe, ignore_errors=True)


def _escapes(rel: str) -> bool:
    """True if a relpath() result leaves its start directory: a real ".." component, not a name like "..foo"."""
    return rel == os.pardir or rel.startswith(os.pardir + os.sep) or (os.altsep and rel.startswith(os.pardir + os.altsep))


def _alias_key_for(dest: str):
    """Returns (key, broad): key(p) is equal for two target paths exactly when they name the same file at dest;
    broad(p) may also merge names the volume keeps apart (fine for picking unused temporary names).
    Parents are resolved first: a directory that already exists at dest may be a symlink (safe_join allows ones
    that stay inside dest), so d1/a and d2/a can be one file. On a case-insensitive volume, names that fold alike
    are then checked against the volume itself: guessing its rules either drops a file (NTFS keeps ss/\u00df,
    NFC/NFD and I-with-dot/i+dot apart) or misses an alias."""
    real: Dict[str, str] = {}                 # one realpath per directory, not per file
    def resolve(p):
        d, b = os.path.split(p)
        r = real.get(d)
        if r is None: r = real[d] = os.path.realpath(d)
        return os.path.join(r, b)
    broad = lambda p: _broad_key(resolve(p))
    if not _case_insensitive(dest):
        return (lambda p: os.path.normcase(resolve(p))), broad
    root = os.path.realpath(dest)
    reps: Dict[str, List[str]] = {}           # broad key -> resolved paths the volume keeps apart
    canon: Dict[str, str] = {}
    def key(p):
        x = resolve(p)
        c = canon.get(x)
        if c is not None: return c
        group = reps.setdefault(_broad_key(x), [])
        for r in group:
            ra, rb = os.path.relpath(r, root), os.path.relpath(x, root)
            if not _escapes(ra) and not _escapes(rb) and _same_on_volume(dest, ra, rb):
                canon[x] = r; return r
        group.append(x); canon[x] = x
        return x
    return key, broad

class Extractable:
    """Selection + safe extraction shared by every container format. A subclass provides entries (dicts with path,
    mode, mtime, size, entry_type, meta) and _write_files(), which writes the selected regular files."""
    manifest: Optional[dict] = None
    stub_end = 0

    @property
    def stub_bytes(self) -> bytes:
        """The executable part only (no manifest, no payload)."""
        return self.buf[:self.stub_end]

    @property
    def total_files(self) -> int:
        return sum(1 for e in self.entries if e["entry_type"] == ET_FILE and not e["path"].startswith(MANIFEST_RESERVED_PREFIX))
    @property
    def total_bytes(self) -> int:
        return sum(e["size"] for e in self.entries if e["entry_type"] == ET_FILE and not e["path"].startswith(MANIFEST_RESERVED_PREFIX))

    # -- selection --
    def select(self, members: Optional[Iterable[str]]) -> List[dict]:
        """Entries matching the given archive paths (a directory selects everything below it)."""
        if not members: return list(self.entries)
        want = {_norm(m) for m in members}
        out = []
        for e in self.entries:
            p = _norm(e["path"])
            if p in want or any(p.startswith(w + "/") for w in want if w): out.append(e)
        missing = [w for w in want if not any(_norm(e["path"]) == w or _norm(e["path"]).startswith(w + "/") for e in out)]
        if missing: raise VFAError("Not in archive: " + ", ".join(sorted(missing)))
        return out

    # -- extraction --
    def extract(self, dest: str, progress: Optional[ProgressCB] = None,
                cancel: Optional[Callable[[], bool]] = None, members: Optional[Iterable[str]] = None,
                links: bool = False, keep_mode_bits: int = 0o777,
                after_entry: Optional[Callable[[dict, str], None]] = None) -> Tuple[List[str], List[str]]:
        """Extract everything (or `members`) into dest. Returns (files, dirs) as '/'-separated relative paths.
        Order: dirs, files, then (links=True, POSIX only) hardlinks and symlinks - links are created last so
        no file is ever written through a link from the archive. after_entry(entry, out_path) runs for every
        created entry (vfa.py uses it to restore metadata)."""
        if self.entries is None: raise VFAError("Call unlock() before extract().")
        os.makedirs(dest, exist_ok=True)
        sel = [e for e in self.select(members) if not e["path"].startswith(MANIFEST_RESERVED_PREFIX)]
        files: List[str] = []; dirs: List[str] = []
        sel_files = [e for e in sel if e["entry_type"] == ET_FILE]
        total_files = len(sel_files); total_bytes = sum(e["size"] for e in sel_files)
        done = {"files": 0, "bytes": 0}
        posix = os.name != "nt"

        def check_cancel():
            if cancel and cancel(): raise VFAError("Cancelled.", code=4)
        partial: Set[str] = set()     # files being written live under NAME.vfapart until fully checked
        def start(e):
            out = targets[id(e)]; os.makedirs(os.path.dirname(out), exist_ok=True)
            tmp = tmps[out]; partial.add(tmp)
            return out, open(tmp, "wb")
        def commit(out, fw):
            fw.close(); os.replace(tmps[out], out); partial.discard(tmps[out])
        def finish(e, out_path):
            ns = e["mtime"] * 1_000_000_000 + e.get("mtime_ns", 0)     # VFA2 stores nanoseconds
            try: os.utime(out_path, ns=(ns, ns))
            except Exception: pass
            if posix:
                perm = e["mode"] & keep_mode_bits     # setuid/setgid/sticky only if the caller asks for them
                if perm:
                    try: os.chmod(out_path, perm)
                    except Exception: pass
            files.append(_norm(e["path"]))
            done["files"] += 1; done["bytes"] += e["size"]
            if after_entry: after_entry(e, out_path)
            if progress: progress(done["files"], total_files, done["bytes"], total_bytes, e["path"])

        # validate every target before writing anything
        sel_dirs = [(e, safe_join(dest, e["path"])) for e in sel if e["entry_type"] == ET_DIR and not _is_root(e["path"])]
        targets = {id(e): safe_join(dest, e["path"]) for e in sel_files}
        # several entries may name the same file (an archive made from "a a", or a crafted one): the last one wins,
        # as with sequential extraction, and only it is written (two writers on one .vfapart would collide).
        # "Same file" follows the destination: case-insensitive volumes (Windows, default macOS) alias A and a.
        alias_key, broad_key = _alias_key_for(dest)
        all_files = list(sel_files)   # before duplicates are dropped: a dropped entry's path still needs its parents
        last = {}
        for e in sel_files: last[alias_key(targets[id(e)])] = id(e)
        dups = [e for e in sel_files if last[alias_key(targets[id(e)])] != id(e)]
        if dups:
            LOGGER.warning(f"{len(dups)} duplicate path(s) in the archive (e.g. {dups[0]['path']!r}): the last entry wins")
            keep = set(last.values()); sel_files = [e for e in sel_files if id(e) in keep]
            total_files = len(sel_files); total_bytes = sum(e["size"] for e in sel_files)
        # a path the archive needs as a directory (an entry's parent, or a directory entry) must not also be one of
        # its files: "z" as a file next to "z/a.txt" is refused here instead of failing half-way with an OS error
        file_keys = {alias_key(targets[id(e)]) for e in sel_files}; seen_dirs: Set[str] = set()
        for e in all_files + [d for d, _ in sel_dirs]:
            parts = [x for x in _norm(e["path"]).split("/") if x]
            need = ["/".join(parts[:i]) for i in range(1, len(parts))]
            if e["entry_type"] == ET_DIR: need.append("/".join(parts))
            for rel in need:
                if rel in seen_dirs: continue
                seen_dirs.add(rel)
                # both the path as written and where it resolves to: with dest/x -> y already there, "x/a" needs
                # "y" as a directory (clash with a file "y"), and still needs "x" itself (clash with a file "x")
                full = os.path.join(dest, *rel.split("/"))
                if alias_key(full) in file_keys or alias_key(os.path.realpath(full)) in file_keys:
                    raise VFAError(f"Archive entry {e['path']!r} needs {rel!r} as a directory, but the archive also "
                                   f"has a file there; refusing to extract.")
        for e, p in sel_dirs:
            os.makedirs(p, exist_ok=True); dirs.append(_norm(e["path"]))
        # temporary names (NAME.vfapart) must not alias a final target or each other: an archive holding both
        # "a" and "a.vfapart" would otherwise have one entry's commit rename the other's half-written file
        # (compared broadly: a temporary name that might alias something just gets a number)
        taken = {broad_key(targets[id(e)]) for e in sel_files}; tmps = {}
        for e in sel_files:
            out = targets[id(e)]; tmp = out + ".vfapart"; n = 0
            while broad_key(tmp) in taken:
                n += 1; tmp = f"{out}.{n}.vfapart"
            taken.add(broad_key(tmp)); tmps[out] = tmp

        active: list = []            # (entry, out, handle) currently open - closed + cleaned up on any failure
        try:
            self._write_files(sel_files, start, commit, finish, check_cancel, active)
        finally:
            for _, _, fw in active:
                try: fw.close()
                except Exception: pass
            for tmp in partial:
                try: os.remove(tmp)
                except Exception: pass

        if links and posix:
            for e in [x for x in sel if x["entry_type"] == ET_HARDLINK]:
                self._make_link(dest, e, hard=True, after_entry=after_entry)
            for e in [x for x in sel if x["entry_type"] == ET_SYMLINK]:
                self._make_link(dest, e, hard=False, after_entry=after_entry)
        else:
            for e in sel:
                if e["entry_type"] in (ET_SYMLINK, ET_HARDLINK):
                    LOGGER.warning(f"Skipping {ET_NAMES[e['entry_type']]} entry: {e['path']}")

        # parent directories implied by files
        seen = set(dirs)
        for f in files:
            d = f.rsplit("/", 1)[0] if "/" in f else ""
            while d and d not in seen:
                seen.add(d); dirs.append(d)
                d = d.rsplit("/", 1)[0] if "/" in d else ""
        for e in sel:
            if e["entry_type"] == ET_DIR and not _is_root(e["path"]) and after_entry:
                after_entry(e, safe_join(dest, e["path"]))
        return files, dirs

    def _make_link(self, dest, e, hard, after_entry):
        try: meta = json.loads(e["meta"].decode("utf-8")) if e["meta"] else {}
        except Exception: meta = {}
        out = safe_join(dest, e["path"], follow_last=False)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        if os.path.lexists(out):
            if os.path.isdir(out) and not os.path.islink(out):
                raise VFAError(f"Cannot create link over a directory: {e['path']!r}")
            os.remove(out)
        if hard:
            target = meta.get("hardlink_to", "")
            src = safe_join(dest, target)        # follows links: a hardlink can never reach outside dest
            if not os.path.isfile(src): raise VFAError(f"Hardlink {e['path']!r} points at missing file {target!r}")
            os.link(src, out)
        else:
            os.symlink(meta.get("link_target", ""), out)
        if after_entry: after_entry(e, out)


class Container(Extractable):
    """Read-only view of [stub+]archive. Use as a context manager.
    Typical use: Container(path) -> verify_digest() -> unlock(pw) -> extract(dest)."""

    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb")
        self.size = os.fstat(self._f.fileno()).st_size
        if self.size < FOOTER_LEN + HEADER_LEN:
            self._f.close(); raise VFAError(f"File too small to hold a VFA payload (size={self.size}).")
        self.buf = _FileView(self._f, 0, self.size)
        self.header = None; self.entries = None; self.key = None; self.blocks: List[Block] = []
        self.manifest: Optional[dict] = None
        self.stub_end = 0
        try: self._locate()
        except Exception: self.close(); raise

    def close(self):
        for fn in (lambda: self._f.close(),):
            try: fn()
            except Exception: pass
    def __enter__(self): return self
    def __exit__(self, *a): self.close()

    # -- locate footer / header / manifest --
    def _locate(self):
        E = effective_end(self.buf, self.size)
        if bytes(self.buf[E - 5:E]) != END_MAGIC:
            if bytes(self.buf[E - 5:E])[:4] == b"/VFA":
                raise VFAError(f"This is a different VFA format ({bytes(self.buf[E - 4:E]).decode('ascii', 'replace')}); "
                               "this reader only understands VFA1. Use a newer VFA (or vfa_extract.open_container).")
            raise VFAError("END_MAGIC not found at end of file; no VFA payload attached.")
        off = E - FOOTER_LEN
        self.toc_off, = struct.unpack("<Q", self.buf[off:off + 8])
        self.toc_sz,  = struct.unpack("<I", self.buf[off + 8:off + 12])
        self.hash_kind = self.buf[off + 12]
        self.digest = bytes(self.buf[off + 13:off + 45])
        self.footer_pos = off
        self.arc_start = E - FOOTER_LEN - self.toc_sz - self.toc_off
        LOGGER.debug(f"Footer: toc_off={self.toc_off} toc_sz={self.toc_sz} hash_kind={self.hash_kind} arc_start={self.arc_start}")
        if self.arc_start < 0 or self.toc_off < HEADER_LEN:
            raise VFAError("Invalid payload offsets (corrupted footer).")
        if bytes(self.buf[self.arc_start:self.arc_start + 4]) != MAGIC:
            raise VFAError("VFA header magic not found at computed start (payload misaligned or corrupted).")
        self.manifest, self.stub_end = find_manifest(self.buf, self.arc_start)
        self.arc = _FileView(self._f, self.arc_start, self.footer_pos - self.arc_start)   # header .. end of TOC
        self.header = parse_header(bytes(self.arc[:HEADER_LEN]))
        self.solid = bool(self.header["flags"] & F_SOLID)
        self.encrypted = bool(self.header["flags"] & F_ENCRYPTED)
        self.has_tocx = bool(self.header["flags"] & F_TOCX)

    # -- integrity --
    def verify_digest(self, progress: Optional[Callable[[int, int], None]] = None) -> Optional[bool]:
        """True = match, False = mismatch, None = archive stores no digest.
        Raises VFAError if the digest algorithm is not available in this build - never silently skips."""
        if self.hash_kind == H_NONE: return None
        h = _make_hasher(self.hash_kind)
        if h is None:
            raise VFAError(f"Cannot verify integrity: archive digest is {HASH_NAMES.get(self.hash_kind, self.hash_kind)}, "
                           "which this build does not include.")
        pos = self.arc_start; end = self.footer_pos; total = end - pos
        while pos < end:
            n = min(1 << 22, end - pos)
            h.update(self.buf[pos:pos + n]); pos += n
            if progress: progress(pos - self.arc_start, total)
        d = h.digest()
        if self.hash_kind == H_XXH64: d = d + b"\x00" * 24
        return d == self.digest

    # -- unlock / TOC --
    def unlock(self, password: Optional[str] = None):
        """Decrypt (if needed) and parse the TOC, then build and cross-check the block table.
        Raises VFAError(code=5) on a wrong password."""
        toc = bytes(self.arc[self.toc_off:self.toc_off + self.toc_sz])
        h = self.header
        if self.encrypted:
            if password is None: raise VFAError("This payload is encrypted; a password is required.", code=5)
            self.key = _kdf(password.encode("utf-8"), h["kdf_id"], h["kdf_t"], h["kdf_m"], h["kdf_p"], h["salt"])
            toc = _aead_decrypt(self.key, h["aead_id"], h["nonce_prefix"], toc_nonce_index(h["toc_gen"]), toc, aad=b"vfa-toc")
        self.entries, recs = parse_toc(toc, self.solid, self.has_tocx)
        self.blocks = self._block_table(recs)
        self._cross_check()
        return self.entries

    def _frame(self, off):
        if off + FRAME_HDR > self.toc_off: raise VFAError("Block header runs into the TOC (corrupted archive).")
        csz, = struct.unpack("<I", self.arc[off:off + 4])
        return csz, self.arc[off + 4]

    def _block_table(self, recs) -> List[Block]:
        blocks = []; pos = HEADER_LEN
        if recs is not None:
            for i, (off, csz, usz, meth, bflags, crc) in enumerate(recs):
                if off != pos: raise VFAError(f"Block table entry {i} points at {off}, expected {pos} (corrupted archive).")
                fcsz, fmeth = self._frame(off)
                if (fcsz, fmeth) != (csz, meth): raise VFAError(f"Block {i} header disagrees with the block table (corrupted archive).")
                if usz > MAX_BLOCK: raise VFAError(f"Block {i} claims {usz} bytes, above the format limit.")
                blocks.append(Block(off, csz, usz, meth, crc if bflags & BF_CRC else None))
                pos = off + FRAME_HDR + csz
        else:   # VFA 1.0 archive: walk the frames (headers only, no decompression)
            while pos < self.toc_off:
                csz, meth = self._frame(pos)
                blocks.append(Block(pos, csz, None, meth, None))
                pos += FRAME_HDR + csz
        if pos != self.toc_off:
            raise VFAError("Block region does not end where the TOC begins (corrupted or truncated archive).")
        return blocks

    def _cross_check(self):
        if self.solid:
            ends = [e["start_off"] + e["size"] for e in self.entries if e["entry_type"] == ET_FILE]
            self.stream_len = max(ends, default=0)
            if all(b.usz is not None for b in self.blocks):
                total = sum(b.usz for b in self.blocks)
                if total != self.stream_len:
                    raise VFAError(f"Solid stream is {total} bytes but the TOC needs {self.stream_len} (corrupted archive).")
            return
        used = set()
        for e in self.entries:
            for (idx, usz, csz, meth) in e["blocks"]:
                if idx >= len(self.blocks): raise VFAError(f"{e['path']!r} references missing block {idx}.")
                b = self.blocks[idx]
                if (b.csz, b.method) != (csz, meth): raise VFAError(f"{e['path']!r}: block {idx} does not match the TOC.")
                if b.usz is None: b.usz = usz
                elif b.usz != usz: raise VFAError(f"{e['path']!r}: block {idx} size disagrees with the block table.")
                if idx in used: raise VFAError(f"Block {idx} is referenced twice (corrupted archive).")
                used.add(idx)

    # -- block access --
    def block_data(self, i: int, limit: Optional[int] = None) -> bytes:
        """Decrypt + decompress block i, checking its size and CRC32 when the archive records them."""
        b = self.blocks[i]
        payload = bytes(self.arc[b.off + FRAME_HDR:b.off + FRAME_HDR + b.csz])
        if self.encrypted:
            h = self.header
            payload = _aead_decrypt(self.key, h["aead_id"], h["nonce_prefix"], i, payload, aad=b"vfa-data")
        cap = b.usz if b.usz is not None else min(MAX_BLOCK, limit if limit is not None else MAX_BLOCK)
        data = _decompress(b.method, payload, cap)
        if b.usz is not None and len(data) != b.usz:
            raise VFAError(f"Block {i} decompressed to {len(data)} bytes, expected {b.usz} (corrupted archive).")
        if len(data) > cap:
            raise VFAError(f"Block {i} decompresses to more data than the archive accounts for (corrupted archive).")
        if b.crc is not None and crc32(data) != b.crc:
            raise VFAError(f"Block {i} failed its CRC32 check (corrupted archive).")
        return data

    def _solid_blocks(self, intervals: List[Tuple[int, int]]) -> Iterator[Tuple[int, bytes]]:
        """Yield (stream_pos, data) for every solid block overlapping one of the [start, end) intervals.
        With a block table, blocks that are not needed are skipped without being read."""
        if not intervals: return
        last = max(e for _, e in intervals)
        known = all(b.usz is not None for b in self.blocks)
        pos = 0
        for i, b in enumerate(self.blocks):
            if pos >= last and last > 0: break
            if known:
                end = pos + b.usz
                if not any(s < end and e > pos for s, e in intervals): pos = end; continue
            data = self.block_data(i, limit=self.stream_len - pos)
            yield pos, data
            pos += len(data)
        if pos < last:
            raise VFAError(f"Solid stream ended at {pos} bytes, the TOC needs {last} (corrupted archive).")

    def iter_entry(self, e: dict) -> Iterator[bytes]:
        """Random access: yield the bytes of one file entry."""
        if e["entry_type"] != ET_FILE: return
        if not self.solid:
            for (idx, usz, csz, meth) in e["blocks"]:
                yield self.block_data(idx)
            return
        s, n = e["start_off"], e["size"]
        if n == 0: return
        for pos, data in self._solid_blocks([(s, s + n)]):
            lo, hi = max(s, pos) - pos, min(s + n, pos + len(data)) - pos
            if hi > lo: yield data[lo:hi]

    def test(self, progress: Optional[Callable[[int, int], None]] = None) -> dict:
        """Decode every block (size + CRC checks). Returns {"blocks": n, "bytes": total}."""
        total = 0; nblk = len(self.blocks)
        for i in range(nblk):
            limit = (self.stream_len - total) if self.solid else None
            total += len(self.block_data(i, limit=limit))
            if progress: progress(i + 1, nblk)
        if self.solid and total != self.stream_len:
            raise VFAError(f"Solid stream is {total} bytes, the TOC needs {self.stream_len}.")
        if not self.solid:
            unused = len(self.blocks) - sum(len(e["blocks"]) for e in self.entries)
            if unused: LOGGER.warning(f"{unused} block(s) are not referenced by any entry.")
        return {"blocks": nblk, "bytes": total}


    def _write_files(self, sel_files, start, commit, finish, check_cancel, active):
        """VFA1: non-solid files block by block; solid files in one forward pass over the needed blocks."""
        if not self.solid:
            for e in sel_files:
                check_cancel()
                out, fw = start(e); active[:] = [(e, out, fw)]
                for chunk in self.iter_entry(e):
                    check_cancel(); fw.write(chunk)
                active.clear(); commit(out, fw); finish(e, out)
        else:
            pending = sorted(sel_files, key=lambda e: (e["start_off"], e["size"]))
            for e in [e for e in pending if e["size"] == 0]:
                out, fw = start(e); commit(out, fw); finish(e, out)
            pending = [e for e in pending if e["size"] > 0]
            nxt = 0
            for pos, data in self._solid_blocks([(e["start_off"], e["start_off"] + e["size"]) for e in pending]):
                check_cancel()
                q = pos + len(data); mv = memoryview(data)
                while nxt < len(pending) and pending[nxt]["start_off"] < q:
                    e = pending[nxt]; nxt += 1
                    out, fw = start(e); active.append((e, out, fw))
                still = []
                for e, out, fw in active:
                    s, t = e["start_off"], e["start_off"] + e["size"]
                    lo, hi = max(s, pos), min(t, q)
                    if hi > lo: fw.write(mv[lo - pos:hi - pos])
                    if t <= q: commit(out, fw); finish(e, out)
                    else: still.append((e, out, fw))
                active[:] = still
            if active or nxt < len(pending):
                raise VFAError("Solid stream ended before all files were complete (corrupted archive).")


def prompt_password(prompt="Password: ") -> str:
    return getpass.getpass(prompt)
