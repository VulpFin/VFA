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

#!/usr/bin/env python3
from __future__ import annotations
import argparse, getpass, io, os, sys, struct, time, pathlib, platform, json, stat, subprocess, ctypes
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict
from datetime import datetime
# from vulp_codec import compress_block, decompress_block
global LOGGER

# ---------- Optional deps ----------
# cryptography and argon2 load on first use (see vfa_extract._crypto / _argon2): only encryption needs them, and
# importing argon2 costs ~0.17 s per run on Windows

import zlib, lzma, hashlib, bz2
try:
    import brotli; HAVE_BROTLI=True
except Exception:
    HAVE_BROTLI=False
try:
    import zstandard as zstd; HAVE_ZSTD=True
except Exception:
    HAVE_ZSTD=False
try:
    import blake3; HAVE_BLAKE3=True
except Exception:
    HAVE_BLAKE3=False
try:
    import xxhash; HAVE_XXH=True
except Exception:
    HAVE_XXH=False
try:
    import lz4.frame as lz4f; HAVE_LZ4=True
except Exception:
    HAVE_LZ4=False

import vfa_extract as vx   # the shared reader (also used by the SFX/SFI stubs and the viewer)
from vfa_extract import VFAError

WIN = (platform.system() == "Windows")
LIN = (sys.platform.startswith("linux"))

if WIN:
    try:
        import win32file, win32con, win32security, pywintypes
        HAVE_WIN32=True
    except Exception:
        HAVE_WIN32=False
else:
    HAVE_WIN32=False

# ---------- Logger ----------
LOG_COL_PIPE = 48

class VLog:
    LEVELS = {"quiet":0, "error":1, "warning":2, "info":3, "debug":4, "trace":5}
    def __init__(self, level:str="warning"):
        self.level = self.LEVELS.get(level, 2)
    def _fmt(self, level_name:str, msg:str):
        now = datetime.now().strftime("%m/%d/%Y %H:%M:%S.%f")[:-1]  # 5 decimals
        prefix = f"[VFA {level_name.upper():<7}] {now}"
        pad = LOG_COL_PIPE - len(prefix) - 1
        if pad < 1: pad = 1
        return f"{prefix}{' ' * pad}| {msg}"
    def _emit(self, lvl:int, name:str, msg:str):
        if self.level >= lvl:
            print(self._fmt(name, msg))
    def error(self, msg:str):   self._emit(1, "ERROR", msg)
    def warning(self, msg:str): self._emit(2, "WARNING", msg)
    def info(self, msg:str):    self._emit(3, "INFO", msg)
    def debug(self, msg:str):   self._emit(4, "DEBUG", msg)
    def trace(self, msg:str):   self._emit(5, "TRACE", msg)

LOGGER = VLog()

def human_bytes(n:int) -> str:
    units = ["B","KiB","MiB","GiB","TiB","PiB"]
    v = float(n); i = 0
    while v >= 1024 and i < len(units)-1:
        v /= 1024.0; i += 1
    return f"{v:.2f} {units[i]}"

class Progress:
    def __init__(self, total_files:int, total_bytes:int):
        self.total_files = total_files
        self.total_bytes = total_bytes
        self.done_files = 0
        self.done_bytes = 0
        self.start_ts = time.time()
    def add_file(self, size:int, duration_s:float):
        self.done_files += 1
        self.done_bytes += size
    def estimate(self):
        elapsed = time.time() - self.start_ts
        rate = self.done_bytes / elapsed if elapsed > 0 else 0.0
        remain_bytes = max(0, self.total_bytes - self.done_bytes)
        eta = (remain_bytes / rate) if rate > 0 else float("inf")
        ratio = (self.done_bytes / self.total_bytes) if self.total_bytes > 0 else 0.0
        return elapsed, eta, rate, ratio

# ---------- Constants ----------
MAGIC = b"VFA1"
END_MAGIC = b"/VFA1"
VERSION = 1

AEAD_NONE = 0
AEAD_AESGCM = 1
KDF_NONE = 0
KDF_ARGON2ID = 1
KDF_SCRYPT = 2

M_NONE = 0
M_ZLIB = 1
M_LZMA = 2
M_BROTLI = 3
M_ZSTD = 4
M_XZ = 5
M_BZ2 = 6
M_LZ4 = 7
# M_VULP = #

# id -> canonical lowercase name
METHOD_NAMES = {
    M_NONE: "none",
    M_ZLIB: "zlib",
    M_LZMA: "lzma",
    M_BROTLI: "brotli",
    M_ZSTD: "zstd",
    M_XZ: "xz",
    M_BZ2: "bz2",
    M_LZ4: "lz4",
#    M_VULP: "vulp",
}

# name -> id (pure reverse map)
NAME_TO_METHOD = {name: mid for (mid, name) in METHOD_NAMES.items()}


# Separate registry for implementations: id -> impl
# (and optionally name -> impl if you like)
class MethodImpl:
    __slots__ = ("id", "name", "compress", "decompress", "level_min", "level_max")

    def __init__(self, mid, name, compress, decompress, level_min=0, level_max=9):
        self.id = int(mid)
        self.name = name
        self.compress = compress
        self.decompress = decompress
        self.level_min = int(level_min)
        self.level_max = int(level_max)


METHOD_IMPLS_BY_ID = {}  # int id -> MethodImpl
METHOD_IMPLS_BY_NAME = {}  # str name -> MethodImpl


def register_method(mid, name, compress, decompress, level_min=0, level_max=9):
    impl = MethodImpl(mid, name, compress, decompress, level_min, level_max)
    METHOD_IMPLS_BY_ID[mid] = impl
    METHOD_IMPLS_BY_NAME[name] = impl

"""
# ---------- VULP glue ----------
def vulp_compress(data: bytes, level: int = 5) -> bytes:
    # Map level to block size (fast, simple knob): 256 KiB .. 2 MiB
    if level is None:
        level = 5
    try:
        level = int(level)
    except Exception:
        level = 5
    if level < 0:
        level = 0
    if level > 12:
        level = 12

    base = 256 * 1024
    top = 2 * 1024 * 1024
    bs = base + ((top - base) * level) // 12

    out = bytearray()
    for i in range(0, len(data), bs):
        out += compress_block(data[i : i + bs])
    return bytes(out)


def vulp_decompress(blob: bytes) -> bytes:
    mv = memoryview(blob)
    off = 0
    out = bytearray()
    while off < len(blob):
        raw, off = decompress_block(mv, off)
        out += raw
    return bytes(out)


# Register VULP without clobbering the name->id map
register_method(
    M_VULP, "vulp", vulp_compress, vulp_decompress, level_min=0, level_max=12
)
"""


# Flags
F_ENCRYPTED=1<<0
F_SOLID=1<<1
F_TOCX=vx.F_TOCX        # TOC carries a block table (offsets, sizes, CRC32) - VFA 1.1

# Hash kind
H_NONE=0; H_SHA256=1; H_BLAKE3=2; H_XXH64=3

DEFAULT_SOLID_CHUNK_EXP = 26    # solid streams are cut into 64 MiB blocks (= the xz/lzma -9 dictionary) unless --solid-chunk-exp says otherwise
MAX_BLOCK_EXP = 30              # vx.MAX_BLOCK: keeps every block's compressed size well inside u32

def default_hash_kind():
    # Always SHA-256: it is in every Python's stdlib, so every reader can verify it.
    # (xxh64/blake3 archives from older builds are still read when the library is present.)
    return H_SHA256

def make_hasher(kind:int):
    if kind==H_XXH64:
        if not HAVE_XXH: raise RuntimeError("xxhash not installed")
        import xxhash as _xx; return _xx.xxh64()
    if kind==H_BLAKE3:
        if not HAVE_BLAKE3: raise RuntimeError("blake3 not installed")
        import blake3 as _b3; return _b3.blake3()
    if kind==H_SHA256:
        return hashlib.sha256()
    raise RuntimeError("bad hash kind")

def hasher_update(h, data:bytes, kind:int): h.update(data)
def hasher_digest(h, kind:int)->bytes:
    if kind==H_XXH64: return h.digest()+b"\x00"*24
    return h.digest()

def nonce_from(prefix12:bytes, index:int)->bytes:
    m=hashlib.sha256(); m.update(prefix12); m.update(struct.pack("<Q", index)); m.update(b"vfa-nonce"); return m.digest()[:12]

# ---------- Header ----------
@dataclass
class HeaderV1:
    version:int=VERSION; flags:int=0
    default_method:int=M_ZSTD if HAVE_ZSTD else M_ZLIB
    default_level:int=5; block_exp:int=22
    threads_hint:int=0; ram_mib_hint:int=0
    kdf_id:int=KDF_NONE; kdf_t:int=0; kdf_m:int=0; kdf_p:int=0
    salt:bytes=b"\x00"*16
    aead_id:int=AEAD_NONE; aead_nonce_prefix:bytes=b"\x00"*12
    reserved:bytes=b"\x00"*16
    def pack(self)->bytes:
        return b"".join([
            MAGIC, struct.pack("<H", self.version), struct.pack("<I", self.flags),
            struct.pack("<B", self.default_method), struct.pack("<B", self.default_level),
            struct.pack("<B", self.block_exp), struct.pack("<H", self.threads_hint),
            struct.pack("<I", self.ram_mib_hint),
            struct.pack("<B", self.kdf_id), struct.pack("<I", self.kdf_t),
            struct.pack("<I", self.kdf_m), struct.pack("<B", self.kdf_p),
            self.salt, struct.pack("<B", self.aead_id), self.aead_nonce_prefix, self.reserved
        ])

# Entry types
ET_FILE=0; ET_DIR=1; ET_SYMLINK=2; ET_HARDLINK=3

@dataclass
class FileEntry:
    path:str
    mode:int
    mtime:int
    size:int
    blocks:List[Tuple[int,int,int,int]] = field(default_factory=list)   # non-solid blocks
    start_off:int=0            # solid offset for files
    entry_type:int=ET_FILE     # 0=file,1=dir,2=symlink,3=hardlink
    meta_json:Optional[bytes]=None

@dataclass
class TOC:
    entries:List[FileEntry]=field(default_factory=list)
    def pack(self, solid: bool=False, block_recs=None)->bytes:
        """block_recs (frame_off, csz, usz, method, crc32) -> appended as the VTX1 extension (needs F_TOCX).
        Older readers stop after the entries and ignore it."""
        if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("dataclass TOC function pack")
        if block_recs is not None:
            body = self.pack(solid)
            return body + vx.pack_tocx(block_recs, body)
        out=io.BytesIO(); out.write(struct.pack("<I", len(self.entries)))
        for e in self.entries:
            p=e.path.encode("utf-8")
            out.write(struct.pack("<H", len(p))); out.write(p)
            out.write(struct.pack("<I", e.mode))
            out.write(struct.pack("<Q", e.mtime))
            out.write(struct.pack("<Q", e.size))
            out.write(struct.pack("<I", len(e.blocks)))
            out.write(struct.pack("<B", e.entry_type))
            meta = e.meta_json or b""
            out.write(struct.pack("<I", len(meta)))
            if meta: out.write(meta)
            if solid:
                out.write(struct.pack("<Q", e.start_off))
            else:
                for (idx, usz, csz, meth) in e.blocks:
                    out.write(struct.pack("<Q", idx))
                    out.write(struct.pack("<I", usz))
                    out.write(struct.pack("<I", csz))
                    out.write(struct.pack("<B", meth))
        return out.getvalue()

# ---------- Crypto ----------
def kdf_derive_key(password:bytes, header:HeaderV1)->bytes:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("crypto func kdf derive key")
    if header.kdf_id==KDF_ARGON2ID:
        argon2ll = vx._argon2()
        if argon2ll is None: raise RuntimeError("argon2-cffi not installed")
        return argon2ll.hash_secret_raw(
            secret=password, salt=header.salt,
            time_cost=header.kdf_t or 3, memory_cost=header.kdf_m or (256*1024),
            parallelism=header.kdf_p or 4, hash_len=32,
            type=argon2ll.Type.ID, version=argon2ll.ARGON2_VERSION)
    if header.kdf_id==KDF_SCRYPT:
        Scrypt = vx._crypto()[1]
        if Scrypt is None: raise RuntimeError("cryptography not installed")
        return Scrypt(salt=header.salt, length=32, n=header.kdf_t or (1<<15),
                      r=header.kdf_m or 8, p=header.kdf_p or 1).derive(password)
    raise RuntimeError("Archive not password-protected")

def aead_encrypt(key:bytes, header:HeaderV1, index:int, plaintext:bytes, aad:bytes=b"")->bytes:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace(f"crypto func aead encrypt with index {index}")
    AESGCM = vx._crypto()[0]
    if header.aead_id!=AEAD_AESGCM or AESGCM is None: raise RuntimeError("AESGCM unavailable")
    return AESGCM(key).encrypt(nonce_from(header.aead_nonce_prefix, index), plaintext, aad)
def aead_decrypt(key:bytes, header:HeaderV1, index:int, ciphertext:bytes, aad:bytes=b"")->bytes:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace(f"crypto func aead decrypt with index {index}")
    AESGCM = vx._crypto()[0]
    if header.aead_id!=AEAD_AESGCM or AESGCM is None: raise RuntimeError("AESGCM unavailable")
    return AESGCM(key).decrypt(nonce_from(header.aead_nonce_prefix, index), ciphertext, aad)

# ---------- Compression ----------
def compress_block(method:int, level:int, data:bytes)->bytes:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace(f"compression func compress block with method {method} data {len(data)} level {level}")
    if method==M_NONE: return data
    if method==M_ZLIB: return zlib.compress(data, level if 1<=level<=9 else 6)
    if method==M_LZMA:
        preset=max(0,min(9,level));
        return lzma.compress(data, format=lzma.FORMAT_ALONE, preset=preset)
        # LZMA ALONE
    if method==M_XZ:
        preset=max(0,min(9,level));
        return lzma.compress(data, format=lzma.FORMAT_XZ, preset=preset)
        # LZMA XZ
    if method==M_BROTLI:
        if not HAVE_BROTLI: raise RuntimeError("brotli not installed")
        return brotli.compress(data, quality=max(0,min(11,level)))
    if method==M_ZSTD:
        if not HAVE_ZSTD: raise RuntimeError("zstandard not installed")
        return zstd.ZstdCompressor(level=max(-5,min(22,level))).compress(data)
    if method==M_BZ2:
        return bz2.compress(data, compresslevel=max(1, min(9, level if level else 9)))
    if method==M_LZ4:
        if not HAVE_LZ4:
            raise RuntimeError("lz4 not installed (pip install lz4)")
        return lz4f.compress(data, compression_level=max(0, min(16, level if level else 9)))
    raise RuntimeError("unknown method")

def decompress_block(method:int, data:bytes)->bytes:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace(f"compression func decompress block with method {method} data {len(data)}")
    if method==M_NONE: return data
    if method==M_ZLIB: return zlib.decompress(data)
    if method==M_LZMA: return lzma.decompress(data, format=lzma.FORMAT_ALONE)
    if method==M_XZ: return lzma.decompress(data, format=lzma.FORMAT_XZ)
    if method==M_BROTLI:
        if not HAVE_BROTLI: raise RuntimeError("brotli not installed")
        return brotli.decompress(data)
    if method==M_ZSTD:
        if not HAVE_ZSTD: raise RuntimeError("zstandard not installed")
        return zstd.ZstdDecompressor().decompress(data)
    if method==M_BZ2:
        return bz2.decompress(data)
    if method==M_LZ4:
        if not HAVE_LZ4:
            raise RuntimeError("lz4 not installed (pip install lz4)")
        return lz4f.decompress(data)
    raise RuntimeError("unknown method")

# ---------- Footer ----------
def write_footer(bw:io.BufferedWriter, toc_offset:int, toc_size:int, hash_kind:int, digest:bytes):
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("footer func write footer")
    bw.write(struct.pack("<Q", toc_offset)); bw.write(struct.pack("<I", toc_size))
    bw.write(struct.pack("<B", hash_kind))
    if len(digest)==32: bw.write(digest)
    else: bw.write(digest[:32].ljust(32,b"\x00"))
    bw.write(END_MAGIC)

# (reading lives in vfa_extract.Container)

# ---------- Walkers & Metadata ----------
def iter_tree(paths: List[str]):
    """Yield (pathlib.Path, lstat, entry_type). Includes dirs (even empty), symlinks, files."""
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func iter tree")
    for p in paths:
        pth = pathlib.Path(p)
        if pth.is_dir():
            for root, dirs, files in os.walk(pth):
                # os.walk lists entries in filesystem order (NTFS: alphabetical, ext4: hash order). Sort them so the
                # entry order - and with it the packing of solid streams - is the same on every machine. (Stored
                # metadata such as modes and timestamps is per-machine by design, so archive bytes can still differ.)
                dirs.sort(); files.sort()
                rp = pathlib.Path(root)
                st = rp.lstat()
                yield rp, st, ET_DIR
                for name in files:
                    fp = rp / name
                    stf = fp.lstat()
                    if stat.S_ISLNK(stf.st_mode):
                        yield fp, stf, ET_SYMLINK
                    elif stat.S_ISREG(stf.st_mode):
                        yield fp, stf, ET_FILE
        else:
            st = pth.lstat()
            if stat.S_ISLNK(st.st_mode):
                yield pth, st, ET_SYMLINK
            elif stat.S_ISDIR(st.st_mode):
                yield pth, st, ET_DIR
            elif stat.S_ISREG(st.st_mode):
                yield pth, st, ET_FILE

# Hardlink table (Linux): map (dev, ino) -> first path
def hl_key(st):
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func hl key")
    return (getattr(st, "st_dev", None), getattr(st, "st_ino", None))

def posix_capture_meta(path:str, st)->dict:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func posix capture meta")
    meta={"posix":{
        "uid": getattr(st,"st_uid",0),
        "gid": getattr(st,"st_gid",0),
        "mode": st.st_mode & 0o7777,
        "atime_ns": getattr(st,"st_atime_ns", int(st.st_atime*1e9)),
        "mtime_ns": getattr(st,"st_mtime_ns", int(st.st_mtime*1e9)),
        "ctime_ns": getattr(st,"st_ctime_ns", int(st.st_ctime*1e9))
    }}
    return meta

def list_xattrs(path:str, follow_symlinks:bool)->Dict[str,bytes]:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func list xattrs")
    out={}
    if hasattr(os, "listxattr") and hasattr(os, "getxattr"):
        try:
            names = os.listxattr(path, follow_symlinks=follow_symlinks)
            for n in names:
                try:
                    v = os.getxattr(path, n, follow_symlinks=follow_symlinks)
                    out[n]=v
                except Exception: pass
        except Exception: pass
    return out

def apply_xattrs(path:str, xattrs:Dict[str,bytes], follow_symlinks:bool):
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func apply xattrs")
    if hasattr(os, "setxattr"):
        for n,v in xattrs.items():
            try: os.setxattr(path, n, v, follow_symlinks=follow_symlinks)
            except Exception: pass

def getfacl_dump(path:str)->Optional[str]:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func getfacl dump")
    try:
        r = subprocess.run(["getfacl","--absolute-names","--tabs","-p","--", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if r.returncode==0: return r.stdout.decode("utf-8", "replace")
    except Exception: pass
    return None

def setfacl_restore(text:str, path:str):
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func setfacl restore")
    try:
        p = subprocess.Popen(["setfacl","--restore=-"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate(input=text.encode("utf-8", "replace"))
    except Exception: pass

def selinux_get(path:str, follow_symlinks:bool)->Optional[bytes]:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func selinux get")
    try:
        return os.getxattr(path, "security.selinux", follow_symlinks=follow_symlinks)
    except Exception:
        return None

def fallocate_punch_hole(fd:int, offset:int, length:int):
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace(f"walkers and metadata func fallocate punch hole")
    # Linux only, best-effort
    if not LIN: return
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        FALLOC_FL_KEEP_SIZE = 0x01
        FALLOC_FL_PUNCH_HOLE = 0x02
        res = libc.fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, ctypes.c_longlong(offset), ctypes.c_longlong(length))
        if res!=0: pass
    except Exception: pass

def detect_sparse(path:str)->List[Tuple[int,int]]:
    """Return list of (offset,length) holes using SEEK_HOLE/SEEK_DATA if supported; else []"""
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func detect sparse")
    holes=[]
    if not LIN: return holes
    try:
        with open(path, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            pos = 0
            while pos < size:
                data_off = os.lseek(f.fileno(), pos, os.SEEK_DATA)
                if data_off is None: break
                if data_off>pos:
                    holes.append((pos, data_off-pos))
                pos = os.lseek(f.fileno(), data_off, os.SEEK_HOLE)
                if pos is None: break
    except Exception:
        return []
    return holes

# ---------- Windows meta helpers ----------
def win_capture_meta(path:str)->dict:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func win capture meta")
    meta={}
    if not (WIN and HAVE_WIN32): return meta
    try:
        attrs = win32file.GetFileAttributesW(path)
        meta["attrs"]=int(attrs)
        h = win32file.CreateFile(
            path, win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ|win32con.FILE_SHARE_WRITE|win32con.FILE_SHARE_DELETE,
            None, win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS, None
        )
        try:
            ct, at, wt = win32file.GetFileTime(h)
            to_ts = lambda ft: int(ft.timestamp())
            meta["ctime"]=to_ts(ct); meta["atime"]=to_ts(at); meta["mtime"]=to_ts(wt)
        finally:
            h.Close()
        sd = win32security.GetFileSecurity(path,
            win32security.OWNER_SECURITY_INFORMATION|
            win32security.GROUP_SECURITY_INFORMATION|
            win32security.DACL_SECURITY_INFORMATION)
        meta["sddl"] = sd.GetSecurityDescriptorSddlForm(
            win32security.OWNER_SECURITY_INFORMATION|
            win32security.GROUP_SECURITY_INFORMATION|
            win32security.DACL_SECURITY_INFORMATION
        )
        # ADS
        ads=[]
        try:
            for s in win32file.FindStreamsW(path):
                name = s[0]
                if name in (":$DATA", "::$DATA"): continue
                try:
                    with open(path + name, "rb") as sf:
                        data = sf.read()
                        if len(data) <= 16*1024*1024:
                            ads.append({"name": name, "hex": data.hex()})
                        else:
                            ads.append({"name": name, "hex": None, "size": len(data)})
                except Exception:
                    ads.append({"name": name, "hex": None})
        except Exception:
            pass
        if ads: meta["ads"]=ads
    except Exception: pass
    return meta

def _safe_ads_name(name) -> bool:
    # ":stream:$DATA" - anything with a path separator could write outside the file it belongs to
    return isinstance(name, str) and name.startswith(":") and not any(c in name for c in "\\/\x00") and ".." not in name

def win_apply_meta(path:str, meta:dict, is_dir:bool, full:bool=False):
    """Attributes and timestamps always; owner/DACL (sddl) and alternate data streams only with full=True
    (vfa x --winmeta), because they let an archive decide who may write the extracted files."""
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("walkers and metadata func win apply meta")
    if not (WIN and HAVE_WIN32): return
    if not full:
        meta = {k: v for k, v in meta.items() if k not in ("sddl", "ads")}
    try:
        if "attrs" in meta:
            win32file.SetFileAttributesW(path, int(meta["attrs"]))
    except Exception: pass
    if any(k in meta for k in ("ctime","atime","mtime")):
        try:
            h = win32file.CreateFile(
                path, win32con.GENERIC_WRITE,
                win32con.FILE_SHARE_READ|win32con.FILE_SHARE_WRITE|win32con.FILE_SHARE_DELETE,
                None, win32con.OPEN_EXISTING, win32con.FILE_FLAG_BACKUP_SEMANTICS, None
            )
            def to_ft(ts): return pywintypes.Time(float(ts))
            ct = to_ft(meta.get("ctime")) if "ctime" in meta else None
            at = to_ft(meta.get("atime")) if "atime" in meta else None
            mt = to_ft(meta.get("mtime")) if "mtime" in meta else None
            win32file.SetFileTime(h, ct, at, mt); h.Close()
        except Exception: pass
    if "sddl" in meta:
        try:
            sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                meta["sddl"], win32security.SDDL_REVISION_1)
            win32security.SetFileSecurity(path,
                win32security.DACL_SECURITY_INFORMATION|
                win32security.OWNER_SECURITY_INFORMATION|
                win32security.GROUP_SECURITY_INFORMATION, sd)
        except Exception: pass
    if "ads" in meta:
        for s in meta["ads"]:
            try:
                if not _safe_ads_name(s.get("name")):
                    LOGGER.warning(f"Skipping unsafe alternate data stream name {s.get('name')!r} on {path}")
                    continue
                if s.get("hex") is not None:
                    data = bytes.fromhex(s["hex"])
                    with open(path + s["name"], "wb") as sf: sf.write(data)
            except Exception: pass

# ---------- Core helpers ----------
def _set_mtime(path, e):
    ns = e["mtime"] * 1_000_000_000 + e.get("mtime_ns", 0)
    try: os.utime(path, ns=(ns, ns))
    except Exception: pass

def _wants_password(args) -> bool:
    return bool(getattr(args, "password", False) or getattr(args, "password_env", None) or getattr(args, "password_file", None))

def get_password(args) -> bytes:
    """--password-env VAR / --password-file FILE for scripts and tests, otherwise an interactive prompt."""
    if getattr(args, "password_env", None):
        v = os.environ.get(args.password_env)
        if v is None: raise SystemExit(f"Environment variable {args.password_env} is not set")
        return v.encode("utf-8")
    if getattr(args, "password_file", None):
        with open(args.password_file, "r", encoding="utf-8") as pf:
            return pf.read().rstrip("\r\n").encode("utf-8")
    return getpass.getpass("Password: ").encode("utf-8")

def _unlock(c: "vx.Container", args):
    pw = None
    if c.encrypted:
        if not _wants_password(args): raise SystemExit("Archive is encrypted; use --password (or --password-env/--password-file)")
        pw = get_password(args).decode("utf-8")
    c.unlock(pw)

def _recompute_hash_until(bf, upto:int, hash_kind:int)->bytes:
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("vfa core func recompute hash util")
    bf.seek(0); h=make_hasher(hash_kind); done=0
    while done<upto:
        chunk=bf.read(min(1024*1024, upto-done))
        if not chunk: break
        hasher_update(h, chunk, hash_kind); done += len(chunk)
    return hasher_digest(h, hash_kind)

def _read_pieces(path:str, piece:int=1<<20):
    """Yield a file's bytes in pieces until EOF (never trusts the size from stat)."""
    with open(path, "rb") as fr:
        while True:
            b = fr.read(piece)
            if not b: return
            yield b

class _BlockSink:
    """Writes [u32 len][u8 method][payload] frames and records the VTX1 block table
    (frame offset, compressed size, uncompressed size, method, CRC32 of the uncompressed data)."""
    def __init__(self, f, header, key, hasher=None, index=0, recs=None):
        self.f=f; self.header=header; self.key=key; self.hasher=hasher; self.index=index
        self.recs = recs if recs is not None else []
    def put(self, method:int, level:int, chunk:bytes):
        off = self.f.tell()
        comp = compress_block(method, level, chunk)
        payload = comp if self.key is None else aead_encrypt(self.key, self.header, self.index, comp, aad=b"vfa-data")
        if len(payload) > 0xFFFFFFFF: raise SystemExit("A compressed block exceeded 4 GiB; use a smaller --block-exp")
        frame = struct.pack("<IB", len(payload), method)
        self.f.write(frame); self.f.write(payload)
        if self.hasher is not None:
            hasher_update(self.hasher, frame, default_hash_kind()); hasher_update(self.hasher, payload, default_hash_kind())
        self.recs.append((off, len(payload), len(chunk), method, vx.crc32(chunk)))
        idx = self.index; self.index += 1
        return (idx, len(chunk), len(payload), method)

class _SolidStream:
    """Buffers the solid byte stream and emits a block every chunk_size bytes, so memory stays at about one block."""
    def __init__(self, sink:_BlockSink, method:int, level:int, chunk_size:int):
        self.sink=sink; self.method=method; self.level=level; self.cs=chunk_size; self.buf=bytearray(); self.pos=0
    def write(self, data:bytes):
        self.pos += len(data); mv = memoryview(data)
        while len(mv):
            take = min(self.cs - len(self.buf), len(mv))
            self.buf += mv[:take]; mv = mv[take:]
            if len(self.buf) == self.cs:
                chunk = bytes(self.buf); self.buf = bytearray()    # release the buffer before compressing
                self.sink.put(self.method, self.level, chunk); del chunk
    def flush(self):
        if self.buf:
            chunk = bytes(self.buf); self.buf = bytearray()
            self.sink.put(self.method, self.level, chunk)

def _check_exp(name:str, v, lo:int):
    if v is not None and not (lo <= int(v) <= MAX_BLOCK_EXP):
        raise SystemExit(f"{name} must be between {lo} and {MAX_BLOCK_EXP}")

def _scan_inputs(items, args):
    """Yield (entry_type, path, stat, meta_json_bytes|None) for the archive, capturing the metadata the flags ask
    for. Symlinks are recorded (Linux), and later links to an already-seen inode become hardlink entries."""
    hardlinks: Dict[Tuple[int,int], str] = {}
    for fp, st, et in items:
        rel = str(fp)
        meta_obj = {}
        if LIN and args.posixmeta:
            meta_obj.update(posix_capture_meta(rel, st))
        if WIN and args.winmeta:
            meta_obj["win"] = win_capture_meta(rel)
        if LIN and args.xattrs:
            x = list_xattrs(rel, follow_symlinks=False)
            if x:
                meta_obj["xattrs"] = {k: v.hex() for k,v in x.items()}
        if LIN and args.selinux:
            sctx = selinux_get(rel, follow_symlinks=False)
            if sctx is not None:
                meta_obj.setdefault("xattrs", {})["security.selinux"] = sctx.hex()
                meta_obj["selinux"] = sctx.decode("utf-8","ignore")
        enc = lambda: json.dumps(meta_obj, ensure_ascii=False).encode("utf-8") if meta_obj else None
        if et == ET_DIR:
            LOGGER.trace(f"Discovered directory {rel}")
            yield ET_DIR, rel, st, enc(); continue
        if et == ET_SYMLINK and LIN:            # elsewhere a symlink is archived as the file it points to (as before)
            meta_obj["link_target"] = os.readlink(rel)
            LOGGER.trace(f"Recorded symlink {rel} -> {meta_obj['link_target']}")
            yield ET_SYMLINK, rel, st, enc(); continue
        if LIN and getattr(st, "st_nlink", 1) > 1:
            key_hl = hl_key(st)
            if key_hl in hardlinks:
                meta_obj["hardlink_to"] = hardlinks[key_hl]
                LOGGER.trace(f"Recorded hardlink {rel} -> {hardlinks[key_hl]}")
                yield ET_HARDLINK, rel, st, enc(); continue
            hardlinks[key_hl] = rel
        if LIN and args.sparse and stat.S_ISREG(st.st_mode):
            holes = detect_sparse(rel)
            if holes: meta_obj["holes"] = holes
        yield ET_FILE, rel, st, enc()

def _collect_items(args, solid: bool):
    items = list(iter_tree(args.inputs))
    if solid and args.solid_by == "ext":
        items.sort(key=lambda it: (it[0].suffix.lower(), str(it[0])))
    return items

# ---------- Commands ----------
def cmd_create_v2(args):
    """VFA2 (see VFA2.md). Coders: lz (default), tans or stored; filter per chunk: auto (default) or forced with
    --filter; content-defined dedup across chunks unless --no-dedup or encrypting."""
    import vfa2
    if args.method not in (None, "lz", "tans", "none", "stored"):
        raise SystemExit(f"VFA2 has the coders 'lz' (default), 'tans' and 'stored'/'none'; --method {args.method} is a VFA1 method")
    coder = {"none": 0, "stored": 0, "tans": 1}.get(args.method, vfa2.CODER_LZ)
    if coder == vfa2.CODER_LZ and not vfa2.NATIVE:
        raise SystemExit(f"--method lz needs the C codec: {vfa2.NATIVE_PROBLEM}. (--method tans works without it, slowly.)")
    try: filt = vfa2.parse_filter(args.filter)
    except ValueError as e: raise SystemExit(str(e))
    if coder == 0 and filt is None: filt = (0, b"")
    if coder == 1 and not vfa2.NATIVE:
        LOGGER.warning(f"Using the very slow pure-Python reference coder: {vfa2.NATIVE_PROBLEM}")
    _check_exp("--chunk-exp", args.chunk_exp, 12)
    pw = get_password(args) if _wants_password(args) else None
    items = _collect_items(args, args.solid)
    nfiles = 0; total = 0; t0 = time.time()
    with open(args.output, "wb") as f:
        w = vfa2.Writer2(f, chunk_size=1 << args.chunk_exp, solid=args.solid, password=pw, coder=coder, filt=filt,
                         level=args.level, dedup=not args.no_dedup, cdc=not args.no_dedup,
                         kdf=(args.kdf_time or 3, args.kdf_mem_kib or 256 * 1024, args.kdf_parallel or 4))
        for et, rel, st, meta in _scan_inputs(items, args):
            mode = st.st_mode & 0o7777; ns = st.st_mtime_ns
            if et == ET_DIR: w.add_dir(rel, mode, 0, meta, mtime_ns=ns)
            elif et in (ET_SYMLINK, ET_HARDLINK): w.add_link(rel, et == ET_HARDLINK, mode, 0, meta, mtime_ns=ns)
            else:
                with open(rel, "rb") as fr: n = w.add_file(rel, mode, 0, fr, meta, mtime_ns=ns)
                if n != st.st_size: LOGGER.warning(f"{rel} changed size while being archived ({st.st_size} -> {n} bytes)")
                nfiles += 1; total += n
        w.close()
    LOGGER.info(f"Done in {time.time() - t0:.2f}s | files {nfiles} | src {human_bytes(total)} | chunks {len(w.chunks)} | arch {human_bytes(w.pos)}"
                + (f" | dedup {w.dedup_segments} segments, {human_bytes(w.dedup_bytes)}" if w.cdc else ""))
    print(f"Created {args.output} (VFA2) with {len(w.entries)} entry(s), {len(w.chunks)} chunk(s). Solid={bool(args.solid)}")

def cmd_create(args):
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("vfa core func cmd create")
    if args.format == "vfa2": return cmd_create_v2(args)
    if args.method in ("tans", "lz"): raise SystemExit(f"--method {args.method} is a VFA2 coder; add --format vfa2")
    if args.filter != "auto": raise SystemExit("--filter applies to --format vfa2 only")
    if args.method is None: args.method = "zstd" if HAVE_ZSTD else "zlib"
    if args.method == "stored": args.method = "none"
    _check_exp("--block-exp", args.block_exp, 12); _check_exp("--solid-chunk-exp", args.solid_chunk_exp, 16)
    block_size=1<<args.block_exp; method=NAME_TO_METHOD.get(args.method)
    if method is None: raise SystemExit(f"Unknown method {args.method}")
    header=HeaderV1(); header.default_method=method; header.default_level=args.level
    header.block_exp=args.block_exp; header.threads_hint=args.threads; header.ram_mib_hint=args.max_ram_mib
    header.flags |= F_TOCX
    if args.solid: header.flags |= F_SOLID
    key=None
    if _wants_password(args):
        if not vx.HAVE_AESGCM: raise SystemExit("cryptography not installed; cannot encrypt")
        if vx.HAVE_ARGON2:
            header.kdf_id=KDF_ARGON2ID; header.kdf_t=args.kdf_time or 3; header.kdf_m=args.kdf_mem_kib or (256*1024); header.kdf_p=args.kdf_parallel or 4
        else:
            header.kdf_id=KDF_SCRYPT; header.kdf_t=args.scrypt_n or (1<<15); header.kdf_m=args.scrypt_r or 8; header.kdf_p=args.scrypt_p or 1
        header.salt=os.urandom(16); header.aead_id=AEAD_AESGCM; header.aead_nonce_prefix=os.urandom(12); header.flags |= F_ENCRYPTED
        LOGGER.info("Encryption enabled (AES-256-GCM).")
        key=kdf_derive_key(get_password(args), header)

    toc=TOC()
    hk = default_hash_kind()

    with open(args.output,"wb") as f:
        bw=f
        header_bytes = header.pack()
        bw.write(header_bytes)
        hasher=make_hasher(hk)
        hasher_update(hasher, header_bytes, hk)
        sink = _BlockSink(bw, header, key, hasher)

        items = _collect_items(args, bool(header.flags & F_SOLID))

        # Progress setup
        file_items = [it for it in items if it[2] == ET_FILE]
        total_files = len(file_items)
        total_bytes = sum(int(getattr(st, "st_size", 0)) for _, st, _ in file_items)
        prog = Progress(total_files, total_bytes)
        LOGGER.info(f"Preparing to compress {total_files} files ({human_bytes(total_bytes)}). Solid={bool(args.solid)} method={args.method} lvl={args.level}")
        solid = None
        if header.flags & F_SOLID:
            chunk_exp = args.solid_chunk_exp if args.solid_chunk_exp is not None else DEFAULT_SOLID_CHUNK_EXP
            LOGGER.info(f"Solid chunk size {human_bytes(1<<int(chunk_exp))}")
            solid = _SolidStream(sink, method, args.level, 1 << int(chunk_exp))

        for et, rel, st, meta_bytes in _scan_inputs(items, args):
            st_mode = (st.st_mode & 0o7777)
            st_mtime = int(getattr(st, "st_mtime", time.time()))
            if et != ET_FILE:
                toc.entries.append(FileEntry(rel, st_mode, st_mtime, 0, [], 0, et, meta_bytes))
                continue
            size = int(st.st_size)
            t0 = time.time()
            if solid is not None:
                LOGGER.debug(f"Streaming file {rel} ({human_bytes(size)}) into solid stream")
                entry = FileEntry(rel, st_mode, st_mtime, 0, [], solid.pos, ET_FILE, meta_bytes)
                for piece in _read_pieces(rel):
                    solid.write(piece); entry.size += len(piece)
            else:
                LOGGER.debug(f"Compressing file {rel} ({human_bytes(size)})")
                entry = FileEntry(rel, st_mode, st_mtime, 0, [], 0, ET_FILE, meta_bytes)
                for chunk in _read_pieces(rel, block_size):
                    entry.blocks.append(sink.put(method, args.level, chunk)); entry.size += len(chunk)
            if entry.size != size:
                LOGGER.warning(f"{rel} changed size while being archived ({size} -> {entry.size} bytes); stored what was read")
            toc.entries.append(entry)
            duration = time.time() - t0
            prog.add_file(entry.size, duration)
            if LOGGER.level >= VLog.LEVELS["debug"]:
                arch_so_far = bw.tell()
                elapsed, eta, rate, ratio = prog.estimate()
                LOGGER.debug(
                    f"Done {rel} in {duration:.2f}s | "
                    f"{prog.done_files}/{prog.total_files} files, "
                    f"{human_bytes(prog.done_bytes)}/{human_bytes(prog.total_bytes)} | "
                    f"arch {human_bytes(arch_so_far)} | "
                    f"elapsed {elapsed:.1f}s | eta {('∞' if eta==float('inf') else f'{eta:.1f}s')}"
                )

        if solid is not None:
            solid.flush()
            arch_so_far = bw.tell()
            saved = max(0, prog.done_bytes - arch_so_far)
            ratio_now = (arch_so_far / prog.done_bytes) if prog.done_bytes else 0.0
            LOGGER.info(
                f"Solid stream written | {len(sink.recs)} block(s) | arch {human_bytes(arch_so_far)} | "
                f"src {human_bytes(prog.done_bytes)} | saved {human_bytes(saved)} | ratio {ratio_now:.3f}"
            )

        toc_data = toc.pack(solid=bool(header.flags & F_SOLID), block_recs=sink.recs)
        LOGGER.trace("Writing TOC...")
        if key is not None: toc_data = aead_encrypt(key, header, vx.toc_nonce_index(0), toc_data, aad=b"vfa-toc")
        toc_off = bw.tell(); bw.write(toc_data); toc_sz=len(toc_data); hasher_update(hasher, toc_data, hk)
        digest=hasher_digest(hasher, hk); write_footer(bw, toc_off, toc_sz, hk, digest)
        arch_final = bw.tell()

    elapsed, eta, rate, ratio = prog.estimate()
    saved = max(0, prog.done_bytes - arch_final)
    ratio_final = (arch_final / prog.done_bytes) if prog.done_bytes else 0.0
    LOGGER.info(
        f"Done in {elapsed:.2f}s | files {prog.done_files}/{prog.total_files} | "
        f"src {human_bytes(prog.done_bytes)} | arch {human_bytes(arch_final)} | "
        f"saved {human_bytes(saved)} | ratio {ratio_final:.3f}"
    )
    print(f"Created {args.output} with {len(toc.entries)} entry(s). Solid={bool(header.flags & F_SOLID)}")

def vfa2_filter_name(fid):
    import vfa2; return vfa2.FILTER_NAMES.get(fid, f"#{fid}")

def vfa2_coder_name(cid):
    import vfa2; return vfa2.CODER_NAMES.get(cid, f"#{cid}")

def cmd_list(args):
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("vfa core func cmd list")
    with vx.open_container(args.archive) as c:
        _unlock(c, args)
        if getattr(c, "format", "VFA1") == "VFA2":
            total=sum(e["size"] for e in c.entries if e["entry_type"]==ET_FILE)
            print(f"Archive: {args.archive}\nFormat: {c.summary()}\nEncrypted: {c.encrypted}")
            print("Integrity: digest sha256, chunk + header + index CRC32s")
            print(f"Entries: {len(c.entries)}, Files total: {total} bytes")
            if getattr(args, "routing", False):
                rt = {r.get("chunk"): r for r in c.routing()}
                print("Chunks (filter / coder / raw -> stored / why):")
                for i, (off, raw, _crc, coder, filt) in enumerate(c.chunks):
                    r = rt.get(i, {})
                    print(f"  #{i:<5d} {str(r.get('filter', vfa2_filter_name(filt))):<14s} {vfa2_coder_name(coder):<10s} "
                          f"{raw:>12d} -> {str(r.get('stored', '?')):>12}  {str(r.get('why', '(no routing record)'))}")
            for e in c.entries:
                info = f"{len(e['extents'])} extent(s)" if e["entry_type"]==ET_FILE else "-"
                print(f"{e['size']:12d}  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['mtime']))}  [{vx.ET_NAMES[e['entry_type']]}]  {e['path']}  ({info})")
            return
        h = c.header
        total=sum(e["size"] for e in c.entries if e["entry_type"]==ET_FILE)
        print(f"Archive: {args.archive}\nVersion: {h['version']}, Method: {METHOD_NAMES.get(h['default_method'])} lvl {h['default_level']}, Block: {1<<h['block_exp']}B")
        print(f"Encrypted: {c.encrypted}, Solid: {c.solid}")
        print(f"Integrity: digest {vx.HASH_NAMES.get(c.hash_kind, c.hash_kind)}, block CRC32s {'yes' if c.has_tocx else 'no (VFA 1.0 archive)'}")
        print(f"Entries: {len(c.entries)}, Files total: {total} bytes")
        for e in c.entries:
            kind = vx.ET_NAMES[e["entry_type"]]
            blocks_info = "solid" if (c.solid and e["entry_type"]==ET_FILE) else (f"{len(e['blocks'])} blocks" if e["entry_type"]==ET_FILE else "-")
            print(f"{e['size']:12d}  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['mtime']))}  [{kind}]  {e['path']}  ({blocks_info})")

def cmd_test(args):
    """Exit code 0 only if the footer digest matches and every block decodes (and passes its CRC32)."""
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("vfa core func cmd test")
    LOGGER.info("Verifying archive footer hash and block integrity...")
    with vx.open_container(args.archive) as c:
        ok = c.verify_digest()
        print(f"Footer hash ({vx.HASH_NAMES.get(c.hash_kind, c.hash_kind)}) match: {'OK' if ok else ('FAIL' if ok is False else 'none stored')}")
        _unlock(c, args)
        try:
            st = c.test()
        except VFAError as e:
            print(f"Block check: FAIL - {e}"); raise SystemExit(1)
        nfiles = sum(1 for e in c.entries if e["entry_type"]==ET_FILE)
        crc = ", CRC32 verified" if c.has_tocx else ", no block CRCs (VFA 1.0 archive)"
        unit = "chunks" if getattr(c, "format", "VFA1") == "VFA2" else "blocks"
        print(f"Tested {nfiles} files{' in SOLID stream' if c.solid else ''}, {st['blocks']} {unit}{crc}: OK.")
        if ok is False: raise SystemExit(1)

def cmd_extract(args):
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("vfa core func cmd extract")
    outdir = args.output or "."
    with vx.open_container(args.archive) as c:
        if not args.no_verify:
            if c.verify_digest() is False:
                raise VFAError("Integrity check FAILED: the archive is corrupted or was modified (--no-verify to try anyway).")
        elif not c.has_tocx:
            LOGGER.warning("This is a VFA 1.0 archive without block CRCs: with --no-verify, corruption can go undetected.")
        _unlock(c, args)

        def after(e, out_path):
            meta = None
            if e["meta"]:
                try: meta = json.loads(e["meta"].decode("utf-8"))
                except Exception: LOGGER.warning(f"Unreadable metadata for {e['path']}")
            et = e["entry_type"]
            if et == ET_DIR:
                if not WIN:
                    try: os.chmod(out_path, e["mode"] & (0o7777 if args.posixmeta else 0o777))
                    except Exception: pass
                _set_mtime(out_path, e)
            if not meta: return
            if WIN and et in (ET_DIR, ET_FILE) and isinstance(meta.get("win"), dict):
                try: win_apply_meta(out_path, meta["win"], et == ET_DIR, full=args.winmeta)
                except Exception: pass
            if LIN and args.posixmeta:
                pos = meta.get("posix", {})
                try:
                    if et == ET_SYMLINK: os.lchown(out_path, pos.get("uid",-1), pos.get("gid",-1))
                    else: os.chown(out_path, pos.get("uid",-1), pos.get("gid",-1))
                except Exception: pass
                try:
                    if args.xattrs and "xattrs" in meta:
                        apply_xattrs(out_path, {k:bytes.fromhex(v) for k,v in meta["xattrs"].items()}, follow_symlinks=False)
                    if args.acl and meta.get("acl") and et != ET_SYMLINK: setfacl_restore(meta["acl"], out_path)
                    if args.sparse and "holes" in meta and et == ET_FILE:
                        with open(out_path, "r+b") as fw:
                            for off, ln in meta["holes"]:
                                fallocate_punch_hole(fw.fileno(), off, ln)
                except Exception: pass
            LOGGER.trace(f"Restored metadata for {e['path']}")

        files, dirs = c.extract(outdir, members=args.members or None, links=LIN,
                                keep_mode_bits=(0o7777 if args.posixmeta else 0o777), after_entry=after)
        LOGGER.info(f"Extracted {len(files)} file(s) to {outdir}")

def cmd_append(args):
    """Append files. Non-solid: new blocks per file. Solid: the new files continue the solid stream in new
    blocks (existing blocks are never rewritten). The archive is upgraded to VFA 1.1 (block table, SHA-256)."""
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("vfa core func cmd append")
    with vx.open_container(args.archive) as c:
        if getattr(c, "format", "VFA1") == "VFA2":
            raise SystemExit("Append to VFA2 archives is not implemented yet (the format allows it; see VFA2.md)")
        if c.arc_start != 0: raise SystemExit("Append works on a plain .vfa, not on an SFX/SFI executable")
        if c.verify_digest() is False: raise SystemExit("Refusing to append: archive integrity check FAILED")
        _unlock(c, args)
        h = c.header
        header = HeaderV1(h["version"], h["flags"], h["default_method"], h["default_level"], h["block_exp"],
                          h["threads"], h["ram_mib"], h["kdf_id"], h["kdf_t"], h["kdf_m"], h["kdf_p"],
                          h["salt"], h["aead_id"], h["nonce_prefix"], h["reserved"])
        if c.solid and any(b.usz is None for b in c.blocks):   # VFA 1.0 solid: learn block sizes once
            LOGGER.info("Upgrading block table (decoding existing solid blocks once)...")
            pos = 0
            for i, b in enumerate(c.blocks):
                d = c.block_data(i, limit=c.stream_len - pos); b.usz = len(d); b.crc = vx.crc32(d); pos += len(d)
        recs = [(b.off, b.csz, b.usz if b.usz is not None else 0, b.method, b.crc) for b in c.blocks]
        toc = TOC([FileEntry(e["path"], e["mode"], e["mtime"], e["size"], list(e["blocks"]), e["start_off"],
                             e["entry_type"], e["meta"] or None) for e in c.entries])
        key, toc_offset, solid = c.key, c.toc_off, c.solid
        stream_len = c.stream_len if solid else 0
        with open(args.archive, "rb") as f:
            f.seek(toc_offset); old_tail = f.read()          # old TOC + footer, restored if anything fails

    if solid:
        if args.method and NAME_TO_METHOD[args.method] != header.default_method:
            raise SystemExit("Solid archives keep one method; --method must match the archive's method")
        method = header.default_method
    else:
        method = header.default_method if (not args.method) else NAME_TO_METHOD[args.method]
    level = header.default_level if (args.level is None) else args.level
    block_size = 1<<header.block_exp
    header.flags |= F_TOCX
    if key is not None:   # a rewritten TOC must never reuse the old TOC's nonce
        gen = struct.unpack("<I", header.reserved[:4])[0] + 1
        header.reserved = struct.pack("<I", gen) + header.reserved[4:]

    items = list(iter_tree(args.inputs))
    file_items = [it for it in items if it[2] == ET_FILE]
    prog = Progress(len(file_items), sum(int(getattr(st, "st_size", 0)) for _, st, _ in file_items))
    LOGGER.info(f"Appending {prog.total_files} files ({human_bytes(prog.total_bytes)})...")

    with open(args.archive, "r+b") as f:
        try:
            f.seek(toc_offset); f.truncate()
            sink = _BlockSink(f, header, key, None, index=len(recs), recs=recs)
            ss = _SolidStream(sink, method, level, 1 << DEFAULT_SOLID_CHUNK_EXP) if solid else None
            if ss: ss.pos = stream_len
            for fp, st, et in items:
                if et!=ET_FILE:
                    LOGGER.trace(f"Skipping non-file during append: {fp}")
                    continue
                rel = str(fp); t0 = time.time()
                entry=FileEntry(rel, st.st_mode & 0o7777, int(getattr(st,"st_mtime", time.time())), 0, [],
                                ss.pos if ss else 0, ET_FILE)
                for chunk in _read_pieces(rel, (1 << 20) if ss else block_size):
                    if ss: ss.write(chunk)
                    else: entry.blocks.append(sink.put(method, level, chunk))
                    entry.size += len(chunk)
                toc.entries.append(entry)
                prog.add_file(entry.size, time.time() - t0)
            if ss: ss.flush()
            f.seek(0); f.write(header.pack())
            f.seek(0, os.SEEK_END)
            toc_data = toc.pack(solid=solid, block_recs=sink.recs)
            if key is not None:
                toc_data = aead_encrypt(key, header, vx.toc_nonce_index(struct.unpack("<I", header.reserved[:4])[0]), toc_data, aad=b"vfa-toc")
            toc_new_off=f.tell(); f.write(toc_data)
            hk = default_hash_kind()
            digest=_recompute_hash_until(f, f.tell(), hk)
            f.seek(0, os.SEEK_END)
            write_footer(f, toc_new_off, len(toc_data), hk, digest)
        except BaseException:
            LOGGER.error("Append failed; restoring the original archive")
            f.seek(0); f.write(HeaderV1(h["version"], h["flags"], h["default_method"], h["default_level"], h["block_exp"],
                          h["threads"], h["ram_mib"], h["kdf_id"], h["kdf_t"], h["kdf_m"], h["kdf_p"],
                          h["salt"], h["aead_id"], h["nonce_prefix"], h["reserved"]).pack())
            f.seek(toc_offset); f.truncate(); f.write(old_tail)
            raise
        arch_final = f.tell()
    LOGGER.info(f"Append done | files {prog.done_files} | added {human_bytes(prog.done_bytes)} | archive now {human_bytes(arch_final)}")

# ---------- CLI ----------
def build_argparser():
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("vfa cli func build argparser")
    from vfa_version import __version__, version_text
    ap = argparse.ArgumentParser(
        prog="vfa", description=f"VulpFin Archive (.vfa) {__version__}"
    )
    ap.add_argument("-V", "--version", action="version", version=version_text("vfa"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    # --- Create ---
    ap_c = sub.add_parser("c", help="Create archive")
    ap_c.add_argument("output", help="Archive filename to create (.vfa)")
    ap_c.add_argument("inputs", nargs="+", help="Input files/folders to include")
    ap_c.add_argument(
        "--method",
        default=None,
        choices=list(NAME_TO_METHOD.keys()) + ["stored", "tans", "lz"],
        help="Compression method, default zstd (VFA1) / lz (VFA2: lz, tans or stored/none; --level 0-9 for lz)",
    )
    ap_c.add_argument("--format", choices=["vfa1", "vfa2"], default="vfa1",
                      help="Container format (default vfa1; vfa2 is the new chunked format, see VFA2.md)")
    ap_c.add_argument("--no-dedup", action="store_true", dest="no_dedup",
                      help="VFA2: do not deduplicate repeated content across chunks")
    ap_c.add_argument("--filter", default="auto",
                      help="VFA2: filter per chunk: auto (default; classifier, reasons kept in the index) | none | delta:N | "
                           "shuffle:K | bitshuffle:K | bcj-x86 | bcj-arm64")
    ap_c.add_argument("--chunk-exp", type=int, default=26, dest="chunk_exp",
                      help="VFA2: chunk size as power of two (default 2^26 = 64 MiB, max 2^30)")
    ap_c.add_argument(
        "--level",
        type=int,
        default=5,
        help="Method specific compression level, default 5",
    )
    ap_c.add_argument(
        "--block-exp",
        type=int,
        default=22,
        dest="block_exp",
        help="Block size as power-of-two exponent (default 2^22=4MiB)",
    )
    ap_c.add_argument("--threads", type=int, default=0, help="Worker threads (0=auto)")
    ap_c.add_argument(
        "--max-ram-mib", type=int, default=0, help="Max RAM usage (MiB, 0=unlimited)"
    )
    ap_c.add_argument(
        "--password",
        action="store_true",
        help="Enable password prompt (encrypt archive)",
    )
    # Solid options
    ap_c.add_argument("--solid", action="store_true", help="Solid mode (single stream)")
    ap_c.add_argument(
        "--solid-chunk-exp",
        type=int,
        default=None,
        help=f"Split solid stream into chunks of 2^N bytes (uncompressed; default 2^{DEFAULT_SOLID_CHUNK_EXP}=64MiB, max 2^{MAX_BLOCK_EXP})",
    )
    ap_c.add_argument(
        "--solid-by",
        choices=["none", "ext"],
        default="none",
        help="Order solid stream by grouping (ext groups similar files together)",
    )
    # Windows / POSIX meta
    ap_c.add_argument(
        "--winmeta",
        action="store_true",
        help="Windows: store attributes/ACL/ADS/timestamps",
    )
    ap_c.add_argument(
        "--posixmeta",
        action="store_true",
        help="Linux/Unix: store uid/gid/mode/atime/mtime/ctime (+links)",
    )
    ap_c.add_argument(
        "--xattrs", action="store_true", help="Store extended attributes (xattrs)"
    )
    ap_c.add_argument(
        "--acl", action="store_true", help="Store POSIX ACLs via getfacl/setfacl"
    )
    ap_c.add_argument(
        "--selinux", action="store_true", help="Store SELinux context (if present)"
    )
    ap_c.add_argument(
        "--sparse",
        action="store_true",
        help="Detect & restore sparse holes (Linux only)",
    )
    # KDF tuning
    ap_c.add_argument(
        "--kdf-time", type=int, default=3, help="Argon2id: time cost (iterations)"
    )
    ap_c.add_argument(
        "--kdf-mem-kib",
        type=int,
        default=256 * 1024,
        help="Argon2id: memory cost (KiB)",
    )
    ap_c.add_argument("--kdf-parallel", type=int, default=4, help="Argon2id: parallelism")
    ap_c.add_argument("--scrypt-n", type=int, default=1 << 15, help="scrypt: N parameter")
    ap_c.add_argument("--scrypt-r", type=int, default=8, help="scrypt: R parameter")
    ap_c.add_argument("--scrypt-p", type=int, default=1, help="scrypt: P parameter")

    # --- Append ---
    ap_a = sub.add_parser("a", help="Append files to archive (non-solid only)")
    ap_a.add_argument("archive")
    ap_a.add_argument("inputs", nargs="+")
    ap_a.add_argument(
        "--method",
        default=None,
        choices=list(NAME_TO_METHOD.keys()),
        help="Override compression method",
    )
    ap_a.add_argument(
        "--level", type=int, default=None, help="Override compression level"
    )
    ap_a.add_argument(
        "--password", action="store_true", help="Prompt for password if encrypted"
    )

    # --- List ---
    ap_l = sub.add_parser("l", help="List archive")
    ap_l.add_argument("archive")
    ap_l.add_argument("--routing", action="store_true", help="VFA2: show each chunk's filter/coder and why it was chosen")
    ap_l.add_argument(
        "--password", action="store_true", help="Prompt for password if encrypted"
    )

    # --- Test ---
    ap_t = sub.add_parser("t", help="Test archive")
    ap_t.add_argument("archive")
    ap_t.add_argument(
        "--password", action="store_true", help="Prompt for password if encrypted"
    )

    # --- Extract ---
    ap_x = sub.add_parser("x", help="Extract archive")
    ap_x.add_argument("archive")
    ap_x.add_argument(
        "-o", "--output", default=".", help="Output directory (default: current)"
    )
    ap_x.add_argument(
        "--password", action="store_true", help="Prompt for password if encrypted"
    )
    ap_x.add_argument("members", nargs="*", help="Only extract these archive paths (a directory selects everything below it)")
    ap_x.add_argument("--no-verify", action="store_true", help="Skip the whole-archive digest check (blocks are still size/CRC checked)")
    ap_x.add_argument("--winmeta", action="store_true", help="Windows: also restore owner/ACL (SDDL) and alternate data streams")
    ap_x.add_argument("--posixmeta", action="store_true", help="Linux/Unix: restore uid/gid and setuid/setgid/sticky bits")
    ap_x.add_argument("--xattrs", action="store_true", help="Restore extended attributes (with --posixmeta)")
    ap_x.add_argument("--acl", action="store_true", help="Restore POSIX ACLs (with --posixmeta)")
    ap_x.add_argument("--sparse", action="store_true", help="Re-punch sparse holes (with --posixmeta, Linux)")

    # Logging + non-interactive password flags for all subcommands
    for sp in (ap_c, ap_a, ap_l, ap_t, ap_x):
        sp.add_argument("--password-env", metavar="VAR", help="Read the password from environment variable VAR (implies --password)")
        sp.add_argument("--password-file", metavar="FILE", help="Read the password from FILE, trailing newline stripped (implies --password)")
        sp.add_argument("--log-level",
            choices=["quiet","error","warning","info","debug","trace"],
            default="warning",
            help="Logging verbosity (default: warning)")
        sp.add_argument("-v","--verbose", action="store_true",
            help="Shortcut for --log-level info")
    return ap


def main(argv=None):
    # set global logger
    global LOGGER
    if LOGGER.level >= VLog.LEVELS["trace"]: LOGGER.trace("vfa runner main")
    for stream in (sys.stdout, sys.stderr):    # a legacy console code page must not crash `vfa l` on a Unicode name
        try: stream.reconfigure(errors="backslashreplace")
        except Exception: pass
    ap=build_argparser()
    if not (sys.argv[1:] if argv is None else argv):    # bare `vfa`: what this is and how to use it, not an error
        ap.print_help(); return
    args, extra = ap.parse_known_args(argv)
    # `vfa x a.vfa -o out some/member` - argparse cannot put positionals after options on its own
    if extra and args.cmd == "x" and not any(x.startswith("-") for x in extra): args.members += extra
    elif extra: ap.error("unrecognized arguments: " + " ".join(extra))
    # verbose alias
    if getattr(args, "verbose", False) and getattr(args, "log_level", None) == "warning":
        args.log_level = "info"
    LOGGER = VLog(getattr(args, "log_level", "warning"))
    vx.set_logger(vx.VLog(getattr(args, "log_level", "warning")))

    try:
        if args.cmd=="c": cmd_create(args)
        elif args.cmd=="a": cmd_append(args)
        elif args.cmd=="l": cmd_list(args)
        elif args.cmd=="t": cmd_test(args)
        elif args.cmd=="x": cmd_extract(args)
        else: ap.print_help()
    except VFAError as e:
        print(f"vfa: error: {e}", file=sys.stderr)
        raise SystemExit(e.code or 1)

if __name__=="__main__": main()
