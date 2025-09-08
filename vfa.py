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

# ---------- Optional deps ----------
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

import zlib, lzma, hashlib
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
MAGIC=b"VFA1"; END_MAGIC=b"/VFA1"; VERSION=1

AEAD_NONE=0; AEAD_AESGCM=1
KDF_NONE=0; KDF_ARGON2ID=1; KDF_SCRYPT=2

M_NONE=0; M_ZLIB=1; M_LZMA=2; M_BROTLI=3; M_ZSTD=4
METHOD_NAMES={M_NONE:"none",M_ZLIB:"zlib",M_LZMA:"lzma",M_BROTLI:"brotli",M_ZSTD:"zstd"}
NAME_TO_METHOD={v:k for k,v in METHOD_NAMES.items()}

# Flags
F_ENCRYPTED=1<<0
F_SOLID=1<<1

# Hash kind
H_NONE=0; H_SHA256=1; H_BLAKE3=2; H_XXH64=3

def default_hash_kind():
    if HAVE_XXH: return H_XXH64
    if HAVE_BLAKE3: return H_BLAKE3
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
    @classmethod
    def unpack(cls, bio: io.BufferedReader)->"HeaderV1":
        if bio.read(4)!=MAGIC: raise ValueError("Not a VFA archive")
        version,=struct.unpack("<H", bio.read(2)); flags,=struct.unpack("<I", bio.read(4))
        dm,=struct.unpack("<B", bio.read(1)); dl,=struct.unpack("<B", bio.read(1))
        be,=struct.unpack("<B", bio.read(1)); th,=struct.unpack("<H", bio.read(2)); rm,=struct.unpack("<I", bio.read(4))
        kid,=struct.unpack("<B", bio.read(1)); kt,=struct.unpack("<I", bio.read(4)); km,=struct.unpack("<I", bio.read(4)); kp,=struct.unpack("<B", bio.read(1))
        salt=bio.read(16); aid,=struct.unpack("<B", bio.read(1)); np=bio.read(12); res=bio.read(16)
        return cls(version,flags,dm,dl,be,th,rm,kid,kt,km,kp,salt,aid,np,res)

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
    def pack(self, solid: bool=False)->bytes:
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
    @classmethod
    def unpack(cls, data:bytes, solid: bool=False)->"TOC":
        bio=io.BytesIO(data); (n,) = struct.unpack("<I", bio.read(4)); entries=[]
        for _ in range(n):
            (plen,) = struct.unpack("<H", bio.read(2)); path=bio.read(plen).decode("utf-8")
            (mode,) = struct.unpack("<I", bio.read(4)); (mtime,) = struct.unpack("<Q", bio.read(8))
            (size,) = struct.unpack("<Q", bio.read(8)); (nb,) = struct.unpack("<I", bio.read(4))
            entry_type=ET_FILE; meta=b""
            pos_before = bio.tell()
            try:
                (entry_type,) = struct.unpack("<B", bio.read(1))
                (mlen,) = struct.unpack("<I", bio.read(4))
                meta = bio.read(mlen) if mlen>0 else b""
            except Exception:
                bio.seek(pos_before)
            blocks=[]; start_off=0
            if solid:
                (start_off,) = struct.unpack("<Q", bio.read(8))
            else:
                for _ in range(nb):
                    (idx,) = struct.unpack("<Q", bio.read(8))
                    (usz,) = struct.unpack("<I", bio.read(4))
                    (csz,) = struct.unpack("<I", bio.read(4))
                    (meth,) = struct.unpack("<B", bio.read(1))
                    blocks.append((idx, usz, csz, meth))
            entries.append(FileEntry(path, mode, mtime, size, blocks, start_off, entry_type, meta or None))
        return cls(entries)

# ---------- Crypto ----------
def kdf_derive_key(password:bytes, header:HeaderV1)->bytes:
    if header.kdf_id==KDF_ARGON2ID:
        if not HAVE_ARGON2: raise RuntimeError("argon2-cffi not installed")
        return argon2ll.hash_secret_raw(
            secret=password, salt=header.salt,
            time_cost=header.kdf_t or 3, memory_cost=header.kdf_m or (256*1024),
            parallelism=header.kdf_p or 4, hash_len=32,
            type=argon2ll.Type.ID, version=argon2ll.ARGON2_VERSION)
    if header.kdf_id==KDF_SCRYPT:
        if Scrypt is None: raise RuntimeError("cryptography not installed")
        return Scrypt(salt=header.salt, length=32, n=header.kdf_t or (1<<15),
                      r=header.kdf_m or 8, p=header.kdf_p or 1).derive(password)
    raise RuntimeError("Archive not password-protected")

def aead_encrypt(key:bytes, header:HeaderV1, index:int, plaintext:bytes, aad:bytes=b"")->bytes:
    if header.aead_id!=AEAD_AESGCM or not HAVE_AESGCM: raise RuntimeError("AESGCM unavailable")
    return AESGCM(key).encrypt(nonce_from(header.aead_nonce_prefix, index), plaintext, aad)
def aead_decrypt(key:bytes, header:HeaderV1, index:int, ciphertext:bytes, aad:bytes=b"")->bytes:
    if header.aead_id!=AEAD_AESGCM or not HAVE_AESGCM: raise RuntimeError("AESGCM unavailable")
    return AESGCM(key).decrypt(nonce_from(header.aead_nonce_prefix, index), ciphertext, aad)

# ---------- Compression ----------
def compress_block(method:int, level:int, data:bytes)->bytes:
    if method==M_NONE: return data
    if method==M_ZLIB: return zlib.compress(data, level if 1<=level<=9 else 6)
    if method==M_LZMA:
        preset=max(0,min(9,level)); return lzma.compress(data, format=lzma.FORMAT_XZ, preset=preset)
    if method==M_BROTLI:
        if not HAVE_BROTLI: raise RuntimeError("brotli not installed")
        return brotli.compress(data, quality=max(0,min(11,level)))
    if method==M_ZSTD:
        if not HAVE_ZSTD: raise RuntimeError("zstandard not installed")
        return zstd.ZstdCompressor(level=max(-5,min(22,level))).compress(data)
    raise RuntimeError("unknown method")

def decompress_block(method:int, data:bytes)->bytes:
    if method==M_NONE: return data
    if method==M_ZLIB: return zlib.decompress(data)
    if method==M_LZMA: return lzma.decompress(data)
    if method==M_BROTLI:
        if not HAVE_BROTLI: raise RuntimeError("brotli not installed")
        return brotli.decompress(data)
    if method==M_ZSTD:
        if not HAVE_ZSTD: raise RuntimeError("zstandard not installed")
        return zstd.ZstdDecompressor().decompress(data)
    raise RuntimeError("unknown method")

# ---------- Footer ----------
def write_footer(bw:io.BufferedWriter, toc_offset:int, toc_size:int, hash_kind:int, digest:bytes):
    bw.write(struct.pack("<Q", toc_offset)); bw.write(struct.pack("<I", toc_size))
    bw.write(struct.pack("<B", hash_kind))
    if len(digest)==32: bw.write(digest)
    else: bw.write(digest[:32].ljust(32,b"\x00"))
    bw.write(END_MAGIC)

def read_footer(br:io.BufferedReader):
    br.seek(-(8+4+1+32+5), os.SEEK_END)
    toc_off=struct.unpack("<Q", br.read(8))[0]
    toc_sz=struct.unpack("<I", br.read(4))[0]
    hk=struct.unpack("<B", br.read(1))[0]
    dig=br.read(32)
    if br.read(5)!=END_MAGIC: raise ValueError("Bad end magic")
    return toc_off, toc_sz, hk, dig

# ---------- Walkers & Metadata ----------
def iter_tree(paths: List[str]):
    """Yield (pathlib.Path, lstat, entry_type). Includes dirs (even empty), symlinks, files."""
    for p in paths:
        pth = pathlib.Path(p)
        if pth.is_dir():
            for root, dirs, files in os.walk(pth):
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
def hl_key(st): return (getattr(st, "st_dev", None), getattr(st, "st_ino", None))

def posix_capture_meta(path:str, st)->dict:
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
    if hasattr(os, "setxattr"):
        for n,v in xattrs.items():
            try: os.setxattr(path, n, v, follow_symlinks=follow_symlinks)
            except Exception: pass

def getfacl_dump(path:str)->Optional[str]:
    try:
        r = subprocess.run(["getfacl","--absolute-names","--tabs","-p","--", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if r.returncode==0: return r.stdout.decode("utf-8", "replace")
    except Exception: pass
    return None

def setfacl_restore(text:str, path:str):
    try:
        p = subprocess.Popen(["setfacl","--restore=-"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate(input=text.encode("utf-8", "replace"))
    except Exception: pass

def selinux_get(path:str, follow_symlinks:bool)->Optional[bytes]:
    try:
        return os.getxattr(path, "security.selinux", follow_symlinks=follow_symlinks)
    except Exception:
        return None

def fallocate_punch_hole(fd:int, offset:int, length:int):
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

def win_apply_meta(path:str, meta:dict, is_dir:bool):
    if not (WIN and HAVE_WIN32): return
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
                if s.get("hex") is not None:
                    data = bytes.fromhex(s["hex"])
                    with open(path + s["name"], "wb") as sf: sf.write(data)
            except Exception: pass

# ---------- Core helpers ----------
def _load_header_toc_and_key(br, need_password:bool):
    header=HeaderV1.unpack(br); toc_off,toc_sz,hk,dig=read_footer(br); br.seek(toc_off)
    toc_data=br.read(toc_sz); key=None
    if header.flags & F_ENCRYPTED:
        if not need_password: raise SystemExit("Archive is encrypted; use --password")
        pw=getpass.getpass("Password: ").encode(); key=kdf_derive_key(pw, header)
        toc_data=aead_decrypt(key, header, 0xFFFFFFFFFFFFFFFF, toc_data, aad=b"vfa-toc")
    toc=TOC.unpack(toc_data, solid=bool(header.flags & F_SOLID))
    return header,toc,key,toc_off,toc_sz,hk,dig

def _recompute_hash_until(bf, upto:int, hash_kind:int)->bytes:
    bf.seek(0); h=make_hasher(hash_kind); done=0
    while done<upto:
        chunk=bf.read(min(1024*1024, upto-done))
        if not chunk: break
        hasher_update(h, chunk, hash_kind); done += len(chunk)
    return hasher_digest(h, hash_kind)

# ---------- Commands ----------
def cmd_create(args):
    block_size=1<<args.block_exp; method=NAME_TO_METHOD.get(args.method)
    if method is None: raise SystemExit(f"Unknown method {args.method}")
    header=HeaderV1(); header.default_method=method; header.default_level=args.level
    header.block_exp=args.block_exp; header.threads_hint=args.threads; header.ram_mib_hint=args.max_ram_mib
    if args.solid: header.flags |= F_SOLID
    key=None
    if args.password:
        if not HAVE_AESGCM: raise SystemExit("cryptography not installed; cannot encrypt")
        if HAVE_ARGON2:
            header.kdf_id=KDF_ARGON2ID; header.kdf_t=args.kdf_time or 3; header.kdf_m=args.kdf_mem_kib or (256*1024); header.kdf_p=args.kdf_parallel or 4
        else:
            header.kdf_id=KDF_SCRYPT; header.kdf_t=args.scrypt_n or (1<<15); header.kdf_m=args.scrypt_r or 8; header.kdf_p=args.scrypt_p or 1
        header.salt=os.urandom(16); header.aead_id=AEAD_AESGCM; header.aead_nonce_prefix=os.urandom(12); header.flags |= F_ENCRYPTED
        LOGGER.info("Encryption enabled (AES-256-GCM).")
        pw=getpass.getpass("Password: ").encode(); key=kdf_derive_key(pw, header)

    toc=TOC(); block_index=0
    hardlinks: Dict[Tuple[int,int], str] = {}

    with open(args.output,"wb") as f:
        bw=f
        header_bytes = header.pack()
        bw.write(header_bytes)
        hasher=make_hasher(default_hash_kind())
        hasher_update(hasher, header_bytes, default_hash_kind())

        # Collect entries
        items = list(iter_tree(args.inputs))
        if (header.flags & F_SOLID) and (args.solid_by == "ext"):
            def ext_key(item):
                fp, st, et = item
                e = fp.suffix.lower()
                return (e if e else ""), str(fp)
            items.sort(key=ext_key)

        # Progress setup
        file_items = [it for it in items if it[2] == ET_FILE]
        total_files = len(file_items)
        total_bytes = sum(int(getattr(st, "st_size", 0)) for _, st, _ in file_items)
        prog = Progress(total_files, total_bytes)
        LOGGER.info(f"Preparing to compress {total_files} files ({human_bytes(total_bytes)}). Solid={bool(args.solid)} method={args.method} lvl={args.level}")
        if (header.flags & F_SOLID) and args.solid_chunk_exp is not None:
            LOGGER.info(f"Solid chunk size ≈ {human_bytes(1<<int(args.solid_chunk_exp))}")

        # For solid mode we concatenate only regular file bytes
        solid_buffer = io.BytesIO(); cur_off = 0
        for fp, st, et in items:
            rel = str(fp)
            st_mode = (st.st_mode & 0o7777)
            st_mtime = int(getattr(st, "st_mtime", time.time()))
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

            if et == ET_DIR:
                entry = FileEntry(rel, st_mode, st_mtime, 0, [], 0, ET_DIR,
                                  json.dumps(meta_obj, ensure_ascii=False).encode("utf-8") if meta_obj else None)
                toc.entries.append(entry)
                if LOGGER.level >= VLog.LEVELS["trace"]:
                    LOGGER.trace(f"Discovered directory {rel}")
                continue

            if et == ET_SYMLINK and LIN:
                target = os.readlink(rel)
                meta_obj["link_target"]=target
                entry = FileEntry(rel, st_mode, st_mtime, 0, [], 0, ET_SYMLINK,
                                  json.dumps(meta_obj, ensure_ascii=False).encode("utf-8"))
                toc.entries.append(entry)
                if LOGGER.level >= VLog.LEVELS["trace"]:
                    LOGGER.trace(f"Recorded symlink {rel} -> {target}")
                continue

            # Handle hardlinks (Linux)
            if LIN and et == ET_FILE and getattr(st, "st_nlink", 1) > 1:
                key_hl = hl_key(st)
                if key_hl in hardlinks:
                    meta_obj["hardlink_to"] = hardlinks[key_hl]
                    entry = FileEntry(rel, st_mode, st_mtime, 0, [], 0, ET_HARDLINK,
                                      json.dumps(meta_obj, ensure_ascii=False).encode("utf-8"))
                    toc.entries.append(entry)
                    if LOGGER.level >= VLog.LEVELS["trace"]:
                        LOGGER.trace(f"Recorded hardlink {rel} -> {hardlinks[key_hl]}")
                    continue
                else:
                    hardlinks[key_hl] = rel

            # regular file
            size = int(st.st_size)
            if LIN and args.sparse and stat.S_ISREG(st.st_mode):
                holes = detect_sparse(rel)
                if holes:
                    meta_obj["holes"]=holes

            meta_bytes = json.dumps(meta_obj, ensure_ascii=False).encode("utf-8") if meta_obj else None

            if header.flags & F_SOLID:
                if LOGGER.level >= VLog.LEVELS["debug"]:
                    LOGGER.debug(f"Queuing file {rel} ({human_bytes(size)}) for solid stream")
                t0 = time.time()
                with open(rel, "rb") as fr:
                    data = fr.read()
                    solid_buffer.write(data)
                duration = time.time() - t0
                prog.add_file(size, duration)
                elapsed, eta, rate, ratio = prog.estimate()
                if LOGGER.level >= VLog.LEVELS["debug"]:
                    arch_so_far = bw.tell()
                    LOGGER.debug(
                        f"Queued {rel} in {duration:.2f}s | "
                        f"{prog.done_files}/{prog.total_files} files, "
                        f"{human_bytes(prog.done_bytes)}/{human_bytes(prog.total_bytes)} | "
                        f"arch {human_bytes(arch_so_far)} | "
                        f"elapsed {elapsed:.1f}s | eta {('∞' if eta==float('inf') else f'{eta:.1f}s')}"
                    )
                entry = FileEntry(rel, st_mode, st_mtime, size, [], cur_off, ET_FILE, meta_bytes)
                cur_off += size
                toc.entries.append(entry)
            else:
                if LOGGER.level >= VLog.LEVELS["debug"]:
                    LOGGER.debug(f"Compressing file {rel} ({human_bytes(size)})")
                t0 = time.time()
                entry = FileEntry(rel, st_mode, st_mtime, size, [], 0, ET_FILE, meta_bytes)
                with open(rel, "rb") as fr:
                    rem=size
                    while rem>0:
                        chunk=fr.read(min(block_size, rem)); rem -= len(chunk)
                        comp=compress_block(method, args.level, chunk)
                        payload=comp if key is None else aead_encrypt(key, header, block_index, comp, aad=b"vfa-data")
                        bw.write(struct.pack("<I", len(payload))); bw.write(struct.pack("<B", method)); bw.write(payload)
                        entry.blocks.append((block_index, len(chunk), len(payload), method))
                        hasher_update(hasher, struct.pack("<I", len(payload))+struct.pack("<B", method)+payload, default_hash_kind())
                        block_index += 1
                duration = time.time() - t0
                toc.entries.append(entry)
                prog.add_file(size, duration)
                arch_so_far = bw.tell()
                elapsed, eta, rate, ratio = prog.estimate()
                if LOGGER.level >= VLog.LEVELS["debug"]:
                    saved = max(0, prog.done_bytes - arch_so_far)
                    ratio_now = (arch_so_far/prog.done_bytes) if prog.done_bytes else 0.0
                    LOGGER.debug(
                        f"Done {rel} in {duration:.2f}s | "
                        f"{prog.done_files}/{prog.total_files} files, "
                        f"{human_bytes(prog.done_bytes)}/{human_bytes(prog.total_bytes)} | "
                        f"arch {human_bytes(arch_so_far)} | "
                        f"saved {human_bytes(saved)} | ratio {ratio_now:.3f} | "
                        f"elapsed {elapsed:.1f}s | eta {('∞' if eta==float('inf') else f'{eta:.1f}s')}"
                    )

        # If solid: emit blocks from solid_buffer (single or chunked)
        if header.flags & F_SOLID:
            whole = solid_buffer.getvalue()
            if args.solid_chunk_exp is not None:
                seg_size = 1 << int(args.solid_chunk_exp)
                if LOGGER.level >= VLog.LEVELS["trace"]:
                    LOGGER.trace(f"Emitting solid chunks of ~{human_bytes(seg_size)}")
                pos = 0; total=len(whole)
                while pos < total:
                    seg = whole[pos:pos+seg_size]; pos += len(seg)
                    comp=compress_block(method, args.level, seg)
                    payload = comp if key is None else aead_encrypt(key, header, block_index, comp, aad=b"vfa-data")
                    bw.write(struct.pack("<I", len(payload))); bw.write(struct.pack("<B", method)); bw.write(payload)
                    hasher_update(hasher, struct.pack("<I", len(payload))+struct.pack("<B", method)+payload, default_hash_kind())
                    block_index += 1
            else:
                comp=compress_block(method, args.level, whole)
                payload = comp if key is None else aead_encrypt(key, header, block_index, comp, aad=b"vfa-data")
                bw.write(struct.pack("<I", len(payload))); bw.write(struct.pack("<B", method)); bw.write(payload)
                hasher_update(hasher, struct.pack("<I", len(payload))+struct.pack("<B", method)+payload, default_hash_kind())
                block_index += 1
            arch_so_far = bw.tell()
            saved = max(0, prog.done_bytes - arch_so_far)
            ratio_now = (arch_so_far / prog.done_bytes) if prog.done_bytes else 0.0
            LOGGER.info(
                f"Solid stream written | arch {human_bytes(arch_so_far)} | "
                f"src {human_bytes(prog.done_bytes)} | saved {human_bytes(saved)} | ratio {ratio_now:.3f}"
            )

        toc_data = toc.pack(solid=bool(header.flags & F_SOLID))
        LOGGER.trace("Writing TOC...")
        if key is not None: toc_data = aead_encrypt(key, header, 0xFFFFFFFFFFFFFFFF, toc_data, aad=b"vfa-toc")
        toc_off = bw.tell(); bw.write(toc_data); toc_sz=len(toc_data); hasher_update(hasher, toc_data, default_hash_kind())
        digest=hasher_digest(hasher, default_hash_kind()); write_footer(bw, toc_off, toc_sz, default_hash_kind(), digest)
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

def cmd_list(args):
    with open(args.archive,"rb") as f:
        br=f; header=HeaderV1.unpack(br); toc_off,toc_sz,hk,digest=read_footer(br)
        br.seek(toc_off); toc_data=br.read(toc_sz)
        if header.flags & F_ENCRYPTED:
            if not args.password: raise SystemExit("Archive is encrypted; use --password")
            pw=getpass.getpass("Password: ").encode(); key=kdf_derive_key(pw, header)
            toc_data=aead_decrypt(key, header, 0xFFFFFFFFFFFFFFFF, toc_data, aad=b"vfa-toc")
        toc=TOC.unpack(toc_data, solid=bool(header.flags & F_SOLID))
        total=sum(e.size for e in toc.entries if e.entry_type==ET_FILE)
        print(f"Archive: {args.archive}\nVersion: {header.version}, Method: {METHOD_NAMES.get(header.default_method)} lvl {header.default_level}, Block: {1<<header.block_exp}B")
        print(f"Encrypted: {bool(header.flags & F_ENCRYPTED)}, Solid: {bool(header.flags & F_SOLID)}")
        print(f"Entries: {len(toc.entries)}, Files total: {total} bytes")
        for e in toc.entries:
            kind = ["file","dir","symlink","hardlink"][e.entry_type]
            blocks_info = "solid" if (header.flags & F_SOLID and e.entry_type==ET_FILE) else (f"{len(e.blocks)} blocks" if e.entry_type==ET_FILE else "-")
            print(f"{e.size:12d}  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e.mtime))}  [{kind}]  {e.path}  ({blocks_info})")

def cmd_test(args):
    LOGGER.info("Verifying archive footer hash and block integrity...")
    with open(args.archive,"rb") as f:
        br=f; header=HeaderV1.unpack(br); toc_off,toc_sz,hk,digest=read_footer(br)
        footer_len=8+4+1+32+5; br.seek(0,os.SEEK_END); end=br.tell(); br.seek(0)
        h=make_hasher(hk); remain=end-footer_len; read=0
        while read<remain:
            chunk=br.read(min(1024*1024, remain-read)); hasher_update(h, chunk, hk); read+=len(chunk)
        ok=(hasher_digest(h,hk)==digest); print(f"Footer hash match: {'OK' if ok else 'FAIL'}")
        br.seek(toc_off); toc_data=br.read(toc_sz); key=None
        if header.flags & F_ENCRYPTED:
            if not args.password: raise SystemExit("Archive is encrypted; use --password to test")
            pw=getpass.getpass("Password: ").encode(); key=kdf_derive_key(pw, header)
            toc_data=aead_decrypt(key, header, 0xFFFFFFFFFFFFFFFF, toc_data, aad=b"vfa-toc")
        toc=TOC.unpack(toc_data, solid=bool(header.flags & F_SOLID))
        br.seek(len(header.pack()))
        if header.flags & F_SOLID:
            total_expected = sum(e.size for e in toc.entries if e.entry_type==ET_FILE)
            data_total=0
            while br.tell() < toc_off:
                hdr = br.read(5)
                if len(hdr) < 5: break
                blen = struct.unpack("<I", hdr[:4])[0]; meth = hdr[4]
                payload = br.read(blen)
                if key is not None:
                    payload = aead_decrypt(key, header, 0, payload, aad=b"vfa-data")
                data = decompress_block(header.default_method, payload)
                data_total += len(data)
            if data_total != total_expected:
                print("Solid size mismatch"); return
            print(f"Tested {sum(1 for e in toc.entries if e.entry_type==ET_FILE)} files in SOLID stream: OK.")
        else:
            blocks=0
            for e in toc.entries:
                if e.entry_type!=ET_FILE: continue
                for (idx, usz, csz, meth) in e.blocks:
                    hdr=br.read(5); 
                    if len(hdr)<5: print("Unexpected EOF"); return
                    blen=struct.unpack("<I", hdr[:4])[0]; mm=hdr[4]
                    payload=br.read(blen); 
                    if key is not None: payload=aead_decrypt(key, header, idx, payload, aad=b"vfa-data")
                    data=decompress_block(meth, payload)
                    if len(data)!=usz: print("Size mismatch"); return
                    blocks+=1
            print(f"Tested {sum(1 for e in toc.entries if e.entry_type==ET_FILE)} files, {blocks} blocks: OK.")

def cmd_extract(args):
    outdir=pathlib.Path(args.output or "."); outdir.mkdir(parents=True, exist_ok=True)
    with open(args.archive,"rb") as f:
        br=f; header=HeaderV1.unpack(br); toc_off,toc_sz,hk,digest=read_footer(br)
        br.seek(toc_off); toc_data=br.read(toc_sz); key=None
        if header.flags & F_ENCRYPTED:
            if not args.password: raise SystemExit("Archive is encrypted; use --password")
            pw=getpass.getpass("Password: ").encode(); key=kdf_derive_key(pw, header)
            toc_data=aead_decrypt(key, header, 0xFFFFFFFFFFFFFFFF, toc_data, aad=b"vfa-toc")
        toc=TOC.unpack(toc_data, solid=bool(header.flags & F_SOLID))
        br.seek(len(header.pack()))

        dirs=[e for e in toc.entries if e.entry_type==ET_DIR]
        syms=[e for e in toc.entries if e.entry_type==ET_SYMLINK]
        hlinks=[e for e in toc.entries if e.entry_type==ET_HARDLINK]
        files=[e for e in toc.entries if e.entry_type==ET_FILE]

        for e in dirs:
            out_path = outdir / e.path
            out_path.mkdir(parents=True, exist_ok=True)
            try: os.chmod(out_path, e.mode)
            except Exception: pass
            try: os.utime(out_path, (e.mtime, e.mtime))
            except Exception: pass
            if e.meta_json and WIN:
                try: win_apply_meta(str(out_path), json.loads(e.meta_json.decode()), True)
                except Exception: pass
            if e.meta_json and LIN and args.posixmeta:
                try:
                    meta=json.loads(e.meta_json.decode()); pos=meta.get("posix",{})
                    try: os.chown(out_path, pos.get("uid", -1), pos.get("gid", -1))
                    except Exception: pass
                    if args.xattrs and "xattrs" in meta:
                        apply_xattrs(str(out_path), {k:bytes.fromhex(v) for k,v in meta["xattrs"].items()}, follow_symlinks=False)
                    if args.acl and meta.get("acl"): setfacl_restore(meta["acl"], str(out_path))
                except Exception: pass
            LOGGER.trace(f"Created directory {e.path}")

        solid_concat=None
        if header.flags & F_SOLID:
            parts=[]
            while br.tell() < toc_off:
                hdr=br.read(5)
                if len(hdr)<5: break
                blen=struct.unpack("<I", hdr[:4])[0]; meth=hdr[4]
                payload=br.read(blen)
                if key is not None: payload=aead_decrypt(key, header, 0, payload, aad=b"vfa-data")
                parts.append(decompress_block(header.default_method, payload))
            solid_concat=b"".join(parts)

        for e in syms:
            out_path = outdir / e.path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            target=""
            try:
                meta=json.loads(e.meta_json.decode()); target=meta.get("link_target","")
            except Exception: pass
            try:
                if LIN:
                    try: os.remove(out_path)
                    except Exception: pass
                    os.symlink(target, out_path)
                    try: os.lchmod(out_path, e.mode)
                    except Exception: pass
                    if args.posixmeta and "posix" in meta:
                        pos=meta["posix"]
                        try: os.lchown(out_path, pos.get("uid",-1), pos.get("gid",-1))
                        except Exception: pass
                    if args.xattrs and "xattrs" in meta:
                        apply_xattrs(str(out_path), {k:bytes.fromhex(v) for k,v in meta["xattrs"].items()}, follow_symlinks=False)
            except Exception: pass
            LOGGER.trace(f"Created symlink {e.path} -> {target}")

        for e in files:
            out_path = outdir / e.path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if header.flags & F_SOLID:
                segment = solid_concat[e.start_off: e.start_off + e.size]
                with open(out_path, "wb") as fw: fw.write(segment)
            else:
                with open(out_path, "wb") as fw:
                    for (idx, usz, csz, meth) in e.blocks:
                        hdr=br.read(5)
                        if len(hdr)<5: raise IOError("Unexpected EOF")
                        blen=struct.unpack("<I", hdr[:4])[0]; mm=hdr[4]
                        payload=br.read(blen)
                        if len(payload)!=blen: raise IOError("Unexpected EOF payload")
                        if key is not None: payload=aead_decrypt(key, header, idx, payload, aad=b"vfa-data")
                        data=decompress_block(meth, payload)
                        if len(data)!=usz: raise IOError("Size mismatch in block")
                        fw.write(data)
            try: os.chmod(out_path, e.mode)
            except Exception: pass
            try: os.utime(out_path, (e.mtime, e.mtime))
            except Exception: pass

            if e.meta_json and WIN:
                try: win_apply_meta(str(out_path), json.loads(e.meta_json.decode()), False)
                except Exception: pass

            if e.meta_json and LIN and args.posixmeta:
                try:
                    meta=json.loads(e.meta_json.decode()); pos=meta.get("posix",{})
                    try: os.chown(out_path, pos.get("uid",-1), pos.get("gid",-1))
                    except Exception: pass
                    if args.xattrs and "xattrs" in meta:
                        apply_xattrs(str(out_path), {k:bytes.fromhex(v) for k,v in meta["xattrs"].items()}, follow_symlinks=False)
                    if args.acl and meta.get("acl"): setfacl_restore(meta["acl"], str(out_path))
                    if args.sparse and "holes" in meta and LIN:
                        with open(out_path, "r+b") as fw:
                            for off, ln in meta["holes"]:
                                fallocate_punch_hole(fw.fileno(), off, ln)
                except Exception: pass

            LOGGER.debug(f"Extracted {e.path}")

        for e in hlinks:
            out_path = outdir / e.path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            target=""
            try:
                meta=json.loads(e.meta_json.decode()); target=meta.get("hardlink_to","")
            except Exception: pass
            try:
                if target:
                    src = outdir / target
                    if src.exists():
                        try:
                            if out_path.exists(): os.remove(out_path)
                        except Exception: pass
                        os.link(src, out_path)
                        LOGGER.trace(f"Created hardlink {e.path} -> {target}")
            except Exception: pass

def cmd_append(args):
    with open(args.archive, "r+b") as f:
        header,toc,key,toc_offset,toc_size,hash_kind,old_digest=_load_header_toc_and_key(f, need_password=args.password)
        if header.flags & F_SOLID:
            raise SystemExit("Append not supported for SOLID archives. Recreate or use non-solid.")
        next_block=sum(len(e.blocks) for e in toc.entries if e.entry_type==ET_FILE)
        f.seek(toc_offset); f.truncate()
        method = header.default_method if (not args.method) else NAME_TO_METHOD[args.method]
        level = header.default_level if (args.level is None) else args.level
        block_size = 1<<header.block_exp

        # Plan progress only for new files being appended
        items = list(iter_tree(args.inputs))
        file_items = [it for it in items if it[2] == ET_FILE]
        total_files = len(file_items)
        total_bytes = sum(int(getattr(st, "st_size", 0)) for _, st, _ in file_items)
        prog = Progress(total_files, total_bytes)
        LOGGER.info(f"Appending {total_files} files ({human_bytes(total_bytes)})...")

        for fp, st, et in items:
            if et!=ET_FILE: 
                LOGGER.trace(f"Skipping non-file during append: {fp}")
                continue
            rel = str(fp)
            st_mode = (st.st_mode & 0o7777)
            st_mtime = int(getattr(st,"st_mtime", time.time()))
            size = int(st.st_size)
            entry=FileEntry(rel, st_mode, st_mtime, size, [], 0, ET_FILE)
            if LOGGER.level >= VLog.LEVELS["debug"]:
                LOGGER.debug(f"Compressing file {rel} ({human_bytes(size)})")
            t0 = time.time()
            with open(rel,"rb") as fr:
                rem=size
                while rem>0:
                    chunk=fr.read(min(block_size, rem)); rem -= len(chunk)
                    comp=compress_block(method, level, chunk)
                    payload=comp if key is None else aead_encrypt(key, header, next_block, comp, aad=b"vfa-data")
                    f.write(struct.pack("<I", len(payload))); f.write(struct.pack("<B", method)); f.write(payload)
                    entry.blocks.append((next_block, len(chunk), len(payload), method)); next_block += 1
            toc.entries.append(entry)
            duration = time.time() - t0
            prog.add_file(size, duration)
            arch_so_far = f.tell()
            elapsed, eta, rate, ratio = prog.estimate()
            if LOGGER.level >= VLog.LEVELS["debug"]:
                saved = max(0, prog.done_bytes - (arch_so_far))  # rough
                ratio_now = (arch_so_far/prog.done_bytes) if prog.done_bytes else 0.0
                LOGGER.debug(
                    f"Done {rel} in {duration:.2f}s | "
                    f"{prog.done_files}/{prog.total_files} files, "
                    f"{human_bytes(prog.done_bytes)}/{human_bytes(prog.total_bytes)} | "
                    f"arch {human_bytes(arch_so_far)} | "
                    f"saved {human_bytes(saved)} | ratio {ratio_now:.3f} | "
                    f"elapsed {elapsed:.1f}s | eta {('∞' if eta==float('inf') else f'{eta:.1f}s')}"
                )

        toc_data=toc.pack(solid=False)
        LOGGER.trace("Writing updated TOC (append)...")
        if key is not None: toc_data=aead_encrypt(key, header, 0xFFFFFFFFFFFFFFFF, toc_data, aad=b"vfa-toc")
        toc_new_off=f.tell(); f.write(toc_data); toc_new_sz=len(toc_data)
        upto=f.tell(); digest=_recompute_hash_until(f, upto, hash_kind if hash_kind!=H_NONE else default_hash_kind())
        write_footer(f, toc_new_off, toc_new_sz, hash_kind if hash_kind!=H_NONE else default_hash_kind(), digest)
        arch_final = f.tell()
        elapsed, eta, rate, ratio = prog.estimate()
        saved = max(0, prog.done_bytes - (arch_final - toc_new_sz))  # rough
        LOGGER.info(
            f"Append done in {elapsed:.2f}s | files {prog.done_files}/{prog.total_files} | "
            f"added {human_bytes(prog.done_bytes)} | archive now {human_bytes(arch_final)}"
        )

# ---------- CLI ----------
def build_argparser():
    ap=argparse.ArgumentParser(prog="vfa", description="Vulpfin Archive (.vfa) — CPython prototype")
    sub=ap.add_subparsers(dest="cmd", required=True)

    ap_c=sub.add_parser("c", help="Create archive")
    ap_c.add_argument("output"); ap_c.add_argument("inputs", nargs="+")
    ap_c.add_argument("--method", default=("zstd" if HAVE_ZSTD else "zlib"), choices=list(NAME_TO_METHOD.keys()))
    ap_c.add_argument("--level", type=int, default=5)
    ap_c.add_argument("--block-exp", type=int, default=22, dest="block_exp")
    ap_c.add_argument("--threads", type=int, default=0); ap_c.add_argument("--max-ram-mib", type=int, default=0)
    ap_c.add_argument("--password", action="store_true")
    # Solid options
    ap_c.add_argument("--solid", action="store_true", help="Solid mode (single stream)")
    ap_c.add_argument("--solid-chunk-exp", type=int, default=None, help="Split solid stream into chunks of 2^N bytes (uncompressed)")
    ap_c.add_argument("--solid-by", choices=["none","ext"], default="none", help="Order solid stream by grouping (ext groups similar files together)")
    # Windows / POSIX meta
    ap_c.add_argument("--winmeta", action="store_true", help="Windows: store attributes/ACL/ADS/timestamps")
    ap_c.add_argument("--posixmeta", action="store_true", help="Linux/Unix: store uid/gid/mode/atime/mtime/ctime (+links)")
    ap_c.add_argument("--xattrs", action="store_true", help="Store extended attributes (xattrs)")
    ap_c.add_argument("--acl", action="store_true", help="Store POSIX ACLs via getfacl/setfacl")
    ap_c.add_argument("--selinux", action="store_true", help="Store SELinux context (if present)")
    ap_c.add_argument("--sparse", action="store_true", help="Detect & restore sparse holes (Linux only)")
    # KDF tuning
    ap_c.add_argument("--kdf-time", type=int, default=3); ap_c.add_argument("--kdf-mem-kib", type=int, default=256*1024); ap_c.add_argument("--kdf-parallel", type=int, default=4)
    ap_c.add_argument("--scrypt-n", type=int, default=1<<15); ap_c.add_argument("--scrypt-r", type=int, default=8); ap_c.add_argument("--scrypt-p", type=int, default=1)

    ap_a=sub.add_parser("a", help="Append files to archive (non-solid only)")
    ap_a.add_argument("archive"); ap_a.add_argument("inputs", nargs="+")
    ap_a.add_argument("--method", default=None, choices=list(NAME_TO_METHOD.keys()))
    ap_a.add_argument("--level", type=int, default=None)
    ap_a.add_argument("--password", action="store_true", help="Prompt for password if encrypted")

    ap_l=sub.add_parser("l", help="List archive"); ap_l.add_argument("archive"); ap_l.add_argument("--password", action="store_true")
    ap_t=sub.add_parser("t", help="Test archive"); ap_t.add_argument("archive"); ap_t.add_argument("--password", action="store_true")
    ap_x=sub.add_parser("x", help="Extract archive"); ap_x.add_argument("archive"); ap_x.add_argument("-o","--output", default="."); ap_x.add_argument("--password", action="store_true")

    # Logging flags for all subcommands
    for sp in (ap_c, ap_a, ap_l, ap_t, ap_x):
        sp.add_argument("--log-level",
            choices=["quiet","error","warning","info","debug","trace"],
            default="warning",
            help="Logging verbosity (default: warning)")
        sp.add_argument("-v","--verbose", action="store_true",
            help="Shortcut for --log-level info")
    return ap

def main(argv=None):
    ap=build_argparser(); args=ap.parse_args(argv)
    # verbose alias
    if getattr(args, "verbose", False) and getattr(args, "log_level", None) == "warning":
        args.log_level = "info"
    # set global logger
    global LOGGER
    LOGGER = VLog(getattr(args, "log_level", "warning"))

    if args.cmd=="c": cmd_create(args)
    elif args.cmd=="a": cmd_append(args)
    elif args.cmd=="l": cmd_list(args)
    elif args.cmd=="t": cmd_test(args)
    elif args.cmd=="x": cmd_extract(args)
    else: ap.print_help()

if __name__=="__main__": main()
