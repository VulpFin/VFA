#!/usr/bin/env python3
# Self-extracting stub for .vfa archives appended to this EXE
# Build:
#   pyinstaller --onefile --clean --name vfa_sfx sfx_stub.py
# Pack:
#   copy /b .\dist\vfa_sfx.exe + .\payload.vfa MySFX.exe
#
# Usage:
#   MySFX.exe [-o OUTPUT_DIR] [--password] [--quiet|--log-level debug] [--from-file PATH]

import sys, os, io, struct, argparse, getpass, time, hashlib, zlib, lzma, pathlib
from datetime import datetime

# ---------------- Logging ----------------

LOG_COL_PIPE = 48
class VLog:
    LEVELS = {"quiet":0, "error":1, "warning":2, "info":3, "debug":4, "trace":5}
    def __init__(self, level="warning"):
        self.level = self.LEVELS.get(level, 2)
    def _fmt(self, name, msg):
        ts = datetime.now().strftime("%m/%d/%Y %H:%M:%S.%f")[:-1]
        prefix = f"[VFA {name.upper():<7}] {ts}"
        pad = LOG_COL_PIPE - len(prefix) - 1
        if pad < 1: pad = 1
        return f"{prefix}{' ' * pad}| {msg}"
    def _emit(self, lvl, name, msg):
        if self.level >= lvl:
            print(self._fmt(name, msg), flush=True)
    def error(self, msg):   self._emit(1, "ERROR", msg)
    def warning(self, msg): self._emit(2, "WARNING", msg)
    def info(self, msg):    self._emit(3, "INFO", msg)
    def debug(self, msg):   self._emit(4, "DEBUG", msg)
    def trace(self, msg):   self._emit(5, "TRACE", msg)

LOGGER = VLog("warning")

# ---------------- VFA constants ----------------

MAGIC=b"VFA1"
END_MAGIC=b"/VFA1"

AEAD_NONE=0; AEAD_AESGCM=1
KDF_NONE=0;  KDF_ARGON2ID=1; KDF_SCRYPT=2

M_NONE=0; M_ZLIB=1; M_LZMA=2; M_BROTLI=3; M_ZSTD=4
F_ENCRYPTED=1<<0
F_SOLID=1<<1

FOOTER_LEN = 8+4+1+32+5  # toc_off u64, toc_sz u32, hash_kind u8, digest[32], END_MAGIC[5]

# ---------------- Optional deps ----------------

try:
    import brotli; HAVE_BROTLI=True
except Exception:
    HAVE_BROTLI=False
try:
    import zstandard as zstd; HAVE_ZSTD=True
except Exception:
    HAVE_ZSTD=False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAVE_AESGCM=True
except Exception:
    AESGCM=None; Scrypt=None; HAVE_AESGCM=False
try:
    import argon2.low_level as argon2ll
    HAVE_ARGON2=True
except Exception:
    argon2ll=None; HAVE_ARGON2=False

# ---------------- Helpers ----------------

def _die(msg, code=2):
    LOGGER.error(msg)
    sys.exit(code)

def _nonce_from(prefix12:bytes, index:int)->bytes:
    m=hashlib.sha256(); m.update(prefix12); m.update(struct.pack("<Q", index)); m.update(b"vfa-nonce"); return m.digest()[:12]

def _aead_decrypt(key:bytes, aead_id:int, nonce_prefix:bytes, index:int, ciphertext:bytes, aad:bytes=b"")->bytes:
    if aead_id!=AEAD_AESGCM or not HAVE_AESGCM:
        _die("Cannot decrypt: AES-GCM support unavailable (install 'cryptography').")
    return AESGCM(key).decrypt(_nonce_from(nonce_prefix, index), ciphertext, aad)

def _kdf(password:bytes, kdf_id:int, t:int, m:int, p:int, salt:bytes)->bytes:
    if kdf_id==KDF_ARGON2ID:
        if not HAVE_ARGON2: _die("Argon2 KDF requested but argon2-cffi not installed.")
        return argon2ll.hash_secret_raw(secret=password, salt=salt, time_cost=t or 3,
                                        memory_cost=m or (256*1024), parallelism=p or 4,
                                        hash_len=32, type=argon2ll.Type.ID, version=argon2ll.ARGON2_VERSION)
    if kdf_id==KDF_SCRYPT:
        if Scrypt is None: _die("Scrypt KDF requested but 'cryptography' not installed.")
        return Scrypt(salt=salt, length=32, n=t or (1<<15), r=m or 8, p=p or 1).derive(password)
    _die("Archive not password-protected (no KDF), but decrypt requested?")

def _decompress(method:int, data:bytes)->bytes:
    if method==M_NONE: return data
    if method==M_ZLIB: return zlib.decompress(data)
    if method==M_LZMA: return lzma.decompress(data)
    if method==M_BROTLI:
        if not HAVE_BROTLI: _die("Brotli not available.")
        return brotli.decompress(data)
    if method==M_ZSTD:
        if not HAVE_ZSTD: _die("zstandard not available.")
        return zstd.ZstdDecompressor().decompress(data)
    _die(f"Unknown method {method}")

def _read_footer(buf:bytes):
    E = len(buf)
    if E < FOOTER_LEN:
        _die(f"File too small for VFA footer (size={E}).")
    end_magic = buf[E-5:E]
    if end_magic != END_MAGIC:
        _die("END_MAGIC not found at EOF; not a VFA SFX payload.")
    off = E - FOOTER_LEN
    toc_off = struct.unpack("<Q", buf[off:off+8])[0]
    toc_sz  = struct.unpack("<I", buf[off+8:off+12])[0]
    hk      = struct.unpack("<B", buf[off+12:off+13])[0]
    digest  = buf[off+13:off+45]
    LOGGER.debug(f"Footer parsed | E={E} toc_off={toc_off} toc_sz={toc_sz} hk={hk} footer_pos={off}")
    return toc_off, toc_sz, hk, digest, off

def _parse_header(bio:io.BytesIO):
    # Strict, with size checks
    hdr = bio.read(4)
    if hdr != MAGIC:
        _die("Bad VFA header magic.")
    raw = bio.read(2)
    if len(raw) != 2: _die("Header truncated reading version.")
    version, = struct.unpack("<H", raw)

    raw = bio.read(4)
    if len(raw) != 4: _die("Header truncated reading flags.")
    flags, = struct.unpack("<I", raw)

    def u1(): 
        b = bio.read(1)
        if len(b)!=1: _die("Header truncated.")
        return struct.unpack("<B", b)[0]
    def u2():
        b = bio.read(2)
        if len(b)!=2: _die("Header truncated.")
        return struct.unpack("<H", b)[0]
    def u4():
        b = bio.read(4)
        if len(b)!=4: _die("Header truncated.")
        return struct.unpack("<I", b)[0]

    dm = u1(); dl = u1(); be = u1()
    th = u2(); rm = u4()
    kid = u1(); kt = u4(); km = u4(); kp = u1()

    salt = bio.read(16)
    if len(salt)!=16: _die("Header truncated reading salt.")
    aid = u1()
    np  = bio.read(12)
    if len(np)!=12: _die("Header truncated reading nonce prefix.")
    res = bio.read(16)
    if len(res)!=16: _die("Header truncated reading reserved.")

    hdr_len = 4+2+4 + 1+1+1 + 2 + 4 + 1 + 4 + 4 + 1 + 16 + 1 + 12 + 16
    LOGGER.debug(f"Header parsed | version={version} flags={flags} method={dm} level={dl} block_exp={be} header_len={hdr_len}")
    return {
        "version":version, "flags":flags,
        "default_method":dm, "default_level":dl,
        "block_exp":be, "threads":th, "ram_mib":rm,
        "kdf_id":kid, "kdf_t":kt, "kdf_m":km, "kdf_p":kp,
        "salt":salt, "aead_id":aid, "nonce_prefix":np,
        "reserved":res, "header_len":hdr_len
    }

def _parse_toc(data:bytes, solid:bool):
    bio=io.BytesIO(data)
    b = bio.read(4)
    if len(b)!=4: _die("TOC truncated reading count.")
    (n,) = struct.unpack("<I", b)
    entries=[]
    for _ in range(n):
        b = bio.read(2)
        if len(b)!=2: _die("TOC truncated reading path length.")
        (plen,) = struct.unpack("<H", b)
        path = bio.read(plen).decode("utf-8", "replace")
        if len(path.encode("utf-8")) != plen: _die("TOC path length mismatch.")

        for_need = [("mode",4), ("mtime",8), ("size",8), ("nb",4)]
        vals={}
        for name,sz in for_need:
            b=bio.read(sz)
            if len(b)!=sz: _die(f"TOC truncated reading {name}.")
            vals[name] = struct.unpack("<I", b)[0] if sz==4 else struct.unpack("<Q", b)[0]

        # try new layout (entry_type + meta_len + meta)
        entry_type = 0
        meta = b""
        pos_before = bio.tell()
        try:
            bb=bio.read(1)
            if len(bb)!=1: raise ValueError
            entry_type = struct.unpack("<B", bb)[0]
            ml=bio.read(4)
            if len(ml)!=4: raise ValueError
            (mlen,) = struct.unpack("<I", ml)
            if mlen>0:
                meta = bio.read(mlen)
                if len(meta)!=mlen: _die("TOC truncated reading meta.")
        except Exception:
            # back-compat: rewind
            bio.seek(pos_before)

        blocks=[]; start_off=0
        if solid:
            b=bio.read(8)
            if len(b)!=8: _die("TOC truncated reading solid offset.")
            (start_off,) = struct.unpack("<Q", b)
        else:
            for _ in range(vals["nb"]):
                chunk = bio.read(8+4+4+1)
                if len(chunk)!=17: _die("TOC truncated reading block tuple.")
                idx, usz, csz = struct.unpack("<QII", chunk[:16])
                meth = chunk[16]
                blocks.append((idx, usz, csz, meth))

        entries.append({"path":path, "mode":vals["mode"], "mtime":vals["mtime"], "size":vals["size"],
                        "blocks":blocks, "start_off":start_off, "entry_type":entry_type, "meta":meta})
    LOGGER.debug(f"TOC parsed | entries={len(entries)} solid={solid}")
    return entries

# ---------------- Main extract ----------------

def extract_self(output_dir:str, need_password:bool=False, quiet:bool=False, from_file:str=None, log_level:str="warning"):
    global LOGGER
    LOGGER = VLog(log_level)

    exe_path = from_file or sys.executable
    LOGGER.info(f"Opening container file: {exe_path}")
    with open(exe_path, "rb") as f:
        buf = f.read()
    E = len(buf)
    LOGGER.debug(f"Container size E={E} bytes")

    # 1) Footer at EOF
    toc_off, toc_sz, hk, digest, footer_pos = _read_footer(buf)

    # 2) Compute archive start from footer
    arc_start = E - FOOTER_LEN - toc_sz - toc_off
    LOGGER.debug(f"Computed arc_start={arc_start} (E - FOOTER_LEN - toc_sz - toc_off)")

    # Sanity checks
    if arc_start < 0 or arc_start > E-4:
        _die(f"Invalid arc_start computed (arc_start={arc_start}, E={E}, toc_off={toc_off}, toc_sz={toc_sz})")

    # 3) Verify header magic at arc_start
    head4 = buf[arc_start:arc_start+4]
    LOGGER.trace(f"Header probe @ {arc_start}: {head4!r}")
    if head4 != MAGIC:
        # Extra diagnostics: try scanning a tiny window backward/forward to help diagnose alignment issues
        span = 64
        window = buf[max(0, arc_start-span):min(E, arc_start+span)]
        idx = window.find(MAGIC)
        if idx != -1:
            real = max(0, arc_start-span) + idx
            LOGGER.warning(f"Magic found near computed start at {real} (adjusting?)")
        _die("VFA header magic not found at computed start (payload misaligned or corrupted).")

    # 4) Slice the archive view
    arc_end = E
    arc = memoryview(buf)[arc_start:arc_end]
    bio = io.BytesIO(arc.tobytes())
    LOGGER.debug(f"Arc view: [{arc_start}, {arc_end}) length={len(arc)}")

    # 5) Parse header (strict)
    header = _parse_header(bio)
    solid = bool(header["flags"] & F_SOLID)
    encrypted = bool(header["flags"] & F_ENCRYPTED)
    LOGGER.info(f"VFA payload: solid={solid} encrypted={encrypted} method={header['default_method']} level={header['default_level']}")

    # 6) Read TOC (relative to arc start)
    if toc_off + toc_sz > len(arc):
        _die(f"TOC out of bounds (toc_off={toc_off}, toc_sz={toc_sz}, arc_len={len(arc)})")
    toc_data = arc[toc_off: toc_off+toc_sz].tobytes()
    LOGGER.debug(f"TOC slice: [toc_off={toc_off}, toc_off+toc_sz={toc_off+toc_sz})")

    key=None
    if encrypted:
        if not need_password:
            LOGGER.info("Encrypted payload detected; prompting for password.")
        pw=getpass.getpass("Password: ").encode("utf-8")
        key = _kdf(pw, header["kdf_id"], header["kdf_t"], header["kdf_m"], header["kdf_p"], header["salt"])
        toc_data = _aead_decrypt(key, header["aead_id"], header["nonce_prefix"], 0xFFFFFFFFFFFFFFFF, toc_data, aad=b"vfa-toc")
        LOGGER.debug("TOC decrypted.")

    entries = _parse_toc(toc_data, solid=solid)

    # 7) Extract blocks
    outdir = pathlib.Path(output_dir); outdir.mkdir(parents=True, exist_ok=True)
    LOGGER.info(f"Extracting to: {outdir}")

    # position where blocks begin: exactly header length
    pos = header["header_len"]
    LOGGER.debug(f"Block region begins at pos={pos}")

    if solid:
    # Read solid blocks up to TOC, decrypt with incrementing indices
        parts = []
        solid_block_index = 0
        while pos < toc_off:
            if pos + 5 > len(arc):
                _die("Unexpected EOF reading solid block header.")
            blen = struct.unpack("<I", arc[pos:pos+4])[0]
            method = arc[pos+4]
            pos += 5

            if pos + blen > len(arc):
                _die("Unexpected EOF in solid payload.")
            payload = arc[pos:pos+blen].tobytes()
            pos += blen

            if encrypted:
                payload = _aead_decrypt(
                    key, header["aead_id"], header["nonce_prefix"],
                    solid_block_index, payload, aad=b"vfa-data"
                )
            parts.append(_decompress(header["default_method"], payload))
            solid_block_index += 1

        data = b"".join(parts)
        LOGGER.debug(f"Solid decompressed len={len(data)}")

        # write files by offsets
        for e in entries:
            if e["entry_type"] != 0:  # not a regular file
                if e["entry_type"] == 1:  # dir
                    (outdir / e["path"]).mkdir(parents=True, exist_ok=True)
                continue
            out_path = outdir / e["path"]
            out_path.parent.mkdir(parents=True, exist_ok=True)
            seg = data[e["start_off"]: e["start_off"] + e["size"]]
            with open(out_path, "wb") as fw:
                fw.write(seg)
            try: os.utime(out_path, (e["mtime"], e["mtime"]))
            except Exception: pass
            LOGGER.debug(f"Extracted {e['path']} ({len(seg)} bytes)")

    else:
        # Non-solid: sequential over files
        for e in entries:
            if e["entry_type"] == 1:
                (outdir / e["path"]).mkdir(parents=True, exist_ok=True)
                continue
            if e["entry_type"] != 0:
                # ignore symlinks/others in SFX for now
                continue

            out_path = outdir / e["path"]
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(out_path, "wb") as fw:
                for (idx, usz, csz, meth) in e["blocks"]:
                    if pos + 5 > len(arc):
                        _die("Unexpected EOF in block header.")

                    blen = struct.unpack("<I", arc[pos:pos+4])[0]
                    method_byte = arc[pos+4]
                    pos += 5

                    if pos + blen > len(arc):
                        _die("Unexpected EOF in payload.")

                    payload = arc[pos:pos+blen].tobytes()
                    pos += blen

                    if encrypted:
                        payload = _aead_decrypt(
                            key, header["aead_id"], header["nonce_prefix"],
                            idx, payload, aad=b"vfa-data"
                        )

                    data = _decompress(meth, payload)
                    if len(data) != usz:
                        _die("Size mismatch while extracting.")
                    fw.write(data)

            try:
                os.utime(out_path, (e["mtime"], e["mtime"]))
            except Exception:
                pass
            LOGGER.debug(f"Extracted {e['path']} ({e['size']} bytes)")

    LOGGER.info("Extraction complete.")

# ---------------- CLI ----------------

def main():
    ap = argparse.ArgumentParser(description="Self-extracting VFA archive")
    ap.add_argument("-o", "--output", default="./_extracted", help="Output directory (default: ./_extracted)")
    ap.add_argument("--password", action="store_true", help="Prompt for password if archive is encrypted (if omitted, we'll still prompt when needed).")
    ap.add_argument("--log-level", choices=["quiet","error","warning","info","debug","trace"], default="warning")
    ap.add_argument("-v","--verbose", action="store_true", help="Shortcut for --log-level info")
    ap.add_argument("--from-file", help="Debug: read container bytes from this path instead of sys.executable")
    args = ap.parse_args()

    if args.verbose and args.log_level == "warning":
        args.log_level = "info"

    # If encrypted and --password not given, we still prompt when needed; the flag is optional now.
    try:
        extract_self(args.output, need_password=args.password, quiet=(args.log_level=="quiet"),
                     from_file=args.from_file, log_level=args.log_level)
    except Exception as e:
        # Last-resort message with some context
        LOGGER.error(f"Unhandled exception: {e!r}")
        raise

if __name__ == "__main__":
    main()
