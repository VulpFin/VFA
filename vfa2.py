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
vfa2 - the VFA2 container (see VFA2.md): a streaming writer and a random-access reader.

    [header][chunk frame]*[index frame][footer]

Every chunk frame is independently decodable and names the filter and coder that produced it; the index at the
end maps files to extents (chunk, offset, length). Readers refuse - by name - any version, feature bit, frame
flag, coder, filter, entry type or critical index record they do not know.

Milestone M1: the only coder is 0 "stored" and the only filter is 0 "none". Real codecs (tANS, CM) and filters
plug into CODERS / FILTERS without changing the container. Standard library only, plus 'cryptography' for
encrypted archives (exactly what VFA1 needs).
"""
import hashlib, io, json, os, struct, zlib
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

import vfa_extract as vx
from vfa_extract import VFAError, ET_FILE, ET_DIR, ET_SYMLINK, ET_HARDLINK, ET_NAMES

# ---------------------------------------------------------------- constants (VFA2.md is normative)

MAGIC = b"VFA2"
END_MAGIC = b"/VFA2"
SPEC_VERSION = 1            # the VFA2.md revision this code writes
READER_VERSION = 1          # archives whose min_reader_version is above this are refused

HDR = struct.Struct("<4sHHHIIBBBBII16s")      # magic, header_size, spec_version, min_reader, required, optional,
                                              # kdf_id, aead_id, kdf_p, reserved, kdf_t, kdf_m, salt
HEADER_SIZE = HDR.size + 4                    # + u32 header CRC32 = 50
MAX_HEADER_SIZE = 4096

RF_ENCRYPTED = 1 << 0                         # required feature bits: unknown bit -> refuse
KNOWN_REQUIRED = RF_ENCRYPTED
KNOWN_OPTIONAL = 0                            # optional feature bits: unknown bit -> ignore

FRAME = struct.Struct("<4sBBBBHQII")         # magic, coder, filter, flags, reserved, params_len, raw_size, payload_size, raw_crc
FRAME_SIZE = FRAME.size + 4                   # + u32 frame-header CRC32 = 30
CHUNK_MAGIC = b"VCK2"
INDEX_MAGIC = b"VIX2"
FF_ENCRYPTED = 1 << 0                         # a 12-byte nonce follows the frame header
KNOWN_FRAME_FLAGS = FF_ENCRYPTED
NONCE_LEN = 12
MAX_CHUNK = 1 << 30                           # raw_size limit for any chunk (reader refuses larger)
MAX_INDEX = 1 << 31

FOOT = struct.Struct("<QQQB32s")              # index_offset, index_frame_len, archive_len, digest_kind, digest
FOOTER_SIZE = FOOT.size + 4 + len(END_MAGIC)  # + u32 footer CRC32 + "/VFA2" = 66
DIGEST_SHA256 = 1

INDEX_TAG = b"VID2"
IX_CHUNK = struct.Struct("<QQIBB")            # frame_offset, raw_size, raw_crc, coder, filter
IX_EXTENT = struct.Struct("<IQQ")             # chunk, offset, length
XR_CRITICAL = 1                               # index extension record flag
XR_ROUTING = 1                                # (optional) why each chunk got its filter/coder - written from M3 on

KDF_NONE, KDF_ARGON2ID, KDF_SCRYPT = 0, 1, 2
AEAD_NONE, AEAD_AESGCM = 0, 1

def crc32(b) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF

# ---------------------------------------------------------------- filters and coders

class Codec:
    """A filter or coder. encode(raw, level) -> (params, data); decode(params, data, raw_size) -> raw.
    decode must return exactly raw_size bytes or raise VFAError, and must never read outside its inputs."""
    def __init__(self, cid, name, encode=None, decode=None):
        self.id, self.name, self.encode, self.decode = cid, name, encode, decode

def _stored_encode(raw, level=0):
    return b"", bytes(raw)

def _stored_decode(params, data, raw_size):
    if params: raise VFAError("stored coder takes no parameters")
    if len(data) != raw_size: raise VFAError(f"stored chunk holds {len(data)} bytes, header says {raw_size}")
    return data

def _none_fwd(raw, level=0):
    return b"", raw

def _none_inv(params, data, raw_size):
    if params: raise VFAError("filter 'none' takes no parameters")
    return data

CODERS: Dict[int, Codec] = {0: Codec(0, "stored", _stored_encode, _stored_decode)}
FILTERS: Dict[int, Codec] = {0: Codec(0, "none", _none_fwd, _none_inv)}
# ids reserved for later milestones - named so a reader can say exactly what it is missing
RESERVED_CODERS = {1: "vulp-tans (M3)", 2: "vulp-cm (M5)"}
RESERVED_FILTERS = {1: "delta (M3)", 2: "bitshuffle (M3)", 3: "bcj-x86 (M3)", 4: "bcj-arm64 (M3)", 5: "text (M3)"}
CODER_NAMES = {**{k: v.name for k, v in CODERS.items()}, **RESERVED_CODERS}

def _codec(table, reserved, kind, cid, where):
    c = table.get(cid)
    if c is None or c.decode is None:
        what = reserved.get(cid, "unknown")
        raise VFAError(f"{where} uses {kind} id {cid} ({what}), which this reader (VFA2 spec {SPEC_VERSION}) "
                       "does not implement. Use a newer VFA.")
    return c

# ---------------------------------------------------------------- keys

def _derive_keys(password: bytes, kdf_id, t, m, p, salt) -> Tuple[bytes, bytes]:
    master = vx._kdf(password, kdf_id, t, m, p, salt)
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except Exception:
        raise VFAError("This archive is encrypted; this build lacks the 'cryptography' package.")
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"VFA2 keys v1").derive(master)
    return okm[:32], okm[32:]          # data key, index key

def _aesgcm(key):
    if not vx.HAVE_AESGCM: raise VFAError("AES-GCM unavailable in this build (needs 'cryptography').")
    return vx.AESGCM(key)

# ---------------------------------------------------------------- writer

class Writer2:
    """Streaming VFA2 writer: never seeks, so it can write to a pipe. Typical use:

        with open(out, "wb") as f:
            w = Writer2(f, chunk_size=1 << 26, solid=True)
            w.add_dir("app", 0o755, mtime); w.add_file("app/a.txt", 0o644, mtime, open("a.txt", "rb"))
            w.close()
    """
    def __init__(self, f, *, chunk_size: int = 1 << 26, solid: bool = False, coder: int = 0, filt: int = 0,
                 level: int = 0, dedup: bool = True, password: Optional[bytes] = None,
                 kdf: Tuple[int, int, int] = (3, 256 * 1024, 4), use_scrypt: bool = False,
                 header_extra: bytes = b"", min_reader: int = 1, required_extra: int = 0):
        """header_extra / min_reader / required_extra exist so tests can write what a future VFA would."""
        if not (1 << 12) <= chunk_size <= MAX_CHUNK: raise ValueError("chunk_size must be 4 KiB .. 1 GiB")
        if coder not in CODERS or CODERS[coder].encode is None: raise ValueError(f"coder {coder} cannot encode")
        if filt not in FILTERS or FILTERS[filt].encode is None: raise ValueError(f"filter {filt} cannot encode")
        self.f, self.cs, self.solid, self.coder, self.filt, self.level, self.dedup = f, chunk_size, solid, coder, filt, level, dedup
        self.pos = 0; self.hasher = hashlib.sha256()
        self.chunks: List[tuple] = []               # (frame_offset, raw_size, raw_crc, coder, filter)
        self.by_hash: Dict[bytes, int] = {}
        self.entries: List[dict] = []
        self.buf = bytearray(); self.pending: List[list] = []      # extents [chunk, off, len] waiting for this chunk
        self.data_key = self.index_key = None
        req = 0; kdf_id = aead = kp = kt = km = 0; salt = b"\0" * 16
        if password is not None:
            req |= RF_ENCRYPTED; aead = AEAD_AESGCM; salt = os.urandom(16)
            if use_scrypt or not vx.HAVE_ARGON2: kdf_id, kt, km, kp = KDF_SCRYPT, 1 << 15, 8, 1
            else: kdf_id, (kt, km, kp) = KDF_ARGON2ID, kdf
            self.data_key, self.index_key = _derive_keys(password, kdf_id, kt, km, kp, salt)
            self.dedup = False      # identical plaintext chunks would otherwise be visible as shared ciphertext
        self.header_size = HEADER_SIZE + len(header_extra)
        body = HDR.pack(MAGIC, self.header_size, SPEC_VERSION, min_reader, req | required_extra, 0, kdf_id, aead, kp, 0, kt, km, salt)
        body += header_extra
        self._out(body + struct.pack("<I", crc32(body)))
        self.closed = False

    def _out(self, b):
        self.f.write(b); self.hasher.update(b); self.pos += len(b)

    def _frame(self, magic, coder, filt, params, payload, raw_size, raw_crc, key) -> int:
        """Write one frame; returns its offset."""
        off = self.pos
        flags = FF_ENCRYPTED if key is not None else 0
        nonce = os.urandom(NONCE_LEN) if key is not None else b""
        size = len(payload) + (16 if key is not None else 0)
        if size > 0xFFFFFFFF: raise VFAError("frame payload exceeds 4 GiB")
        hdr = FRAME.pack(magic, coder, filt, flags, 0, len(params), raw_size, size, raw_crc)
        hdr += struct.pack("<I", crc32(hdr))
        if key is not None:
            payload = _aesgcm(key).encrypt(nonce, bytes(payload), hdr + nonce + params)   # header is authenticated
        self._out(hdr + nonce + params); self._out(payload)
        return off

    def _flush(self):
        if not self.buf and not self.pending: return
        raw = bytes(self.buf); self.buf = bytearray()
        h = hashlib.sha256(raw).digest() if self.dedup else None
        if h is not None and h in self.by_hash:
            idx = self.by_hash[h]
        else:
            fparams, fdata = FILTERS[self.filt].encode(raw, self.level)
            cparams, payload = CODERS[self.coder].encode(fdata, self.level)
            params = struct.pack("<H", len(fparams)) + fparams + cparams if (fparams or cparams) else b""
            c = crc32(raw)
            off = self._frame(CHUNK_MAGIC, self.coder, self.filt, params, payload, len(raw), c, self.data_key)
            idx = len(self.chunks); self.chunks.append((off, len(raw), c, self.coder, self.filt))
            if h is not None: self.by_hash[h] = idx
        for ext in self.pending: ext[0] = idx
        self.pending = []

    def _entry(self, etype, path, mode, mtime, size=0, meta=None, mtime_ns=None):
        """mtime in seconds (int/float), or exact integer nanoseconds via mtime_ns."""
        if mtime_ns is not None: sec, ns = divmod(int(mtime_ns), 1_000_000_000)
        else: mt = float(mtime); sec = int(mt // 1); ns = int(round((mt - sec) * 1e9)) % 1_000_000_000
        e = {"type": etype, "path": path.replace("\\", "/"), "mode": mode & 0xFFFFFFFF, "mtime": sec, "mtime_ns": ns,
             "size": size, "meta": meta or b"", "extents": []}
        self.entries.append(e); return e

    def add_dir(self, path, mode=0o755, mtime=0, meta=None, mtime_ns=None):
        self._entry(ET_DIR, path, mode, mtime, 0, meta, mtime_ns)

    def add_link(self, path, hard: bool, mode=0o777, mtime=0, meta=None, mtime_ns=None):
        self._entry(ET_HARDLINK if hard else ET_SYMLINK, path, mode, mtime, 0, meta, mtime_ns)

    def add_file(self, path, mode, mtime, src, meta=None, piece: int = 1 << 20, mtime_ns=None) -> int:
        """src: a binary file object or bytes. Returns the number of bytes stored."""
        e = self._entry(ET_FILE, path, mode, mtime, 0, meta, mtime_ns)
        if not self.solid and self.buf: self._flush()          # non-solid: every file starts a new chunk
        if isinstance(src, (bytes, bytearray, memoryview)): src = io.BytesIO(bytes(src))
        while True:
            b = src.read(piece)
            if not b: break
            mv = memoryview(b)
            while len(mv):
                take = min(self.cs - len(self.buf), len(mv))
                cur = e["extents"][-1] if e["extents"] else None
                if cur is not None and cur[0] is None and cur[1] + cur[2] == len(self.buf):
                    cur[2] += take                               # same unflushed chunk: grow the extent
                else:
                    ext = [None, len(self.buf), take]           # chunk id is filled in by _flush()
                    e["extents"].append(ext); self.pending.append(ext)
                self.buf += mv[:take]; mv = mv[take:]; e["size"] += take
                if len(self.buf) == self.cs: self._flush()
        if not self.solid: self._flush()
        return e["size"]

    def _index_bytes(self, records=()) -> bytes:
        out = bytearray(INDEX_TAG); out += struct.pack("<I", len(self.chunks))
        for c in self.chunks: out += IX_CHUNK.pack(*c)
        out += struct.pack("<I", len(self.entries))
        for e in self.entries:
            p = e["path"].encode("utf-8")
            out += struct.pack("<BBH", e["type"], 0, len(p)) + p
            out += struct.pack("<IqIQI", e["mode"], e["mtime"], e["mtime_ns"], e["size"], len(e["meta"])) + e["meta"]
            out += struct.pack("<I", len(e["extents"]))
            for ch, off, ln in e["extents"]: out += IX_EXTENT.pack(ch, off, ln)
        out += struct.pack("<I", len(records))
        for rtype, rflags, data in records: out += struct.pack("<HHI", rtype, rflags, len(data)) + data
        return bytes(out)

    def close(self, records=()):
        """Flush the last chunk, write index + footer. records: extra (type, flags, data) index records."""
        if self.closed: return
        self._flush()
        raw = self._index_bytes(records)
        off = self._frame(INDEX_MAGIC, 0, 0, b"", raw, len(raw), crc32(raw), self.index_key)
        idx_len = self.pos - off
        archive_len = self.pos + FOOTER_SIZE
        digest = self.hasher.digest()
        body = FOOT.pack(off, idx_len, archive_len, DIGEST_SHA256, digest)
        self.f.write(body + struct.pack("<I", crc32(body)) + END_MAGIC)
        self.pos += FOOTER_SIZE; self.closed = True

# ---------------------------------------------------------------- reader

class Archive2(vx.Extractable):
    """Read-only VFA2 archive (plain .vfa, SFX, SFI or Authenticode-signed). Same interface as vfa_extract.Container:
    verify_digest() -> unlock(pw) -> entries / extract() / iter_entry() / test()."""
    format = "VFA2"

    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb")
        try:
            self.size = os.fstat(self._f.fileno()).st_size
            self.buf = vx._FileView(self._f, 0, self.size)
            self.entries = None; self.chunks: List[tuple] = []; self._cache = (None, None)
            self.data_key = self.index_key = None
            self._locate()
        except Exception:
            self._f.close(); raise

    def close(self):
        try: self._f.close()
        except Exception: pass
    def __enter__(self): return self
    def __exit__(self, *a): self.close()

    # -- locate --
    def _locate(self):
        E = vx.effective_end(self.buf, self.size)
        if E < HEADER_SIZE + FOOTER_SIZE: raise VFAError(f"File too small to hold a VFA2 archive (size={self.size}).")
        if self.buf[E - 5:E] != END_MAGIC:
            raise VFAError("VFA2 end magic not found; not a VFA2 archive.")
        fstart = E - FOOTER_SIZE
        body = self.buf[fstart:fstart + FOOT.size]
        if struct.unpack("<I", self.buf[fstart + FOOT.size:fstart + FOOT.size + 4])[0] != crc32(body):
            raise VFAError("Footer failed its CRC32 check (corrupted or truncated archive).")
        self.index_off, self.index_len, archive_len, self.digest_kind, self.digest = FOOT.unpack(body)
        self.arc_start = E - archive_len
        self.footer_pos = fstart
        if archive_len > E or self.arc_start < 0: raise VFAError("Footer archive length is out of range (corrupted archive).")
        self.arc = vx._FileView(self._f, self.arc_start, fstart - self.arc_start)      # header .. end of index frame
        if self.buf[self.arc_start:self.arc_start + 4] != MAGIC:
            raise VFAError("VFA2 header magic not found where the footer says the archive starts (corrupted archive).")
        if self.index_off + self.index_len != len(self.arc) or self.index_off < HEADER_SIZE:
            raise VFAError("Index position in the footer is inconsistent (corrupted archive).")
        self.manifest, self.stub_end = vx.find_manifest(self.buf, self.arc_start)
        self._parse_header()

    def _parse_header(self):
        if len(self.arc) < HDR.size + 2: raise VFAError("Header truncated.")
        hsize, = struct.unpack("<H", self.arc[4:6])
        if not HEADER_SIZE <= hsize <= MAX_HEADER_SIZE or hsize > len(self.arc):
            raise VFAError(f"Header size {hsize} is invalid (corrupted archive).")
        raw = self.arc[0:hsize]
        if struct.unpack("<I", raw[hsize - 4:])[0] != crc32(raw[:hsize - 4]):
            raise VFAError("Header failed its CRC32 check (corrupted archive).")
        (_, _, self.spec_version, min_reader, req, opt, kdf_id, aead, kp, _r, kt, km, salt) = HDR.unpack(raw[:HDR.size])
        if min_reader > READER_VERSION:
            raise VFAError(f"Archive needs a VFA2 reader of version {min_reader}; this one is version {READER_VERSION}. Use a newer VFA.")
        if req & ~KNOWN_REQUIRED:
            raise VFAError(f"Archive requires features 0x{req & ~KNOWN_REQUIRED:x} this reader does not understand. Use a newer VFA.")
        self.header_size = hsize
        self.encrypted = bool(req & RF_ENCRYPTED)
        if self.encrypted and (aead != AEAD_AESGCM or kdf_id not in (KDF_ARGON2ID, KDF_SCRYPT)):
            raise VFAError(f"Unknown encryption (aead {aead}, kdf {kdf_id}); use a newer VFA.")
        self.kdf = (kdf_id, kt, km, kp, salt)
        self.solid = False                     # per-chunk packing is not a global property in VFA2
        self.has_tocx = True                   # every chunk carries a CRC32 (vfa.py prints this)
        self.hash_kind = vx.H_SHA256 if self.digest_kind == DIGEST_SHA256 else self.digest_kind
        self.header = {"format": "VFA2", "version": self.spec_version, "flags": req, "default_method": None, "default_level": None}

    def summary(self) -> str:
        coders = sorted({CODER_NAMES.get(c[3], f"#{c[3]}") for c in self.chunks}) if self.chunks else []
        return f"VFA2 spec {self.spec_version}, {len(self.chunks)} chunk(s), coders: {', '.join(coders) or '-'}"

    # -- integrity --
    def verify_digest(self, progress: Optional[Callable[[int, int], None]] = None) -> Optional[bool]:
        if self.digest_kind != DIGEST_SHA256:
            raise VFAError(f"Unknown digest kind {self.digest_kind}; use a newer VFA.")
        h = hashlib.sha256(); pos, end = self.arc_start, self.footer_pos; total = end - pos
        while pos < end:
            n = min(1 << 22, end - pos); h.update(self.buf[pos:pos + n]); pos += n
            if progress: progress(pos - self.arc_start, total)
        return h.digest() == self.digest

    # -- frames --
    def _read_frame_header(self, off: int, magic: bytes, what: str):
        if off < self.header_size or off + FRAME_SIZE > len(self.arc):
            raise VFAError(f"{what} lies outside the archive (corrupted archive).")
        hdr = self.arc[off:off + FRAME_SIZE]
        if struct.unpack("<I", hdr[FRAME.size:])[0] != crc32(hdr[:FRAME.size]):
            raise VFAError(f"{what} header failed its CRC32 check (corrupted archive).")
        m, coder, filt, flags, res, plen, raw_size, psize, raw_crc = FRAME.unpack(hdr[:FRAME.size])
        if m != magic: raise VFAError(f"{what} has the wrong frame magic {m!r} (corrupted archive).")
        if flags & ~KNOWN_FRAME_FLAGS or res:
            raise VFAError(f"{what} uses frame flags 0x{flags:x} this reader does not understand. Use a newer VFA.")
        if bool(flags & FF_ENCRYPTED) != self.encrypted:
            raise VFAError(f"{what} encryption flag disagrees with the archive header (corrupted archive).")
        body = off + FRAME_SIZE + (NONCE_LEN if self.encrypted else 0)
        end = body + plen + psize
        if end > len(self.arc): raise VFAError(f"{what} runs past the end of the archive (corrupted or truncated).")
        return {"off": off, "coder": coder, "filter": filt, "params_len": plen, "raw_size": raw_size, "payload_size": psize,
                "raw_crc": raw_crc, "hdr": hdr, "nonce": self.arc[off + FRAME_SIZE:body], "body": body, "end": end}

    def _frame_payload(self, fh, key) -> Tuple[bytes, bytes]:
        params = self.arc[fh["body"]:fh["body"] + fh["params_len"]]
        payload = self.arc[fh["body"] + fh["params_len"]:fh["end"]]
        if self.encrypted:
            try: payload = _aesgcm(key).decrypt(fh["nonce"], payload, fh["hdr"] + fh["nonce"] + params)
            except VFAError: raise
            except Exception: raise VFAError("Decryption failed (wrong password or corrupted data).", code=5)
        return params, payload

    # -- unlock / index --
    def unlock(self, password: Optional[str] = None):
        if self.encrypted:
            if password is None: raise VFAError("This archive is encrypted; a password is required.", code=5)
            kdf_id, kt, km, kp, salt = self.kdf
            self.data_key, self.index_key = _derive_keys(password.encode("utf-8"), kdf_id, kt, km, kp, salt)
        fh = self._read_frame_header(self.index_off, INDEX_MAGIC, "Index")
        if fh["end"] != len(self.arc) or fh["coder"] or fh["filter"] or fh["params_len"]:
            raise VFAError("Index frame is malformed (corrupted archive, or written by a newer VFA).")
        if fh["raw_size"] > MAX_INDEX: raise VFAError("Index is implausibly large (corrupted archive).")
        _, raw = self._frame_payload(fh, self.index_key)
        if len(raw) != fh["raw_size"] or crc32(raw) != fh["raw_crc"]:
            raise VFAError("Index failed its CRC32 check (corrupted archive).")
        self._parse_index(raw)
        return self.entries

    def _parse_index(self, raw: bytes):
        r = vx._Reader(raw, "Index")
        if bytes(r.need(4, "tag")) != INDEX_TAG: raise VFAError("Index tag missing (corrupted archive).")
        n = r.u("<I", "chunk count")
        if n * IX_CHUNK.size > r.left: raise VFAError("Index truncated reading chunks.")
        self.chunks = []
        prev_end = self.header_size
        for i in range(n):
            off, raw_size, rcrc, coder, filt = IX_CHUNK.unpack(r.need(IX_CHUNK.size, "chunk"))
            fh = self._read_frame_header(off, CHUNK_MAGIC, f"Chunk {i}")
            if off != prev_end: raise VFAError(f"Chunk {i} is not where the previous one ends (corrupted archive).")
            if (fh["raw_size"], fh["raw_crc"], fh["coder"], fh["filter"]) != (raw_size, rcrc, coder, filt):
                raise VFAError(f"Chunk {i} header disagrees with the index (corrupted archive).")
            if raw_size > MAX_CHUNK: raise VFAError(f"Chunk {i} claims {raw_size} bytes, above the format limit.")
            self.chunks.append((off, raw_size, rcrc, coder, filt)); prev_end = fh["end"]
        if prev_end != self.index_off: raise VFAError("Chunk region does not end where the index begins (corrupted archive).")
        cnt = r.u("<I", "entry count")
        entries = []
        for _ in range(cnt):
            etype = r.u("<B", "entry type"); r.u("<B", "entry reserved"); plen = r.u("<H", "path length")
            try: path = bytes(r.need(plen, "path")).decode("utf-8")
            except UnicodeDecodeError: raise VFAError("Index contains a path that is not valid UTF-8.")
            if etype > ET_HARDLINK: raise VFAError(f"Unknown entry type {etype} for {path!r}; this archive needs a newer VFA.")
            mode = r.u("<I", "mode"); mtime = r.u("<q", "mtime"); mns = r.u("<I", "mtime ns"); size = r.u("<Q", "size")
            if mns >= 1_000_000_000: raise VFAError(f"{path!r}: invalid timestamp.")
            mlen = r.u("<I", "meta length"); meta = bytes(r.need(mlen, "meta")) if mlen else b""
            ne = r.u("<I", "extent count")
            if ne * IX_EXTENT.size > r.left: raise VFAError("Index truncated reading extents.")
            exts = [IX_EXTENT.unpack(r.need(IX_EXTENT.size, "extent")) for _ in range(ne)]
            if etype != ET_FILE and (exts or size): raise VFAError(f"{path!r} ({ET_NAMES[etype]}) claims file data.")
            total = 0
            for ch, off, ln in exts:
                if ch >= len(self.chunks) or off + ln > self.chunks[ch][1] or ln == 0:
                    raise VFAError(f"{path!r} has an extent outside its chunk (corrupted archive).")
                total += ln
            if total != size: raise VFAError(f"{path!r}: extents add up to {total} bytes, entry says {size}.")
            entries.append({"path": path, "mode": mode, "mtime": mtime, "mtime_ns": mns, "size": size, "entry_type": etype,
                            "meta": meta, "extents": exts, "blocks": [], "start_off": 0})
        nrec = r.u("<I", "record count")
        self.records = {}
        for _ in range(nrec):
            rtype, rflags, rlen = struct.unpack("<HHI", r.need(8, "record header"))
            data = bytes(r.need(rlen, "record"))
            if rtype == XR_ROUTING: self.records[rtype] = data
            elif rflags & XR_CRITICAL:
                raise VFAError(f"Archive uses index record type {rtype} this reader does not understand. Use a newer VFA.")
        if r.left: raise VFAError(f"Index has {r.left} unexpected trailing bytes (corrupted archive).")
        self.entries = entries

    # -- chunk access --
    def chunk_data(self, i: int) -> bytes:
        """Decode chunk i (frame -> decrypt -> coder -> inverse filter), checking size and CRC32. Caches the last one."""
        if self._cache[0] == i: return self._cache[1]
        off, raw_size, rcrc, coder, filt = self.chunks[i]
        fh = self._read_frame_header(off, CHUNK_MAGIC, f"Chunk {i}")
        cdc = _codec(CODERS, RESERVED_CODERS, "coder", coder, f"Chunk {i}")
        flt = _codec(FILTERS, RESERVED_FILTERS, "filter", filt, f"Chunk {i}")
        params, payload = self._frame_payload(fh, self.data_key)
        fparams, cparams = b"", b""
        if params:
            if len(params) < 2: raise VFAError(f"Chunk {i} parameters are malformed.")
            fl, = struct.unpack("<H", params[:2])
            if 2 + fl > len(params): raise VFAError(f"Chunk {i} parameters are malformed.")
            fparams, cparams = params[2:2 + fl], params[2 + fl:]
        try:
            data = cdc.decode(cparams, payload, raw_size)       # coder output is the filtered stream (same size for M1 filters)
            raw = flt.decode(fparams, data, raw_size)
        except VFAError as e:
            raise VFAError(f"Chunk {i}: {e}")
        if len(raw) != raw_size: raise VFAError(f"Chunk {i} decoded to {len(raw)} bytes, expected {raw_size} (corrupted archive).")
        if crc32(raw) != rcrc: raise VFAError(f"Chunk {i} failed its CRC32 check (corrupted archive).")
        self._cache = (i, raw)
        return raw

    def iter_entry(self, e: dict) -> Iterator[bytes]:
        for ch, off, ln in e.get("extents", ()):
            yield memoryview(self.chunk_data(ch))[off:off + ln]

    def test(self, progress=None) -> dict:
        total = 0
        for i in range(len(self.chunks)):
            total += len(self.chunk_data(i))
            if progress: progress(i + 1, len(self.chunks))
        return {"blocks": len(self.chunks), "bytes": total}

    def _write_files(self, sel_files, start, commit, finish, check_cancel, active):
        # in extent order, so each chunk is decoded once when files were written in order (the cache holds one chunk)
        order = sorted(sel_files, key=lambda e: (e["extents"][0][0], e["extents"][0][1]) if e["extents"] else (-1, 0))
        for e in order:
            check_cancel()
            out, fw = start(e); active[:] = [(e, out, fw)]
            for piece in self.iter_entry(e):
                check_cancel(); fw.write(piece)
            active.clear(); commit(out, fw); finish(e, out)
