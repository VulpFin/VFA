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

Coders: 0 stored, 1 vulp-tans (M3), 2 vulp-cm (M5), 3 vulp-lz (M4). Filters: 0 none, 1 delta, 2 shuffle, 3 bcj-x86, 4 bcj-arm64,
6 segmented (M3). The writer also deduplicates content-defined segments across chunks (M4). The codecs are
the C extension _vulp (vulp/vulp.c, built by build_vulp.py); without it, decoding falls back to the pure-Python
reference vulp_ref.py (slow, same results). The writer picks a filter per chunk with an integer cost estimate over a
sample and records why in the index (ROUTING record). Standard library only otherwise, plus 'cryptography' for
encrypted archives (exactly what VFA1 needs).
"""
import collections, hashlib, io, json, os, struct, zlib
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

import vfa_extract as vx
from vfa_extract import VFAError, ET_FILE, ET_DIR, ET_SYMLINK, ET_HARDLINK, ET_NAMES

# ---------------------------------------------------------------- constants (VFA2.md is normative)

MAGIC = b"VFA2"
END_MAGIC = b"/VFA2"
SPEC_VERSION = 4            # the VFA2.md revision this code writes (2 = M3: tANS + filters, 3 = M4: vulp-lz + dedup,
                            # 4 = M5: vulp-cm)
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
CACHE_CHUNKS = 2                              # reader: decoded chunks kept (each <= MAX_CHUNK; 64 MiB by default)

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

NATIVE_API = 4                               # vulp.h VULP_VERSION this code needs (2: vulp-lz, cdc; 3: optimal parser;
                                             # 4: vulp-cm)
NATIVE_PROBLEM = ""                          # why the C extension is not used, if it is not
try:
    import _vulp as _native                  # C codec core (build_vulp.py)
    if getattr(_native, "VERSION", 0) < NATIVE_API or not all(hasattr(_native, f) for f in ("lz_encode", "lz_decode", "cdc", "cm_encode", "cm_decode")):
        # a module built from older sources (e.g. left over from M3): never call into it half-way
        NATIVE_PROBLEM = (f"the _vulp extension at {getattr(_native, '__file__', '?')} is out of date (API "
                          f"{getattr(_native, 'VERSION', 0)}, need {NATIVE_API}); rebuild it with: python build_vulp.py")
        raise ImportError(NATIVE_PROBLEM)
    NATIVE = True
except ImportError:                          # pure-Python reference: identical output, ~100x slower
    import vulp_ref as _native
    NATIVE = False
    NATIVE_PROBLEM = NATIVE_PROBLEM or "the _vulp C extension is not built; build it with: python build_vulp.py"

def _vulp_call(fn, *a):
    try: return fn(*a)
    except ValueError as e: raise VFAError(str(e))

def _stored_encode(raw, level=0):
    return b"", bytes(raw)

def _stored_decode(params, data, raw_size):
    if params: raise VFAError("stored coder takes no parameters")
    if len(data) != raw_size: raise VFAError(f"stored chunk holds {len(data)} bytes, header says {raw_size}")
    return data

def _tans_encode(raw, level=0):
    return b"", _native.tans_encode(raw)

def _tans_decode(params, data, raw_size):
    if params: raise VFAError("vulp-tans takes no parameters")
    return _vulp_call(_native.tans_decode, data, raw_size)

def _lz_encode(raw, level=6):
    """None when vulp-lz would not make the data smaller (the writer then stores the chunk)."""
    if not NATIVE: raise VFAError(f"vulp-lz encoding needs the C codec: {NATIVE_PROBLEM}")
    out = _native.lz_encode(raw, max(0, min(9, int(level))))
    return b"", out

def _lz_decode(params, data, raw_size):
    if params: raise VFAError("vulp-lz takes no parameters")
    return _vulp_call(_native.lz_decode, data, raw_size)

CM_MODEL = 1                                 # vulp-cm params: u8 model (1), u8 table bits (16..24)
CM_MINBITS, CM_MAXBITS = 16, 24
CM_MIN_GAIN_PCT = 1                          # --method cm keeps vulp-cm only if it writes >= 1% less than vulp-lz:
                                             # below that, ~100x slower extraction is not worth it

def cm_bits(level) -> int:
    """--level -> vulp-cm table bits. Encoder and decoder each need about 13 * 2^bits bytes: 20 -> 14 MiB,
    22 -> 55 MiB (the default, levels 4-6), 24 -> 220 MiB."""
    level = int(level)
    return 20 if level <= 3 else 22 if level <= 6 else 24

def _cm_encode(raw, level=5):
    """None when vulp-cm would not make the data smaller."""
    if not NATIVE: raise VFAError(f"vulp-cm encoding needs the C codec: {NATIVE_PROBLEM}")
    bits = cm_bits(level)
    return bytes((CM_MODEL, bits)), _native.cm_encode(raw, bits)

def _cm_decode(params, data, raw_size):
    if len(params) != 2: raise VFAError(f"vulp-cm parameters must be 2 bytes, not {len(params)}")
    if params[0] != CM_MODEL:
        raise VFAError(f"vulp-cm model {params[0]} is not implemented by this reader (VFA2 spec {SPEC_VERSION}). "
                       "Use a newer VFA.")
    if not CM_MINBITS <= params[1] <= CM_MAXBITS: raise VFAError(f"vulp-cm table bits {params[1]} out of range")
    return _vulp_call(_native.cm_decode, data, raw_size, params[1])

def _filter_codec(fid, name):
    """Filters in this revision are size-preserving bijections; params are the filter's own bytes (VFA2.md)."""
    return Codec(fid, name, lambda raw, params=b"": (params, _vulp_call(_native.filter_fwd, fid, params, raw)),
                 lambda params, data, raw_size: _vulp_call(_native.filter_inv, fid, params, data))

CODERS: Dict[int, Codec] = {0: Codec(0, "stored", _stored_encode, _stored_decode),
                            1: Codec(1, "vulp-tans", _tans_encode, _tans_decode),
                            2: Codec(2, "vulp-cm", _cm_encode, _cm_decode),
                            3: Codec(3, "vulp-lz", _lz_encode, _lz_decode)}
CODER_CM = 2
CODER_LZ = 3
FILTERS: Dict[int, Codec] = {0: _filter_codec(0, "none"), 1: _filter_codec(1, "delta"), 2: _filter_codec(2, "shuffle"),
                             3: _filter_codec(3, "bcj-x86"), 4: _filter_codec(4, "bcj-arm64")}
SEGMENTED = 6
SEG = struct.Struct("<IBB")                  # segment: length, filter id, params length (then the params)

def seg_pack(segs) -> bytes:
    """segs: [(length, filter id, params)] -> params of filter 6 'segmented'."""
    out = bytearray(struct.pack("<I", len(segs)))
    for ln, fid, fp in segs: out += SEG.pack(ln, fid, len(fp)) + fp
    return bytes(out)

def seg_unpack(params: bytes, raw_size: int):
    """Strict parse: every segment non-empty, a plain filter (0..4, never 6), lengths sum to the chunk size."""
    if len(params) < 4: raise VFAError("segmented filter parameters truncated")
    n, = struct.unpack_from("<I", params, 0); pos = 4; segs = []; total = 0
    if n == 0 or n > (len(params) - 4) // SEG.size: raise VFAError("segmented filter: bad segment count")
    for _ in range(n):
        if pos + SEG.size > len(params): raise VFAError("segmented filter parameters truncated")
        ln, fid, pl = SEG.unpack_from(params, pos); pos += SEG.size
        if pos + pl > len(params): raise VFAError("segmented filter parameters truncated")
        fp = bytes(params[pos:pos + pl]); pos += pl
        if ln == 0 or fid not in FILTERS or fid == SEGMENTED:
            raise VFAError(f"segmented filter: segment uses filter id {fid} ({FILTER_NAMES.get(fid, 'unknown')}), "
                           "which is not allowed or not implemented here")
        segs.append((ln, fid, fp)); total += ln
    if pos != len(params): raise VFAError("segmented filter parameters have trailing bytes")
    if total != raw_size: raise VFAError(f"segmented filter covers {total} bytes, chunk has {raw_size}")
    return segs

def _seg_apply(params, data, inverse):
    segs = seg_unpack(params, len(data)); out = bytearray(); pos = 0
    for ln, fid, fp in segs:
        piece = data[pos:pos + ln]; pos += ln
        out += _vulp_call(_native.filter_inv if inverse else _native.filter_fwd, fid, fp, piece)
    return bytes(out)

FILTERS[SEGMENTED] = Codec(SEGMENTED, "segmented", lambda raw, params=b"": (params, _seg_apply(params, raw, False)),
                           lambda params, data, raw_size: _seg_apply(params, data, True))
# ids reserved for later milestones - named so a reader can say exactly what it is missing
RESERVED_CODERS: Dict[int, str] = {}
RESERVED_FILTERS = {5: "text (reserved)"}
CODER_NAMES = {**{k: v.name for k, v in CODERS.items()}, **RESERVED_CODERS}
FILTER_NAMES = {**{k: v.name for k, v in FILTERS.items()}, **RESERVED_FILTERS}

def filter_label(fid: int, params: bytes) -> str:
    name = FILTER_NAMES.get(fid, f"#{fid}")
    if fid == 1 and len(params) == 1: return f"delta:{params[0]}"
    if fid == 2 and len(params) == 2: return f"{'bitshuffle' if params[1] else 'shuffle'}:{params[0]}"
    if fid == SEGMENTED:
        return f"segmented({struct.unpack_from('<I', params)[0]})" if len(params) >= 4 else "segmented"
    return name

def parse_filter(spec: str):
    """CLI filter spec -> None (auto) or (id, params). auto | none | delta:N | shuffle:K | bitshuffle:K | bcj-x86 | bcj-arm64"""
    s = spec.strip().lower()
    if s == "auto": return None
    name, _, arg = s.partition(":")
    try:
        if name == "none" and not arg: return (0, b"")
        if name == "delta" and 1 <= int(arg) <= 32: return (1, bytes([int(arg)]))
        if name in ("shuffle", "bitshuffle") and int(arg) in (2, 4, 8, 16): return (2, bytes([int(arg), name == "bitshuffle"]))
        if name == "bcj-x86" and not arg: return (3, b"")
        if name == "bcj-arm64" and not arg: return (4, b"")
    except ValueError: pass
    raise ValueError(f"unknown filter {spec!r} (auto, none, delta:N, shuffle:K, bitshuffle:K, bcj-x86, bcj-arm64)")

# ---------------------------------------------------------------- classifier (encoder only; integer arithmetic only)

CANDIDATES = [(0, b""), (1, b"\x01"), (1, b"\x02"), (1, b"\x04"), (1, b"\x08"), (2, b"\x02\x00"), (2, b"\x04\x00"),
              (2, b"\x08\x00"), (2, b"\x04\x01"), (2, b"\x08\x01"), (3, b""), (4, b"")]
SAMPLE_PIECE, SAMPLE_PIECES = 1 << 16, 4
# cross-chunk dedup (writer only; readers just follow extents)
CDC_MIN, CDC_AVG_LOG, CDC_MAX = 1 << 14, 16, 1 << 18       # segments 16 KiB .. 256 KiB, about 64 KiB on average
CDC_READ = 1 << 23
DEDUP_MIN = 1 << 12                                         # smaller segments (file tails) are not worth an extent
DEDUP_MAX_SEGMENTS = 1 << 20                                # index cap: ~64 GiB of distinct data, ~200 MiB of RAM
MIN_GAIN_DIV = 64                            # a filter must beat 'none' by more than 1/64 (~1.6%) of the estimate

def _sample(raw) -> List[bytes]:
    n = len(raw)
    if n <= SAMPLE_PIECE * SAMPLE_PIECES: return [bytes(raw)]
    out = []
    for i in range(SAMPLE_PIECES):           # evenly spread, 64-byte aligned so element strides stay aligned
        off = (i * (n - SAMPLE_PIECE) // (SAMPLE_PIECES - 1)) & ~63
        out.append(bytes(raw[off:off + SAMPLE_PIECE]))
    return out

def _hint(raw) -> str:
    b = bytes(raw[:4])
    if b[:2] == b"MZ": return "PE/MZ header"
    if b == b"\x7fELF": return "ELF header"
    if b in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"): return "Mach-O header"
    return ""

UNIT_BIG = 1 << 18                           # a file piece this large is classified on its own
UNIT_MAX = 1 << 23                           # ... in units of at most 8 MiB
UNIT_RUN = 1 << 20                           # small files are pooled into runs of about 1 MiB

def units(pieces: List[Tuple[int, int]], total: int) -> List[Tuple[int, int]]:
    """Cut a chunk into classification units from its file pieces [(offset, length)] (file boundaries)."""
    out: List[Tuple[int, int]] = []; run = None
    def flush():
        nonlocal run
        if run: out.append(run); run = None
    for off, ln in sorted(pieces):
        if ln >= UNIT_BIG:
            flush()
            for o in range(off, off + ln, UNIT_MAX): out.append((o, min(UNIT_MAX, off + ln - o)))
        else:
            run = (run[0], off + ln - run[0]) if run else (off, ln)
            if run[1] >= UNIT_RUN: flush()
    flush()
    # gaps (cannot happen with the writer's own extents, but never leave bytes uncovered)
    cov = []; pos = 0
    for off, ln in out:
        if off > pos: cov.append((pos, off - pos))
        cov.append((off, ln)); pos = off + ln
    if pos < total: cov.append((pos, total - pos))
    return [u for u in cov if u[1]]

def route(raw, pieces=None, coder: int = 1) -> Tuple[int, bytes, dict]:
    """Choose the filter for a whole chunk: classify each unit; one filter if they agree, else filter 6 'segmented'."""
    us = units(pieces or [(0, len(raw))], len(raw))
    segs = []; seginfo = []
    mv = memoryview(raw)
    for off, ln in us:
        fid, fp, info = classify(mv[off:off + ln], coder)
        info = {"off": off, "len": ln, "filter": filter_label(fid, fp), **info}
        if segs and segs[-1][1:] == (fid, fp):
            segs[-1] = (segs[-1][0] + ln, fid, fp); seginfo[-1]["len"] += ln; seginfo[-1]["merged"] = seginfo[-1].get("merged", 1) + 1
        else:
            segs.append((ln, fid, fp)); seginfo.append(info)
    if len(segs) == 1:
        info = seginfo[0]; info.pop("off", None); info.pop("len", None); info.pop("filter", None)
        return segs[0][1], segs[0][2], info
    return SEGMENTED, seg_pack(segs), {"why": f"{len(segs)} segments with different filters", "segments": seginfo}

CLASSIFY_LZ_LEVEL = 1                        # the classifier compresses samples fast; the chunk itself uses --level
SHORTLIST = 2                                # vulp-lz: besides 'none', try this many best order-0 candidates

def _code_hints(pieces) -> List[Tuple[int, bytes]]:
    """Filters worth an LZ trial because the sample looks like machine code (integer counts only)."""
    n = sum(len(p) for p in pieces) or 1; out = []
    e8 = sum(p.count(b"\xe8") + p.count(b"\xe9") for p in pieces)
    if e8 * 250 >= n: out.append((3, b""))                          # >= 0.4% E8/E9 bytes: x86 calls/jumps
    bl = 0
    for p in pieces:                                                # top byte of aligned LE words: 0x94..0x97 = BL
        top = p[3::4]; bl += sum(top.count(x) for x in (0x94, 0x95, 0x96, 0x97))
    if bl * 4 * 50 >= n: out.append((4, b""))                       # >= 2% of words are BL: ARM64 code
    return out

def classify(raw, coder: int = 1) -> Tuple[int, bytes, dict]:
    """Pick a filter for one unit. Returns (filter id, params, routing info). Deterministic: integer costs, ties
    go to the earlier candidate. Every candidate gets an order-0 estimate (what vulp-tans codes). For vulp-lz the
    order-0 statistics are not what matters (BCJ, for one, helps matches, not byte statistics), so 'none', the best
    order-0 candidates and the code filters suggested by the sample are compressed with vulp-lz (fast level) and
    the smallest actual output wins."""
    pieces = _sample(raw); est = {}
    for fid, params in CANDIDATES:
        c = 0
        for pc in pieces:
            c += _native.cost(_native.filter_fwd(fid, params, pc) if fid else pc)
        est[filter_label(fid, params)] = (c + (8 << 16) - 1) >> 19          # Q16 bits -> bytes, rounded up
    sampled = sum(len(p) for p in pieces)
    if coder == CODER_LZ and NATIVE:
        ranked = sorted(CANDIDATES[1:], key=lambda c: (est[filter_label(*c)], CANDIDATES.index(c)))
        trial = [(0, b"")] + ranked[:SHORTLIST]
        for c in _code_hints(pieces):
            if c not in trial: trial.append(c)
        lz = {}
        for fid, params in trial:
            size = 0
            for pc in pieces:
                data = _native.filter_fwd(fid, params, pc) if fid else pc
                enc = _native.lz_encode(data, CLASSIFY_LZ_LEVEL)
                size += len(enc) if enc is not None else len(pc)
            lz[filter_label(fid, params)] = size
        est = {"lz": lz}                          # the decision is made on these; order-0 numbers only chose the shortlist
        base = lz["none"]; best = (0, b""); best_c = base
        for fid, params in trial[1:]:
            c = lz[filter_label(fid, params)]
            if c < best_c: best, best_c = (fid, params), c
    else:
        base = est["none"]; best = (0, b""); best_c = base
        for fid, params in CANDIDATES[1:]:
            c = est[filter_label(fid, params)]
            if c < best_c: best, best_c = (fid, params), c
    if best != (0, b"") and (base - best_c) * MIN_GAIN_DIV <= base:
        why = f"no filter beat 'none' by more than 1/{MIN_GAIN_DIV} (best {filter_label(*best)} {best_c} B vs {base} B)"
        best = (0, b"")
    elif best == (0, b""):
        why = f"'none' had the lowest estimate ({base} B)"
    else:
        why = f"{filter_label(*best)} lowest estimate: {best_c} B vs none {base} B ({(base - best_c) * 100 // max(base, 1)}% smaller)"
    hint = _hint(raw)
    info = {"why": why + (f"; {hint}" if hint else ""), "sampled": sampled, "est": est}
    return best[0], best[1], info

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
    def __init__(self, f, *, chunk_size: int = 1 << 26, solid: bool = False, coder: int = 0, filt=0,
                 level: int = 0, dedup: bool = True, password: Optional[bytes] = None,
                 kdf: Tuple[int, int, int] = (3, 256 * 1024, 4), use_scrypt: bool = False,
                 header_extra: bytes = b"", min_reader: int = 1, required_extra: int = 0, cdc: bool = False):
        """coder: 0 stored, 1 vulp-tans. filt: a filter id, an (id, params) tuple, or None = choose per chunk
        (classify(); needs a real coder). A chunk the coder cannot shrink is stored instead.
        header_extra / min_reader / required_extra exist so tests can write what a future VFA would."""
        if not (1 << 12) <= chunk_size <= MAX_CHUNK: raise ValueError("chunk_size must be 4 KiB .. 1 GiB")
        if coder not in CODERS or CODERS[coder].encode is None: raise ValueError(f"coder {coder} cannot encode")
        if isinstance(filt, int): filt = (filt, b"")
        # cross-chunk dedup of content-defined segments; off when encrypting (set below). Without the C extension
        # the pure-Python chunker gives the same cuts (slower, ~5 MB/s), so the archive does not depend on it
        self.cdc = bool(dedup) and cdc
        if filt is not None and (filt[0] not in FILTERS or FILTERS[filt[0]].encode is None):
            raise ValueError(f"filter {filt[0]} cannot encode")
        self.routing: List[dict] = []
        self.f, self.cs, self.solid, self.coder, self.filt, self.level, self.dedup = f, chunk_size, solid, coder, filt, level, dedup
        self.pos = 0; self.hasher = hashlib.sha256()
        self.chunks: List[tuple] = []               # (frame_offset, raw_size, raw_crc, coder, filter)
        self.by_hash: Dict[bytes, int] = {}
        self.entries: List[dict] = []
        self.buf = bytearray(); self.pending: List[list] = []      # extents [chunk, off, len] waiting for this chunk
        self.pending_refs: List[list] = []                          # dedup records/references into the current buffer
        self.buf_file_starts: List[int] = []                        # buffer offsets where a file's bytes begin
        self._last_appended = None
        self.seg_index: Dict[bytes, list] = {}                      # segment SHA-256 -> [chunk, offset, length]
        # segments must fit a chunk: below 256 KiB chunks they shrink with it (a quarter of a chunk on average, at
        # least 1 KiB, where an extent's 12 bytes are still worth it). Default chunk sizes keep the constants.
        smax = min(CDC_MAX, chunk_size); smin = max(1 << 10, min(CDC_MIN, smax >> 3))
        self.cdc_params = (smin, min(CDC_AVG_LOG, smax.bit_length() - 3), smax)
        self.dedup_min = min(DEDUP_MIN, smin)
        self.dedup_segments = self.dedup_bytes = 0
        self.data_key = self.index_key = None
        req = 0; kdf_id = aead = kp = kt = km = 0; salt = b"\0" * 16
        if password is not None:
            req |= RF_ENCRYPTED; aead = AEAD_AESGCM; salt = os.urandom(16)
            if use_scrypt or not vx.HAVE_ARGON2: kdf_id, kt, km, kp = KDF_SCRYPT, 1 << 15, 8, 1
            else: kdf_id, (kt, km, kp) = KDF_ARGON2ID, kdf
            self.data_key, self.index_key = _derive_keys(password, kdf_id, kt, km, kp, salt)
            self.dedup = False      # identical plaintext chunks/segments would otherwise be visible as shared data
            self.cdc = False
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
        # file boundaries inside this chunk (dedup references split a file's stored bytes into several extents, but
        # those bytes are still one contiguous run per file, so units follow files, not extents)
        starts = sorted(set(self.buf_file_starts) | {0}); ends = starts[1:] + [len(raw)]
        self.piece_bounds = [(a, b - a) for a, b in zip(starts, ends) if b > a]
        self.buf_file_starts = []
        h = hashlib.sha256(raw).digest() if self.dedup else None
        if h is not None and h in self.by_hash:
            idx = self.by_hash[h]
        else:
            coder = self.coder; info = None
            # vulp-cm picks its filter the way vulp-lz does (BCJ, for one, helps both the same way)
            if self.filt is None and coder != 0:
                fid, fp, info = route(raw, self.piece_bounds, CODER_LZ if coder == CODER_CM else coder)
            elif self.filt is None: fid, fp = 0, b""
            else: fid, fp = self.filt; info = {"why": "forced (--filter)"} if coder != 0 else None
            fparams, fdata = FILTERS[fid].encode(raw, fp)
            cparams, payload = CODERS[coder].encode(fdata, self.level)
            if coder == CODER_CM:     # opt-in slow coder: keep it only where it beats vulp-lz (decodes ~100x faster)
                lp, lpay = _lz_encode(fdata, self.level)
                cm_size = len(payload) if payload is not None else None
                # compare what each choice writes: payload + params (vulp-cm's 2 coder bytes, and the 2-byte
                # filter-params length that any params need). vulp-cm must write at least CM_MIN_GAIN_PCT % less than
                # vulp-lz (or than the raw chunk, when vulp-lz cannot shrink it); otherwise vulp-lz is kept
                def written(cp, pay): return len(pay) + (2 + len(fparams) + len(cp) if (fparams or cp) else 0)
                lz_w = written(lp, lpay) if lpay is not None else len(raw)
                if payload is None or written(cparams, payload) * 100 > lz_w * (100 - CM_MIN_GAIN_PCT):
                    coder, cparams, payload = CODER_LZ, lp, lpay
                if payload is not None and written(cparams, payload) >= len(raw):
                    payload = None                  # whichever won, its params would eat the gain: store the chunk
                info = dict(info or {})
                info["why"] = (info.get("why", "") + f"; vulp-cm {cm_size if cm_size is not None else 'no gain'} B, vulp-lz "
                               f"{len(lpay) if lpay is not None else 'no gain'} B: kept {CODERS[coder].name}").lstrip("; ")
            if coder != 0 and (payload is None or len(payload) >= len(raw)):   # the coder did not help: store the chunk
                got = "no smaller output" if payload is None else f"{len(payload)} B >= {len(raw)} B raw"
                info = dict(info or {}); info["why"] = (info.get("why", "") + f"; {CODERS[coder].name} gave {got}, "
                                                        "stored instead").lstrip("; ")
                fid, fparams, coder, cparams, payload = 0, b"", 0, b"", raw
            params = struct.pack("<H", len(fparams)) + fparams + cparams if (fparams or cparams) else b""
            c = crc32(raw)
            off = self._frame(CHUNK_MAGIC, coder, fid, params, payload, len(raw), c, self.data_key)
            idx = len(self.chunks); self.chunks.append((off, len(raw), c, coder, fid))
            if info is not None:
                self.routing.append({"chunk": idx, "filter": filter_label(fid, fparams), "coder": CODERS[coder].name,
                                     "raw": len(raw), "stored": len(payload), **info})
            if h is not None: self.by_hash[h] = idx
        for ext in self.pending: ext[0] = idx
        for ext in self.pending_refs: ext[0] = idx      # dedup references into this chunk, and its segment records
        self.pending = []; self.pending_refs = []

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

    def _append(self, e, mv):
        """Append file bytes to the current chunk buffer, flushing full chunks."""
        if e is not self._last_appended:
            self._last_appended = e; self.buf_file_starts.append(len(self.buf))
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
            if len(mv) and not self.buf: self.buf_file_starts.append(0)

    def _reference(self, e, loc):
        """Point the file at bytes already stored (dedup): no data is written."""
        cid, off, ln = loc
        cur = e["extents"][-1] if e["extents"] else None
        if cur is not None and cur[0] == cid and cur[1] + cur[2] == off:
            cur[2] += ln                                     # contiguous with the previous extent: grow it
        else:
            ext = [cid, off, ln]; e["extents"].append(ext)
            if cid is None: self.pending_refs.append(ext)   # points into the unflushed buffer
        e["size"] += ln

    def _segment(self, e, seg: memoryview):
        """One content-defined segment: reference an identical earlier one, or store it (and remember where)."""
        n = len(seg)
        if n >= self.dedup_min:
            h = hashlib.sha256(seg).digest()
            loc = self.seg_index.get(h)
            if loc is not None:
                self._reference(e, loc); self.dedup_segments += 1; self.dedup_bytes += n
                return
            if n <= self.cs and len(self.seg_index) < DEDUP_MAX_SEGMENTS:
                if len(self.buf) + n > self.cs: self._flush()   # a segment is never split: start the next chunk
                loc = [None, len(self.buf), n]              # registered before the append: a flush patches it
                self.pending_refs.append(loc); self.seg_index[h] = loc
        self._append(e, seg)

    def add_file(self, path, mode, mtime, src, meta=None, piece: int = 1 << 20, mtime_ns=None) -> int:
        """src: a binary file object or bytes. Returns the number of bytes stored."""
        e = self._entry(ET_FILE, path, mode, mtime, 0, meta, mtime_ns)
        if not self.solid and self.buf: self._flush()          # non-solid: every file starts a new chunk
        if isinstance(src, (bytes, bytearray, memoryview)): src = io.BytesIO(bytes(src))
        if not self.cdc:
            while True:
                b = src.read(piece)
                if not b: break
                self._append(e, memoryview(b))
        else:
            # content-defined segments (cut points depend only on content, so shifted copies still line up);
            # the last segment of each read is carried over, since its end is the read size, not content
            carry = b""
            while True:
                b = src.read(CDC_READ)
                data = carry + b if carry else b
                if not data: break
                cuts = _native.cdc(data, *self.cdc_params)
                mv = memoryview(data); start = 0
                last = len(cuts) if not b else len(cuts) - 1
                for end in cuts[:last]:
                    self._segment(e, mv[start:end]); start = end
                carry = bytes(mv[start:]) if b else b""
                if not b: break
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
        if self.routing:                     # non-critical: readers that do not know it skip it
            doc = {"v": 1, "chunks": self.routing}
            if self.cdc: doc["dedup"] = {"segments": self.dedup_segments, "bytes": self.dedup_bytes}
            rt = json.dumps(doc, separators=(",", ":"), sort_keys=True).encode("utf-8")
            records = [(XR_ROUTING, 0, rt), *records]
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
            self.entries = None; self.chunks: List[tuple] = []; self._cache = collections.OrderedDict()
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

    def routing(self) -> List[dict]:
        """Why each chunk got its filter and coder (ROUTING index record), or [] if the archive has none."""
        data = getattr(self, "records", {}).get(XR_ROUTING)
        if not data: return []
        try: doc = json.loads(data.decode("utf-8"))
        except ValueError: return []                        # debug information only: never fail on it
        chunks = doc.get("chunks") if isinstance(doc, dict) else None
        if not isinstance(chunks, list): return []
        return [c for c in chunks if isinstance(c, dict) and type(c.get("chunk")) is int]

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
        if not NATIVE and any(c[3] != 0 or c[4] != 0 for c in self.chunks):
            vx.LOGGER.warning(f"Decoding with the slow pure-Python reference codec: {NATIVE_PROBLEM}")
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
        if i in self._cache: self._cache.move_to_end(i); return self._cache[i]
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
            data = cdc.decode(cparams, payload, raw_size)       # coder output is the filtered stream (filters keep the size)
            raw = flt.decode(fparams, data, raw_size)
        except VFAError as e:
            raise VFAError(f"Chunk {i}: {e}")
        if len(raw) != raw_size: raise VFAError(f"Chunk {i} decoded to {len(raw)} bytes, expected {raw_size} (corrupted archive).")
        if crc32(raw) != rcrc: raise VFAError(f"Chunk {i} failed its CRC32 check (corrupted archive).")
        # keep the last CACHE_CHUNKS decoded chunks: a deduplicated file alternates between its own chunk and the
        # chunk holding the shared segments, which would otherwise be decoded again for every extent
        self._cache[i] = raw
        while len(self._cache) > CACHE_CHUNKS: self._cache.popitem(last=False)
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

    MAX_OPEN = 128                            # extraction: files kept open at once (the rest are reopened as needed)

    def _write_files(self, sel_files, start, commit, finish, check_cancel, active):
        """Chunk-major extraction: every needed chunk is decoded exactly once, in order, and its bytes are written
        at the right offset into every file that uses them. Dedup makes files share chunks, so a file-by-file order
        would decode the same chunk again and again. Memory: one decoded chunk at a time."""
        plan = collections.defaultdict(list)          # chunk -> [(entry, file offset, chunk offset, length)]
        remaining = {}
        for e in sel_files:
            pos = 0
            for ch, off, ln in e.get("extents", ()):
                plan[ch].append((e, pos, off, ln)); pos += ln
            remaining[id(e)] = pos
        state = {}                                    # id(entry) -> [out path, handle or None]
        lru = collections.OrderedDict()               # id(entry) -> entry, for files with an open handle

        def handle(e):
            k = id(e); st = state.get(k)
            if st is None:
                out, fw = start(e); st = state[k] = [out, fw, fw.name]; active.append((e, out, fw))
            elif st[1] is None:                       # reopen a file closed to stay under MAX_OPEN
                st[1] = open(st[2], "r+b"); active.append((e, st[0], st[1]))
            lru[k] = e; lru.move_to_end(k)
            while len(lru) > self.MAX_OPEN:
                ok, oe = lru.popitem(last=False); ost = state[ok]
                ost[1].close(); active[:] = [a for a in active if a[2] is not ost[1]]; ost[1] = None
            return st[1]

        def done(e):
            k = id(e); out, fw, tmp = state[k]
            if fw is None: fw = open(tmp, "r+b")
            else: lru.pop(k, None)
            active[:] = [a for a in active if a[2] is not fw]
            commit(out, fw); finish(e, out)

        for e in sel_files:                           # empty files first: nothing to decode
            if remaining[id(e)] == 0:
                check_cancel(); handle(e); done(e)
        for ch in sorted(plan):
            check_cancel()
            data = memoryview(self.chunk_data(ch))
            for e, fpos, off, ln in plan[ch]:
                fw = handle(e); fw.seek(fpos); fw.write(data[off:off + ln])
                remaining[id(e)] -= ln
                if remaining[id(e)] == 0: done(e)
            self._cache.pop(ch, None); del data       # used once: do not keep it around
