#!/usr/bin/env python3
"""
Experimental VFA neural-ish adaptive codec.

This is a practical first pass / scaffold for the requested custom method:

  * adaptive chunking
  * long-range context features over prior chunks
  * context-mixing style scoring to choose an entropy backend
  * per-segment codec switching
  * optional hardware/runtime detection metadata

Important: this is NOT a trained neural arithmetic coder yet. A true neural
entropy coder needs a deterministic trained model, quantized probability output,
range/ANS coding, model version pinning, and usually GPU/CPU kernels. This file
creates the stable container hook so that VFA can use `--method neural` today and
so the real neural coder can be swapped in behind this interface later without
changing the VFA archive format again.
"""
from __future__ import annotations

import bz2
import hashlib
import lzma
import os
import struct
import zlib
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Tuple

try:
    import brotli  # type: ignore

    HAVE_BROTLI = True
except Exception:  # pragma: no cover - optional dependency
    brotli = None
    HAVE_BROTLI = False

try:
    import zstandard as zstd  # type: ignore

    HAVE_ZSTD = True
except Exception:  # pragma: no cover - optional dependency
    zstd = None
    HAVE_ZSTD = False

try:
    import lz4.frame as lz4f  # type: ignore

    HAVE_LZ4 = True
except Exception:  # pragma: no cover - optional dependency
    lz4f = None
    HAVE_LZ4 = False

MAGIC = b"VFANNC1\0"
VERSION = 1

C_STORE = 0
C_ZLIB = 1
C_LZMA = 2
C_BROTLI = 3
C_ZSTD = 4
C_BZ2 = 5
C_LZ4 = 6

# This limits decompression allocation for corrupt data.
MAX_SEGMENT = 128 * 1024 * 1024


@dataclass
class SegmentFeatures:
    size: int
    unique: int
    zero_ratio_permille: int
    printable_ratio_permille: int
    entropy_millibits: int
    long_range_match_permille: int


def _shannon_millibits(data: bytes) -> int:
    """Return entropy in millibits/byte, 0..8000."""
    if not data:
        return 0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    # Avoid importing math in the hot path until needed.
    import math

    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return int(ent * 1000)


def _features(data: bytes, history_hashes: Dict[bytes, int]) -> SegmentFeatures:
    if not data:
        return SegmentFeatures(0, 0, 0, 0, 0, 0)
    unique = len(set(data))
    zero = data.count(0)
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)

    # Cheap long-range signal: sample 64-byte shingles and count prior sightings.
    matches = 0
    samples = 0
    step = max(64, len(data) // 32)
    for i in range(0, max(0, len(data) - 63), step):
        h = hashlib.blake2s(data[i : i + 64], digest_size=8).digest()
        samples += 1
        if h in history_hashes:
            matches += 1
    lrm = int((matches * 1000) / samples) if samples else 0

    return SegmentFeatures(
        size=len(data),
        unique=unique,
        zero_ratio_permille=int(zero * 1000 / len(data)),
        printable_ratio_permille=int(printable * 1000 / len(data)),
        entropy_millibits=_shannon_millibits(data),
        long_range_match_permille=lrm,
    )


def _update_history(data: bytes, history_hashes: Dict[bytes, int]) -> None:
    step = max(64, len(data) // 64) if data else 64
    for i in range(0, max(0, len(data) - 63), step):
        h = hashlib.blake2s(data[i : i + 64], digest_size=8).digest()
        history_hashes[h] = history_hashes.get(h, 0) + 1
    # Bounded memory; this is only a heuristic context store.
    if len(history_hashes) > 8192:
        for k in list(history_hashes.keys())[:2048]:
            history_hashes.pop(k, None)


def _compress_candidates(data: bytes, level: int, f: SegmentFeatures) -> Iterable[Tuple[int, bytes]]:
    """Context-mixer: choose likely useful codecs, then let byte size decide."""
    yield C_STORE, data

    # Fast/general choices first.
    yield C_ZLIB, zlib.compress(data, max(1, min(9, level if level else 6)))

    if HAVE_ZSTD:
        zlevel = max(-5, min(22, level if level is not None else 5))
        yield C_ZSTD, zstd.ZstdCompressor(level=zlevel).compress(data)  # type: ignore[union-attr]

    # Text or structured low/medium entropy data often likes brotli/lzma/bz2.
    textish = f.printable_ratio_permille >= 700
    low_entropy = f.entropy_millibits <= 7200 or f.zero_ratio_permille >= 100
    repeated_context = f.long_range_match_permille >= 50

    if HAVE_BROTLI and (textish or repeated_context):
        yield C_BROTLI, brotli.compress(data, quality=max(0, min(11, level)))  # type: ignore[union-attr]

    if low_entropy or repeated_context or level >= 7:
        yield C_LZMA, lzma.compress(data, format=lzma.FORMAT_XZ, preset=max(0, min(9, level)))
        yield C_BZ2, bz2.compress(data, compresslevel=max(1, min(9, level if level else 9)))

    if HAVE_LZ4 and level <= 2:
        yield C_LZ4, lz4f.compress(data, compression_level=max(0, min(16, level if level else 0)))  # type: ignore[union-attr]


def _decompress_segment(codec: int, payload: bytes) -> bytes:
    if codec == C_STORE:
        return payload
    if codec == C_ZLIB:
        return zlib.decompress(payload)
    if codec == C_LZMA:
        return lzma.decompress(payload, format=lzma.FORMAT_XZ)
    if codec == C_BROTLI:
        if not HAVE_BROTLI:
            raise RuntimeError("brotli not installed; cannot decode neural segment")
        return brotli.decompress(payload)  # type: ignore[union-attr]
    if codec == C_ZSTD:
        if not HAVE_ZSTD:
            raise RuntimeError("zstandard not installed; cannot decode neural segment")
        return zstd.ZstdDecompressor().decompress(payload)  # type: ignore[union-attr]
    if codec == C_BZ2:
        return bz2.decompress(payload)
    if codec == C_LZ4:
        if not HAVE_LZ4:
            raise RuntimeError("lz4 not installed; cannot decode neural segment")
        return lz4f.decompress(payload)  # type: ignore[union-attr]
    raise RuntimeError(f"bad neural segment codec id {codec}")


def _target_segment_size(level: int) -> int:
    """Adaptive target: level 0 = smaller/faster, level 12 = larger/stronger."""
    level = max(0, min(12, int(level if level is not None else 5)))
    return (128 * 1024) + ((2 * 1024 * 1024 - 128 * 1024) * level // 12)


def _adaptive_segments(data: bytes, level: int) -> List[Tuple[int, int]]:
    """Content-defined chunking using a rolling hash boundary heuristic."""
    if not data:
        return []
    target = _target_segment_size(level)
    min_size = max(16 * 1024, target // 4)
    max_size = max(min_size, target * 4)
    mask_bits = max(12, min(21, target.bit_length() - 1))
    mask = (1 << mask_bits) - 1

    out: List[Tuple[int, int]] = []
    start = 0
    rh = 0
    for i, b in enumerate(data):
        rh = ((rh << 1) + b + 0x9E3779B1) & 0xFFFFFFFF
        cur = i + 1 - start
        if cur >= min_size and (((rh & mask) == 0) or cur >= max_size):
            out.append((start, i + 1))
            start = i + 1
            rh = 0
    if start < len(data):
        out.append((start, len(data)))
    return out


def hardware_acceleration_report() -> str:
    """Best-effort human-readable runtime detection."""
    bits = []
    if HAVE_ZSTD:
        bits.append("zstd-native")
    if HAVE_BROTLI:
        bits.append("brotli-native")
    if HAVE_LZ4:
        bits.append("lz4-native")
    try:
        import torch  # type: ignore

        if torch.cuda.is_available():
            bits.append("torch-cuda")
        elif getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            bits.append("torch-mps")
        else:
            bits.append("torch-cpu")
    except Exception:
        pass
    return ",".join(bits) if bits else "python-cpu"


def compress_neural(data: bytes, level: int = 5) -> bytes:
    """Compress one VFA block with the experimental neural-ish codec."""
    level = max(0, min(12, int(level if level is not None else 5)))
    history: Dict[bytes, int] = {}
    records = []

    for start, end in _adaptive_segments(data, level):
        raw = data[start:end]
        f = _features(raw, history)
        best_codec = C_STORE
        best_payload = raw
        for codec, payload in _compress_candidates(raw, level, f):
            if len(payload) < len(best_payload):
                best_codec, best_payload = codec, payload
        records.append((best_codec, len(raw), best_payload))
        _update_history(raw, history)

    out = bytearray()
    out += MAGIC
    out += struct.pack("<BBII", VERSION, level, len(data), len(records))
    for codec, raw_len, payload in records:
        out += struct.pack("<BII", codec, raw_len, len(payload))
        out += payload
    return bytes(out)


def decompress_neural(blob: bytes) -> bytes:
    """Decompress one VFA block created by compress_neural."""
    if not blob.startswith(MAGIC):
        raise RuntimeError("not a VFA neural codec payload")
    off = len(MAGIC)
    if len(blob) < off + 10:
        raise RuntimeError("truncated neural payload header")
    version, _level, total_len, nseg = struct.unpack_from("<BBII", blob, off)
    off += 10
    if version != VERSION:
        raise RuntimeError(f"unsupported neural codec version {version}")

    out = bytearray()
    for _ in range(nseg):
        if len(blob) < off + 9:
            raise RuntimeError("truncated neural segment header")
        codec, raw_len, comp_len = struct.unpack_from("<BII", blob, off)
        off += 9
        if raw_len > MAX_SEGMENT or comp_len > len(blob) - off:
            raise RuntimeError("invalid neural segment length")
        payload = blob[off : off + comp_len]
        off += comp_len
        raw = _decompress_segment(codec, payload)
        if len(raw) != raw_len:
            raise RuntimeError("neural segment size mismatch")
        out += raw

    if len(out) != total_len:
        raise RuntimeError("neural payload size mismatch")
    return bytes(out)
