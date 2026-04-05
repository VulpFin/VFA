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

# --- Compact, working v0 reference (fits in one file) ---
from __future__ import annotations
import struct, zlib, collections, heapq

MAGIC = b"VULP"
VER = 0
F_NONE, F_DELTA1, F_DELTA2, F_DELTA4 = 0, 1, 2, 3


def _delta(b, N, inv=False):
    out = bytearray(b)
    if not inv:
        for i in range(N, len(out)):
            out[i] = (out[i] - out[i - N]) & 0xFF
    else:
        for i in range(N, len(out)):
            out[i] = (out[i] + out[i - N]) & 0xFF
    return bytes(out)


def filt(b, fid, inv=False):
    if fid == F_NONE:
        return b
    if fid == F_DELTA1:
        return _delta(b, 1, inv)
    if fid == F_DELTA2:
        return _delta(b, 2, inv)
    if fid == F_DELTA4:
        return _delta(b, 4, inv)
    raise ValueError("bad filter")


# Canonical Huffman (minimal)
class Huff:

    def __init__(self, lens: dict[int, int]):
        # Ensure no zero-length codes: bump any 0 to 1 (singleton case)
        if not lens:
            lens = {0: 1}
        else:
            # If every symbol has length 0 (singleton produced by build_lengths), fix it
            if all(L == 0 for L in lens.values()):
                # assign length 1 to the only symbol (or to each, but it will be one symbol in practice)
                lens = {s: 1 for s in lens.keys()}

        self.lens = dict(lens)

        # canonical code assignment
        import collections

        bl_count = collections.Counter(self.lens.values())
        max_bits = max(self.lens.values()) if self.lens else 1
        code = 0
        next_code = {}
        for bits in range(1, max_bits + 1):
            code = (code + bl_count.get(bits - 1, 0)) << 1
            next_code[bits] = code

        self.codes = {}
        for sym, bits in sorted(self.lens.items(), key=lambda kv: (kv[1], kv[0])):
            # bits is guaranteed >= 1 here
            self.codes[sym] = next_code[bits]
            next_code[bits] += 1

        self.maxb = max_bits

    def enc(self, syms):
        out = bytearray()
        buf = 0
        bc = 0

        def put(v, n):
            nonlocal buf, bc
            buf |= (v & ((1 << n) - 1)) << bc
            bc += n
            while bc >= 8:
                out.append(buf & 0xFF)
                buf >>= 8
                bc -= 8

        for s in syms:
            put(self.codes[s], self.lens[s])
        if bc:
            out.append(buf & 0xFF)
        return bytes(out)

    @staticmethod
    def build_lengths(freq: dict[int, int]) -> dict[int, int]:
        import heapq

        # remove zero-frequency symbols
        pq = []
        for s, f in freq.items():
            if f > 0:
                heapq.heappush(pq, (f, id(s), {s: 0}))

        if not pq:
            # totally empty: synthesize a 1-bit code for symbol 0
            return {0: 1}

        if len(pq) == 1:
            # singleton alphabet: assign 1-bit code to that single symbol
            _, _, t = heapq.heappop(pq)
            s = next(iter(t.keys()))
            return {s: 1}

        # merge until one tree remains; lengths accumulate as depth
        while len(pq) > 1:
            f1, _, t1 = heapq.heappop(pq)
            f2, _, t2 = heapq.heappop(pq)
            merged = {
                **{k: v + 1 for k, v in t1.items()},
                **{k: v + 1 for k, v in t2.items()},
            }
            heapq.heappush(pq, (f1 + f2, id(merged), merged))
        return heapq.heappop(pq)[2]

    @staticmethod
    def ser(lens: dict[int, int]) -> bytes:
        items = sorted(lens.items())
        b = bytearray(struct.pack("<H", len(items)))
        for s, L in items:
            b += struct.pack("<HB", s, L)
        return bytes(b)

    @staticmethod
    def de(mv: memoryview, off: int) -> tuple["Huff", int]:
        (n,) = struct.unpack_from("<H", mv, off)
        off += 2
        lens = {}
        for _ in range(n):
            s, L = struct.unpack_from("<HB", mv, off)
            off += 3
            lens[s] = L
        return Huff(lens), off


def lz(block: bytes):
    n = len(block)
    out = []
    lit = bytearray()
    last = [-1] * 4096

    def H(p4):
        return ((p4 * 0x9E3779B1) & 0xFFFFFFFF) >> 20

    def flush():
        nonlocal lit
        if lit:
            out.append(("lit", bytes(lit)))
            lit = bytearray()

    i = 0
    while i < n:
        if i + 4 <= n:
            p4 = int.from_bytes(block[i : i + 4], "little")
            h = H(p4)
            j = last[h]
            last[h] = i
            if j >= 0 and i - j <= 65535:
                L = 0
                while (
                    i + L < n and j + L < n and block[i + L] == block[j + L] and L < 255
                ):
                    L += 1
                if L >= 4:
                    flush()
                    out.append(("m", L, i - j))
                    i += L
                    continue
        lit.append(block[i])
        i += 1
    flush()
    return out


def pack_bits(flags):
    out = bytearray()
    buf = 0
    bc = 0
    for bit in flags:
        buf |= (1 if bit else 0) << bc
        bc += 1
        if bc == 8:
            out.append(buf)
            buf = 0
            bc = 0
    if bc:
        out.append(buf)
    return bytes(out)


def unpack_bits(b, count):
    out = []
    i = 0
    byte = 0
    bc = 0
    for _ in range(count):
        if bc == 0:
            byte = b[i] if i < len(b) else 0
            i += 1
            bc = 8
        out.append(byte & 1)
        byte >>= 1
        bc -= 1
    return out


def compress_block(raw: bytes) -> bytes:
    # choose filter by quick probe
    best = (1 << 60, F_NONE)
    for fid in (F_NONE, F_DELTA1, F_DELTA2, F_DELTA4):
        t = filt(raw[:65536], fid)
        est = len(lz(t)) * 3  # crude
        if est < best[0]:
            best = (est, fid)
    fid = best[1]
    tr = filt(raw, fid)
    ops = lz(tr)

    len_syms = []
    dist_syms = []
    tags = []
    lit_payload = bytearray()
    dist_payload = bytearray()
    for op in ops:
        if op[0] == "lit":
            data = op[1]
            L = len(data)
            while L > 255:
                len_syms.append(255)
                tags.append(0)
                lit_payload += data[:255]
                data = data[255:]
                L -= 255
            len_syms.append(L)
            tags.append(0)
            lit_payload += data
        else:
            L, D = op[1], op[2]
            len_syms.append(L)
            tags.append(1)
            # distance encoded as two raw bytes but still put a small huff on MSB to help a bit
            dist_syms.append((D >> 8) & 0xFF)
            dist_payload += bytes([D & 0xFF])

    len_freq = collections.Counter(len_syms) or {0: 1}
    dist_freq = collections.Counter(dist_syms) or {0: 1}
    len_h = Huff(Huff.build_lengths(len_freq))
    dist_h = Huff(Huff.build_lengths(dist_freq))

    tag_bits = pack_bits(tags)
    len_bits = len_h.enc(len_syms)
    dist_bits = dist_h.enc(dist_syms)

    header = bytearray()
    header += MAGIC
    header += struct.pack("<B", VER)
    header += struct.pack("<B", fid)
    header += struct.pack("<I", len(raw))
    header += struct.pack("<I", zlib.crc32(raw) & 0xFFFFFFFF)

    payload = bytearray()
    payload += Huff.ser(len_h.lens)
    payload += Huff.ser(dist_h.lens)
    payload += struct.pack("<I", len(tag_bits))
    payload += tag_bits
    payload += struct.pack("<I", len(len_bits))
    payload += len_bits
    payload += struct.pack("<I", len(dist_bits))
    payload += dist_bits
    payload += struct.pack("<I", len(dist_payload))
    payload += dist_payload
    payload += struct.pack("<I", len(lit_payload))
    payload += lit_payload

    header += struct.pack("<I", len(payload))
    return bytes(header) + bytes(payload)


def decompress_block(b: memoryview, off: int) -> tuple[bytes, int]:
    assert b[off : off + 4].tobytes() == MAGIC
    off += 4
    ver = b[off]
    off += 1
    if ver != VER:
        raise ValueError("ver")
    fid = b[off]
    off += 1
    (raw_len,) = struct.unpack_from("<I", b, off)
    off += 4
    (crc_exp,) = struct.unpack_from("<I", b, off)
    off += 4
    (plen,) = struct.unpack_from("<I", b, off)
    off += 4
    mv = b[off : off + plen]
    off += plen
    p = 0
    len_h, p = Huff.de(mv, p)
    dist_h, p = Huff.de(mv, p)
    (tag_len,) = struct.unpack_from("<I", mv, p)
    p += 4
    tags = mv[p : p + tag_len].tobytes()
    p += tag_len
    (len_len,) = struct.unpack_from("<I", mv, p)
    p += 4
    len_bits = mv[p : p + len_len].tobytes()
    p += len_len
    (dist_len,) = struct.unpack_from("<I", mv, p)
    p += 4
    dist_bits = mv[p : p + dist_len].tobytes()
    p += dist_len
    (dist_payload_len,) = struct.unpack_from("<I", mv, p)
    p += 4
    dist_payload = mv[p : p + dist_payload_len].tobytes()
    p += dist_payload_len
    (lit_len,) = struct.unpack_from("<I", mv, p)
    p += 4
    lit_payload = mv[p : p + lit_len].tobytes()
    p += lit_len

    # decode variable-length code streams
    def dec_stream(h: Huff, data: bytes):
        # reverse table
        rev = {}
        for s, L in h.lens.items():
            rev.setdefault(L, {})[h.codes[s]] = s
        maxb = h.maxb
        out = []
        buf = 0
        bc = 0
        i = 0
        while i < len(data) or bc > 0:
            while bc < maxb and i < len(data):
                buf |= data[i] << bc
                bc += 8
                i += 1
            matched = False
            for L in range(1, maxb + 1):
                code = buf & ((1 << L) - 1)
                table = rev.get(L)
                if table and code in table:
                    out.append(table[code])
                    buf >>= L
                    bc -= L
                    matched = True
                    break
            if not matched:
                break
        return out

    len_syms = dec_stream(len_h, len_bits)
    dist_syms = dec_stream(dist_h, dist_bits)
    tag_list = unpack_bits(tags, len(len_syms))

    lit_ofs = 0
    dist_ofs = 0
    out = bytearray()
    for tag, sym in zip(tag_list, len_syms):
        if tag == 0:
            L = sym
            out += lit_payload[lit_ofs : lit_ofs + L]
            lit_ofs += L
        else:
            L = sym
            msb = dist_syms[dist_ofs]
            dist_ofs += 1
            # consume one LSB from payload
            if len(dist_payload) < dist_ofs:
                raise ValueError("dist underflow")
            lsb = dist_payload[dist_ofs - 1]
            D = (msb << 8) | lsb
            # copy match
            start = len(out) - D
            if start < 0:
                raise ValueError("bad dist")
            for _ in range(L):
                out.append(out[start])
                start += 1

    raw = filt(bytes(out), fid, inv=True)
    if len(raw) != raw_len or (zlib.crc32(raw) & 0xFFFFFFFF) != crc_exp:
        raise ValueError("corrupt block")
    return raw, off
