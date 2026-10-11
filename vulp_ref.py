# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
#!/usr/bin/env python3
"""
vulp_ref - pure-Python reference implementation of the VFA2 codecs (vulp/vulp.c), written from VFA2.md.

Two jobs:
  1. An independent check on the C code: Python integers are exact, so the reference cannot have a compiler- or
     CPU-dependent result. test_vfa.py requires the C encoder's output to equal this encoder's output bit for bit,
     and each decoder to accept exactly what the other produced.
  2. A fallback decoder if the _vulp extension is missing (slow: roughly 1 MB/s).

Same API as the _vulp extension: tans_encode, tans_decode, filter_fwd, filter_inv, cost. Integer arithmetic only.
"""
import struct

VERSION = 1
BLOCK = 1 << 17
MAXLOG, MINLOG = 12, 5
BLK_RAW, BLK_RLE, BLK_TANS = 0, 1, 2

def _hb(v):                                  # floor(log2(v)), v > 0
    return v.bit_length() - 1

def log2_q16(x):
    if x == 0: return 0
    hb = _hb(x); y = (x << 31) >> hb; r = hb << 16
    for i in range(15, -1, -1):
        y = (y * y) >> 31
        if y >= 2 << 31: y >>= 1; r |= 1 << i
    return r

def cost(data) -> int:
    data = bytes(data); bits = 0
    for done in range(0, len(data), BLOCK):
        blk = data[done:done + BLOCK]; cnt = [0] * 256
        for b in blk: cnt[b] += 1
        lN = log2_q16(len(blk)); nsym = 0
        for c in cnt:
            if c: bits += c * (lN - log2_q16(c)); nsym += 1
        bits += (nsym * 12 + 120) << 16
    return bits

# ---------------------------------------------------------------- tANS

def _spread(freq, log):
    ts = 1 << log; mask = ts - 1; step = (ts >> 1) + (ts >> 3) + 3; pos = 0; sym_at = [0] * ts
    for s, f in enumerate(freq):
        for _ in range(f): sym_at[pos] = s; pos = (pos + step) & mask
    if pos != 0: raise ValueError("corrupt encoded data")
    return sym_at

def _normalise(cnt, nsym, total, log):
    ts = 1 << log; freq = []
    for s in range(nsym):
        f = 0
        if cnt[s]: f = max(1, (cnt[s] * ts + total // 2) // total)
        freq.append(f)
    sm = sum(freq)
    while sm > ts:
        best = None
        for s in range(nsym):
            if freq[s] > 1 and (best is None or freq[s] > freq[best]): best = s
        freq[best] -= 1; sm -= 1
    if sm < ts:
        best = 0
        for s in range(1, nsym):
            if cnt[s] > cnt[best]: best = s
        freq[best] += ts - sm
    return freq

def _enc_block(blk, cnt, log):
    nsym = max(s for s in range(256) if cnt[s]) + 1
    ts = 1 << log
    freq = _normalise(cnt, nsym, len(blk), log)
    sym_at = _spread(freq, log)
    cum = [0]
    for f in freq: cum.append(cum[-1] + f)
    fill = cum[:-1]; stab = [0] * ts
    for u in range(ts):
        s = sym_at[u]; stab[fill[s]] = ts + u; fill[s] += 1
    dnb = [0] * nsym; dfs = [0] * nsym
    for s, f in enumerate(freq):
        if f == 0: continue
        if f == 1: dnb[s] = (log << 16) - ts
        else: mbo = log - _hb(f - 1); dnb[s] = (mbo << 16) - (f << mbo)
        dfs[s] = cum[s] - f
    hdr = bytearray([BLK_TANS]) + struct.pack("<I", len(blk)) + bytes([log, nsym - 1])
    for f in freq: hdr += bytes([0x80 | (f & 0x7F), f >> 7]) if f >= 128 else bytes([f])
    acc = 0; nbits = 0; state = ts
    for i in range(len(blk) - 1, -1, -1):
        sy = blk[i]; nb = (state + dnb[sy]) >> 16
        acc |= (state & ((1 << nb) - 1)) << nbits; nbits += nb
        state = stab[(state >> nb) + dfs[sy]]
    body = acc.to_bytes((nbits + 7) >> 3, "little")
    return bytes(hdr) + struct.pack("<IH", nbits, state - ts) + body

def tans_encode(data) -> bytes:
    data = bytes(data); out = bytearray()
    for done in range(0, len(data), BLOCK):
        blk = data[done:done + BLOCK]; cnt = [0] * 256
        for b in blk: cnt[b] += 1
        present = [s for s in range(256) if cnt[s]]
        best = bytes([BLK_RAW]) + struct.pack("<I", len(blk)) + blk
        if len(present) == 1:
            best = bytes([BLK_RLE]) + struct.pack("<I", len(blk)) + blk[:1]
        else:
            lo = max(MINLOG, _hb(present[-1]) + 2)
            for log in range(lo, MAXLOG + 1):
                if log != lo and log < 9: continue
                e = _enc_block(blk, cnt, log)
                if len(e) < len(best): best = e
        out += best
    return bytes(out)

def tans_decode(payload, n: int) -> bytes:
    p = bytes(payload); ip = 0; out = bytearray()
    def bad(): raise ValueError("corrupt encoded data")
    while len(out) < n:
        if len(p) - ip < 5: bad()
        kind = p[ip]; ln, = struct.unpack_from("<I", p, ip + 1); ip += 5
        if ln == 0 or ln > n - len(out): bad()
        if kind == BLK_RAW:
            if len(p) - ip < ln: bad()
            out += p[ip:ip + ln]; ip += ln
        elif kind == BLK_RLE:
            if len(p) - ip < 1: bad()
            out += p[ip:ip + 1] * ln; ip += 1
        elif kind == BLK_TANS:
            if len(p) - ip < 2: bad()
            log = p[ip]; nsym = p[ip + 1] + 1; ip += 2
            if not MINLOG <= log <= MAXLOG: bad()
            ts = 1 << log; freq = []
            for _ in range(nsym):
                if ip >= len(p): bad()
                f = p[ip]; ip += 1
                if f & 0x80:
                    if ip >= len(p) or p[ip] & 0x80: bad()
                    f = (f & 0x7F) | (p[ip] << 7); ip += 1
                    if f < 128: bad()
                if f > ts: bad()
                freq.append(f)
            if sum(freq) != ts or freq[-1] == 0: bad()
            if len(p) - ip < 6: bad()
            nbits, X = struct.unpack_from("<IH", p, ip); ip += 6
            nbytes = (nbits + 7) >> 3
            if X >= ts or len(p) - ip < nbytes: bad()
            acc = int.from_bytes(p[ip:ip + nbytes], "little")
            if acc >> nbits: bad()                                # padding bits must be zero
            sym_at = _spread(freq, log); nxt = list(freq)
            dsym = [0] * ts; dnb = [0] * ts; dbase = [0] * ts
            for u in range(ts):
                s = sym_at[u]; ns = nxt[s]; nxt[s] += 1; nb = log - _hb(ns)
                dsym[u] = s; dnb[u] = nb; dbase[u] = (ns << nb) - ts
            pos = nbits; blk = bytearray(ln)
            for i in range(ln):
                nb = dnb[X]; blk[i] = dsym[X]
                if nb > pos: bad()
                pos -= nb
                X = dbase[X] + ((acc >> pos) & ((1 << nb) - 1))
            if pos != 0 or X != 0: bad()
            out += blk; ip += nbytes
        else:
            bad()
    if ip != len(p): bad()
    return bytes(out)

# ---------------------------------------------------------------- filters (naive definitions from VFA2.md)

def _check(fid, p):
    p = bytes(p)
    if fid in (0, 3, 4) and p: raise ValueError("bad parameters")
    if fid == 1 and not (len(p) == 1 and 1 <= p[0] <= 32): raise ValueError("bad parameters")
    if fid == 2 and not (len(p) == 2 and p[0] in (2, 4, 8, 16) and p[1] <= 1): raise ValueError("bad parameters")
    if fid not in (0, 1, 2, 3, 4): raise ValueError("bad parameters")
    return p

def _shuffle(d, k, bitmode, inverse):
    n = len(d); m = n // k; out = bytearray(n)
    if not bitmode:
        for b in range(k):
            for j in range(m):
                if inverse: out[j * k + b] = d[b * m + j]
                else: out[b * m + j] = d[j * k + b]
        out[m * k:] = d[m * k:]
        return bytes(out)
    m8 = m - m % 8; groups = m8 // 8
    for b in range(k):
        for i in range(8):
            for g in range(groups):
                plane = (b * 8 + i) * groups + g
                if not inverse:
                    v = 0
                    for t in range(8): v |= ((d[(8 * g + t) * k + b] >> i) & 1) << t
                    out[plane] = v
                else:
                    v = d[plane]
                    for t in range(8): out[(8 * g + t) * k + b] |= ((v >> t) & 1) << i
    out[m8 * k:] = d[m8 * k:]
    return bytes(out)

def _bcj_x86(d, inverse):
    b = bytearray(d); i = 0; n = len(b)
    while i + 5 <= n:
        if b[i] in (0xE8, 0xE9):                  # always consumes 5 bytes, converted or not (VFA2.md)
            if b[i + 4] in (0x00, 0xFF):
                v, = struct.unpack_from("<I", b, i + 1); pos = i + 5
                w = ((v - pos) if inverse else (v + pos)) & 0x1FFFFFF
                if w & 0x1000000: w |= 0xFE000000
                struct.pack_into("<I", b, i + 1, w)
            i += 5
        else:
            i += 1
    return bytes(b)

def _bcj_arm64(d, inverse):
    b = bytearray(d)
    for i in range(0, len(b) - 3, 4):
        insn, = struct.unpack_from("<I", b, i)
        if insn & 0xFC000000 == 0x94000000:
            imm = insn & 0x03FFFFFF; pc = i >> 2
            imm = ((imm - pc) if inverse else (imm + pc)) & 0x03FFFFFF
            struct.pack_into("<I", b, i, 0x94000000 | imm)
    return bytes(b)

def _filter(fid, params, data, inverse):
    p = _check(fid, params); d = bytes(data)
    if fid == 0: return d
    if fid == 1:
        s = p[0]; out = bytearray(d)
        if inverse:
            for i in range(s, len(out)): out[i] = (out[i] + out[i - s]) & 0xFF
        else:
            for i in range(len(out) - 1, s - 1, -1): out[i] = (d[i] - d[i - s]) & 0xFF
        return bytes(out)
    if fid == 2: return _shuffle(d, p[0], p[1], inverse)
    if fid == 3: return _bcj_x86(d, inverse)
    return _bcj_arm64(d, inverse)

def filter_fwd(fid, params, data) -> bytes: return _filter(fid, params, data, False)
def filter_inv(fid, params, data) -> bytes: return _filter(fid, params, data, True)

# ---------------------------------------------------------------- vulp-lz (coder 3) decoder and CDC (VFA2.md)

LZ_MINMATCH, LZ_MAXCODE = 4, 71

def _lz_value(code, bits):
    if code < 16: return code
    if code > LZ_MAXCODE: raise ValueError("corrupt encoded data")
    k = code - 16; hb = k // 2 + 4
    extra = bits(hb - 1)
    return ((2 | (k & 1)) << (hb - 1)) | extra

def lz_decode(payload, n: int) -> bytes:
    p = bytes(payload); ip = 0; out = bytearray(); rep = 1
    def bad(): raise ValueError("corrupt encoded data")
    def u32():
        nonlocal ip
        if len(p) - ip < 4: bad()
        v, = struct.unpack_from("<I", p, ip); ip += 4; return v
    def stream(count):
        nonlocal ip
        sz = u32()
        if len(p) - ip < sz: bad()
        d = tans_decode(p[ip:ip + sz], count); ip += sz; return d
    while len(out) < n:
        raw, nseq, nlit = u32(), u32(), u32()
        if raw == 0 or raw > n - len(out) or nlit > raw or nseq > raw // LZ_MINMATCH: bad()
        bend = len(out) + raw
        lits = stream(nlit); llc = stream(nseq); mlc = stream(nseq); ofc = stream(nseq)
        nbits = u32(); nbytes = (nbits + 7) >> 3
        if len(p) - ip < nbytes: bad()
        acc = int.from_bytes(p[ip:ip + nbytes], "little")
        if acc >> nbits: bad()                                  # padding bits must be zero
        pos = 0
        def bits(nb):
            nonlocal pos
            if nb > nbits - pos: bad()
            v = (acc >> pos) & ((1 << nb) - 1); pos += nb; return v
        lp = 0
        for i in range(nseq):
            ll = _lz_value(llc[i], bits); mv = _lz_value(mlc[i], bits); ov = _lz_value(ofc[i], bits)
            if ll > nlit - lp or ll > bend - len(out): bad()
            out += lits[lp:lp + ll]; lp += ll
            ml = mv + LZ_MINMATCH
            if ov: rep = ov
            if rep > len(out) or ml > bend - len(out): bad()
            start = len(out) - rep
            for k in range(ml): out.append(out[start + k])   # byte by byte: overlapping copies repeat the pattern
        if pos != nbits: bad()
        if nlit - lp != bend - len(out): bad()
        out += lits[lp:]
        ip += nbytes
    if ip != len(p): bad()
    return bytes(out)

def cdc(data, min_size, avg_log, max_size):
    gear = []; x = 0x9E3779B9
    for _ in range(256):
        x ^= (x << 13) & 0xFFFFFFFF; x ^= x >> 17; x ^= (x << 5) & 0xFFFFFFFF; gear.append(x)
    avg_log = max(1, min(30, avg_log)); cuts = []; h = 0; start = 0; d = bytes(data)
    for i, b in enumerate(d):
        h = ((h << 1) + gear[b]) & 0xFFFFFFFF
        ln = i - start + 1
        if (ln >= min_size and (h >> (32 - avg_log)) == 0) or ln >= max_size:
            cuts.append(i + 1); start = i + 1; h = 0
    if len(d) > start: cuts.append(len(d))
    return cuts
