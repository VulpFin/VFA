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
        if raw == 0 or raw > n - len(out) or nlit > raw or nseq > (raw - nlit) // LZ_MINMATCH: bad()
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

# ---------------------------------------------------------------- vulp-cm (coder 2, M5): context mixing
# A line-by-line transcription of vulp/vulp_cm.c (read that file for the description). Python's >> on a negative
# number is a floor, like asr32/asr64 there; 32-bit products are masked. Very slow (a few KB/s): it exists to check
# the C code bit for bit and to read small archives without the extension.

CM_NH = 9; CM_NI = CM_NH + 3; CM_MINLEN = 6; CM_MINBITS = 16; CM_MAXBITS = 24; CM_MODEL = 1
_SQ_T = (1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546, 2047, 2549, 2994, 3348, 3607,
         3785, 3901, 3975, 4022, 4050, 4068, 4079, 4085, 4089, 4092, 4093, 4094)
_M32 = 0xFFFFFFFF
P_INIT = 1 << 31

def _squash(d):
    if d > 2047: d = 2047
    if d < -2047: d = -2047
    x = d + 2048; i = x >> 7; w = x & 127
    return (_SQ_T[i] * (128 - w) + _SQ_T[i + 1] * w + 64) >> 7

def _cm_tables():
    st = [0] * 4096; pi = 0
    for i in range(-2047, 2048):
        v = _squash(i)
        for j in range(pi, v + 1): st[j] = i
        pi = v + 1
    for j in range(pi, 4096): st[j] = 2047
    dt = [131072 // (2 * i + 3) for i in range(1024)]
    return st, dt

_CM_TABLES = None

def _hmix(a, b):
    h = ((a * 0x9E3779B1) ^ (((b + 0x7F4A7C15) & _M32) * 0x85EBCA6B)) & _M32
    h ^= h >> 15; h = (h * 0x2C1B3C6D) & _M32; h ^= h >> 13; h = (h * 0x297A2D39) & _M32; h ^= h >> 16
    return h

def _hist_n(s): return (s & 7) + ((s >> 3) & 7)

def _hist_up(s, bit):
    n0 = s & 7; n1 = (s >> 3) & 7
    if bit:
        if n1 < 7: n1 += 1
        if n0 > 2: n0 = n0 // 2 + 1
    else:
        if n0 < 7: n0 += 1
        if n1 > 2: n1 = n1 // 2 + 1
    return n0 | n1 << 3 | bit << 6

def _len_bucket(l): return l if l < 16 else 16 + min((l - 16) >> 3, 47)

def _wclamp(w): return (1 << 23) if w > (1 << 23) else -(1 << 23) if w < -(1 << 23) else w

class _CM:
    def __init__(self, tbits, buf):
        global _CM_TABLES
        if _CM_TABLES is None: _CM_TABLES = _cm_tables()
        self.st, self.dt = _CM_TABLES
        self.tbits = tbits; self.buf = buf
        self.t = [bytearray(1 << tbits) for _ in range(CM_NH)]
        self.smap = [[P_INIT] * 256 for _ in range(CM_NH)]
        self.base = [0] * CM_NH; self.h = [0] * CM_NH; self.spi = [0] * CM_NH
        self.o0 = [P_INIT] * 256; self.msm = [P_INIT] * 128
        self.mm = [0] * (1 << tbits)
        self.pos = 0; self.mptr = 0; self.mlen = 0; self.mexp = -1
        self.w = [[1 << 14] * CM_NI for _ in range(1024)]; self.w2 = [[1 << 14] * CM_NI for _ in range(256 * 8)]
        self.x = [0] * CM_NI; self.wsel = self.wsel2 = self.pm1 = self.pm2 = self.pmix = 0
        row = [_squash((j - 16) * 128) * 16 for j in range(33)]
        self.a1 = row * 256; self.a2 = row * 65536; self.a1i = self.a2i = 0
        self.c0 = 1; self.bitpos = 0; self.nib = 1
        self.c4 = self.c8 = self.word = self.word1 = 0; self.line0 = self.line1 = 0

    def slot_up(self, arr, i, bit, limit):
        v = arr[i]; n = v & 1023; p = v >> 10
        d = ((1 << 22) - 1 if bit else 0) - p
        if d >= 0: p += (d * self.dt[n]) >> 16
        else: p -= ((-d) * self.dt[n]) >> 16
        if n < limit: n += 1
        arr[i] = ((p << 10) | n) & _M32

    def set_bases(self):
        mask = ((1 << self.tbits) - 1) & ~15
        for i in range(CM_NH):
            h = _hmix(self.h[i], self.c0); chk = (h >> 24) | 1
            b0 = h & mask; b1 = b0 ^ 16; t = self.t[i]
            if t[b0] == chk: self.base[i] = b0; continue
            if t[b1] == chk: self.base[i] = b1; continue
            b = b0 if _hist_n(t[b0 + 1]) <= _hist_n(t[b1 + 1]) else b1
            t[b] = chk; t[b + 1:b + 16] = bytes(15)
            self.base[i] = b

    def byte_update(self, c):
        pos = self.pos; buf = self.buf
        self.c8 = ((self.c8 << 8) | (self.c4 >> 24)) & _M32
        self.c4 = ((self.c4 << 8) | c) & _M32
        c4 = self.c4; c8 = self.c8
        if 97 <= c <= 122 or 65 <= c <= 90: self.word = ((self.word ^ (c | 32)) * 0x01000193) & _M32
        elif self.word: self.word1 = self.word; self.word = 0
        if c == 10: self.line1 = self.line0; self.line0 = pos
        h = self.h
        h[0] = _hmix(c4 & 0xff, 1); h[1] = _hmix(c4 & 0xffff, 2); h[2] = _hmix(c4 & 0xffffff, 3)
        h[3] = _hmix(c4, 4); h[4] = _hmix(_hmix(c4, c8 & 0xffff), 5); h[5] = _hmix(self.word, 6)
        h[6] = _hmix(_hmix(self.word, self.word1), 7); h[7] = _hmix(_hmix(c4, c8 & 0xff), 8)
        col = pos - self.line0; above = self.line1 + col
        ab = buf[above] if above < self.line0 else 0
        h[8] = _hmix(_hmix(ab, col if col < 255 else 255), (c4 & 0xff) | 0x900)
        if self.mlen:
            if buf[self.mptr] == c: self.mlen += 1; self.mptr += 1
            else: self.mlen = 0
        if pos >= CM_MINLEN:
            hh = _hmix(c4, c8 & 0xffff) >> (32 - self.tbits)
            if not self.mlen:
                p = self.mm[hh]; l = 0
                if p:
                    while l < 64 and l < p and buf[p - 1 - l] == buf[pos - 1 - l]: l += 1
                    if l >= CM_MINLEN: self.mlen = l; self.mptr = p
            self.mm[hh] = pos
        if self.mlen > 65535: self.mlen = 65535

    def apm_p(self, t, pr, cx):
        s = self.st[pr] + 2048; lo = s >> 7; w = s & 127
        return cx * 33 + lo + (w >> 6), (t[cx * 33 + lo] * (128 - w) + t[cx * 33 + lo + 1] * w) >> 11

    def predict(self):
        st = self.st; x = self.x; lb = 0
        for i in range(CM_NH):
            si = self.base[i] + self.nib; self.spi[i] = si
            x[i] = st[self.smap[i][self.t[i][si]] >> 20]
        x[CM_NH] = st[self.o0[self.c0] >> 20]
        self.mexp = -1; x[CM_NH + 1] = 0
        if self.mlen:
            eb = self.buf[self.mptr] | 256
            if (eb >> (8 - self.bitpos)) == self.c0:
                self.mexp = (eb >> (7 - self.bitpos)) & 1
                lb = _len_bucket(self.mlen)
                x[CM_NH + 1] = st[self.msm[lb * 2 + self.mexp] >> 20]
        x[CM_NH + 2] = 256
        self.wsel = self.c0 + 256 * (0 if self.mexp < 0 else 1 if lb < 16 else 2 if lb < 32 else 3)
        self.wsel2 = (self.c4 & 0xff) * 8 + self.bitpos
        w = self.w[self.wsel]; w2 = self.w2[self.wsel2]
        s = sum(x[i] * w[i] for i in range(CM_NI)) >> 16
        s2 = sum(x[i] * w2[i] for i in range(CM_NI)) >> 16
        s = max(-2047, min(2047, s)); s2 = max(-2047, min(2047, s2))
        self.pm1 = _squash(s); self.pm2 = _squash(s2)
        self.pmix = _squash((s + s2) >> 1)
        self.a1i, p1 = self.apm_p(self.a1, self.pmix, self.c0)
        self.a2i, p2 = self.apm_p(self.a2, self.pmix, self.c0 | ((self.c4 & 0xff) << 8))
        p = (2 * self.pmix + p1 + p2 + 2) >> 2
        p = (p + p2 + 1) >> 1
        return 1 if p < 1 else 4095 if p > 4095 else p

    def update(self, bit):
        for i in range(CM_NH):
            t = self.t[i]; si = self.spi[i]; s = t[si]
            self.slot_up(self.smap[i], s, bit, 1023)
            t[si] = _hist_up(s, bit)
        self.slot_up(self.o0, self.c0, bit, 1023)
        if self.mexp >= 0:
            self.slot_up(self.msm, _len_bucket(self.mlen) * 2 + self.mexp, bit, 1023)
            if self.mexp != bit: self.mlen = 0
        err = ((bit << 12) - self.pm1) * 7; err2 = ((bit << 12) - self.pm2) * 7
        w = self.w[self.wsel]; w2 = self.w2[self.wsel2]; x = self.x
        for i in range(CM_NI):
            w[i] = _wclamp(w[i] + ((x[i] * err) >> 14)); w2[i] = _wclamp(w2[i] + ((x[i] * err2) >> 14))
        g = 65535 if bit else 0
        self.a1[self.a1i] += (g - self.a1[self.a1i]) >> 7
        self.a2[self.a2i] += (g - self.a2[self.a2i]) >> 7
        self.c0 = (self.c0 << 1) | bit; self.nib = (self.nib << 1) | bit; self.bitpos += 1
        if self.bitpos == 8:
            c = self.c0 & 255; self.pos += 1
            self.byte_update(c)
            self.c0 = 1; self.bitpos = 0; self.nib = 1; self.set_bases()
        elif self.bitpos == 4:
            self.nib = 1; self.set_bases()

def _cm_check(tbits, n):
    if not (CM_MINBITS <= tbits <= CM_MAXBITS) or n > _M32: raise ValueError("bad parameters")

def cm_encode(data, tbits=22):
    """Same output as the C encoder; None if it would not fit in len(data) + 4096 bytes (like _vulp.cm_encode)."""
    d = bytes(data); _cm_check(tbits, len(d)); m = _CM(tbits, d); m.set_bases()
    x1 = 0; x2 = _M32; out = bytearray(); cap = len(d) + 4096
    for byte in d:
        for b in range(7, -1, -1):
            bit = (byte >> b) & 1; p = m.predict()
            r = (x2 - x1) & _M32; xm = (x1 + (r >> 12) * p + (((r & 0xfff) * p) >> 12)) & _M32
            if bit: x2 = xm
            else: x1 = (xm + 1) & _M32
            m.update(bit)
            while ((x1 ^ x2) & 0xff000000) == 0:
                out.append(x2 >> 24); x1 = (x1 << 8) & _M32; x2 = ((x2 << 8) | 255) & _M32
    for _ in range(4): out.append(x1 >> 24); x1 = (x1 << 8) & _M32
    return bytes(out) if len(out) <= cap else None

def cm_decode(payload, n: int, tbits: int) -> bytes:
    p = bytes(payload); _cm_check(tbits, n)
    if len(p) < 4: raise ValueError("corrupt encoded data")
    out = bytearray(n); m = _CM(tbits, out); m.set_bases()
    x1 = 0; x2 = _M32; x = int.from_bytes(p[:4], "big"); ip = 4
    for i in range(n):
        c = 0
        for b in range(7, -1, -1):
            pr = m.predict()
            r = (x2 - x1) & _M32; xm = (x1 + (r >> 12) * pr + (((r & 0xfff) * pr) >> 12)) & _M32
            bit = 1 if x <= xm else 0
            if bit: x2 = xm
            else: x1 = (xm + 1) & _M32
            c = (c << 1) | bit
            if b == 0: out[i] = c
            m.update(bit)
            while ((x1 ^ x2) & 0xff000000) == 0:
                if ip >= len(p): raise ValueError("corrupt encoded data")
                x1 = (x1 << 8) & _M32; x2 = ((x2 << 8) | 255) & _M32; x = ((x << 8) | p[ip]) & _M32; ip += 1
    if ip != len(p): raise ValueError("corrupt encoded data")
    return bytes(out)
