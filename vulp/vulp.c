/* Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
 *
 * vulp - VFA2 codec core: tANS coder, filters, integer cost estimator. See vulp.h and VFA2.md.
 * Integer arithmetic only (see vulp.h). Every read from encoded data is bounds-checked; a decoder error is
 * returned as VULP_E_CORRUPT, never as wrong bytes: a tANS block must end with its bit stream fully consumed
 * and its state back at the encoder's start state, and the caller still checks the chunk CRC32 on top.
 */
#include "vulp.h"
#include <stdlib.h>
#include <string.h>

#define BLK_RAW  0
#define BLK_RLE  1
#define BLK_TANS 2

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static void wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

static unsigned highbit32(uint32_t v)        /* floor(log2(v)), v > 0; portable, no intrinsics */
{
    unsigned r = 0;
    while (v >>= 1) r++;
    return r;
}

const char *vulp_strerror(int err)
{
    switch (err) {
    case VULP_OK: return "ok";
    case VULP_E_CORRUPT: return "corrupt encoded data";
    case VULP_E_PARAM: return "bad parameters";
    case VULP_E_NOMEM: return "out of memory";
    case VULP_E_SPACE: return "output buffer too small";
    default: return "unknown error";
    }
}

/* ------------------------------------------------------------------ integer log2 and cost */

uint32_t vulp_log2_q16(uint32_t x)           /* log2(x) in Q16, x >= 1; exact bit-by-bit squaring method */
{
    unsigned hb, i;
    uint64_t y;
    uint32_t r;
    if (x == 0) return 0;
    hb = highbit32(x);
    y = ((uint64_t)x << 31) >> hb;           /* x / 2^hb in Q31: [2^31, 2^32) */
    r = (uint32_t)hb << 16;
    for (i = 16; i-- > 0;) {
        y = (y * y) >> 31;                   /* y < 2^32 so y*y < 2^64 */
        if (y >= ((uint64_t)2 << 31)) { y >>= 1; r |= (uint32_t)1 << i; }
    }
    return r;
}

uint64_t vulp_cost_order0(const uint8_t *in, size_t n)
{
    uint32_t cnt[256];
    uint64_t bits = 0;
    size_t i, done = 0;
    /* per encoder block, like the real coder: sum c*(log2 N - log2 c) plus ~12 bits of table per symbol */
    while (done < n) {
        size_t len = n - done < VULP_TANS_BLOCK ? n - done : VULP_TANS_BLOCK;
        uint32_t lN, nsym = 0;
        memset(cnt, 0, sizeof cnt);
        for (i = 0; i < len; i++) cnt[in[done + i]]++;
        lN = vulp_log2_q16((uint32_t)len);
        for (i = 0; i < 256; i++)
            if (cnt[i]) { bits += (uint64_t)cnt[i] * (lN - vulp_log2_q16(cnt[i])); nsym++; }
        bits += ((uint64_t)nsym * 12 + 120) << 16;
        done += len;
    }
    return bits;
}

/* ------------------------------------------------------------------ tANS tables */

static uint32_t spread_step(uint32_t ts) { return (ts >> 1) + (ts >> 3) + 3; }

/* symbol spread shared by encoder and decoder (FSE-style); ts >= 32 makes the step odd, so it visits every cell */
static int spread(const uint16_t *freq, unsigned nsym, unsigned log, uint8_t *sym_at)
{
    uint32_t ts = (uint32_t)1 << log, mask = ts - 1, step = spread_step(ts), pos = 0, s, k;
    for (s = 0; s < nsym; s++)
        for (k = 0; k < freq[s]; k++) { sym_at[pos] = (uint8_t)s; pos = (pos + step) & mask; }
    return pos == 0 ? VULP_OK : VULP_E_CORRUPT;
}

typedef struct { uint16_t base; uint8_t sym; uint8_t nbits; } dentry;

static int build_dtable(const uint16_t *freq, unsigned nsym, unsigned log, dentry *dt)
{
    uint8_t sym_at[1 << VULP_TANS_MAXLOG];
    uint32_t next[256];
    uint32_t ts = (uint32_t)1 << log, u, s;
    if (spread(freq, nsym, log, sym_at) != VULP_OK) return VULP_E_CORRUPT;
    for (s = 0; s < nsym; s++) next[s] = freq[s];
    for (u = 0; u < ts; u++) {
        uint32_t ns = next[sym_at[u]]++;                /* in [f, 2f) */
        unsigned nb = log - highbit32(ns);
        dt[u].sym = sym_at[u];
        dt[u].nbits = (uint8_t)nb;
        dt[u].base = (uint16_t)((ns << nb) - ts);
    }
    return VULP_OK;
}

/* Normalise counts to frequencies summing to 2^log, every present symbol >= 1. Integer only, deterministic. */
static void normalise(const uint32_t *cnt, unsigned nsym, uint32_t total, unsigned log, uint16_t *freq)
{
    uint32_t ts = (uint32_t)1 << log, sum = 0, s, best;
    for (s = 0; s < nsym; s++) {
        uint32_t f = 0;
        if (cnt[s]) {
            f = (uint32_t)(((uint64_t)cnt[s] * ts + total / 2) / total);
            if (f == 0) f = 1;
        }
        freq[s] = (uint16_t)f; sum += f;
    }
    while (sum > ts) {                            /* take from the largest (lowest index on ties) */
        best = nsym;
        for (s = 0; s < nsym; s++) if (freq[s] > 1 && (best == nsym || freq[s] > freq[best])) best = s;
        freq[best]--; sum--;
    }
    if (sum < ts) {                               /* give the remainder to the most frequent symbol */
        best = 0;
        for (s = 1; s < nsym; s++) if (cnt[s] > cnt[best]) best = s;
        freq[best] = (uint16_t)(freq[best] + (ts - sum));
    }
}

/* ------------------------------------------------------------------ tANS encode */

typedef struct { uint8_t *p; size_t cap, len; uint64_t acc; unsigned nacc; uint64_t nbits; } bitw;

static void bw_put(bitw *w, uint32_t v, unsigned nb)       /* LSB-first; caller guarantees capacity */
{
    w->acc |= (uint64_t)v << w->nacc; w->nacc += nb; w->nbits += nb;
    while (w->nacc >= 8) { w->p[w->len++] = (uint8_t)w->acc; w->acc >>= 8; w->nacc -= 8; }
}

static void bw_flush(bitw *w) { if (w->nacc) { w->p[w->len++] = (uint8_t)w->acc; w->acc = 0; w->nacc = 0; } }

/* Encode one block with table size 2^log. Returns encoded size, or 0 if it does not fit in cap. */
static size_t enc_tans_block(const uint8_t *in, uint32_t len, const uint32_t *cnt, unsigned log, uint8_t *out, size_t cap)
{
    uint16_t freq[256], stab[1 << VULP_TANS_MAXLOG];
    uint8_t sym_at[1 << VULP_TANS_MAXLOG];
    uint32_t cum[257], dnb[256], ts = (uint32_t)1 << log, s, u, state;
    int32_t dfs[256];
    unsigned nsym = 0;
    size_t hp, i;
    bitw w;
    for (s = 0; s < 256; s++) if (cnt[s]) nsym = s + 1;
    normalise(cnt, nsym, len, log, freq);
    if (spread(freq, nsym, log, sym_at) != VULP_OK) return 0;
    cum[0] = 0;
    for (s = 0; s < nsym; s++) cum[s + 1] = cum[s] + freq[s];
    {   /* state table: for each symbol, its cells in table order */
        uint32_t fill[256];
        for (s = 0; s < nsym; s++) fill[s] = cum[s];
        for (u = 0; u < ts; u++) stab[fill[sym_at[u]]++] = (uint16_t)(ts + u);
    }
    for (s = 0; s < nsym; s++) {
        uint32_t f = freq[s];
        if (f == 0) { dnb[s] = 0; dfs[s] = 0; continue; }
        if (f == 1) dnb[s] = ((uint32_t)log << 16) - ts;
        else { uint32_t mbo = log - highbit32(f - 1); dnb[s] = (mbo << 16) - (f << mbo); }
        dfs[s] = (int32_t)cum[s] - (int32_t)f;
    }
    /* header: kind u8, raw_len u32, log u8, nsym-1 u8, freqs (LEB128, <= 2 bytes), nbits u32, state u16 */
    hp = 0;
    if (cap < 7 + 2 * (size_t)nsym + 6) return 0;
    out[hp++] = BLK_TANS; wr32(out + hp, len); hp += 4;
    out[hp++] = (uint8_t)log; out[hp++] = (uint8_t)(nsym - 1);
    for (s = 0; s < nsym; s++) {
        uint32_t f = freq[s];
        if (f >= 128) { out[hp++] = (uint8_t)(0x80 | (f & 0x7F)); out[hp++] = (uint8_t)(f >> 7); }
        else out[hp++] = (uint8_t)f;
    }
    {
        size_t bits_at = hp, room = cap - hp - 6;
        w.p = out + hp + 6; w.cap = room; w.len = 0; w.acc = 0; w.nacc = 0; w.nbits = 0;
        state = ts;
        for (i = len; i-- > 0;) {
            uint32_t sy = in[i];
            uint32_t nb = (state + dnb[sy]) >> 16;
            if (w.len + 8 > w.cap) return 0;       /* ran out of room: the caller falls back to RAW */
            bw_put(&w, state & (((uint32_t)1 << nb) - 1), nb);
            state = stab[(int32_t)(state >> nb) + dfs[sy]];
        }
        bw_flush(&w);
        if (w.nbits > 0xFFFFFFFFu) return 0;
        wr32(out + bits_at, (uint32_t)w.nbits);
        wr16(out + bits_at + 4, state - ts);
        return hp + 6 + w.len;
    }
}

size_t vulp_tans_bound(size_t n)
{
    return n + 5 * (n / VULP_TANS_BLOCK + 1) + 16;
}

int vulp_tans_encode(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t done = 0, op = 0;
    uint8_t *scratch = NULL, *best = NULL;
    size_t scap = 7 + 2 * 256 + 6 + VULP_TANS_BLOCK + 64;
    int rc = VULP_OK;
    scratch = (uint8_t *)malloc(scap); best = (uint8_t *)malloc(scap);
    if (!scratch || !best) { rc = VULP_E_NOMEM; goto out; }
    while (done < n) {
        uint32_t len = (uint32_t)(n - done < VULP_TANS_BLOCK ? n - done : VULP_TANS_BLOCK);
        uint32_t cnt[256], s;
        unsigned nsym = 0, distinct = 0, log, lo;
        size_t bsz = 5 + (size_t)len;                 /* RAW */
        const uint8_t *blk = in + done;
        memset(cnt, 0, sizeof cnt);
        for (s = 0; s < len; s++) cnt[blk[s]]++;
        for (s = 0; s < 256; s++) if (cnt[s]) { nsym = s + 1; distinct++; }
        best[0] = BLK_RAW; wr32(best + 1, len); memcpy(best + 5, blk, len);
        if (distinct == 1) {
            bsz = 6; best[0] = BLK_RLE; wr32(best + 1, len); best[5] = blk[0];
        } else {
            /* smallest table that fits the alphabet, then the usual sizes; keep whichever encodes smallest */
            lo = highbit32(nsym - 1) + 2;
            if (lo < VULP_TANS_MINLOG) lo = VULP_TANS_MINLOG;
            for (log = lo; log <= VULP_TANS_MAXLOG; log++) {
                size_t sz;
                if (log != lo && log < 9) continue;
                sz = enc_tans_block(blk, len, cnt, log, scratch, scap);
                if (sz && sz < bsz) { uint8_t *t = best; best = scratch; scratch = t; bsz = sz; }
            }
        }
        if (op + bsz > cap) { rc = VULP_E_SPACE; goto out; }
        memcpy(out + op, best, bsz); op += bsz; done += len;
    }
    *out_len = op;
out:
    free(scratch); free(best);
    return rc;
}

/* ------------------------------------------------------------------ tANS decode */

int vulp_tans_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t n)
{
    size_t ip = 0, op = 0;
    dentry dt[1 << VULP_TANS_MAXLOG];
    while (op < n) {
        uint32_t kind, len;
        if (in_len - ip < 5) return VULP_E_CORRUPT;
        kind = in[ip]; len = rd32(in + ip + 1); ip += 5;
        if (len == 0 || len > n - op) return VULP_E_CORRUPT;
        if (kind == BLK_RAW) {
            if (in_len - ip < len) return VULP_E_CORRUPT;
            memcpy(out + op, in + ip, len); ip += len;
        } else if (kind == BLK_RLE) {
            if (in_len - ip < 1) return VULP_E_CORRUPT;
            memset(out + op, in[ip], len); ip += 1;
        } else if (kind == BLK_TANS) {
            uint16_t freq[256];
            unsigned log, nsym, s;
            uint32_t ts, sum = 0, X, nbits, i;
            uint64_t bitpos;
            const uint8_t *bits;
            size_t nbytes;
            if (in_len - ip < 2) return VULP_E_CORRUPT;
            log = in[ip]; nsym = (unsigned)in[ip + 1] + 1; ip += 2;
            if (log < VULP_TANS_MINLOG || log > VULP_TANS_MAXLOG) return VULP_E_CORRUPT;
            ts = (uint32_t)1 << log;
            for (s = 0; s < nsym; s++) {
                uint32_t f;
                if (ip >= in_len) return VULP_E_CORRUPT;
                f = in[ip++];
                if (f & 0x80) {
                    if (ip >= in_len || in[ip] & 0x80) return VULP_E_CORRUPT;
                    f = (f & 0x7F) | ((uint32_t)in[ip++] << 7);
                    if (f < 128) return VULP_E_CORRUPT;          /* canonical encoding only */
                }
                if (f > ts) return VULP_E_CORRUPT;
                freq[s] = (uint16_t)f; sum += f;
            }
            if (sum != ts || freq[nsym - 1] == 0) return VULP_E_CORRUPT;
            if (in_len - ip < 6) return VULP_E_CORRUPT;
            nbits = rd32(in + ip); X = rd16(in + ip + 4); ip += 6;
            nbytes = (size_t)(((uint64_t)nbits + 7) >> 3);
            if (X >= ts || in_len - ip < nbytes) return VULP_E_CORRUPT;
            bits = in + ip;
            if ((nbits & 7) && (bits[nbytes - 1] >> (nbits & 7))) return VULP_E_CORRUPT;   /* padding must be zero */
            if (build_dtable(freq, nsym, log, dt) != VULP_OK) return VULP_E_CORRUPT;
            bitpos = nbits;
            for (i = 0; i < len; i++) {
                const dentry *e = &dt[X];
                unsigned nb = e->nbits;
                uint32_t v = 0;
                out[op + i] = e->sym;
                if (nb) {
                    uint64_t start;
                    size_t bi;
                    uint32_t w;
                    if (nb > bitpos) return VULP_E_CORRUPT;
                    start = bitpos - nb; bitpos = start;
                    bi = (size_t)(start >> 3);
                    w = bits[bi];                                /* nb <= 12 and shift <= 7: at most 3 bytes */
                    if (bi + 1 < nbytes) w |= (uint32_t)bits[bi + 1] << 8;
                    if (bi + 2 < nbytes) w |= (uint32_t)bits[bi + 2] << 16;
                    v = (w >> (start & 7)) & (((uint32_t)1 << nb) - 1);
                }
                X = e->base + v;                                 /* < ts by construction of the table */
            }
            if (bitpos != 0 || X != 0) return VULP_E_CORRUPT;   /* must end exactly where the encoder began */
            ip += nbytes;
        } else {
            return VULP_E_CORRUPT;
        }
        op += len;
    }
    return ip == in_len ? VULP_OK : VULP_E_CORRUPT;              /* no trailing bytes */
}

/* ------------------------------------------------------------------ filters */

static void delta_fwd(const uint8_t *in, uint8_t *out, size_t n, size_t d)
{
    size_t i;
    for (i = 0; i < n && i < d; i++) out[i] = in[i];
    for (; i < n; i++) out[i] = (uint8_t)(in[i] - in[i - d]);
}

static void delta_inv(const uint8_t *in, uint8_t *out, size_t n, size_t d)
{
    size_t i;
    for (i = 0; i < n && i < d; i++) out[i] = in[i];
    for (; i < n; i++) out[i] = (uint8_t)(in[i] + out[i - d]);
}

/* 8x8 bit-matrix transpose: byte t of x is row t; result byte i holds bit i of every row (bit t = row t) */
static uint64_t transpose8(uint64_t x)
{
    uint64_t t;
    t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AAULL;  x = x ^ t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCULL; x = x ^ t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0ULL; x = x ^ t ^ (t << 28);
    return x;
}

/* SHUFFLE. m = n / k elements. byte mode: out[b*m + j] = in[j*k + b], tail copied.
 * bit mode: m8 = m rounded down to 8; plane (b, i) = m8/8 bytes, plane byte g bit t = bit i of in[(8g+t)*k + b];
 * planes in order b = 0..k-1, i = 0..7; then the remaining n - m8*k bytes copied. */
static void shuffle(const uint8_t *in, uint8_t *out, size_t n, size_t k, int bitmode, int inverse)
{
    size_t m = n / k, j, b;
    if (!bitmode) {
        for (b = 0; b < k; b++)
            for (j = 0; j < m; j++) {
                if (inverse) out[j * k + b] = in[b * m + j];
                else out[b * m + j] = in[j * k + b];
            }
        memcpy(out + m * k, in + m * k, n - m * k);
    } else {
        size_t m8 = m & ~(size_t)7, groups = m8 / 8, g, t, i;
        for (b = 0; b < k; b++)
            for (g = 0; g < groups; g++) {
                uint64_t x = 0, y;
                if (!inverse) {
                    for (t = 0; t < 8; t++) x |= (uint64_t)in[(8 * g + t) * k + b] << (8 * t);
                    y = transpose8(x);
                    for (i = 0; i < 8; i++) out[(b * 8 + i) * groups + g] = (uint8_t)(y >> (8 * i));
                } else {
                    for (i = 0; i < 8; i++) x |= (uint64_t)in[(b * 8 + i) * groups + g] << (8 * i);
                    y = transpose8(x);
                    for (t = 0; t < 8; t++) out[(8 * g + t) * k + b] = (uint8_t)(y >> (8 * t));
                }
            }
        memcpy(out + m8 * k, in + m8 * k, n - m8 * k);
    }
}

/* BCJ x86: E8/E9 rel32 whose top byte is 0x00/0xFF becomes absolute modulo 2^25, sign-extended from bit 24, so the
 * top byte stays 0x00/0xFF and the same test selects the same instructions in both directions.
 * Every E8/E9 consumes 5 bytes, converted or not: a decision at i reads bytes i..i+4 only, and no conversion can
 * touch those (it starts at i+5 or later, or ended before i), so encoder and decoder make identical decisions. */
static void bcj_x86(uint8_t *buf, size_t n, int inverse)
{
    size_t i = 0;
    while (i + 5 <= n) {
        uint8_t op = buf[i];
        if (op == 0xE8 || op == 0xE9) {
            if (buf[i + 4] == 0x00 || buf[i + 4] == 0xFF) {
                uint32_t v = rd32(buf + i + 1), pos = (uint32_t)(i + 5), w;
                w = (inverse ? v - pos : v + pos) & 0x1FFFFFFu;
                if (w & 0x1000000u) w |= 0xFE000000u;
                wr32(buf + i + 1, w);
            }
            i += 5;
        } else {
            i += 1;
        }
    }
}

/* BCJ ARM64: BL imm26 (word-aligned within the chunk) becomes absolute, modulo 2^26. */
static void bcj_arm64(uint8_t *buf, size_t n, int inverse)
{
    size_t i;
    for (i = 0; i + 4 <= n; i += 4) {
        uint32_t insn = rd32(buf + i);
        if ((insn & 0xFC000000u) == 0x94000000u) {
            uint32_t imm = insn & 0x03FFFFFFu, pc = (uint32_t)(i >> 2);
            imm = (inverse ? imm - pc : imm + pc) & 0x03FFFFFFu;
            wr32(buf + i, 0x94000000u | imm);
        }
    }
}

static int filter(int id, const uint8_t *p, size_t plen, const uint8_t *in, uint8_t *out, size_t n, int inverse)
{
    switch (id) {
    case VULP_F_NONE:
        if (plen) return VULP_E_PARAM;
        memcpy(out, in, n); return VULP_OK;
    case VULP_F_DELTA:
        if (plen != 1 || p[0] < 1 || p[0] > 32) return VULP_E_PARAM;
        if (inverse) delta_inv(in, out, n, p[0]); else delta_fwd(in, out, n, p[0]);
        return VULP_OK;
    case VULP_F_SHUFFLE:
        if (plen != 2 || !(p[0] == 2 || p[0] == 4 || p[0] == 8 || p[0] == 16) || p[1] > 1) return VULP_E_PARAM;
        shuffle(in, out, n, p[0], p[1], inverse); return VULP_OK;
    case VULP_F_BCJ_X86:
        if (plen) return VULP_E_PARAM;
        memcpy(out, in, n); bcj_x86(out, n, inverse); return VULP_OK;
    case VULP_F_BCJ_ARM64:
        if (plen) return VULP_E_PARAM;
        memcpy(out, in, n); bcj_arm64(out, n, inverse); return VULP_OK;
    default:
        return VULP_E_PARAM;
    }
}

int vulp_filter_fwd(int id, const uint8_t *params, size_t plen, const uint8_t *in, uint8_t *out, size_t n)
{ return filter(id, params, plen, in, out, n, 0); }

int vulp_filter_inv(int id, const uint8_t *params, size_t plen, const uint8_t *in, uint8_t *out, size_t n)
{ return filter(id, params, plen, in, out, n, 1); }
