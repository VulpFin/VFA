/* Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
 *
 * vulp-cm (coder 2, M5): bit-wise context mixing. Integer arithmetic only (vulp.h).
 *
 * Every bit of the chunk is coded with a binary arithmetic coder from a probability that is predicted afresh for
 * that bit. The prediction comes from:
 *   - 9 hashed context models (orders 1-6 bytes, a word, a word pair, and the byte above in the previous line).
 *     Each nibble context owns a 16-byte bucket: byte 0 a check value, bytes 1-15 one bit-history state per bit
 *     position in the nibble. A bit history (counts of 0s and 1s, capped at 7, plus the last bit) is turned into a
 *     probability by a per-model adaptive table, so the model learns what each history means for this data.
 *   - an order-0 model and a match model (the longest earlier occurrence of the last 6+ bytes predicts the next bit)
 *   - two mixers (weights chosen by the partial byte and match state, and by the previous byte) combine the
 *     stretched predictions; their outputs are averaged and refined by two adaptive probability maps (APM).
 * Decoding runs the same model, so it is as slow as encoding (about 0.5-1 MB/s).
 *
 * Payload: the arithmetic-coded bits, MSB first per byte, ending with the 4 bytes that flush the coder. Frame
 * params (vfa2.py): u8 model (1), u8 table bits (16..24). Decoding refuses a payload it does not use up exactly.
 */
#include <stdlib.h>
#include <string.h>
#include "vulp.h"

#define CM_NH 9                 /* hashed context models */
#define CM_NI (CM_NH + 3)       /* + order 0, match, bias */
#define CM_MINLEN 6             /* match model: bytes of context that find a match */

static inline int32_t asr32(int32_t x, int k) { return x >= 0 ? x >> k : ~((~x) >> k); }   /* floor(x / 2^k) */
static inline int64_t asr64(int64_t x, int k) { return x >= 0 ? x >> k : ~((~x) >> k); }
static inline int32_t wclamp(int32_t w) { return w > (1 << 23) ? (1 << 23) : w < -(1 << 23) ? -(1 << 23) : w; }

/* logistic function in 12-bit fixed point: squash(d) = 4096 / (1 + e^(-d/256)), by interpolation in a table */
static const int SQ_T[33] = {1,2,3,6,10,16,27,45,73,120,194,310,488,747,1101,1546,2047,2549,2994,3348,3607,
                             3785,3901,3975,4022,4050,4068,4079,4085,4089,4092,4093,4094};
static int squash(int d)
{
    int x, i, w;
    if (d > 2047) d = 2047;
    if (d < -2047) d = -2047;
    x = d + 2048; i = x >> 7; w = x & 127;
    return (SQ_T[i] * (128 - w) + SQ_T[i + 1] * w + 64) >> 7;
}

/* adaptive probability: 22-bit p in the top bits, 10-bit count below; the rate falls as 1/(count+1.5) */
#define P_INIT (1u << 31)
static inline int p12(uint32_t s) { return (int)(s >> 20); }

/* bit history: n0 | n1 << 3 | last bit << 6, n0 and n1 capped at 7; the opposite count decays past 2 */
static inline int hist_n(uint8_t s) { return (s & 7) + ((s >> 3) & 7); }
static inline uint8_t hist_up(uint8_t s, int bit)
{
    int n0 = s & 7, n1 = (s >> 3) & 7;
    if (bit) { if (n1 < 7) n1++; if (n0 > 2) n0 = n0 / 2 + 1; }
    else     { if (n0 < 7) n0++; if (n1 > 2) n1 = n1 / 2 + 1; }
    return (uint8_t)(n0 | n1 << 3 | bit << 6);
}

static inline uint32_t hmix(uint32_t a, uint32_t b)
{
    uint32_t h = a * 0x9E3779B1u ^ (b + 0x7F4A7C15u) * 0x85EBCA6Bu;
    h ^= h >> 15; h *= 0x2C1B3C6Du; h ^= h >> 13; h *= 0x297A2D39u; h ^= h >> 16;
    return h;
}

typedef struct {
    int16_t stretch[4096];
    uint32_t dt[1024];
    int tbits;
    uint8_t *t[CM_NH];
    uint32_t base[CM_NH], h[CM_NH], smap[CM_NH][256];
    uint8_t *sp[CM_NH];
    uint32_t o0[256];
    uint32_t *mm;                       /* match table: hash of the last 6 bytes -> position after them */
    uint32_t msm[64 * 2];               /* match model: (length bucket, expected bit) */
    const uint8_t *buf; size_t pos;     /* history: the chunk itself */
    uint32_t mptr, mlen; int mexp;
    int32_t w[1024][CM_NI], w2[256 * 8][CM_NI];
    int x[CM_NI], wsel, wsel2, pm1, pm2, pmix;
    uint16_t *a1, *a2; int a1i, a2i;
    int c0, bitpos, nib;
    uint32_t c4, c8, word, word1;
    size_t line0, line1;
} Model;

static void slot_up(const Model *m, uint32_t *s, int bit, uint32_t limit)
{
    uint32_t v = *s, n = v & 1023, p = v >> 10;
    int32_t d = (bit ? (1 << 22) - 1 : 0) - (int32_t)p;
    if (d >= 0) p += (uint32_t)(((uint64_t)(uint32_t)d * m->dt[n]) >> 16);
    else        p -= (uint32_t)(((uint64_t)(uint32_t)(-d) * m->dt[n]) >> 16);
    if (n < limit) n++;
    *s = (p << 10) | n;
}

static void model_free(Model *m)
{
    int i;
    if (!m) return;
    for (i = 0; i < CM_NH; i++) free(m->t[i]);
    free(m->mm); free(m->a1); free(m->a2); free(m);
}

static Model *model_new(int tbits, const uint8_t *buf)
{
    Model *m = (Model *)calloc(1, sizeof(Model));
    int i, j, pi = 0;
    if (!m) return NULL;
    m->tbits = tbits; m->buf = buf;
    for (i = -2047; i <= 2047; i++) {                        /* stretch = inverse of squash */
        int v = squash(i);
        for (j = pi; j <= v; j++) m->stretch[j] = (int16_t)i;
        pi = v + 1;
    }
    for (j = pi; j < 4096; j++) m->stretch[j] = 2047;
    for (i = 0; i < 1024; i++) m->dt[i] = 131072u / (2u * (uint32_t)i + 3u);
    for (i = 0; i < CM_NH; i++) {
        m->t[i] = (uint8_t *)calloc((size_t)1 << tbits, 1);
        if (!m->t[i]) { model_free(m); return NULL; }
        for (j = 0; j < 256; j++) m->smap[i][j] = P_INIT;
    }
    m->mm = (uint32_t *)calloc((size_t)1 << tbits, 4);
    m->a1 = (uint16_t *)malloc((size_t)256 * 33 * 2);
    m->a2 = (uint16_t *)malloc((size_t)65536 * 33 * 2);
    if (!m->mm || !m->a1 || !m->a2) { model_free(m); return NULL; }
    for (i = 0; i < 256; i++) m->o0[i] = P_INIT;
    for (i = 0; i < 128; i++) m->msm[i] = P_INIT;
    for (i = 0; i < 1024; i++) for (j = 0; j < CM_NI; j++) m->w[i][j] = 1 << 14;
    for (i = 0; i < 256 * 8; i++) for (j = 0; j < CM_NI; j++) m->w2[i][j] = 1 << 14;
    for (j = 0; j < 33; j++) {
        uint16_t v = (uint16_t)(squash((j - 16) * 128) * 16);
        for (i = 0; i < 256; i++) m->a1[i * 33 + j] = v;
        for (i = 0; i < 65536; i++) m->a2[i * 33 + j] = v;
    }
    m->c0 = 1; m->nib = 1;
    return m;
}

/* Each nibble context looks at two neighbouring buckets for its check value; on a miss it takes over the bucket
 * whose first slot has seen fewer bits. */
static void set_bases(Model *m)
{
    uint32_t mask = ((1u << m->tbits) - 1) & ~15u;
    int i;
    for (i = 0; i < CM_NH; i++) {
        uint32_t h = hmix(m->h[i], (uint32_t)m->c0), chk = (h >> 24) | 1u;
        uint32_t b0 = h & mask, b1 = b0 ^ 16u, b;
        uint8_t *t = m->t[i];
        if (t[b0] == chk) { m->base[i] = b0; continue; }
        if (t[b1] == chk) { m->base[i] = b1; continue; }
        b = hist_n(t[b0 + 1]) <= hist_n(t[b1 + 1]) ? b0 : b1;
        t[b] = (uint8_t)chk; memset(t + b + 1, 0, 15);
        m->base[i] = b;
    }
}

static int len_bucket(uint32_t l) { return l < 16 ? (int)l : 16 + (int)(((l - 16) >> 3) > 47 ? 47 : (l - 16) >> 3); }

static void byte_update(Model *m, int c)
{
    uint32_t c4;
    size_t pos = m->pos;
    m->c8 = (m->c8 << 8) | (m->c4 >> 24);
    m->c4 = (m->c4 << 8) | (uint32_t)c;
    c4 = m->c4;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) m->word = (m->word ^ (uint32_t)(c | 32)) * 0x01000193u;
    else if (m->word) { m->word1 = m->word; m->word = 0; }
    if (c == '\n') { m->line1 = m->line0; m->line0 = pos; }
    m->h[0] = hmix(c4 & 0xff, 1);
    m->h[1] = hmix(c4 & 0xffff, 2);
    m->h[2] = hmix(c4 & 0xffffff, 3);
    m->h[3] = hmix(c4, 4);
    m->h[4] = hmix(hmix(c4, m->c8 & 0xffff), 5);
    m->h[5] = hmix(m->word, 6);
    m->h[6] = hmix(hmix(m->word, m->word1), 7);
    m->h[7] = hmix(hmix(c4, m->c8 & 0xff), 8);
    {   /* column: the byte above in the previous line, and the column */
        size_t col = pos - m->line0, above = m->line1 + col;
        uint32_t ab = above < m->line0 ? m->buf[above] : 0;
        m->h[8] = hmix(hmix(ab, (uint32_t)(col < 255 ? col : 255)), (c4 & 0xff) | 0x900u);
    }
    if (m->mlen) {
        if (m->buf[m->mptr] == (uint8_t)c) { m->mlen++; m->mptr++; } else m->mlen = 0;
    }
    if (pos >= CM_MINLEN) {
        uint32_t hh = hmix(c4, m->c8 & 0xffff) >> (32 - m->tbits);
        if (!m->mlen) {
            uint32_t p = m->mm[hh], l = 0;
            if (p) {
                while (l < 64 && l < p && m->buf[p - 1 - l] == m->buf[pos - 1 - l]) l++;
                if (l >= CM_MINLEN) { m->mlen = l; m->mptr = p; }
            }
        }
        m->mm[hh] = (uint32_t)pos;
    }
    if (m->mlen > 65535) m->mlen = 65535;
}

static int apm_p(const Model *m, const uint16_t *t, int pr, int cx, int *idx)
{
    int s = m->stretch[pr] + 2048, lo = s >> 7, w = s & 127;
    *idx = cx * 33 + lo + (w >> 6);
    return (t[cx * 33 + lo] * (128 - w) + t[cx * 33 + lo + 1] * w) >> 11;
}

static int predict(Model *m)
{
    int i, s, s2, p, p1, p2, lb = 0;
    int64_t dot = 0, dot2 = 0;
    for (i = 0; i < CM_NH; i++) {
        m->sp[i] = &m->t[i][m->base[i] + (uint32_t)m->nib];
        m->x[i] = m->stretch[p12(m->smap[i][*m->sp[i]])];
    }
    m->x[CM_NH] = m->stretch[p12(m->o0[m->c0])];
    m->mexp = -1; m->x[CM_NH + 1] = 0;
    if (m->mlen) {
        int eb = m->buf[m->mptr] | 256;
        if ((eb >> (8 - m->bitpos)) == m->c0) {
            m->mexp = (eb >> (7 - m->bitpos)) & 1;
            lb = len_bucket(m->mlen);
            m->x[CM_NH + 1] = m->stretch[p12(m->msm[lb * 2 + m->mexp])];
        }
    }
    m->x[CM_NH + 2] = 256;
    m->wsel = m->c0 + 256 * (m->mexp < 0 ? 0 : lb < 16 ? 1 : lb < 32 ? 2 : 3);
    m->wsel2 = (int)(m->c4 & 0xff) * 8 + m->bitpos;
    for (i = 0; i < CM_NI; i++) {
        dot += (int64_t)m->x[i] * m->w[m->wsel][i];
        dot2 += (int64_t)m->x[i] * m->w2[m->wsel2][i];
    }
    s = (int)asr64(dot, 16); s2 = (int)asr64(dot2, 16);
    if (s > 2047) s = 2047;
    if (s < -2047) s = -2047;
    if (s2 > 2047) s2 = 2047;
    if (s2 < -2047) s2 = -2047;
    m->pm1 = squash(s); m->pm2 = squash(s2);
    m->pmix = squash(asr32(s + s2, 1));
    p1 = apm_p(m, m->a1, m->pmix, m->c0, &m->a1i);
    p2 = apm_p(m, m->a2, m->pmix, (int)(m->c0 | ((m->c4 & 0xff) << 8)), &m->a2i);
    p = (2 * m->pmix + p1 + p2 + 2) >> 2;
    p = (p + p2 + 1) >> 1;
    if (p < 1) p = 1;
    if (p > 4095) p = 4095;
    return p;
}

static void update(Model *m, int bit)
{
    int i, err, err2;
    int32_t g = bit ? 65535 : 0;
    for (i = 0; i < CM_NH; i++) {
        slot_up(m, &m->smap[i][*m->sp[i]], bit, 1023);
        *m->sp[i] = hist_up(*m->sp[i], bit);
    }
    slot_up(m, &m->o0[m->c0], bit, 1023);
    if (m->mexp >= 0) {
        slot_up(m, &m->msm[len_bucket(m->mlen) * 2 + m->mexp], bit, 1023);
        if (m->mexp != bit) m->mlen = 0;
    }
    err = ((bit << 12) - m->pm1) * 7; err2 = ((bit << 12) - m->pm2) * 7;
    for (i = 0; i < CM_NI; i++) {     /* weights stay within +-2^23 (+-128.0): no overflow, ever */
        m->w[m->wsel][i] = wclamp(m->w[m->wsel][i] + asr32(m->x[i] * err, 14));
        m->w2[m->wsel2][i] = wclamp(m->w2[m->wsel2][i] + asr32(m->x[i] * err2, 14));
    }
    m->a1[m->a1i] = (uint16_t)(m->a1[m->a1i] + asr32(g - m->a1[m->a1i], 7));
    m->a2[m->a2i] = (uint16_t)(m->a2[m->a2i] + asr32(g - m->a2[m->a2i], 7));
    m->c0 = (m->c0 << 1) | bit; m->nib = (m->nib << 1) | bit; m->bitpos++;
    if (m->bitpos == 8) {
        int c = m->c0 & 255;
        m->pos++;
        byte_update(m, c);
        m->c0 = 1; m->bitpos = 0; m->nib = 1; set_bases(m);
    } else if (m->bitpos == 4) {
        m->nib = 1; set_bases(m);
    }
}

size_t vulp_cm_bound(size_t n) { return n + (n >> 6) + 64; }

int vulp_cm_encode(const uint8_t *in, size_t n, int tbits, uint8_t *out, size_t cap, size_t *out_len)
{
    Model *m;
    uint32_t x1 = 0, x2 = 0xffffffffu;
    size_t i, o = 0;
    int b, k;
    if (tbits < VULP_CM_MINBITS || tbits > VULP_CM_MAXBITS || n > 0xFFFFFFFFu) return VULP_E_PARAM;
    m = model_new(tbits, in);
    if (!m) return VULP_E_NOMEM;
    set_bases(m);
    for (i = 0; i < n; i++) {
        for (b = 7; b >= 0; b--) {
            int bit = (in[i] >> b) & 1, p = predict(m);
            uint32_t r = x2 - x1, xm = x1 + (r >> 12) * (uint32_t)p + (((r & 0xfff) * (uint32_t)p) >> 12);
            if (bit) x2 = xm; else x1 = xm + 1;
            update(m, bit);
            while (((x1 ^ x2) & 0xff000000u) == 0) {
                if (o >= cap) { model_free(m); return VULP_E_SPACE; }
                out[o++] = (uint8_t)(x2 >> 24); x1 <<= 8; x2 = (x2 << 8) | 255;
            }
        }
    }
    for (k = 0; k < 4; k++) {
        if (o >= cap) { model_free(m); return VULP_E_SPACE; }
        out[o++] = (uint8_t)(x1 >> 24); x1 <<= 8;
    }
    model_free(m);
    *out_len = o;
    return VULP_OK;
}

int vulp_cm_decode(const uint8_t *in, size_t in_len, int tbits, uint8_t *out, size_t n)
{
    Model *m;
    uint32_t x1 = 0, x2 = 0xffffffffu, x = 0;
    size_t i, ip = 0;
    int b, k;
    if (tbits < VULP_CM_MINBITS || tbits > VULP_CM_MAXBITS || n > 0xFFFFFFFFu) return VULP_E_PARAM;
    if (in_len < 4) return VULP_E_CORRUPT;
    m = model_new(tbits, out);
    if (!m) return VULP_E_NOMEM;
    for (k = 0; k < 4; k++) x = (x << 8) | in[ip++];
    set_bases(m);
    for (i = 0; i < n; i++) {
        int c = 0;
        for (b = 7; b >= 0; b--) {
            int p = predict(m), bit;
            uint32_t r = x2 - x1, xm = x1 + (r >> 12) * (uint32_t)p + (((r & 0xfff) * (uint32_t)p) >> 12);
            bit = x <= xm;
            if (bit) x2 = xm; else x1 = xm + 1;
            c = (c << 1) | bit;
            if (b == 0) out[i] = (uint8_t)c;            /* in the history before byte_update reads it */
            update(m, bit);
            while (((x1 ^ x2) & 0xff000000u) == 0) {
                if (ip >= in_len) { model_free(m); return VULP_E_CORRUPT; }   /* the payload ran out */
                x1 <<= 8; x2 = (x2 << 8) | 255; x = (x << 8) | in[ip++];
            }
        }
    }
    model_free(m);
    return ip == in_len ? VULP_OK : VULP_E_CORRUPT;     /* every payload byte is accounted for */
}
