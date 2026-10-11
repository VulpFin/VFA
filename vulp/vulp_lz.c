/* Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
 *
 * vulp_lz - VFA2 coder 3 "vulp-lz" (M4) and content-defined chunking. See vulp.h and VFA2.md ("vulp-lz").
 * Integer arithmetic only. The decoder bounds-checks every read and every copy and must consume its input exactly.
 *
 * Payload = LZ blocks, back to back, whose raw sizes add up to the chunk's filtered size:
 *   u32 raw_len   u32 nseq   u32 nlit
 *   u32 size, tANS(literals, nlit bytes)
 *   u32 size, tANS(literal-length codes, nseq bytes)
 *   u32 size, tANS(match-length codes, nseq bytes)
 *   u32 size, tANS(offset codes, nseq bytes)
 *   u32 nbits, extra-bits stream (LSB-first, read forwards)
 * Sequence i: copy ll literals, then copy ml bytes from `offset` bytes back. Values are sent as a code (byte) plus
 * extra bits: v < 16 -> code v; else hb = floor(log2 v), code = 16 + 2(hb-4) + bit (hb-1) of v, extra = low hb-1 bits.
 * ll = value, ml = value + MINMATCH, offset value 0 = repeat the previous offset (initially 1), else the offset.
 * After the sequences, the remaining literals of the block are copied. Offsets reach back across blocks (one chunk).
 */
#include "vulp.h"
#include <stdlib.h>
#include <string.h>

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

static unsigned highbit32(uint32_t v) { unsigned r = 0; while (v >>= 1) r++; return r; }

/* ------------------------------------------------------------------ value codes */

static unsigned vcode(uint32_t v, uint32_t *extra, unsigned *nb)
{
    unsigned hb;
    if (v < 16) { *extra = 0; *nb = 0; return v; }
    hb = highbit32(v);
    *nb = hb - 1;
    *extra = v & (((uint32_t)1 << (hb - 1)) - 1);
    return 16 + 2 * (hb - 4) + ((v >> (hb - 1)) & 1);
}

/* ------------------------------------------------------------------ bit streams (forward, LSB-first) */

typedef struct { uint8_t *p; size_t len, cap; uint64_t acc; unsigned nacc; uint64_t nbits; int overflow; } fbw;

static void fbw_put(fbw *w, uint32_t v, unsigned nb)
{
    if (!nb) return;
    w->acc |= (uint64_t)v << w->nacc; w->nacc += nb; w->nbits += nb;
    while (w->nacc >= 8) {
        if (w->len < w->cap) w->p[w->len] = (uint8_t)w->acc; else w->overflow = 1;
        w->len++; w->acc >>= 8; w->nacc -= 8;
    }
}

static void fbw_flush(fbw *w)
{
    if (w->nacc) { if (w->len < w->cap) w->p[w->len] = (uint8_t)w->acc; else w->overflow = 1; w->len++; w->acc = 0; w->nacc = 0; }
}

typedef struct { const uint8_t *p; uint64_t nbits, pos; } fbr;

static int fbr_get(fbr *r, unsigned nb, uint32_t *out)
{
    uint64_t v = 0;
    unsigned got = 0;
    if (nb > r->nbits - r->pos) return VULP_E_CORRUPT;
    while (got < nb) {
        uint64_t byte = r->p[r->pos >> 3];
        unsigned off = (unsigned)(r->pos & 7), take = 8 - off;
        if (take > nb - got) take = nb - got;
        v |= ((byte >> off) & ((1u << take) - 1)) << got;
        got += take; r->pos += take;
    }
    *out = (uint32_t)v;
    return VULP_OK;
}

/* ------------------------------------------------------------------ encoder */

typedef struct {
    const uint8_t *in; size_t n;
    /* local hash chains */
    uint32_t *head, *chain; unsigned hlog; uint32_t wmask, depth; int lazy; unsigned skip_shift;
    /* long-range sparse table of rolling hashes */
    uint32_t *ltab; unsigned llog; uint32_t h, bpow; size_t hpos;
    /* current block */
    uint8_t *lits; uint32_t nlit, litcap;
    uint8_t *llc, *mlc, *ofc; uint32_t nseq, seqcap;
    fbw extra; uint8_t *extrabuf;
    uint64_t block_raw;
    uint32_t rep;
    /* output */
    uint8_t *out; size_t cap, olen; int err;
} lzenc;

#define LH_MUL 2654435761u
#define RH_BASE 0x01000193u

static uint32_t hash4(const uint8_t *p, unsigned bits) { return (rd32(p) * LH_MUL) >> (32 - bits); }

/* Long-range anchors are content-defined: a position is inserted into (and looked up in) the sparse table only when
 * its rolling hash passes this test (about 1 in VULP_LZ_LONG_STRIDE). A duplicated region has the same anchors in
 * both copies, so it is still found, and backward extension recovers the true start of the match. */
static int is_anchor(uint32_t h) { return ((h * 0x85EBCA6Bu) >> 28) == 0; }

static void roll_init(lzenc *e, size_t p)
{
    unsigned i;
    e->h = 0;
    for (i = 0; i < VULP_LZ_LONG_MIN; i++) e->h = e->h * RH_BASE + e->in[p + i];
    e->hpos = p;
}

/* insert position q (all positions are inserted exactly once, in order) */
static void advance(lzenc *e, size_t q)
{
    if (q + VULP_LZ_MINMATCH <= e->n) {
        uint32_t hv = hash4(e->in + q, e->hlog);
        e->chain[q & e->wmask] = e->head[hv];
        e->head[hv] = (uint32_t)(q + 1);
    }
    if (e->ltab && q + VULP_LZ_LONG_MIN <= e->n) {
        if (e->hpos != q) roll_init(e, q);
        if (is_anchor(e->h)) e->ltab[(e->h * LH_MUL) >> (32 - e->llog)] = (uint32_t)(q + 1);
        if (q + VULP_LZ_LONG_MIN < e->n) {
            e->h = (e->h - e->in[q] * e->bpow) * RH_BASE + e->in[q + VULP_LZ_LONG_MIN];
            e->hpos = q + 1;
        }
    }
}

static size_t match_len(const uint8_t *a, const uint8_t *b, size_t max)
{
    size_t l = 0;
    while (l < max && a[l] == b[l]) l++;
    return l;
}

/* long-range candidate only (used on positions the accelerated literal scan does not search fully) */
static size_t find_long(lzenc *e, size_t p, uint32_t *off_out)
{
    size_t l;
    uint32_t c;
    if (!e->ltab || p + VULP_LZ_LONG_MIN > e->n || e->hpos != p || !is_anchor(e->h)) return 0;
    c = e->ltab[(e->h * LH_MUL) >> (32 - e->llog)];
    if (!c || (size_t)c - 1 >= p || memcmp(e->in + c - 1, e->in + p, VULP_LZ_LONG_MIN)) return 0;
    l = match_len(e->in + p, e->in + c - 1, e->n - p);
    *off_out = (uint32_t)(p - (c - 1));
    return l;
}

/* best match at p over positions < p: returns length (0 if < MINMATCH) and offset */
static size_t find_match(lzenc *e, size_t p, uint32_t *off_out)
{
    const uint8_t *in = e->in;
    size_t max = e->n - p, best = 0, l;
    uint32_t best_off = 0, depth = e->depth, cur;
    if (max < VULP_LZ_MINMATCH) return 0;
    /* repeat offset */
    if (e->rep <= p) {
        l = match_len(in + p, in + p - e->rep, max);
        if (l >= VULP_LZ_MINMATCH) { best = l; best_off = e->rep; }
    }
    /* local chains */
    cur = e->head[hash4(in + p, e->hlog)];
    while (cur && depth--) {
        size_t cand = (size_t)cur - 1;
        if (cand >= p || p - cand > e->wmask) break;
        if (best < max && in[cand + best] == in[p + best]) {
            l = match_len(in + p, in + cand, max);
            if (l > best) { best = l; best_off = (uint32_t)(p - cand); }   /* nearest first: ties keep the smaller offset */
        }
        {
            uint32_t nxt = e->chain[cand & e->wmask];
            if (nxt >= cur) break;
            cur = nxt;
        }
    }
    /* long range */
    if (e->ltab && p + VULP_LZ_LONG_MIN <= e->n && e->hpos == p && is_anchor(e->h)) {   /* rolling hash is at p */
        uint32_t c = e->ltab[(e->h * LH_MUL) >> (32 - e->llog)];
        if (c) {
            size_t cand = (size_t)c - 1;
            if (cand < p && !memcmp(in + cand, in + p, VULP_LZ_LONG_MIN)) {
                l = match_len(in + p, in + cand, max);
                if (l > best + 8 || (l > best && best < VULP_LZ_LONG_MIN)) { best = l; best_off = (uint32_t)(p - cand); }
            }
        }
    }
    if (best < VULP_LZ_MINMATCH) return 0;
    *off_out = best_off;
    return best;
}

static void put_u32(lzenc *e, uint32_t v)
{
    if (e->err) return;
    if (e->cap - e->olen < 4) { e->err = VULP_E_SPACE; return; }
    wr32(e->out + e->olen, v); e->olen += 4;
}

static void put_tans(lzenc *e, const uint8_t *data, size_t n)
{
    size_t at, got = 0;
    int rc;
    if (e->err) return;
    if (e->cap - e->olen < 4) { e->err = VULP_E_SPACE; return; }
    at = e->olen; e->olen += 4;
    rc = vulp_tans_encode(data, n, e->out + e->olen, e->cap - e->olen, &got);
    if (rc != VULP_OK) { e->err = rc; return; }
    if (got > 0xFFFFFFFFu) { e->err = VULP_E_SPACE; return; }
    wr32(e->out + at, (uint32_t)got); e->olen += got;
}

static void flush_block(lzenc *e)
{
    if (e->block_raw == 0) return;
    if (e->block_raw > 0xFFFFFFFFu) { e->err = VULP_E_SPACE; return; }
    fbw_flush(&e->extra);
    if (e->extra.overflow) { e->err = VULP_E_SPACE; return; }
    put_u32(e, (uint32_t)e->block_raw); put_u32(e, e->nseq); put_u32(e, e->nlit);
    put_tans(e, e->lits, e->nlit);
    put_tans(e, e->llc, e->nseq); put_tans(e, e->mlc, e->nseq); put_tans(e, e->ofc, e->nseq);
    if (!e->err && e->extra.nbits > 0xFFFFFFFFu) e->err = VULP_E_SPACE;
    put_u32(e, (uint32_t)e->extra.nbits);
    if (!e->err) {
        if (e->cap - e->olen < e->extra.len) e->err = VULP_E_SPACE;
        else { memcpy(e->out + e->olen, e->extrabuf, e->extra.len); e->olen += e->extra.len; }
    }
    e->nlit = 0; e->nseq = 0; e->block_raw = 0;
    e->extra.len = 0; e->extra.acc = 0; e->extra.nacc = 0; e->extra.nbits = 0;
}

static void add_literals(lzenc *e, size_t from, size_t to)
{
    memcpy(e->lits + e->nlit, e->in + from, to - from);
    e->nlit += (uint32_t)(to - from);
    e->block_raw += to - from;
}

static void add_seq(lzenc *e, size_t lit_from, size_t p, size_t ml, uint32_t off)
{
    uint32_t extra, ov;
    unsigned nb, c;
    size_t ll = p - lit_from;
    add_literals(e, lit_from, p);
    c = vcode((uint32_t)ll, &extra, &nb); e->llc[e->nseq] = (uint8_t)c; fbw_put(&e->extra, extra, nb);
    c = vcode((uint32_t)(ml - VULP_LZ_MINMATCH), &extra, &nb); e->mlc[e->nseq] = (uint8_t)c; fbw_put(&e->extra, extra, nb);
    ov = (off == e->rep) ? 0 : off;
    c = vcode(ov, &extra, &nb); e->ofc[e->nseq] = (uint8_t)c; fbw_put(&e->extra, extra, nb);
    e->rep = off;
    e->nseq++;
    e->block_raw += ml;
}

size_t vulp_lz_bound(size_t n)
{
    /* worst case: short matches with far offsets cost up to ~7 bytes per 4 input bytes (3 RAW code bytes + extra
     * bits), so allow 2n plus per-block headers and tANS block headers. Callers may pass a smaller buffer and treat
     * VULP_E_SPACE as "LZ does not pay off here". */
    size_t blocks = n / (VULP_LZ_BLOCK / 2) + 2;
    return 2 * n + blocks * (12 + 4 * 4 + 4 + 4 * 64) + 64;
}

int vulp_lz_encode(const uint8_t *in, size_t n, int level, uint8_t *out, size_t cap, size_t *out_len)
{
    lzenc e;
    size_t p = 0, lit_start = 0, adv = 0, ltsize;
    static const uint32_t depths[10] = {2, 4, 6, 8, 12, 16, 24, 32, 64, 128};
    static const unsigned skips[10] = {5, 5, 6, 6, 7, 7, 7, 8, 9, 0};       /* 0: search every position */
    unsigned i;
    int rc;
    if (n > 0xFFFFFFFFu) return VULP_E_PARAM;
    if (level < 0) level = 0;
    if (level > 9) level = 9;
    memset(&e, 0, sizeof e);
    e.in = in; e.n = n; e.out = out; e.cap = cap; e.rep = 1;
    e.hlog = 17; e.wmask = ((uint32_t)1 << VULP_LZ_WINDOW_LOG) - 1;
    e.depth = depths[level]; e.lazy = level >= 4; e.skip_shift = skips[level];
    e.bpow = 1;
    for (i = 0; i < VULP_LZ_LONG_MIN - 1; i++) e.bpow *= RH_BASE;   /* RH_BASE^(MIN-1): weight of the outgoing byte */
    e.litcap = VULP_LZ_BLOCK + 8; e.seqcap = VULP_LZ_BLOCK / VULP_LZ_MINMATCH + 8;
    e.head = (uint32_t *)calloc((size_t)1 << e.hlog, sizeof(uint32_t));
    e.chain = (uint32_t *)calloc((size_t)e.wmask + 1, sizeof(uint32_t));
    e.lits = (uint8_t *)malloc(e.litcap);
    e.llc = (uint8_t *)malloc(e.seqcap); e.mlc = (uint8_t *)malloc(e.seqcap); e.ofc = (uint8_t *)malloc(e.seqcap);
    e.extra.cap = (size_t)e.seqcap * 12 + 16; e.extrabuf = (uint8_t *)malloc(e.extra.cap); e.extra.p = e.extrabuf;
    if (n >= 4 * VULP_LZ_LONG_MIN) {
        ltsize = 1; e.llog = 0;
        while (ltsize < n / VULP_LZ_LONG_STRIDE && e.llog < 22) { ltsize <<= 1; e.llog++; }
        if (e.llog < 8) { e.llog = 8; ltsize = 256; }
        e.ltab = (uint32_t *)calloc(ltsize, sizeof(uint32_t));
        if (!e.ltab) { rc = VULP_E_NOMEM; goto done; }
    }
    if (!e.head || !e.chain || !e.lits || !e.llc || !e.mlc || !e.ofc || !e.extrabuf) { rc = VULP_E_NOMEM; goto done; }
    e.hpos = (size_t)-1;
    if (e.ltab) roll_init(&e, 0);

    while (p + VULP_LZ_MINMATCH <= n && !e.err) {
        uint32_t off = 0, off2 = 0;
        size_t len, len2;
        while (adv < p) advance(&e, adv++);
        /* accelerated literal scan: the longer the current literal run, the fewer positions get a full search
         * (every position is still inserted, and long-range anchors are still checked everywhere) */
        if (e.skip_shift && p - lit_start >= ((size_t)1 << e.skip_shift) &&
            ((p - lit_start) % (1 + ((p - lit_start) >> e.skip_shift))) != 0)
            len = find_long(&e, p, &off);
        else
            len = find_match(&e, p, &off);
        if (len && e.lazy && len < 64 && p + 1 + VULP_LZ_MINMATCH <= n) {
            advance(&e, adv++);                           /* p is now inserted; look one position ahead */
            len2 = find_match(&e, p + 1, &off2);
            if (len2 > len + 1) { p++; len = len2; off = off2; }
        }
        if (!len) {
            p++;
            if (e.block_raw + (p - lit_start) >= VULP_LZ_BLOCK) {   /* long literal run: end the block here */
                add_literals(&e, lit_start, p); lit_start = p; flush_block(&e);
            }
            continue;
        }
        while (p > lit_start && p > off && in[p - 1] == in[p - 1 - off]) { p--; len++; }   /* extend backwards */
        add_seq(&e, lit_start, p, len, off);
        p += len; lit_start = p;
        if (e.block_raw >= VULP_LZ_BLOCK || e.nseq + 2 >= e.seqcap) flush_block(&e);
    }
    /* trailing literals: the run so far is < VULP_LZ_BLOCK (flushed above otherwise), plus < MINMATCH tail bytes */
    if (!e.err && lit_start < n) add_literals(&e, lit_start, n);
    flush_block(&e);
    rc = e.err;
    if (rc == VULP_OK) *out_len = e.olen;
done:
    free(e.head); free(e.chain); free(e.ltab); free(e.lits); free(e.llc); free(e.mlc); free(e.ofc); free(e.extrabuf);
    return rc;
}

/* ------------------------------------------------------------------ decoder */

static int get_u32(const uint8_t *in, size_t in_len, size_t *ip, uint32_t *v)
{
    if (in_len - *ip < 4) return VULP_E_CORRUPT;
    *v = rd32(in + *ip); *ip += 4;
    return VULP_OK;
}

static int get_stream(const uint8_t *in, size_t in_len, size_t *ip, uint8_t *dst, size_t n)
{
    uint32_t sz;
    if (get_u32(in, in_len, ip, &sz) != VULP_OK || in_len - *ip < sz) return VULP_E_CORRUPT;
    if (vulp_tans_decode(in + *ip, sz, dst, n) != VULP_OK) return VULP_E_CORRUPT;
    *ip += sz;
    return VULP_OK;
}

static int get_value(fbr *r, unsigned code, uint32_t *v)
{
    unsigned k, hb;
    uint32_t extra;
    if (code < 16) { *v = code; return VULP_OK; }
    if (code > VULP_LZ_MAXCODE) return VULP_E_CORRUPT;
    k = code - 16; hb = k / 2 + 4;
    if (fbr_get(r, hb - 1, &extra) != VULP_OK) return VULP_E_CORRUPT;
    *v = ((uint32_t)(2 | (k & 1)) << (hb - 1)) | extra;
    return VULP_OK;
}

int vulp_lz_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t n)
{
    size_t ip = 0, op = 0;
    uint32_t rep = 1;
    uint8_t *lits = NULL, *codes = NULL;
    size_t litcap = 0, codecap = 0;
    int rc = VULP_E_CORRUPT;
    while (op < n) {
        uint32_t raw, nseq, nlit, nbits, i, ll, mv, ov;
        size_t lp = 0, bend, nbytes;
        fbr r;
        if (get_u32(in, in_len, &ip, &raw) || get_u32(in, in_len, &ip, &nseq) || get_u32(in, in_len, &ip, &nlit)) goto out;
        if (raw == 0 || raw > n - op || nlit > raw || nseq > raw / VULP_LZ_MINMATCH) goto out;
        bend = op + raw;
        if (nlit > litcap) { free(lits); litcap = nlit; lits = (uint8_t *)malloc(litcap ? litcap : 1); if (!lits) { rc = VULP_E_NOMEM; goto out; } }
        if ((size_t)nseq * 3 > codecap) { free(codes); codecap = (size_t)nseq * 3; codes = (uint8_t *)malloc(codecap ? codecap : 1); if (!codes) { rc = VULP_E_NOMEM; goto out; } }
        if (get_stream(in, in_len, &ip, lits, nlit) || get_stream(in, in_len, &ip, codes, nseq) ||
            get_stream(in, in_len, &ip, codes + nseq, nseq) || get_stream(in, in_len, &ip, codes + 2 * (size_t)nseq, nseq)) goto out;
        if (get_u32(in, in_len, &ip, &nbits)) goto out;
        nbytes = (size_t)(((uint64_t)nbits + 7) >> 3);
        if (in_len - ip < nbytes) goto out;
        if ((nbits & 7) && (in[ip + nbytes - 1] >> (nbits & 7))) goto out;          /* padding bits must be zero */
        r.p = in + ip; r.nbits = nbits; r.pos = 0;
        for (i = 0; i < nseq; i++) {
            uint64_t ml;
            if (get_value(&r, codes[i], &ll) || get_value(&r, codes[nseq + i], &mv) || get_value(&r, codes[2 * (size_t)nseq + i], &ov)) goto out;
            if (ll > nlit - lp || ll > bend - op) goto out;
            memcpy(out + op, lits + lp, ll); op += ll; lp += ll;
            ml = (uint64_t)mv + VULP_LZ_MINMATCH;
            if (ov) rep = ov;
            if (rep > op || ml > bend - op) goto out;
            {
                uint8_t *d = out + op; const uint8_t *s = d - rep;
                size_t k, m = (size_t)ml;
                if (rep >= m) memcpy(d, s, m);
                else for (k = 0; k < m; k++) d[k] = s[k];                          /* overlapping copy */
                op += m;
            }
        }
        if (r.pos != r.nbits) goto out;                                           /* every extra bit used */
        if (nlit - lp != bend - op) goto out;                                     /* trailing literals fill the block */
        memcpy(out + op, lits + lp, nlit - lp); op += nlit - lp;
        ip += nbytes;
    }
    rc = ip == in_len ? VULP_OK : VULP_E_CORRUPT;
out:
    free(lits); free(codes);
    return rc;
}

/* ------------------------------------------------------------------ content-defined chunking */

size_t vulp_cdc(const uint8_t *in, size_t n, uint32_t min_size, unsigned avg_log, uint32_t max_size,
                uint64_t *cuts, size_t max_cuts)
{
    uint32_t gear[256], x = 0x9E3779B9u, h = 0;
    size_t i, start = 0, nc = 0;
    if (avg_log < 1) avg_log = 1;
    if (avg_log > 30) avg_log = 30;
    for (i = 0; i < 256; i++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; gear[i] = x; }   /* fixed table */
    for (i = 0; i < n && nc < max_cuts; i++) {
        size_t len = i - start + 1;
        h = (h << 1) + gear[in[i]];          /* the top bits depend on the last 32 bytes: test those */
        if ((len >= min_size && (h >> (32 - avg_log)) == 0) || len >= max_size) {
            cuts[nc++] = i + 1; start = i + 1; h = 0;
        }
    }
    if (n > start && nc < max_cuts) cuts[nc++] = n;
    return nc;
}
