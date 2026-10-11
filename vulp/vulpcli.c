/* Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
 *
 * vulpcli - standalone driver for vulp.c, used by test_vfa.py (no Python involved, so each compiler and
 * optimisation level is tested on its own):
 *
 *   vulpcli digest FILE...        every filter config + tANS: one line per file with a running CRC32 of every
 *                                 output (cost as u64 LE, filtered bytes, encoded bytes). Builds must print identical
 *                                 lines; test_vfa.py recomputes the same CRC through the _vulp extension.
 *                                 Also decodes everything back and exits 1 on any mismatch.
 *   vulpcli fuzz FILE N SEED      encode FILE, then decode N corrupted/truncated variants. Built with sanitizers,
 *                                 the oracle is "no crash, no sanitizer report"; prints how many were refused.
 */
#include "vulp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct { int id; uint8_t p[2]; size_t plen; } CONFIGS[] = {
    {VULP_F_NONE, {0, 0}, 0},   {VULP_F_DELTA, {1, 0}, 1},   {VULP_F_DELTA, {2, 0}, 1},   {VULP_F_DELTA, {4, 0}, 1},
    {VULP_F_SHUFFLE, {2, 0}, 2}, {VULP_F_SHUFFLE, {4, 0}, 2}, {VULP_F_SHUFFLE, {8, 0}, 2}, {VULP_F_SHUFFLE, {4, 1}, 2},
    {VULP_F_SHUFFLE, {8, 1}, 2}, {VULP_F_SHUFFLE, {16, 1}, 2}, {VULP_F_BCJ_X86, {0, 0}, 0}, {VULP_F_BCJ_ARM64, {0, 0}, 0},
};
#define NCONF (sizeof CONFIGS / sizeof CONFIGS[0])

static uint32_t crc(uint32_t c, const uint8_t *p, size_t n)    /* zlib CRC-32, bitwise: same as zlib.crc32 */
{
    size_t i;
    int k;
    c = ~c;
    for (i = 0; i < n; i++) {
        c ^= p[i];
        for (k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

static uint8_t *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    uint8_t *b = NULL;
    size_t cap = 0, len = 0, r;
    if (!f) return NULL;
    for (;;) {
        if (len == cap) { uint8_t *nb; cap = cap ? cap * 2 : 1 << 16; nb = (uint8_t *)realloc(b, cap); if (!nb) { free(b); fclose(f); return NULL; } b = nb; }
        r = fread(b + len, 1, cap - len, f);
        if (!r) break;
        len += r;
    }
    fclose(f);
    *n = len;
    return b ? b : (uint8_t *)malloc(1);
}

static int digest(const char *path)
{
    size_t n, c, elen;
    uint8_t *in = slurp(path, &n), *flt, *enc, *dec, *back;
    uint32_t h = 0;
    int bad = 0;
    if (!in) { fprintf(stderr, "cannot read %s\n", path); return 1; }
    flt = (uint8_t *)malloc(n + 1); dec = (uint8_t *)malloc(n + 1); back = (uint8_t *)malloc(n + 1);
    enc = (uint8_t *)malloc(vulp_tans_bound(n));
    if (!flt || !dec || !back || !enc) { fprintf(stderr, "out of memory\n"); return 1; }
    for (c = 0; c < NCONF; c++) {
        uint64_t cost;
        uint8_t cb[8];
        int i;
        if (vulp_filter_fwd(CONFIGS[c].id, CONFIGS[c].p, CONFIGS[c].plen, in, flt, n) != VULP_OK) { bad = 1; break; }
        cost = vulp_cost_order0(flt, n);
        for (i = 0; i < 8; i++) cb[i] = (uint8_t)(cost >> (8 * i));
        if (vulp_tans_encode(flt, n, enc, vulp_tans_bound(n), &elen) != VULP_OK) { bad = 1; break; }
        h = crc(h, cb, 8); h = crc(h, flt, n); h = crc(h, enc, elen);
        if (vulp_tans_decode(enc, elen, dec, n) != VULP_OK || memcmp(dec, flt, n)) { bad = 1; break; }
        if (vulp_filter_inv(CONFIGS[c].id, CONFIGS[c].p, CONFIGS[c].plen, dec, back, n) != VULP_OK || memcmp(back, in, n)) { bad = 1; break; }
        if (c == 0) printf("size=%lu tans=%lu", (unsigned long)n, (unsigned long)elen);
    }
    printf(" digest=%08lx%s\n", (unsigned long)h, bad ? " ROUNDTRIP-FAIL" : "");
    free(in); free(flt); free(enc); free(dec); free(back);
    return bad;
}

static uint64_t rng_state;
static uint32_t rnd(void)                       /* xorshift64* */
{
    rng_state ^= rng_state >> 12; rng_state ^= rng_state << 25; rng_state ^= rng_state >> 27;
    return (uint32_t)((rng_state * 0x2545F4914F6CDD1DULL) >> 32);
}

static int fuzz(const char *path, long iters, unsigned long seed)
{
    size_t n, elen, i;
    uint8_t *in = slurp(path, &n), *enc, *mut, *out;
    long it, refused = 0, same = 0, differ = 0;
    if (!in) { fprintf(stderr, "cannot read %s\n", path); return 1; }
    if (n > (1u << 20)) n = 1u << 20;
    enc = (uint8_t *)malloc(vulp_tans_bound(n)); out = (uint8_t *)malloc(n + 1);
    if (!enc || !out || vulp_tans_encode(in, n, enc, vulp_tans_bound(n), &elen) != VULP_OK) return 1;
    rng_state = seed * 0x9E3779B97F4A7C15ULL + 1;
    for (it = 0; it < iters; it++) {
        size_t mlen = elen, k, flips;
        size_t outn = n;
        uint32_t how = rnd() % 4;
        mut = (uint8_t *)malloc(elen + 1);
        if (!mut) return 1;
        memcpy(mut, enc, elen);
        if (how == 0 && elen) mlen = rnd() % elen;                               /* truncate */
        else if (how == 3) outn = n ? rnd() % (n + 1) : 0;                       /* wrong expected size */
        else {
            flips = 1 + rnd() % 8;                                               /* flip / set bytes */
            for (k = 0; k < flips && elen; k++) {
                i = rnd() % elen;
                if (how == 1) mut[i] ^= (uint8_t)(1u << (rnd() % 8)); else mut[i] = (uint8_t)rnd();
            }
        }
        if (vulp_tans_decode(mut, mlen, out, outn) != VULP_OK) refused++;
        else if (outn == n && !memcmp(out, in, n)) same++;
        else differ++;
        free(mut);
    }
    /* "differ" is not a format failure by itself: VFA2 checks every decoded chunk against its CRC32 */
    printf("fuzz %s: %ld cases, refused %ld, identical %ld, decoded-but-different %ld\n", path, iters, refused, same, differ);
    free(in); free(enc); free(out);
    return 0;
}

int main(int argc, char **argv)
{
    int i, rc = 0;
    if (argc >= 3 && !strcmp(argv[1], "digest")) {
        for (i = 2; i < argc; i++) rc |= digest(argv[i]);
        return rc;
    }
    if (argc == 5 && !strcmp(argv[1], "fuzz")) return fuzz(argv[2], atol(argv[3]), strtoul(argv[4], NULL, 10));
    fprintf(stderr, "usage: vulpcli digest FILE... | vulpcli fuzz FILE N SEED\n");
    return 2;
}
