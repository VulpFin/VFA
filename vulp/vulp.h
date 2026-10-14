/* Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
 *
 * vulp - the VFA2 codec core (VFA2.md, "Coders" and "Filters"). Plain C99, no dependencies beyond libc.
 *
 * RULE: integer arithmetic only. No float, no double, no <math.h>. The encoder and decoder must produce
 * bit-identical results on every compiler, optimisation level and CPU; test_vfa.py lints this file for
 * floating-point types and scans the compiled objects for floating-point instructions.
 */
#ifndef VULP_H
#define VULP_H

#include <stddef.h>
#include <stdint.h>

#define VULP_VERSION 4               /* bump when the API grows or encoder output changes (2: vulp-lz, cdc;
                                        3: optimal parser at levels 7-9; 4: vulp-cm) */

#define VULP_OK          0
#define VULP_E_CORRUPT  -1           /* the encoded data is invalid; never "best effort" output */
#define VULP_E_PARAM    -2           /* unknown filter id or malformed parameters */
#define VULP_E_NOMEM    -3
#define VULP_E_SPACE    -4           /* output buffer too small (encoder) */

/* filter ids (VFA2.md, "Filters") */
#define VULP_F_NONE       0
#define VULP_F_DELTA      1          /* params: u8 stride (1..32) */
#define VULP_F_SHUFFLE    2          /* params: u8 elem_size (2,4,8,16), u8 mode (0 byte planes, 1 bit planes) */
#define VULP_F_BCJ_X86    3          /* params: none */
#define VULP_F_BCJ_ARM64  4          /* params: none */

#define VULP_TANS_BLOCK   (1u << 17) /* block size the encoder uses; the decoder accepts any size */
#define VULP_TANS_MAXLOG  12
#define VULP_TANS_MINLOG  5

/* tANS ("vulp-tans", coder 1). The payload is a sequence of blocks (RAW / RLE / TANS) whose sizes add up to n. */
size_t vulp_tans_bound(size_t n);
int vulp_tans_encode(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *out_len);
int vulp_tans_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t n);

/* Estimated order-0 coded size of `in`, in 1/65536 bits (integer log2, Q16). Used by the encoder's classifier. */
uint64_t vulp_cost_order0(const uint8_t *in, size_t n);
uint32_t vulp_log2_q16(uint32_t x);

/* Filters are size-preserving bijections: out has exactly n bytes. in and out must not overlap. */
int vulp_filter_fwd(int id, const uint8_t *params, size_t plen, const uint8_t *in, uint8_t *out, size_t n);
int vulp_filter_inv(int id, const uint8_t *params, size_t plen, const uint8_t *in, uint8_t *out, size_t n);

/* LZ ("vulp-lz", coder 3, M4): LZ77 parse + tANS-coded literal / length / offset streams. Matches may reach back
 * anywhere in the chunk. Two match finders feed the parser (encoder only; the decoder does not care):
 *   local:  hash chains over a sliding window of 2^VULP_LZ_WINDOW_LOG bytes (sized for L2 cache)
 *   long:   a sparse table of rolling hashes of VULP_LZ_LONG_MIN-byte windows at content-defined anchors (about
 *           one position in VULP_LZ_LONG_STRIDE), covering the whole chunk (positions only - the data is the chunk) */
#define VULP_LZ_MINMATCH    4
#define VULP_LZ_WINDOW_LOG  19          /* 512 KiB local window */
#define VULP_LZ_LONG_MIN    32
#define VULP_LZ_LONG_STRIDE 16
#define VULP_LZ_BLOCK       (1u << 20)  /* raw bytes per LZ block the encoder aims for; the decoder accepts any */
#define VULP_LZ_MAXCODE     71          /* largest length/offset code (values up to 2^32-1) */
size_t vulp_lz_bound(size_t n);
int vulp_lz_encode(const uint8_t *in, size_t n, int level, uint8_t *out, size_t cap, size_t *out_len);
int vulp_lz_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t n);

/* CM ("vulp-cm", coder 2, M5): bit-wise context mixing (vulp_cm.c). tbits sets the size of each context table
 * (2^tbits bytes, 9 tables, plus a 4 * 2^tbits match table); decoding needs the same tbits and as much memory as
 * encoding, and is as slow (about 0.5-1 MB/s). The payload must be used up exactly. */
#define VULP_CM_MODEL    1
#define VULP_CM_MINBITS  16
#define VULP_CM_MAXBITS  24
size_t vulp_cm_bound(size_t n);
int vulp_cm_encode(const uint8_t *in, size_t n, int tbits, uint8_t *out, size_t cap, size_t *out_len);
int vulp_cm_decode(const uint8_t *in, size_t in_len, int tbits, uint8_t *out, size_t n);

/* Content-defined chunking (gear rolling hash) for the writer's cross-chunk dedup. Writes segment END offsets to
 * cuts (at most max_cuts) and returns how many; the last cut is always n (for n > 0). Encoder only. */
size_t vulp_cdc(const uint8_t *in, size_t n, uint32_t min_size, unsigned avg_log, uint32_t max_size,
                uint64_t *cuts, size_t max_cuts);

const char *vulp_strerror(int err);

#endif
