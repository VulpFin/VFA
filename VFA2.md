# VFA2 container format: spec revision 3 (milestone M4)

VFA2 is VFA's chunked container. Revision 1 (M1) defined the container with the single coder `stored`. Revision 2
(M3) added the `vulp-tans` coder, four filters, the `segmented` filter and the ROUTING record. **Revision 3 (M4) adds
the `vulp-lz` coder (LZ77 with a local and a long-range match finder, tANS-coded streams) and, in the writer,
content-defined dedup across chunks.** The container itself is unchanged since revision 1: an older reader opens a
newer archive and refuses, by name, exactly the chunks whose coder or filter it lacks. Dedup needs no reader
support at all; it is expressed with ordinary index extents. Context mixing (M5) is still to come.

- `vfa2.py` implements it: `Writer2` for writing, `Archive2` for reading. The codecs are C (`vulp/vulp.c`, built by
  `build_vulp.py` into the `_vulp` extension); `vulp_ref.py` is an independent pure-Python implementation of the
  same codecs, used to check the C code and as a slow fallback decoder.
- `vfa_extract.open_container()` picks VFA1 or VFA2 from the end magic. `vfa x/l/t`, `sfx_stub.py`,
  `sfi_stub.py` and `vfa_viewer.py` all go through it.
- `vfa c --format vfa2` writes VFA2.
- `test_vfa.py --format vfa2` is the correctness harness.

All integers are little-endian. "CRC32" means the zlib/IEEE CRC-32.

## Design rules

1. **Every chunk decodes on its own.** No chunk references another chunk's data. Long-range matching (M4) works
   *inside* a chunk; chunks are large (default 64 MiB, up to 1 GiB). Duplicate data *across* chunks is handled by
   the index instead: an extent is `(chunk, offset, length)` and may point into **any** chunk, so identical data is
   stored once and referenced from every file that contains it. Today the writer deduplicates whole identical
   chunks; content-defined dedup (sharing the common *parts* of two files, e.g. two versions of a setup exe) needs
   only a smarter writer, not a format change. One damaged chunk therefore never damages another, and random access
   costs at most one chunk decode per extent.
2. **Every chunk says how it was made.** Its frame names the filter and the coder. A reader that does not
   implement one of them refuses that chunk, naming the id (and the milestone it belongs to). It never guesses.
3. **Everything that matters is checked.**
   - header, each frame header, each chunk's *decoded* bytes, the index and the footer: each has a CRC32
   - the whole archive: a SHA-256 digest
   - encrypted archives: AES-256-GCM over every payload, with the cleartext frame header as associated data
4. **Streaming write.** The writer never seeks: header first, chunks as they fill, index and footer last. The
   output can be a pipe.
5. **The SFX/SFI/VFA1 conventions are kept.** The footer comes last; offsets are measured from the start of the
   archive (so `copy /b stub + a.vfa` works); the optional SFI manifest sits in front. New: the archive is still
   found after `signtool sign` appends an Authenticode certificate (see *Locating the archive*).

## Layout

```
[header][chunk frame]*[index frame][footer 66 B]
```

### Header (50 bytes in revision 1; `header_size` says how many)

| off | size | field | rule |
|---|---|---|---|
| 0 | 4 | magic | `VFA2` |
| 4 | 2 | header_size | 50 ≤ size ≤ 4096. Bytes past 46 + 4 are future *optional* fields; readers skip them. |
| 6 | 2 | spec_version | Revision of this document the writer used. Informational. |
| 8 | 2 | min_reader_version | A reader whose version is lower **refuses** ("needs a VFA2 reader of version N"). |
| 10 | 4 | required_features | bit0 `ENCRYPTED`. **Any unknown bit → refuse.** |
| 14 | 4 | optional_features | Unknown bits are ignored. |
| 18 | 1 | kdf_id | 0 none, 1 Argon2id, 2 scrypt |
| 19 | 1 | aead_id | 0 none, 1 AES-256-GCM |
| 20 | 1 | kdf_p | |
| 21 | 1 | reserved | 0 |
| 22 | 4 | kdf_t | Argon2 time / scrypt N |
| 26 | 4 | kdf_m | Argon2 KiB / scrypt r. Readers apply VFA1's caps (≤ 4 GiB of KDF memory). |
| 30 | 16 | salt | |
| size−4 | 4 | header CRC32 | over bytes `0 .. header_size−4` |

### Frames (chunks and the index)

```
magic[4]  "VCK2" (chunk) or "VIX2" (index)
u8  coder        u8 filter        u8 flags       u8 reserved (0)
u16 params_len   u64 raw_size     u32 payload_size   u32 raw_crc32
u32 frame-header CRC32   (over the 26 bytes above)
[nonce 12 B]     only if flags bit0 ENCRYPTED
params[params_len]
payload[payload_size]
```

- `raw_size`, `raw_crc32`: size and CRC32 of the chunk's **original** bytes, after decoding and the inverse
  filter. The CRC is on decoded output, so it catches a desynchronised codec, not just bit rot.
- `raw_size` ≤ 1 GiB (2^30). Readers refuse larger values, so memory per chunk is bounded.
- `flags`: bit0 ENCRYPTED. Any other bit, or a non-zero reserved byte, makes the reader refuse. Every frame's
  ENCRYPTED bit must match the header.
- `params`: empty, or `u16 filter_params_len, filter_params, coder_params`. Each filter/coder owns its own bytes.
- Chunks are contiguous: the first starts right after the header, and the last ends exactly where the index frame
  begins. The index frame uses coder 0, filter 0 and no params.

Decoding a chunk: decrypt (if encrypted) → coder decode → inverse filter → check `raw_size` and `raw_crc32`.

**Coders** (ids are never reused):

| id | name | params | status |
|---|---|---|---|
| 0 | stored | none | M1: payload = filtered data |
| 1 | vulp-tans | none | M3: see *vulp-tans* |
| 2 | vulp-cm | | reserved, M5 |
| 3 | vulp-lz | none | M4: see *vulp-lz*. The writer's default. |

**Filters** (all size-preserving bijections in this revision: filtered size = `raw_size`):

| id | name | params | status |
|---|---|---|---|
| 0 | none | none | M1 |
| 1 | delta | u8 stride, 1..32 | M3 |
| 2 | shuffle | u8 element size (2, 4, 8, 16), u8 mode (0 bytes, 1 bits) | M3. Called "bitshuffle" in the plan; mode 0 is byte-shuffle |
| 3 | bcj-x86 | none | M3 |
| 4 | bcj-arm64 | none | M3 |
| 5 | text | | reserved, not implemented (see *Known limits*) |
| 6 | segmented | segment list | M3: different filters for different parts of one chunk |

A filter or coder given parameters it does not define, or values outside the ranges above, is refused.

Adding a coder or filter does **not** need a format revision. An old reader refuses only the chunks that use it,
and names what is missing (for example "uses coder id 1 (vulp-tans (M3)), which this reader does not implement").

### Integer-only rule

Every coder and filter (and the writer's classifier) uses integer arithmetic only, so encoding and decoding are
bit-identical on every compiler, optimisation level and CPU. A future context-mixing coder (M5) is held to the same
rule: its predictor and mixer are fixed-point. `test_vfa.py --only native,codec` enforces this: source lint (C and
Python AST), a scan of the compiled code for floating-point instructions, identical output from gcc and clang at
`-O0`, `-O3` and `-O3 -march=native -ffast-math` (MSVC `/Od` and `/O2` on Windows), and bit-exact agreement between
the C codec and the pure-Python reference.

### vulp-tans (coder 1)

The payload is a sequence of blocks; their `len` fields add up to exactly the filtered size, and no bytes may
follow the last block. The writer uses 128 KiB blocks; a reader accepts any block length ≥ 1.

```
u8 kind    u32 len
kind 0 RAW:   len bytes
kind 1 RLE:   1 byte, repeated len times
kind 2 TANS:  u8 log (5..12)   u8 nsym-1   nsym x freq (LEB128, 1-2 bytes, canonical)
              u32 nbits   u16 state   bitstream[ceil(nbits/8)]
```

TANS block rules (any violation → the chunk is refused):

- `ts = 2^log`. `freq[s]` is the normalised frequency of symbol `s` for `s < nsym`; frequencies sum to exactly `ts`,
  and `freq[nsym-1] > 0`.
- **Spread:** `step = ts/2 + ts/8 + 3`, `pos = 0`; for each symbol `s` in order, `freq[s]` times: `cell[pos] = s`,
  `pos = (pos + step) mod ts`.
- **Decode table:** `next[s] = freq[s]`; for `u = 0 .. ts-1`: `s = cell[u]`, `x = next[s]++`,
  `nb[u] = log - floor(log2 x)`, `base[u] = (x << nb[u]) - ts`.
- **Decoding:** `X = state` (must be `< ts`), `pos = nbits`. For each of `len` symbols: output `cell[X]`; then take
  the `nb[X]` bits ending at `pos` (bits are numbered LSB-first through the bitstream bytes; `pos -= nb[X]`, value
  = bits `pos .. pos+nb[X]-1`, low bit first) and set `X = base[X] + value`.
- **End check:** after the last symbol, `pos` must be 0 and `X` must be 0 (the encoder's start state). Padding bits
  in the last byte must be 0. Together with the chunk CRC32, a corrupted block cannot silently decode.
- The writer's encoder (normalisation, table-size choice, block kind choice) is not normative: any encoder whose
  output decodes per the rules above is valid. VFA's own encoder is deterministic and integer-only.

Example: the 64 bytes `00`×48 `01`×16 as one TANS block (22 bytes):

```
02 | 40 00 00 00 | 05 | 01 | 18 08 | 33 00 00 00 | 11 00 | 40 55 55 55 f9 ff 07
kind len=64       log=5 nsym=2 f=24,8  nbits=51      state=17  bitstream (7 bytes)
```

### vulp-lz (coder 3)

The payload is a sequence of LZ blocks; their `raw_len` fields add up to exactly the filtered size, and no bytes may
follow the last block. Matches may reach back across blocks to any earlier byte **of the same chunk** (never into
another chunk). The writer aims for 1 MiB blocks; a reader accepts any size.

```
u32 raw_len (>= 1)   u32 nseq (<= raw_len / 4)   u32 nlit (<= raw_len)
u32 size, vulp-tans payload of the nlit literal bytes
u32 size, vulp-tans payload of nseq literal-length codes
u32 size, vulp-tans payload of nseq match-length codes
u32 size, vulp-tans payload of nseq offset codes
u32 nbits, extra-bits stream (ceil(nbits/8) bytes, bits LSB-first, read forwards; padding bits 0)
```

Each embedded stream is a complete vulp-tans payload (same block rules as coder 1) of exactly the stated length.

**Values.** Each literal length, match length and offset is sent as a code (one byte, in its stream) plus extra bits
(in the shared bit stream, in sequence order: literal length, match length, offset):
- `v < 16`: code `v`, no extra bits.
- otherwise `hb = floor(log2 v)`, code `= 16 + 2·(hb−4) + (bit hb−1 of v)`, extra = the low `hb−1` bits of v.
  Decoding code `c ≥ 16`: `k = c − 16`, `hb = k/2 + 4`, `v = ((2 + (k mod 2)) << (hb−1)) | extra`. Codes above 71 are
  invalid.

**Sequences.** For each sequence: copy `ll` literals (next bytes of the literal stream); then the match:
`ml = mv + 4`; the offset value `ov = 0` means "repeat the previous offset" (initially 1 at the start of each
chunk), otherwise the offset is `ov` (and becomes the previous offset). Copy `ml` bytes starting `offset` bytes back,
one byte at a time, so a short offset repeats a pattern. After the last sequence, the rest of the literal stream is
copied.

**Decoder rules** (any violation → the chunk is refused): every length and offset stays inside the block and the
chunk (`offset ≤` bytes already produced); the literals end exactly at the end of the block; every extra bit is
used; all four streams decode to exactly their stated lengths; no trailing bytes.

**Encoder (informative, not normative).** Two match finders feed a lazy parser:
- *local:* hash chains (2^17 heads) over a 512 KiB sliding window, sized for an L2 cache;
- *long-range:* a sparse table of rolling hashes of 32-byte windows at content-defined anchor positions (about 1 in
  16 positions), covering the whole chunk. It stores positions only, at most 2^22 entries (16 MiB), whatever the
  chunk size. Found matches are extended backwards into the pending literals.
On long literal runs the parser searches fewer positions (level 9 searches all), but it still inserts every
position and checks every long-range anchor, so long repeats inside incompressible data (e.g. two installers that
carry the same compressed payload) are still found. Levels 0–9 trade chain depth for speed (`--level`).

### Filters

`n` is the chunk's (or segment's) size; positions are offsets from the start of the chunk (or segment).

- **delta(d):** `out[i] = in[i] - in[i-d] (mod 256)` for `i ≥ d`; the first `d` bytes are copied.
- **shuffle(k, mode):** `m = n div k` elements.
  - mode 0: `out[b·m + j] = in[j·k + b]` for byte `b < k`, element `j < m`; the last `n - m·k` bytes are copied.
  - mode 1 (bit planes): `m8 = m` rounded down to a multiple of 8, `g = m8/8`. For byte `b < k` and bit `i < 8`,
    plane `(b, i)` is the `g` bytes at `out[(8b + i)·g ...]`; bit `t` of plane byte `q` is bit `i` of
    `in[(8q + t)·k + b]`. The last `n - m8·k` bytes are copied.
- **bcj-x86:** scan `i = 0, 1, ...` while `i + 5 ≤ n`. If `in[i]` is `E8` or `E9`: when byte `i+4` is `00` or `FF`,
  replace the u32 at `i+1` by `((v ± (i+5)) mod 2^25)` sign-extended from bit 24 (`+` to encode, `-` to decode);
  then, **converted or not**, continue at `i + 5`. Otherwise continue at `i + 1`. (Consuming 5 bytes even when not
  converting is what makes the transform invertible: a decision never reads a byte that a later conversion
  rewrites.)
- **bcj-arm64:** for each 4-byte-aligned word `w` (LE) with `(w & 0xFC000000) = 0x94000000` (BL): replace its low
  26 bits `imm` by `(imm ± i/4) mod 2^26`.
- **segmented (6):** params = `u32 count`, then `count` × (`u32 length`, `u8 filter`, `u8 params_len`, params).
  Each segment is filtered on its own with filter 0–4 (never 6), positions starting at 0. Lengths are ≥ 1 and add
  up to exactly `raw_size`; trailing parameter bytes are refused.

### Encryption

```
master   = Argon2id / scrypt(password, salt, header params)          (same KDFs and caps as VFA1)
data_key || index_key = HKDF-SHA256(master, salt, info="VFA2 keys v1", 64 bytes)
payload  = AES-256-GCM(key, nonce = 12 random bytes stored in the frame,
                       aad = frame header (30 B) || nonce || params)
```

- Chunks use `data_key`; the index frame uses `index_key`.
- Random nonces, so an append can never reuse one: VFA1 needed a generation counter for this.
- The frame header and params are authenticated. The coder/filter ids, sizes and CRC stay readable (the format
  stays self-describing) but cannot be changed undetected.
- Dedup is turned off when encrypting, so identical files do not reveal themselves as shared chunks.

### Index (payload of the index frame)

```
"VID2"
u32 n_chunks,   n x (u64 frame_offset, u64 raw_size, u32 raw_crc32, u8 coder, u8 filter)
u32 n_entries,  n x entry
u32 n_records,  n x (u16 type, u16 flags, u32 len, data[len])
entry:
    u8 type (0 file, 1 dir, 2 symlink, 3 hardlink)   u8 reserved   u16 path_len   path (UTF-8, '/'-separated, relative)
    u32 mode   i64 mtime (s)   u32 mtime_ns   u64 size   u32 meta_len   meta (JSON, same keys as VFA1)
    u32 n_extents,  n x (u32 chunk, u64 offset_in_chunk, u64 length)
```

- Each chunk record must equal its frame header (offset, size, CRC, coder, filter). Frames must be contiguous.
- A file's extents must lie inside their chunks, have non-zero length, and add up to `size`. Several entries may
  share an extent (dedup). Non-file entries carry no extents and size 0.
- **Records:** `flags` bit0 CRITICAL means a reader that does not know `type` must refuse. Unknown non-critical
  records are skipped.
- **Type 1 ROUTING** (non-critical, written from revision 2 on): UTF-8 JSON
  `{"v": 1, "chunks": [{"chunk", "filter", "coder", "raw", "stored", "why", "est", "segments": [...]}]}` saying why
  each chunk got its filter and coder: the classifier's size estimate for every candidate filter, the winner, and
  why a chunk was stored instead. Debugging information only: readers never depend on it, and `vfa l --routing`
  prints it.
- Unknown entry types and trailing bytes are refused.

### Footer (66 bytes, always last)

```
u64 index_offset   u64 index_frame_len   u64 archive_len   u8 digest_kind (1 = SHA-256)   digest[32]
u32 footer CRC32   "/VFA2"
```

- `archive_len` counts from the `V` of the header to the end of the footer. So
  `archive_start = end − archive_len`.
- The digest covers `archive_start .. footer`.
- `index_offset + index_frame_len` must be exactly where the footer starts.

## Locating the archive

1. `end` = file size.
2. **Signed stubs.** If the file is a PE whose security directory (Authenticode) points at a certificate table
   that ends exactly at `end`, then `end` = the table's start, minus up to 7 zero padding bytes. Without this step,
   signing an installer would hide its payload.
3. `end − 5 .. end` must read `/VFA2`. `/VFA1` means a VFA1 archive; `open_container()` dispatches on this.
4. Read the footer; `archive_start = end − archive_len`; the header magic must be there.
5. An SFI manifest (`[JSON][u32 len]["/VFIM1"]`) may sit immediately before `archive_start`, exactly as in VFA1.

## Writer behaviour (vfa.py / Writer2)

- **Non-solid** (default): each file starts a new chunk; files larger than the chunk size are split.
- **`--solid`**: files are packed back to back into chunks of 2^`--chunk-exp` bytes (default 2^26 = 64 MiB). A
  file may span chunks.
- Identical chunks (same SHA-256) are written once, unless encrypting.
- **Cross-chunk dedup** (default; `--no-dedup` turns it off; always off when encrypting). Each file's bytes are cut
  into content-defined segments (gear rolling hash, 16 KiB minimum, about 64 KiB on average, 256 KiB maximum). A
  segment of 4 KiB or more whose SHA-256 was seen before is not written again: the file gets an extent pointing at
  the earlier copy, in an earlier chunk or earlier in the current one. Because the cut points depend only on
  content, data shifted by insertions (a new version of an installer) still lines up. The writer keeps only the
  segment fingerprints (at most 2^20, about 200 MiB of RAM, covering ~64 GiB of distinct data), never the data. Readers
  need nothing new: these are ordinary extents. VFA's reader extracts chunk by chunk (each needed chunk is decoded
  once, and its bytes are written at the right offsets into every file that uses them), so deduplicated files do not
  cost repeated decodes, and extraction holds one decoded chunk at a time. Reading one file on its own (random
  access, the viewer) keeps the last two decoded chunks.
- **Coder:** `--method lz` (default), `--method tans` or `--method stored`. A chunk that the coder does not make
  smaller is stored, and the ROUTING record says so.
- **Filter:** `--filter auto` (default) or a forced filter (`none`, `delta:N`, `shuffle:K`, `bitshuffle:K`,
  `bcj-x86`, `bcj-arm64`). Auto routing:
  1. The chunk is cut into *units* at file boundaries: a file piece of 256 KiB or more is its own unit (split at
     8 MiB); smaller files are pooled into runs of about 1 MiB.
  2. Each unit is sampled (up to 4 × 64 KiB, evenly spread, 64-byte aligned). Every candidate filter (none, delta
     1/2/4/8, shuffle 2/4/8, bit-shuffle 4/8, bcj-x86, bcj-arm64) is applied to the sample and its order-0 coded
     size is estimated with an integer log2 (Q16).
  3. The lowest estimate wins if it beats `none` by more than 1/64; ties go to the earlier candidate.
  4. Adjacent units with the same filter are merged. One filter for the whole chunk is written as that filter;
     otherwise as `segmented`.
  With vulp-lz, order-0 statistics are the wrong yardstick (BCJ helps matches, not byte statistics), so step 3 is
  different: `none`, the two best order-0 candidates, and bcj-x86 / bcj-arm64 when the sample looks like machine
  code (≥ 0.4% E8/E9 bytes, or ≥ 2% aligned BL words) are each compressed with vulp-lz at a fast level, and the
  smallest real output wins under the same 1/64 rule. The ROUTING record keeps both sets of numbers.
- Same input and same options give a byte-identical archive (the harness checks this). Encrypted archives differ
  every time, by design (salt, nonces).
- mtime is stored to the nanosecond and restored with `os.utime(ns=...)`.
- **Memory** (measured, Linux, see BENCHMARKS.md): peak RSS is bounded by the chunk size, not the file size. With
  64 MiB chunks, about 250 MiB to create and about 205 MiB to extract, from 256 MiB inputs to 1 GiB, and the same
  shape at 4 GiB.
- Not yet: **append** (the format allows it; `vfa a` refuses VFA2 for now).

## What the checks do and do not protect against

- The CRCs and the SHA-256 digest detect **accidents**: bit rot, truncation, bad downloads, codec bugs.
- They do **not** prove who made the archive. The digest is stored inside the file, so anyone who edits the file
  can recompute it. Authenticity comes from:
  - encryption (AES-GCM fails on any edit without the password), or
  - signing the final installer with Authenticode, which VFA2 now survives.

## Minimal archive, annotated

`printf 'hi\n' > hi.txt` with mtime 1760140800 and mode 0o666, then
`vfa c min.vfa hi.txt --format vfa2 --method stored` gives 279 bytes. (Without `--method stored`, tANS cannot shrink
3 bytes, so the chunk is still stored, but the index gains a ROUTING record saying so.)

```
00000000: 5646 4132 3200 0300 0100 0000 0000 0000  VFA22...........
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 3196  ..............1.
00000030: 3ef9 5643 4b32 0000 0000 0000 0300 0000  >.VCK2..........
00000040: 0000 0000 0300 0000 7a7a 6fed aeb3 c9f4  ........zzo.....
00000050: 6869 0a56 4958 3200 0000 0000 0064 0000  hi.VIX2......d..
00000060: 0000 0000 0064 0000 0082 2012 4b49 989a  .....d.... .KI..
00000070: f656 4944 3201 0000 0032 0000 0000 0000  .VID2....2......
00000080: 0003 0000 0000 0000 007a 7a6f ed00 0001  .........zzo....
00000090: 0000 0000 0006 0068 692e 7478 74b6 0100  .......hi.txt...
000000a0: 0000 9ee9 6800 0000 0000 0000 0003 0000  ....h...........
000000b0: 0000 0000 0000 0000 0001 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 0003 0000 0000 0000  ................
000000d0: 0000 0000 0053 0000 0000 0000 0082 0000  .....S..........
000000e0: 0000 0000 0017 0100 0000 0000 0001 27f6  ..............'.
000000f0: a3c0 8967 21dc 9226 7886 1386 7e1c 605a  ...g!..&x...~.`Z
00000100: f7cf 5886 3d79 0579 48f9 f609 f5f1 1f01  ..X.=y.yH.......
00000110: 67fe 2f56 4641 32                        g./VFA2
```

| bytes | field |
|---|---|
| **Header** | |
| `00–03` | `VFA2` |
| `04–05` | header_size 50 |
| `06–07` | spec_version 3 |
| `08–09` | min_reader 1 |
| `0a–11` | required / optional features: 0 |
| `12–2d` | KDF / AEAD / salt: unused (zeros) |
| `2e–31` | header CRC32 |
| **Chunk frame 0** | |
| `32–35` | `VCK2` |
| `36` | coder 0 (stored) |
| `37` | filter 0 (none) |
| `38` | flags 0 |
| `39` | reserved |
| `3a–3b` | params_len 0 |
| `3c–43` | raw_size 3 |
| `44–47` | payload_size 3 |
| `48–4b` | raw CRC32 = CRC32(`hi\n`) |
| `4c–4f` | frame-header CRC32 |
| `50–52` | `hi\n` |
| **Index frame** | |
| `53–56` | `VIX2` |
| `57–5c` | coder / filter / flags / reserved / params_len: 0 |
| `5d–64` | raw_size 100 |
| `65–68` | payload_size 100 |
| `69–6c` | index CRC32 |
| `6d–70` | frame-header CRC32 |
| **Index payload** | |
| `71–74` | `VID2` |
| `75–78` | 1 chunk |
| `79–8e` | chunk record: offset 0x32, size 3, CRC, coder 0, filter 0 |
| `8f–92` | 1 entry |
| `93–96` | type file, reserved, path_len 6 |
| `97–9c` | `hi.txt` |
| `9d–a0` | mode 0o666 |
| `a1–a8` | mtime 0x68E99E00 |
| `a9–ac` | mtime_ns 0 |
| `ad–b4` | size 3 |
| `b5–b8` | meta_len 0 |
| `b9–bc` | 1 extent |
| `bd–d0` | extent: chunk 0, offset 0, length 3 |
| `d1–d4` | 0 records |
| **Footer** | |
| `d5–dc` | index_offset 0x53 |
| `dd–e4` | index_frame_len 130 |
| `e5–ec` | archive_len 279 |
| `ed` | digest kind 1 (SHA-256) |
| `ee–10d` | digest |
| `10e–111` | footer CRC32 |
| `112–116` | `/VFA2` |

## Known limits of revision 3

- **vulp-lz is a zstd-class coder, not an LZMA-class one.** Its sequences are tANS-coded per stream with no context
  modelling, so on text it stays a few percent behind xz -9e (see BENCHMARKS.md). The M5 context-mixing tier is
  where that gap is meant to close.
- **The `text` filter (id 5) is not implemented.** It will be designed against the M5 context-mixing coder, or
  dropped if it does not help there.
- **Small or sparse blocks fall back to RAW:** the TANS frequency table is stored densely up to the highest symbol
  present (≤ 256 entries, 1–2 bytes each), about 0.2% of a 128 KiB block.
- **No append yet.**
- The container code (framing, index, CRCs) is Python; the codecs are C. Without the `_vulp` extension VFA2
  decodes with `vulp_ref.py`, correctly but at roughly 1 MB/s.
- **Path/metadata rules are VFA1's:** see VFA1.md, "Reader guarantees", items 5–7.
