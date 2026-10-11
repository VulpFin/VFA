# VFA1 container format (1.0 and 1.1)

This describes what `vfa.py` writes and what `vfa_extract.py` accepts. `vfa_extract.py` is the single reader:
`vfa l/t/x`, `sfx_stub.py`, `sfi_stub.py` and `vfa_viewer.py` all use it. All integers are little-endian.

**VFA 1.1** adds a block table with CRC32s, a TOC checksum and SHA-256 digests. It is a strict superset of 1.0: older
readers can still read 1.1 archives (they ignore the extension), and this reader still reads 1.0 archives.

## Layout

```
[ header 74 B ][ block frame ]*[ TOC (+ VTX1 extension) ][ footer 50 B ]
```

Every offset is measured from the start of the archive (the `V` of `VFA1`), not from the start of the file. That
is what lets an archive be glued onto a stub (`copy /b vfa_sfx.exe + a.vfa setup.exe`). A reader finds the
archive from the end of the file:
`archive_start = file_size - 50 - toc_size - toc_offset`.

### Header (74 bytes)

| off | size | field | notes |
|---|---|---|---|
| 0 | 4 | magic | `VFA1` |
| 4 | 2 | version | must be `1`. A reader refuses any other value. |
| 6 | 4 | flags | bit0 `ENCRYPTED`, bit1 `SOLID`, bit2 `TOCX` (1.1). **A reader refuses any unknown bit.** |
| 10 | 1 | default_method | Method of solid blocks. Non-solid blocks carry their own method. |
| 11 | 1 | default_level | Informational. |
| 12 | 1 | block_exp | Non-solid block size = 2^block_exp. Informational for readers. |
| 13 | 2 | threads_hint | Informational. |
| 15 | 4 | ram_mib_hint | Informational. |
| 19 | 1 | kdf_id | 0 none, 1 Argon2id, 2 scrypt |
| 20 | 4 | kdf_t | Argon2 time cost / scrypt N |
| 24 | 4 | kdf_m | Argon2 memory (KiB) / scrypt r |
| 28 | 1 | kdf_p | Parallelism / scrypt p |
| 29 | 16 | salt | |
| 45 | 1 | aead_id | 0 none, 1 AES-256-GCM. Any other value is refused when ENCRYPTED is set. |
| 46 | 12 | nonce_prefix | |
| 58 | 16 | reserved | bytes 0..3 = `toc_gen` (u32, 1.1); the rest are zero |

To stop a damaged or hostile header from demanding unlimited resources, readers cap the KDF cost:
- Argon2: t ≤ 64, m ≤ 4 GiB, p ≤ 64
- scrypt: N ≤ 2^24, r ≤ 64, p ≤ 64, and 128·N·r ≤ 4 GiB

### Block frame

```
u32 payload_len, u8 method, payload[payload_len]
```

Methods: 0 none, 1 zlib, 2 lzma (alone), 3 brotli, 4 zstd, 5 xz, 6 bz2, 7 lz4 (frame). An unknown method is
refused ("this archive needs a newer VFA").

Encrypted payload: `AES-256-GCM(key, nonce = SHA256(nonce_prefix ‖ u64 i ‖ "vfa-data")[:12], aad = "vfa-data")`.
Here `i` is the frame's ordinal (0, 1, 2, … in file order).

Frames are contiguous: the first starts at offset 74, and the last ends exactly at `toc_offset`. Writers keep each
block at or below 1 GiB uncompressed (`--block-exp` / `--solid-chunk-exp` ≤ 30). That keeps `payload_len` well
inside u32.

- **Non-solid:** each file is cut into blocks of 2^block_exp bytes.
- **Solid:** all regular files are concatenated into one stream, cut into blocks of 2^solid_chunk_exp. The default
  is 2^26 = 64 MiB in 1.1 (the xz/lzma -9 dictionary size, so splitting costs almost no ratio); 1.0 wrote a single block. Writing and extracting both hold about one block in memory.

### TOC

Possibly encrypted as a whole: `index = 0xFFFFFFFFFFFFFFFF - toc_gen`, `aad = "vfa-toc"`.

```
u32 count
count x entry:
    u16 path_len, path (UTF-8, '/' or '\' separated, relative)
    u32 mode, u64 mtime, u64 size, u32 nblocks
    u8  entry_type        0 file, 1 dir, 2 symlink, 3 hardlink  (anything else: refused)
    u32 meta_len, meta    JSON: win/posix metadata, link_target, hardlink_to, holes
    solid:     u64 start_off            offset in the solid stream
    non-solid: nblocks x (u64 frame_index, u32 usize, u32 csize, u8 method)
[1.1 only, when flag TOCX] VTX1 extension
```

**VTX1 extension (1.1):**

```
"VTX1", u32 nrec, nrec x (u16 type, u16 rflags, u32 len, data[len])
```

`rflags` bit0 = **critical**: a reader that does not know `type` must refuse. Unknown non-critical records are
skipped.

| type | data |
|---|---|
| 1 BLOCKS | `u32 n`, then n × `(u64 frame_off, u32 csize, u32 usize, u8 method, u8 bflags, u32 crc32)`. One record per frame, in order. `bflags` bit0 = the CRC is valid. The CRC is of the **uncompressed** block, so it also catches codec bugs, not just bit rot. |
| 2 TOCCRC | `u32` CRC32 of the TOC bytes before `VTX1` (the entries) |

Both are written as critical. When the TOCX flag is set, both must be present.

The TOC must be consumed exactly. Trailing bytes are an error. (The pre-1.1 parsers silently "retried with an old
layout" on a parse error. No VFA ever wrote that layout, so the fallback is gone.)

### Footer (50 bytes)

```
u64 toc_offset, u32 toc_size, u8 hash_kind, digest[32], "/VFA1"
```

`hash_kind`: 1 SHA-256 (1.1 always writes this), 2 BLAKE3, 3 XXH64 (zero-padded to 32). The digest covers
`archive_start .. footer`. A reader that cannot compute the stored kind **fails**; it never skips the check.
`build.py` bundles `xxhash` so that 1.0 archives still verify.

If the end of the file reads `/VFA<n>` with n ≠ 1, the reader reports "newer VFA format" instead of "not an archive".

## Reader guarantees (`vfa_extract.Container`)

1. The digest is checked before anything is written. Stubs always check it; `vfa x` checks it unless `--no-verify`.
2. The block table is cross-checked against the frame headers and the TOC: offsets, sizes, methods, and each
   block referenced at most once.
3. Decompression stops at the size the TOC claims (no decompression bombs). Exception: brotli, whose Python API has
   no output cap.
4. Every block is length-checked. In 1.1 archives every block is also CRC32-checked, so random access (`vfa x a.vfa
   some/file`) and `--no-verify` still detect corruption.
5. Every path is validated before the first byte is written. Refused: absolute paths, drive letters, `..`, NUL,
   and on Windows also device names (`CON`, `AUX`, …), `<>:"|?*`, control characters, and a trailing dot or space.
6. Links are created after all files (POSIX only), so no file is ever written through a link from the archive. A
   hardlink target must resolve inside the destination.
7. Files are written as `NAME.vfapart` and renamed only after their last block checks out.
8. Random access reads only the blocks that overlap the requested files, in both solid and non-solid archives.

## Compatibility

| | 1.0 reader (old vfa/vfa_extract/sfx/viewer) | 1.1 reader |
|---|---|---|
| 1.0 archive | yes | yes (no block CRCs; `--no-verify` warns that corruption can go undetected) |
| 1.1 archive | yes, ignores VTX1 | yes |
| 1.1 archive after an *encrypted* append | **no**: TOC decryption fails cleanly, since `toc_gen` ≠ 0 | yes |

Appending to an encrypted archive bumps `toc_gen`. That is the only way to rewrite the TOC without reusing an
AES-GCM nonce (1.0 reused it, which leaks the TOC's keystream and breaks GCM authentication). The cost is that 1.0
readers can no longer open that archive.

## Minimal archive, annotated

`printf 'hi\n' > hi.txt` with mtime 1760140800, then `vfa c min.vfa hi.txt --method none` gives 244 bytes:

```
00000000: 5646 4131 0100 0400 0000 0005 1600 0000  VFA1............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0300 0000 0068  ...............h
00000050: 690a 0100 0000 0600 6869 2e74 7874 b601  i.......hi.txt..
00000060: 0000 009e e968 0000 0000 0300 0000 0000  .....h..........
00000070: 0000 0100 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0003 0000 0003 0000 0000 5654 5831  ............VTX1
00000090: 0200 0000 0200 0100 0400 0000 e7ef 3d10  ..............=.
000000a0: 0100 0100 1a00 0000 0100 0000 4a00 0000  ............J...
000000b0: 0000 0000 0300 0000 0300 0000 0001 7a7a  ..............zz
000000c0: 6fed 5200 0000 0000 0000 7000 0000 0104  o.R.......p.....
000000d0: 8822 90d3 dd21 6853 0b15 0ed4 006b 8f6b  ."...!hS.....k.k
000000e0: 916b df89 a7d3 8065 d047 21c1 8c43 0e2f  .k.....e.G!..C./
000000f0: 5646 4131                                VFA1
```

| bytes | meaning |
|---|---|
| `00–03` | `VFA1` |
| `04–05` | version 1 |
| `06–09` | flags `0x4` = TOCX |
| `0a` | default method 0 |
| `0b` | level 5 |
| `0c` | block_exp 22 |
| `0d–49` | threads, ram, KDF, salt, AEAD, nonce, reserved: all zero |
| `4a–4e` | frame: payload_len 3, method 0 (none) |
| `4f–51` | payload `hi\n` |
| `52` | **TOC**: count 1 |
| `56–57` | path_len 6 |
| `58–5d` | `hi.txt` |
| `5e–61` | mode 0o666 |
| `62–69` | mtime 0x68E99E00 |
| `6a–71` | size 3 |
| `72–75` | nblocks 1 |
| `76` | entry_type 0 (file) |
| `77–7a` | meta_len 0 |
| `7b–8b` | block tuple: frame 0, usize 3, csize 3, method 0 |
| `8c–8f` | `VTX1` |
| `90–93` | 2 records |
| `94–9f` | TOCCRC record: type 2, critical, len 4, CRC32 `0x103defe7` |
| `a0–a7` | BLOCKS record header: type 1, critical, len 26 |
| `a8–ab` | n = 1 |
| `ac–c1` | block record: frame_off 0x4a, csize 3, usize 3, method 0, bflags 1, CRC32(`hi\n`) |
| `c2–c9` | **footer**: toc_offset 0x52 |
| `ca–cd` | toc_size 112 |
| `ce` | hash_kind 1 (SHA-256) |
| `cf–ee` | digest |
| `ef–f3` | `/VFA1` |

## Known limits

- **Append is not crash-safe against power loss.** It truncates the old TOC and writes the new one. A Python
  exception restores the original tail; a power cut can leave the archive without a TOC.
- **brotli output is not capped** during decompression (see guarantee 3).
- **1.0 archives have no block CRCs.** Their integrity rests entirely on the digest.
- **The TOC is 32-bit in places:** `toc_size` is u32, so a TOC over 4 GiB (tens of millions of files) cannot be
  written.
