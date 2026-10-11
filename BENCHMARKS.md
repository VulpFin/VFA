# VFA benchmarks

Measured by `bench.py` on the owner's data. Each section is one run.

## 2026-10-11 01:44 M1 (VFA2 = stored only), sample\

Machine: Windows-10-10.0.19045-SP0, AMD64 Family 25 Model 33 Stepping 0, AuthenticAMD, 16 logical CPUs. Tools: python 3.10.5; xz xz (XZ Utils) 5.2.6; zstd not found; 7z 7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29; python-zstandard 0.24.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9600 | 39,774,832 | 53.5 | 28.9 | 38.8 MiB | 45.6 MiB | 11.9 MiB | ok |
| vfa-zstd19-solid | 0.8101 | 33,563,543 | 5.3 | 27.3 | 180.9 MiB | 146.0 MiB | 11.9 MiB | ok |
| vfa-xz9-solid | 0.3974 (best) | 16,465,070 | 5.2 | 25.5 | 519.4 MiB | 162.3 MiB | 11.9 MiB | ok |
| vfa2-stored-solid | 1.0001 | 41,432,330 | 52.1 | 28.6 | 107.1 MiB | 67.6 MiB | 11.9 MiB | ok |
| xz-9e | 0.3975 | 16,467,036 | 4.1 | 140.0 | 426.2 MiB | 45.1 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 0.4488 | 18,594,852 | 12.6 | 175.7 | 392.1 MiB | 58.3 MiB | 0.2 MiB | ok |
| zstd22-pylib | 0.3976 | 16,472,634 | 13.4 | 35.5 | 708.9 MiB | 60.1 MiB | - | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.

## 2026-10-11 06:58 M3 (VFA2 = auto filter + order-0 tANS, no match finder yet), Linux cloud container

Machine: Linux-6.18.44-fc-v114-x86_64-with-glibc2.39, x86_64, 4 logical CPUs. Tools: python 3.13.16; xz xz (XZ Utils) 5.4.5; zstd *** Zstandard CLI (64-bit) v1.5.5, by Yann Collet ***; 7z 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20; python-zstandard 0.25.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9600 | 39,774,832 | 76.0 | 68.0 | 46.2 MiB | 53.6 MiB | - | ok |
| vfa-zstd19-solid | 0.8101 | 33,563,628 | 2.7 | 56.5 | 185.2 MiB | 119.1 MiB | - | ok |
| vfa-xz9-solid | 0.3974 (best) | 16,465,086 | 2.3 | 44.5 | 523.1 MiB | 165.1 MiB | - | ok |
| vfa-lzma9-solid | 0.4003 | 16,585,705 | 2.4 | 23.4 | 523.3 MiB | 165.3 MiB | - | ok |
| vfa-brotli11-solid | 0.8092 | 33,523,843 | 0.3 | 51.3 | 198.1 MiB | 146.3 MiB | - | ok |
| vfa2-stored-solid | 1.0001 | 41,432,330 | 79.9 | 60.0 | 113.3 MiB | 113.8 MiB | - | ok |
| vfa2-tans | 0.9713 | 40,238,953 | 30.5 | 86.8 | 87.5 MiB | 99.6 MiB | - | ok |
| vfa2-tans-solid | 0.9714 | 40,243,815 | 25.6 | 51.1 | 186.4 MiB | 228.2 MiB | - | ok |
| xz-9e | 0.3975 | 16,466,920 | 2.0 | 107.9 | 422.5 MiB | 41.6 MiB | - | ok |
| zstd-ultra22 | 0.3975 | 16,469,958 | 6.0 | 588.2 | 708.2 MiB | 43.5 MiB | - | ok |
| 7z-lzma2-mx9 | 0.4488 | 18,595,617 | 6.5 | 99.7 | 390.6 MiB | 56.6 MiB | - | ok |

### SfiDemoSetup.exe (18,046,052 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9835 | 17,747,839 | 60.2 | 52.8 | 45.8 MiB | 53.3 MiB | - | ok |
| vfa-zstd19-solid | 0.9748 | 17,591,085 | 2.4 | 51.2 | 147.4 MiB | 81.4 MiB | - | ok |
| vfa-xz9-solid | 0.8839 | 15,950,778 | 2.0 | 27.3 | 298.8 MiB | 97.5 MiB | - | ok |
| vfa-lzma9-solid | 0.8902 | 16,065,012 | 1.8 | 11.2 | 298.8 MiB | 97.7 MiB | - | ok |
| vfa-brotli11-solid | 0.9733 | 17,565,106 | 0.3 | 38.2 | 140.8 MiB | 86.2 MiB | - | ok |
| vfa2-stored-solid | 1.0000 | 18,046,338 | 51.8 | 70.0 | 65.2 MiB | 69.0 MiB | - | ok |
| vfa2-tans | 0.9960 | 17,974,406 | 22.2 | 41.1 | 83.5 MiB | 86.2 MiB | - | ok |
| vfa2-tans-solid | 0.9960 | 17,974,406 | 25.0 | 58.3 | 82.6 MiB | 86.2 MiB | - | ok |
| xz-9e | 0.8840 | 15,952,108 | 1.9 | 59.5 | 221.4 MiB | 19.3 MiB | - | ok |
| zstd-ultra22 | 0.8843 | 15,957,802 | 2.8 | 470.4 | 685.1 MiB | 21.0 MiB | - | ok |
| 7z-lzma2-mx9 | 0.8833 (best) | 15,939,476 | 7.9 | 51.5 | 235.0 MiB | 38.9 MiB | - | ok |

### blob.bin (1,048,576 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.0006 | 606 | 4.6 | 5.9 | 34.6 MiB | 32.9 MiB | - | ok |
| vfa-zstd19-solid | 0.0006 | 592 | 5.7 | 5.3 | 49.7 MiB | 32.9 MiB | - | ok |
| vfa-xz9-solid | 0.0007 | 746 | 3.9 | 6.1 | 105.8 MiB | 33.6 MiB | - | ok |
| vfa-lzma9-solid | 0.0007 | 702 | 4.0 | 6.9 | 106.1 MiB | 33.7 MiB | - | ok |
| vfa-brotli11-solid | 0.0004 | 452 | 6.0 | 7.3 | 42.4 MiB | 33.8 MiB | - | ok |
| vfa2-stored-solid | 1.0003 | 1,048,854 | 7.0 | 7.4 | 32.6 MiB | 32.8 MiB | - | ok |
| vfa2-tans | 0.0007 | 749 | 6.7 | 7.1 | 34.0 MiB | 32.7 MiB | - | ok |
| vfa2-tans-solid | 0.0007 | 749 | 6.5 | 6.7 | 33.1 MiB | 32.7 MiB | - | ok |
| xz-9e | 0.0005 | 512 | 15.4 | 144.7 | 12.4 MiB | 3.0 MiB | - | ok |
| zstd-ultra22 | 0.0003 (best) | 359 | 1.9 | 158.3 | 652.8 MiB | 3.4 MiB | - | ok |
| 7z-lzma2-mx9 | 0.0006 | 578 | 39.5 | 97.1 | 21.9 MiB | 6.4 MiB | - | ok |

### random.bin (500,000 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0005 | 500,266 | 3.2 | 3.4 | 34.8 MiB | 32.6 MiB | - | ok |
| vfa-zstd19-solid | 1.0005 | 500,257 | 1.7 | 3.2 | 41.3 MiB | 32.5 MiB | - | ok |
| vfa-xz9-solid | 1.0006 | 500,320 | 1.3 | 3.5 | 101.2 MiB | 32.5 MiB | - | ok |
| vfa-lzma9-solid | 1.0142 | 507,095 | 1.2 | 2.7 | 101.2 MiB | 32.6 MiB | - | ok |
| vfa-brotli11-solid | 1.0005 | 500,241 | 1.1 | 3.7 | 44.2 MiB | 32.6 MiB | - | ok |
| vfa2-stored-solid | 1.0006 | 500,280 | 3.0 | 3.2 | 31.7 MiB | 31.8 MiB | - | ok |
| vfa2-tans | 1.0015 | 500,770 | 3.1 | 3.4 | 32.9 MiB | 31.8 MiB | - | ok |
| vfa2-tans-solid | 1.0015 | 500,770 | 2.7 | 3.6 | 32.4 MiB | 31.8 MiB | - | ok |
| xz-9e | 1.0002 | 500,084 | 1.7 | 92.9 | 70.9 MiB | 2.7 MiB | - | ok |
| zstd-ultra22 | 1.0000 (best) | 500,022 | 0.7 | 77.7 | 653.0 MiB | 3.5 MiB | - | ok |
| 7z-lzma2-mx9 | 1.0003 | 500,164 | 9.0 | 51.8 | 14.1 MiB | 6.4 MiB | - | ok |

### app.ico (1,630,489 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0002 | 1,630,779 | 10.7 | 11.4 | 36.9 MiB | 37.9 MiB | - | ok |
| vfa-zstd19-solid | 1.0002 | 1,630,770 | 3.2 | 9.2 | 67.6 MiB | 37.9 MiB | - | ok |
| vfa-xz9-solid | 1.0002 | 1,630,861 | 1.9 | 8.6 | 115.7 MiB | 36.9 MiB | - | ok |
| vfa-lzma9-solid | 1.0110 | 1,648,440 | 2.0 | 5.1 | 115.6 MiB | 37.0 MiB | - | ok |
| vfa-brotli11-solid | 1.0001 | 1,630,730 | 0.6 | 9.1 | 63.8 MiB | 37.0 MiB | - | ok |
| vfa2-stored-solid | 1.0002 | 1,630,766 | 8.2 | 7.9 | 33.8 MiB | 34.0 MiB | - | ok |
| vfa2-tans | 1.0004 | 1,631,221 | 7.2 | 7.5 | 36.4 MiB | 33.9 MiB | - | ok |
| vfa2-tans-solid | 1.0004 | 1,631,221 | 6.0 | 10.6 | 35.8 MiB | 33.9 MiB | - | ok |
| xz-9e | 1.0001 | 1,630,628 | 1.9 | 175.5 | 80.7 MiB | 3.6 MiB | - | ok |
| zstd-ultra22 | 1.0000 (best) | 1,630,538 | 1.4 | 161.9 | 655.5 MiB | 4.7 MiB | - | ok |
| 7z-lzma2-mx9 | 1.0001 | 1,630,714 | 8.8 | 102.1 | 28.9 MiB | 8.5 MiB | - | ok |

### payload.vfa (2,135,012 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0001 | 2,135,319 | 11.3 | 12.7 | 37.9 MiB | 39.7 MiB | - | ok |
| vfa-zstd19-solid | 0.9986 | 2,131,918 | 2.6 | 10.5 | 84.0 MiB | 39.9 MiB | - | ok |
| vfa-xz9-solid | 0.9989 | 2,132,609 | 2.2 | 11.9 | 120.9 MiB | 38.8 MiB | - | ok |
| vfa-lzma9-solid | 1.0099 | 2,156,220 | 2.0 | 6.3 | 121.0 MiB | 38.8 MiB | - | ok |
| vfa-brotli11-solid | 1.0001 | 2,135,257 | 0.6 | 11.5 | 69.1 MiB | 38.9 MiB | - | ok |
| vfa2-stored-solid | 1.0001 | 2,135,293 | 10.5 | 11.4 | 34.8 MiB | 34.9 MiB | - | ok |
| vfa2-tans | 1.0003 | 2,135,748 | 9.8 | 9.0 | 37.3 MiB | 34.9 MiB | - | ok |
| vfa2-tans-solid | 1.0003 | 2,135,748 | 8.7 | 13.5 | 37.3 MiB | 34.9 MiB | - | ok |
| xz-9e | 0.9988 | 2,132,368 | 2.1 | 150.8 | 84.9 MiB | 4.0 MiB | - | ok |
| zstd-ultra22 | 0.9984 (best) | 2,131,682 | 1.3 | 185.5 | 656.7 MiB | 5.4 MiB | - | ok |
| 7z-lzma2-mx9 | 0.9990 | 2,132,888 | 7.7 | 90.5 | 37.3 MiB | 9.5 MiB | - | ok |

### vfa.py (59,938 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.3007 | 18,025 | 0.3 | 0.3 | 32.0 MiB | 31.2 MiB | - | ok |
| vfa-zstd19-solid | 0.2782 | 16,677 | 0.3 | 0.3 | 32.8 MiB | 31.3 MiB | - | ok |
| vfa-xz9-solid | 0.2746 | 16,460 | 0.2 | 0.3 | 95.8 MiB | 30.9 MiB | - | ok |
| vfa-lzma9-solid | 0.2738 | 16,413 | 0.3 | 0.3 | 95.7 MiB | 31.0 MiB | - | ok |
| vfa-brotli11-solid | 0.2599 (best) | 15,579 | 0.2 | 0.4 | 34.6 MiB | 31.1 MiB | - | ok |
| vfa2-stored-solid | 1.0046 | 60,214 | 0.3 | 0.4 | 31.0 MiB | 30.9 MiB | - | ok |
| vfa2-tans | 0.6365 | 38,153 | 0.4 | 0.4 | 31.2 MiB | 31.0 MiB | - | ok |
| vfa2-tans-solid | 0.6365 | 38,153 | 0.4 | 0.4 | 31.0 MiB | 31.0 MiB | - | ok |
| xz-9e | 0.2709 | 16,236 | 0.7 | 8.3 | 30.4 MiB | 2.1 MiB | - | ok |
| zstd-ultra22 | 0.2744 | 16,447 | 0.1 | 11.6 | 651.4 MiB | 2.8 MiB | - | ok |
| 7z-lzma2-mx9 | 0.2719 | 16,296 | 2.9 | 6.5 | 7.6 MiB | 5.6 MiB | - | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.
**Reading the M3 run (measured above, Linux container, not the owner's Windows machine).** VFA2 at M3 is an order-0
entropy coder plus filters, with no match finder yet. On this data it loses to every LZ-based tool, and that is the
expected M3 state:

- **sample (whole): 0.971 vs xz -9e 0.398.** Almost all of xz's gain comes from the two near-identical 18 MB setup
  exes: a long-range *match* that only the M4 match finder (or content-defined dedup) can find.
- **SfiDemoSetup.exe: 0.996 vs 0.883; payload.vfa, app.ico, random.bin: ≈1.000 for everyone.** This content is already
  compressed, so no tool gains much. VFA2 stores what tANS cannot shrink, so it costs at most ~0.1%.
- **vfa.py (text): 0.637 vs 0.271.** Order-0 statistics cannot see repeated words. This is the class where M4 must
  close the gap.
- **blob.bin (a ramp): 0.0007,** on par with the others, because the classifier routed it to delta:1.
- Speed: VFA2 compresses at 22–31 MB/s and decompresses at 41–87 MB/s on the large inputs. The Python container code
  (CRC, framing) is a large share of that. RSS ≈ 31 MiB floor = the Python interpreter.
