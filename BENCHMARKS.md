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

## 2026-10-11 16:36 M3, Windows

Machine: Windows-10-10.0.19045-SP0, AMD64 Family 25 Model 33 Stepping 0, AuthenticAMD, 16 logical CPUs. Tools: python 3.10.5; xz xz (XZ Utils) 5.2.6; zstd not found; 7z 7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29; python-zstandard 0.24.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9600 | 39,774,832 | 51.2 | 28.0 | 37.6 MiB | 43.9 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.8101 | 33,563,543 | 5.3 | 27.5 | 178.6 MiB | 144.1 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.3974 (best) | 16,465,070 | 5.4 | 25.6 | 517.5 MiB | 160.5 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.4003 | 16,585,693 | 5.4 | 20.0 | 517.5 MiB | 160.5 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.8091 | 33,522,689 | 0.7 | 26.7 | 171.8 MiB | 141.2 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0001 | 41,432,330 | 49.9 | 28.4 | 105.7 MiB | 105.2 MiB | 12.3 MiB | ok |
| vfa2-tans | 0.9713 | 40,238,953 | 31.0 | 28.1 | 78.2 MiB | 94.9 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.9719 | 40,263,936 | 30.4 | 27.4 | 179.8 MiB | 218.2 MiB | 12.3 MiB | ok |
| xz-9e | 0.3975 | 16,467,064 | 4.3 | 137.3 | 425.3 MiB | 44.2 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 0.4488 | 18,594,869 | 11.8 | 173.9 | 391.0 MiB | 57.1 MiB | 0.2 MiB | ok |
| zstd22-pylib | 0.3976 | 16,472,685 | 13.2 | 35.3 | 707.8 MiB | 59.0 MiB | - | ok |

### SfiDemoSetup.exe (18,046,052 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9835 | 17,747,839 | 25.6 | 12.9 | 36.8 MiB | 43.5 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.9748 | 17,591,085 | 4.3 | 12.8 | 140.9 MiB | 86.7 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.8839 | 15,950,778 | 3.7 | 11.7 | 293.4 MiB | 92.8 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.8902 | 16,065,012 | 3.9 | 9.1 | 293.8 MiB | 92.9 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.9733 | 17,565,106 | 0.5 | 12.7 | 120.1 MiB | 81.7 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0000 | 18,046,338 | 25.1 | 13.1 | 60.9 MiB | 60.5 MiB | 12.3 MiB | ok |
| vfa2-tans | 0.9960 | 17,974,406 | 19.1 | 12.9 | 78.0 MiB | 77.5 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.9960 | 17,974,406 | 19.1 | 12.9 | 78.0 MiB | 77.5 MiB | 12.3 MiB | ok |
| xz-9e | 0.8840 | 15,952,108 | 4.0 | 70.3 | 224.1 MiB | 21.8 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 0.8833 (best) | 15,939,476 | 17.8 | 96.2 | 236.1 MiB | 39.4 MiB | 0.2 MiB | ok |
| zstd22-pylib | 0.8844 | 15,960,149 | 6.2 | 15.4 | 428.9 MiB | 35.9 MiB | - | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.

## 2026-10-11 16:42 M3, Windows

Machine: Windows-10-10.0.19045-SP0, AMD64 Family 25 Model 33 Stepping 0, AuthenticAMD, 16 logical CPUs. Tools: python 3.10.5; xz xz (XZ Utils) 5.2.6; zstd not found; 7z 7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29; python-zstandard 0.24.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9600 | 39,774,832 | 51.6 | 27.6 | 36.7 MiB | 43.9 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.8101 | 33,563,543 | 5.1 | 27.4 | 178.4 MiB | 144.2 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.3974 (best) | 16,465,070 | 5.4 | 25.3 | 517.1 MiB | 160.3 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.4003 | 16,585,693 | 5.4 | 19.9 | 517.6 MiB | 160.5 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.8091 | 33,522,689 | 0.6 | 26.5 | 171.6 MiB | 141.3 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0001 | 41,432,330 | 49.5 | 28.5 | 105.1 MiB | 105.1 MiB | 12.3 MiB | ok |
| vfa2-tans | 0.9713 | 40,238,953 | 31.7 | 27.9 | 78.1 MiB | 94.8 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.9719 | 40,263,936 | 29.4 | 27.5 | 180.1 MiB | 218.1 MiB | 12.3 MiB | ok |
| xz-9e | 0.3975 | 16,467,064 | 4.3 | 136.7 | 425.3 MiB | 44.2 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 0.4488 | 18,594,869 | 13.4 | 179.4 | 391.0 MiB | 57.1 MiB | 0.2 MiB | ok |
| zstd22-pylib | 0.3976 | 16,472,685 | 13.5 | 35.2 | 707.8 MiB | 59.0 MiB | - | ok |

### SfiDemoSetup.exe (18,046,052 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9835 | 17,747,839 | 25.1 | 13.0 | 36.7 MiB | 44.2 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.9748 | 17,591,085 | 4.3 | 12.8 | 141.0 MiB | 86.7 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.8839 | 15,950,778 | 3.8 | 11.8 | 293.5 MiB | 92.9 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.8902 | 16,065,012 | 3.8 | 9.2 | 293.7 MiB | 92.8 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.9733 | 17,565,106 | 0.5 | 12.6 | 120.7 MiB | 81.3 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0000 | 18,046,338 | 24.9 | 13.1 | 60.7 MiB | 60.4 MiB | 12.3 MiB | ok |
| vfa2-tans | 0.9960 | 17,974,406 | 19.3 | 13.0 | 78.2 MiB | 77.5 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.9960 | 17,974,406 | 19.3 | 12.9 | 77.8 MiB | 77.4 MiB | 12.3 MiB | ok |
| xz-9e | 0.8840 | 15,952,108 | 4.0 | 67.8 | 224.0 MiB | 21.8 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 0.8833 (best) | 15,939,476 | 18.4 | 100.6 | 236.1 MiB | 39.4 MiB | 0.2 MiB | ok |
| zstd22-pylib | 0.8844 | 15,960,149 | 6.3 | 15.5 | 428.9 MiB | 35.9 MiB | - | ok |

### blob.bin (1,048,576 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.0006 | 606 | 1.6 | 0.8 | 31.1 MiB | 27.8 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.0006 | 592 | 1.6 | 0.8 | 44.6 MiB | 28.0 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.0007 | 746 | 1.5 | 0.8 | 101.4 MiB | 29.0 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.0007 | 702 | 1.5 | 0.8 | 101.2 MiB | 29.0 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.0004 | 452 | 1.4 | 0.8 | 37.2 MiB | 29.0 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0003 | 1,048,854 | 1.6 | 0.8 | 29.1 MiB | 28.0 MiB | 12.3 MiB | ok |
| vfa2-tans | 0.0007 | 749 | 1.6 | 0.8 | 29.2 MiB | 27.9 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.0007 | 749 | 1.6 | 0.8 | 28.7 MiB | 28.1 MiB | 12.3 MiB | ok |
| xz-9e | 0.0005 | 512 | 9.4 | 11.6 | 14.8 MiB | 5.6 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 0.0006 | 578 | 10.7 | 11.8 | 23.5 MiB | 7.1 MiB | 0.2 MiB | ok |
| zstd22-pylib | 0.0003 (best) | 358 | 2.3 | 0.9 | 29.1 MiB | 12.6 MiB | - | ok |

### random.bin (500,000 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0005 | 500,266 | 0.8 | 0.4 | 31.1 MiB | 27.8 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 1.0005 | 500,257 | 0.7 | 0.4 | 36.6 MiB | 28.1 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 1.0006 | 500,320 | 0.7 | 0.4 | 97.2 MiB | 28.0 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0142 | 507,095 | 0.7 | 0.4 | 97.0 MiB | 27.8 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0005 | 500,241 | 0.6 | 0.4 | 38.3 MiB | 27.8 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0006 | 500,280 | 0.8 | 0.4 | 27.9 MiB | 27.0 MiB | 12.3 MiB | ok |
| vfa2-tans | 1.0015 | 500,770 | 0.7 | 0.4 | 28.3 MiB | 26.8 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0015 | 500,770 | 0.7 | 0.4 | 27.7 MiB | 27.0 MiB | 12.3 MiB | ok |
| xz-9e | 1.0002 | 500,084 | 2.5 | 5.6 | 73.3 MiB | 5.1 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 1.0003 | 500,164 | 4.3 | 5.7 | 15.9 MiB | 7.0 MiB | 0.2 MiB | ok |
| zstd22-pylib | 1.0000 (best) | 500,021 | 1.1 | 0.4 | 21.1 MiB | 12.5 MiB | - | ok |

### app.ico (1,630,489 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0002 | 1,630,779 | 2.5 | 1.2 | 31.8 MiB | 31.7 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 1.0002 | 1,630,770 | 2.0 | 1.2 | 62.3 MiB | 31.5 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 1.0002 | 1,630,861 | 1.7 | 1.2 | 110.0 MiB | 32.3 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0110 | 1,648,440 | 1.7 | 1.2 | 109.7 MiB | 32.2 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0001 | 1,630,730 | 1.1 | 1.2 | 51.2 MiB | 32.3 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0002 | 1,630,766 | 2.5 | 1.2 | 29.3 MiB | 29.2 MiB | 12.3 MiB | ok |
| vfa2-tans | 1.0004 | 1,631,221 | 2.4 | 1.2 | 31.5 MiB | 29.2 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0004 | 1,631,221 | 2.0 | 1.2 | 31.0 MiB | 29.0 MiB | 12.3 MiB | ok |
| xz-9e | 1.0001 | 1,630,628 | 4.0 | 17.7 | 83.0 MiB | 6.1 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 1.0001 | 1,630,714 | 9.9 | 17.4 | 30.6 MiB | 9.2 MiB | 0.2 MiB | ok |
| zstd22-pylib | 1.0000 (best) | 1,630,537 | 2.7 | 1.4 | 47.3 MiB | 14.8 MiB | - | ok |

### payload.vfa (2,135,012 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0001 | 2,135,319 | 3.2 | 1.6 | 32.7 MiB | 34.2 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.9986 | 2,131,918 | 2.4 | 1.6 | 78.8 MiB | 34.3 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.9989 | 2,132,609 | 2.0 | 1.6 | 115.2 MiB | 34.2 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0099 | 2,156,220 | 2.0 | 1.5 | 115.2 MiB | 34.2 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0001 | 2,135,257 | 1.2 | 1.6 | 55.7 MiB | 34.1 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0001 | 2,135,293 | 3.1 | 1.6 | 30.2 MiB | 30.1 MiB | 12.3 MiB | ok |
| vfa2-tans | 1.0003 | 2,135,748 | 3.1 | 1.6 | 32.5 MiB | 29.9 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0003 | 2,135,748 | 3.1 | 1.6 | 32.4 MiB | 29.9 MiB | 12.3 MiB | ok |
| xz-9e | 0.9988 | 2,132,368 | 4.4 | 22.4 | 87.4 MiB | 6.7 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 0.9990 | 2,132,888 | 11.7 | 23.1 | 38.9 MiB | 10.1 MiB | 0.2 MiB | ok |
| zstd22-pylib | 0.9984 (best) | 2,131,681 | 3.0 | 1.8 | 80.3 MiB | 15.7 MiB | - | ok |

### vfa.py (61,219 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.2958 | 18,107 | 0.1 | 0.0 | 30.0 MiB | 26.2 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.2734 | 16,736 | 0.1 | 0.0 | 27.7 MiB | 26.2 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.2695 | 16,496 | 0.1 | 0.0 | 90.8 MiB | 26.2 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.2687 | 16,452 | 0.1 | 0.0 | 91.1 MiB | 26.1 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.2552 (best) | 15,622 | 0.1 | 0.0 | 29.7 MiB | 26.1 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0045 | 61,495 | 0.1 | 0.0 | 27.2 MiB | 26.2 MiB | 12.3 MiB | ok |
| vfa2-tans | 0.6415 | 39,275 | 0.1 | 0.0 | 26.9 MiB | 26.1 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.6415 | 39,275 | 0.1 | 0.0 | 27.0 MiB | 26.0 MiB | 12.3 MiB | ok |
| xz-9e | 0.2658 | 16,272 | 0.6 | 0.7 | 33.0 MiB | 4.6 MiB | - | ok |
| zstd-ultra22 | | | | | | | - | **not run**: zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`) |
| 7z-lzma2-mx9 | 0.2669 | 16,341 | 0.6 | 0.6 | 9.4 MiB | 6.1 MiB | 0.2 MiB | ok |
| zstd22-pylib | 0.2696 | 16,504 | 0.1 | 0.1 | 13.0 MiB | 11.8 MiB | - | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.
**Reading the M3 Windows runs (owner's machine, measured).** The 16:36 run covered two inputs and the 16:42 run all
seven; their shared rows agree. The ratios match the Linux run: VFA2 has no match finder until M4, so it loses to every
LZ tool on compressible data and ties on already-compressed data. Windows-specific:

- **Stub: 12.3 MiB (12,866,010 bytes)**, up from 11.9 MiB (12,511,526) in the M1 run. The codec's share is the
  `_vulp` extension at **20 KiB**. The M1 figure came from a stub built *before* VFA 1.1 (`bin\windows` had not been
  rebuilt at the time), so the remaining ~326 KiB of growth comes from everything else changed since then. It has not
  been broken down further.
- **vfa2-tans-solid on sample: 40,263,936 here vs 40,243,815 on Linux.** The cause is file order, not the codec:
  `os.walk` lists files alphabetically on NTFS and in hash order on ext4, so the solid stream was packed in a different
  order. Fixed after this run: VFA now sorts directory entries, so files are packed in the same order on every machine.
  (Archives can still differ by the metadata they preserve, such as permission bits and timestamps.)
- **Small inputs:** every VFA row shows ~0.65 s to compress and ~1.34 s to extract regardless of size, which is
  interpreter and import start-up, so small-file MB/s figures say nothing about the codec. The ~0.7 s extra on
  extraction appears on Windows only (Linux: ~0.15 s for both) and has not been investigated yet.
- `zstd --ultra -22` did not run (CLI not installed); `zstd22-pylib` is the same library at level 22, labelled as a
  stand-in.

## 2026-10-11 22:29 M4 (VFA2 = vulp-lz + dedup), Linux cloud container

Machine: Linux-6.18.44-fc-v114-x86_64-with-glibc2.39, x86_64, 4 logical CPUs. Tools: python 3.13.16; xz xz (XZ Utils) 5.4.5; zstd *** Zstandard CLI (64-bit) v1.5.5, by Yann Collet ***; 7z 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20; python-zstandard 0.25.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9600 | 39,774,832 | 144.3 | 140.3 | 45.6 MiB | 53.1 MiB | - | ok |
| vfa-zstd19-solid | 0.8101 | 33,561,417 | 5.7 | 111.3 | 184.5 MiB | 118.8 MiB | - | ok |
| vfa-xz9-solid | 0.3974 (best) | 16,465,674 | 4.3 | 72.0 | 522.2 MiB | 164.8 MiB | - | ok |
| vfa-lzma9-solid | 0.4003 | 16,585,458 | 4.4 | 28.4 | 522.5 MiB | 164.9 MiB | - | ok |
| vfa-brotli11-solid | 0.8153 | 33,778,173 | 0.5 | 77.8 | 197.6 MiB | 146.1 MiB | - | ok |
| vfa2-stored-solid | 0.4587 | 19,003,385 | 150.8 | 270.9 | 73.0 MiB | 70.7 MiB | - | ok |
| vfa2-tans-solid | 0.4508 | 18,678,012 | 58.6 | 114.8 | 119.0 MiB | 122.8 MiB | - | ok |
| vfa2-lz | 0.4159 | 17,230,428 | 35.4 | 206.7 | 91.8 MiB | 83.1 MiB | - | ok |
| vfa2-lz-solid | 0.3988 | 16,524,337 | 35.4 | 128.4 | 102.1 MiB | 120.8 MiB | - | ok |
| vfa2-lz9-solid | 0.3983 | 16,500,020 | 18.0 | 100.1 | 102.0 MiB | 120.8 MiB | - | ok |
| xz-9e | 0.3975 | 16,466,920 | 3.5 | 118.8 | 422.7 MiB | 41.5 MiB | - | ok |
| zstd-ultra22 | 0.3975 | 16,469,958 | 12.1 | 983.3 | 707.9 MiB | 43.6 MiB | - | ok |
| 7z-lzma2-mx9 | 0.4488 | 18,595,617 | 9.6 | 119.3 | 390.0 MiB | 56.6 MiB | - | ok |

### SfiDemoSetup.exe (18,046,052 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9835 | 17,747,839 | 96.6 | 83.7 | 45.4 MiB | 53.0 MiB | - | ok |
| vfa-zstd19-solid | 0.9748 | 17,591,085 | 4.9 | 84.4 | 147.1 MiB | 81.0 MiB | - | ok |
| vfa-xz9-solid | 0.8839 | 15,950,778 | 2.8 | 34.8 | 298.3 MiB | 97.2 MiB | - | ok |
| vfa-lzma9-solid | 0.8902 | 16,065,012 | 2.8 | 13.5 | 298.5 MiB | 97.3 MiB | - | ok |
| vfa-brotli11-solid | 0.9733 | 17,565,106 | 0.4 | 48.3 | 140.6 MiB | 85.8 MiB | - | ok |
| vfa2-stored-solid | 0.9684 | 17,476,277 | 72.6 | 103.2 | 66.2 MiB | 67.7 MiB | - | ok |
| vfa2-tans-solid | 0.9644 | 17,404,416 | 30.8 | 94.4 | 80.7 MiB | 84.2 MiB | - | ok |
| vfa2-lz | 0.8871 | 16,009,199 | 18.5 | 64.0 | 91.7 MiB | 82.9 MiB | - | ok |
| vfa2-lz-solid | 0.8871 | 16,009,199 | 16.5 | 98.2 | 90.9 MiB | 82.9 MiB | - | ok |
| vfa2-lz9-solid | 0.8858 | 15,984,793 | 7.6 | 75.7 | 90.9 MiB | 82.9 MiB | - | ok |
| xz-9e | 0.8840 | 15,952,108 | 2.8 | 63.0 | 221.5 MiB | 19.3 MiB | - | ok |
| zstd-ultra22 | 0.8843 | 15,957,802 | 5.6 | 869.8 | 685.0 MiB | 20.6 MiB | - | ok |
| 7z-lzma2-mx9 | 0.8833 (best) | 15,939,476 | 14.1 | 69.3 | 235.0 MiB | 39.0 MiB | - | ok |

### blob.bin (1,048,576 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.0006 | 606 | 10.2 | 10.6 | 34.3 MiB | 32.4 MiB | - | ok |
| vfa-zstd19-solid | 0.0006 | 592 | 9.6 | 10.2 | 49.3 MiB | 32.4 MiB | - | ok |
| vfa-xz9-solid | 0.0007 | 746 | 5.0 | 11.1 | 105.7 MiB | 33.4 MiB | - | ok |
| vfa-lzma9-solid | 0.0007 | 702 | 6.5 | 11.1 | 105.7 MiB | 33.3 MiB | - | ok |
| vfa-brotli11-solid | 0.0004 | 452 | 9.0 | 11.0 | 42.0 MiB | 33.4 MiB | - | ok |
| vfa2-stored-solid | 0.2503 | 262,482 | 10.5 | 7.9 | 31.8 MiB | 31.0 MiB | - | ok |
| vfa2-tans-solid | 0.0008 | 808 | 8.4 | 8.0 | 31.9 MiB | 30.9 MiB | - | ok |
| vfa2-lz | 0.0009 | 899 | 9.6 | 7.9 | 34.7 MiB | 30.8 MiB | - | ok |
| vfa2-lz-solid | 0.0009 | 899 | 6.7 | 7.8 | 34.5 MiB | 30.9 MiB | - | ok |
| vfa2-lz9-solid | 0.0009 | 899 | 8.8 | 11.6 | 34.4 MiB | 30.8 MiB | - | ok |
| xz-9e | 0.0005 | 512 | 24.2 | 223.5 | 12.3 MiB | 3.0 MiB | - | ok |
| zstd-ultra22 | 0.0003 (best) | 359 | 3.0 | 224.0 | 652.8 MiB | 3.5 MiB | - | ok |
| 7z-lzma2-mx9 | 0.0006 | 578 | 48.0 | 113.0 | 21.9 MiB | 6.4 MiB | - | ok |

### random.bin (500,000 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0005 | 500,266 | 3.9 | 4.9 | 34.4 MiB | 32.2 MiB | - | ok |
| vfa-zstd19-solid | 1.0005 | 500,257 | 3.7 | 5.2 | 40.9 MiB | 32.2 MiB | - | ok |
| vfa-xz9-solid | 1.0006 | 500,320 | 2.0 | 4.7 | 100.8 MiB | 32.2 MiB | - | ok |
| vfa-lzma9-solid | 1.0142 | 507,095 | 1.9 | 4.0 | 100.8 MiB | 32.3 MiB | - | ok |
| vfa-brotli11-solid | 1.0005 | 500,241 | 1.9 | 5.1 | 43.9 MiB | 32.1 MiB | - | ok |
| vfa2-stored-solid | 1.0006 | 500,280 | 3.8 | 5.1 | 31.3 MiB | 31.5 MiB | - | ok |
| vfa2-tans-solid | 1.0016 | 500,803 | 3.7 | 5.3 | 32.2 MiB | 31.4 MiB | - | ok |
| vfa2-lz | 1.0017 | 500,850 | 3.2 | 3.6 | 36.1 MiB | 31.5 MiB | - | ok |
| vfa2-lz-solid | 1.0017 | 500,850 | 3.3 | 5.3 | 35.8 MiB | 31.5 MiB | - | ok |
| vfa2-lz9-solid | 1.0017 | 500,850 | 3.1 | 5.3 | 35.9 MiB | 31.5 MiB | - | ok |
| xz-9e | 1.0002 | 500,084 | 2.9 | 154.7 | 70.8 MiB | 2.7 MiB | - | ok |
| zstd-ultra22 | 1.0000 (best) | 500,022 | 1.2 | 126.9 | 653.0 MiB | 3.2 MiB | - | ok |
| 7z-lzma2-mx9 | 1.0003 | 500,164 | 14.3 | 68.4 | 14.2 MiB | 6.4 MiB | - | ok |

### app.ico (1,630,489 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0002 | 1,630,779 | 15.9 | 16.3 | 36.5 MiB | 37.6 MiB | - | ok |
| vfa-zstd19-solid | 1.0002 | 1,630,770 | 5.3 | 15.6 | 67.1 MiB | 37.6 MiB | - | ok |
| vfa-xz9-solid | 1.0002 | 1,630,861 | 2.9 | 13.9 | 115.3 MiB | 36.6 MiB | - | ok |
| vfa-lzma9-solid | 1.0110 | 1,648,440 | 2.8 | 7.4 | 115.3 MiB | 36.6 MiB | - | ok |
| vfa-brotli11-solid | 1.0001 | 1,630,730 | 1.3 | 15.6 | 63.4 MiB | 36.5 MiB | - | ok |
| vfa2-stored-solid | 1.0002 | 1,630,766 | 14.2 | 14.8 | 33.6 MiB | 33.6 MiB | - | ok |
| vfa2-tans-solid | 1.0005 | 1,631,254 | 10.9 | 14.0 | 35.4 MiB | 33.5 MiB | - | ok |
| vfa2-lz | 1.0005 | 1,631,375 | 8.7 | 11.7 | 39.9 MiB | 33.6 MiB | - | ok |
| vfa2-lz-solid | 1.0005 | 1,631,375 | 7.7 | 16.5 | 39.8 MiB | 33.6 MiB | - | ok |
| vfa2-lz9-solid | 1.0002 | 1,630,755 | 5.8 | 15.9 | 39.8 MiB | 35.0 MiB | - | ok |
| xz-9e | 1.0001 | 1,630,628 | 3.4 | 307.9 | 80.5 MiB | 3.5 MiB | - | ok |
| zstd-ultra22 | 1.0000 (best) | 1,630,538 | 3.0 | 327.8 | 655.5 MiB | 4.7 MiB | - | ok |
| 7z-lzma2-mx9 | 1.0001 | 1,630,714 | 15.8 | 196.0 | 28.9 MiB | 8.5 MiB | - | ok |

### payload.vfa (2,135,012 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0001 | 2,135,319 | 21.4 | 19.3 | 37.6 MiB | 39.5 MiB | - | ok |
| vfa-zstd19-solid | 0.9986 | 2,131,918 | 7.2 | 20.1 | 83.5 MiB | 39.6 MiB | - | ok |
| vfa-xz9-solid | 0.9989 | 2,132,609 | 2.8 | 13.3 | 120.6 MiB | 38.4 MiB | - | ok |
| vfa-lzma9-solid | 1.0099 | 2,156,220 | 2.9 | 8.4 | 120.5 MiB | 38.6 MiB | - | ok |
| vfa-brotli11-solid | 1.0001 | 2,135,257 | 1.2 | 18.7 | 68.8 MiB | 38.4 MiB | - | ok |
| vfa2-stored-solid | 1.0001 | 2,135,293 | 19.9 | 21.1 | 34.7 MiB | 34.6 MiB | - | ok |
| vfa2-tans-solid | 1.0004 | 2,135,781 | 12.5 | 15.1 | 36.8 MiB | 34.5 MiB | - | ok |
| vfa2-lz | 0.9989 | 2,132,636 | 10.4 | 20.2 | 41.9 MiB | 37.4 MiB | - | ok |
| vfa2-lz-solid | 0.9989 | 2,132,636 | 10.0 | 19.1 | 41.7 MiB | 37.3 MiB | - | ok |
| vfa2-lz9-solid | 0.9985 | 2,131,858 | 6.0 | 21.8 | 41.7 MiB | 37.4 MiB | - | ok |
| xz-9e | 0.9988 | 2,132,368 | 3.5 | 145.4 | 84.8 MiB | 4.0 MiB | - | ok |
| zstd-ultra22 | 0.9984 (best) | 2,131,682 | 3.4 | 403.1 | 656.6 MiB | 5.2 MiB | - | ok |
| 7z-lzma2-mx9 | 0.9990 | 2,132,888 | 18.4 | 143.1 | 37.2 MiB | 9.6 MiB | - | ok |

### vfa.py (61,025 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.3019 | 18,422 | 0.6 | 0.5 | 31.6 MiB | 30.8 MiB | - | ok |
| vfa-zstd19-solid | 0.2793 | 17,046 | 0.4 | 0.6 | 32.4 MiB | 30.8 MiB | - | ok |
| vfa-xz9-solid | 0.2755 | 16,812 | 0.4 | 0.6 | 95.4 MiB | 30.6 MiB | - | ok |
| vfa-lzma9-solid | 0.2748 | 16,768 | 0.4 | 0.6 | 95.4 MiB | 30.6 MiB | - | ok |
| vfa-brotli11-solid | 0.2606 (best) | 15,905 | 0.3 | 0.6 | 34.2 MiB | 30.7 MiB | - | ok |
| vfa2-stored-solid | 1.0045 | 61,301 | 0.6 | 0.5 | 30.5 MiB | 30.5 MiB | - | ok |
| vfa2-tans-solid | 0.6364 | 38,835 | 0.6 | 0.6 | 30.7 MiB | 30.5 MiB | - | ok |
| vfa2-lz | 0.3046 | 18,591 | 0.5 | 0.5 | 33.7 MiB | 30.5 MiB | - | ok |
| vfa2-lz-solid | 0.3046 | 18,591 | 0.5 | 0.6 | 33.5 MiB | 30.6 MiB | - | ok |
| vfa2-lz9-solid | 0.3038 | 18,538 | 0.5 | 0.6 | 33.5 MiB | 30.5 MiB | - | ok |
| xz-9e | 0.2719 | 16,592 | 1.3 | 12.6 | 30.7 MiB | 2.1 MiB | - | ok |
| zstd-ultra22 | 0.2756 | 16,819 | 0.2 | 17.9 | 651.3 MiB | 2.8 MiB | - | ok |
| 7z-lzma2-mx9 | 0.2729 | 16,653 | 4.3 | 10.6 | 7.6 MiB | 5.6 MiB | - | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.

### M4: peak RSS against file size (measured, Linux container, GNU time per process)

VFA2 default settings (`vulp-lz`, dedup, 64 MiB chunks). Synthetic input like the harness's 4 GiB test: every MiB is
512 KiB of random bytes plus 512 KiB of repeated text, so dedup removes the text and the archive is about half the
input. Every row round-trips byte-identically.

| input | create RSS (non-solid / solid) | extract RSS | extract time |
|---:|---:|---:|---:|
| 64 MiB | 206 / 198 MiB | 178 MiB | 0.3 s |
| 256 MiB | 250 / 250 MiB | 204 MiB | 0.8 s |
| 1 GiB | 259 / 259 MiB | 205 MiB | 3.0–3.5 s |
| 4 GiB + 123,457 B (`test_vfa.py --big`) | 275 / 266 MiB | 207 MiB | - |

Memory is bounded by the chunk size, not the file size. Writing holds about three copies of one chunk at once (raw
chunk, filtered copy, LZ output) plus the long-range table (at most 16 MiB). Reading holds one decoded chunk:
extraction goes chunk by chunk and decodes each chunk once. The writer's dedup index grows with the number of
*distinct* 64 KiB segments: about 13 MiB at 4 GiB, capped at 2^20 segments (about 200 MiB).

**Reading the M4 run (sample\ and its files, measured above).**
- **sample\ (whole): VFA2 0.3988 solid / 0.4159 non-solid, against xz -9e 0.3975, zstd -22 0.3975 and 7z 0.4488.**
  Long-range matching and dedup find the second setup exe, which the M3 coder could not. VFA2 compresses at
  35 MB/s (xz: 3.5, zstd -22: 12) with 102 MiB of RAM (xz: 423, zstd -22: 708).
- **Text (vfa.py): 0.3046, against 0.27–0.28 for xz/zstd -19/7z: VFA2 loses here.** About 4.6% of that is the coder:
  vulp-lz uses a lazy parse and per-stream tANS, while zstd -19/xz use optimal parsing and context modelling. On a
  61 KB file, about 4% is container overhead (header, frame, index, footer, routing record: ~540 bytes). The
  context-mixing tier (M5) is the planned answer for text.
- **Decompression speed: 100–200 MB/s for VFA2 on sample\, against ~1 GB/s for zstd.** The C decoder alone runs at
  300–800 MB/s on these inputs; the rest is the Python container (CRC32, SHA-256, file writes).
- **Already-compressed data (exe payload, icon, random.bin): within 0.1% of every other tool.** There is nothing to
  find, and VFA2 stores what it cannot shrink.
- **Small files (blob.bin, 1 MiB ramp): 899 bytes, against 359–746 for the others.** That is the fixed container
  overhead on a tiny archive.

## 2026-10-12 07:52 M4.1 optimal parser (levels 7-9), Linux

Machine: Linux-6.18.44-fc-v114-x86_64-with-glibc2.39, x86_64, 4 logical CPUs. Tools: python 3.13.16; xz xz (XZ Utils) 5.4.5; zstd *** Zstandard CLI (64-bit) v1.5.5, by Yann Collet ***; 7z 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20; python-zstandard 0.25.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa2-lz-solid | 0.3988 | 16,523,530 | 25.5 | 93.1 | 102.2 MiB | 121.2 MiB | - | ok |
| vfa2-lz9-solid | 0.3981 | 16,494,918 | 2.6 | 103.1 | 134.8 MiB | 121.3 MiB | - | ok |
| xz-9e | 0.3975 (best) | 16,466,920 | 2.7 | 142.6 | 422.7 MiB | 41.5 MiB | - | ok |
| zstd-ultra22 | 0.3975 | 16,469,958 | 6.6 | 723.1 | 708.0 MiB | 43.5 MiB | - | ok |
| 7z-lzma2-mx9 | 0.4488 | 18,595,617 | 7.1 | 118.8 | 390.2 MiB | 56.5 MiB | - | ok |

### vfa.py (60,974 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa2-lz-solid | 0.3012 | 18,364 | 0.5 | 0.5 | 33.8 MiB | 30.9 MiB | - | ok |
| vfa2-lz9-solid | 0.2923 | 17,825 | 0.4 | 0.5 | 37.2 MiB | 31.0 MiB | - | ok |
| xz-9e | 0.2719 (best) | 16,580 | 1.0 | 13.9 | 30.7 MiB | 2.0 MiB | - | ok |
| zstd-ultra22 | 0.2757 | 16,808 | 0.0 | 14.6 | 651.3 MiB | 2.6 MiB | - | ok |
| 7z-lzma2-mx9 | 0.2730 | 16,645 | 3.0 | 6.3 | 7.6 MiB | 5.6 MiB | - | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.

### M4.1: what the optimal parser buys (measured)

Levels 7–9 replace the greedy/lazy parse with a price-driven optimal parse. Only the encoder changes: the stream
format, the decoder and the SFX stub are the same, and archives made at these levels open with any M4 reader.
Levels 0–6 produce exactly the same output as before.

Text, through the `_vulp` extension directly (no interpreter start-up), one chunk per input. Sizes in bytes, then
compress / decompress MB/s:

| input | lz -6 | lz -7 | lz -8 | lz -9 | xz -9e | zstd -19 |
|---|---:|---:|---:|---:|---:|---:|
| Python 3.13 stdlib, 155 .py files concatenated (4,590,540) | 1,045,409 (15 / 162) | 972,167 (3.0 / 209) | 952,849 (1.5 / 228) | **939,212** (1.0 / 209) | 878,068 | 896,033 |
| /usr/share/common-licenses concatenated (303,076) | 48,780 (30 / 318) | 46,957 (7.4 / 269) | 46,432 (5.6 / 220) | **46,112** (4.6 / 297) | 43,736 | 45,134 |
| this repo's *.py + *.md (540,877) | 139,684 (13 / 145) | 133,649 (3.8 / 172) | 132,324 (3.0 / 167) | **131,424** (2.7 / 202) | 125,060 | 128,090 |

Reading:
- **Text:** level 9 is 5–10% smaller than level 6, and decodes as fast or faster (fewer, longer sequences). It
  still loses to xz -9e by 5–7% and to zstd -19 by 2–5%. The rest of the gap is in the format, not the parser: xz and
  zstd remember several recent offsets (vulp-lz: one) and xz codes literals with context. Closing it needs a format
  change, which is its own decision.
- **sample\ (mostly x86 executables):** 0.3983 → 0.3981. Binary data was already close to xz; the parser has little
  to add there.
- **Cost:** level 9 compresses sample\ at 2.6 MB/s (xz -9e: 2.7), with 135 MiB peak RSS (xz -9e: 423 MiB). On
  repetitive text it drops to about 1 MB/s; the time is in walking hash chains over the 8 MiB window. A binary-tree
  match finder would be the fix if that matters.
- **Determinism:** level 9 is now part of the cross-compiler digest in the `native` test group. gcc and clang at
  -O0, -O3 and -O3 -march=native -ffast-math give identical level-9 output (Linux). MSVC: not yet run with the
  new parser.
- **Rejected on the way:** a dictionary-free text transform (capital-letter flags + per-chunk word dictionary)
  measured -2.1% on code, -0.3% on prose, -0.8% on this repo, and 0% on sample\ (20 KB of text in 40 MB). Not built;
  filter 5 stays reserved.

## 2026-10-12 03:53 M4 (merged main, before the optimal parser), Windows

Machine: Windows-10-10.0.19045-SP0, AMD64 Family 25 Model 33 Stepping 0, AuthenticAMD, 16 logical CPUs. Tools: python 3.10.5; xz xz (XZ Utils) 5.2.6; zstd *** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***; 7z 7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29; python-zstandard 0.24.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9600 | 39,774,832 | 49.9 | 27.2 | 37.5 MiB | 44.4 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.8101 | 33,561,417 | 5.5 | 27.1 | 179.1 MiB | 144.6 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.3974 (best) | 16,465,674 | 5.5 | 25.6 | 517.8 MiB | 161.0 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.4003 | 16,585,458 | 5.5 | 20.1 | 518.1 MiB | 161.1 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.8153 | 33,778,173 | 0.7 | 26.5 | 173.5 MiB | 142.5 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 0.4587 | 19,003,385 | 47.4 | 29.1 | 73.1 MiB | 63.2 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.4508 | 18,678,012 | 37.0 | 28.2 | 97.6 MiB | 115.2 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.4158 | 17,226,935 | 27.1 | 28.6 | 87.8 MiB | 75.6 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.3988 | 16,523,530 | 27.6 | 28.5 | 97.6 MiB | 113.1 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.3982 | 16,499,213 | 17.5 | 28.7 | 97.5 MiB | 113.0 MiB | 12.3 MiB | ok |
| xz-9e | 0.3975 | 16,467,064 | 4.3 | 137.0 | 425.7 MiB | 44.7 MiB | - | ok |
| zstd-ultra22 | 0.3976 | 16,472,069 | 13.6 | 201.9 | 13.9 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.4488 | 18,594,869 | 13.6 | 172.3 | 391.6 MiB | 57.6 MiB | 0.2 MiB | ok |

### SfiDemoSetup.exe (18,046,052 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9835 | 17,747,839 | 24.0 | 12.8 | 37.5 MiB | 45.1 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.9748 | 17,591,085 | 4.4 | 12.6 | 141.9 MiB | 87.3 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.8839 | 15,950,778 | 3.9 | 11.6 | 294.3 MiB | 93.5 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.8902 | 16,065,012 | 3.8 | 9.0 | 294.1 MiB | 93.7 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.9733 | 17,565,106 | 0.6 | 12.5 | 121.2 MiB | 82.1 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 0.9684 | 17,476,277 | 23.0 | 12.9 | 73.1 MiB | 60.1 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.9644 | 17,404,416 | 18.2 | 12.8 | 77.0 MiB | 77.3 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.8871 | 16,008,969 | 13.9 | 12.8 | 87.8 MiB | 75.1 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.8871 | 16,008,969 | 13.5 | 12.8 | 86.9 MiB | 75.3 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.8858 | 15,984,563 | 8.5 | 12.8 | 87.6 MiB | 75.3 MiB | 12.3 MiB | ok |
| xz-9e | 0.8840 | 15,952,108 | 4.1 | 66.6 | 224.5 MiB | 22.3 MiB | - | ok |
| zstd-ultra22 | 0.8844 | 15,959,910 | 6.2 | 89.1 | 13.9 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.8833 (best) | 15,939,476 | 18.6 | 95.2 | 236.6 MiB | 39.9 MiB | 0.2 MiB | ok |

### blob.bin (1,048,576 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.0006 | 606 | 1.5 | 0.8 | 31.6 MiB | 28.8 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.0006 | 592 | 1.5 | 0.8 | 45.3 MiB | 28.8 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.0007 | 746 | 1.4 | 0.8 | 101.9 MiB | 29.5 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.0007 | 702 | 1.4 | 0.8 | 102.0 MiB | 29.6 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.0004 | 452 | 1.5 | 0.8 | 38.1 MiB | 29.5 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 0.2503 | 262,482 | 1.5 | 0.8 | 36.1 MiB | 27.1 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.0008 | 808 | 1.5 | 0.8 | 36.1 MiB | 27.2 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.0007 | 687 | 1.5 | 0.8 | 36.0 MiB | 27.0 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.0007 | 687 | 1.5 | 0.8 | 36.1 MiB | 27.3 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.0007 | 687 | 1.5 | 0.8 | 36.2 MiB | 27.2 MiB | 12.3 MiB | ok |
| xz-9e | 0.0005 | 512 | 8.3 | 10.6 | 15.3 MiB | 6.1 MiB | - | ok |
| zstd-ultra22 | 0.0003 (best) | 359 | 3.5 | 5.1 | 14.0 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.0006 | 578 | 9.7 | 10.6 | 24.0 MiB | 7.6 MiB | 0.2 MiB | ok |

### random.bin (500,000 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0005 | 500,266 | 0.7 | 0.4 | 31.7 MiB | 28.6 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 1.0005 | 500,257 | 0.7 | 0.4 | 37.3 MiB | 28.8 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 1.0006 | 500,320 | 0.6 | 0.4 | 97.9 MiB | 28.6 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0142 | 507,095 | 0.6 | 0.4 | 97.8 MiB | 28.4 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0005 | 500,241 | 0.6 | 0.4 | 38.9 MiB | 28.5 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0006 | 500,280 | 0.7 | 0.4 | 36.0 MiB | 27.7 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0016 | 500,803 | 0.7 | 0.4 | 36.0 MiB | 27.8 MiB | 12.3 MiB | ok |
| vfa2-lz | 1.0012 | 500,620 | 0.7 | 0.4 | 35.9 MiB | 27.7 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 1.0012 | 500,620 | 0.7 | 0.4 | 35.7 MiB | 27.7 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 1.0012 | 500,620 | 0.7 | 0.4 | 35.7 MiB | 27.7 MiB | 12.3 MiB | ok |
| xz-9e | 1.0002 | 500,084 | 2.4 | 5.0 | 73.8 MiB | 5.6 MiB | - | ok |
| zstd-ultra22 | 1.0000 (best) | 500,022 | 1.3 | 2.4 | 13.9 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 1.0003 | 500,164 | 3.9 | 4.9 | 16.4 MiB | 7.5 MiB | 0.2 MiB | ok |

### app.ico (1,630,489 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0002 | 1,630,779 | 2.3 | 1.2 | 32.5 MiB | 32.5 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 1.0002 | 1,630,770 | 2.0 | 1.2 | 63.1 MiB | 32.4 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 1.0002 | 1,630,861 | 1.6 | 1.2 | 110.6 MiB | 32.9 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0110 | 1,648,440 | 1.7 | 1.1 | 110.5 MiB | 32.9 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0001 | 1,630,730 | 1.1 | 1.2 | 52.0 MiB | 32.9 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0002 | 1,630,766 | 2.3 | 1.2 | 37.9 MiB | 30.0 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0005 | 1,631,254 | 2.2 | 1.2 | 38.8 MiB | 29.9 MiB | 12.3 MiB | ok |
| vfa2-lz | 1.0004 | 1,631,145 | 2.1 | 1.2 | 37.8 MiB | 29.9 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 1.0004 | 1,631,145 | 2.1 | 1.2 | 38.8 MiB | 29.9 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 1.0000 (best) | 1,630,525 | 1.9 | 1.2 | 37.9 MiB | 31.4 MiB | 12.3 MiB | ok |
| xz-9e | 1.0001 | 1,630,628 | 4.0 | 15.3 | 83.6 MiB | 6.6 MiB | - | ok |
| zstd-ultra22 | 1.0000 | 1,630,538 | 2.9 | 7.6 | 14.0 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 1.0001 | 1,630,714 | 9.5 | 15.3 | 31.1 MiB | 9.6 MiB | 0.2 MiB | ok |

### payload.vfa (2,135,012 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0001 | 2,135,319 | 3.0 | 1.6 | 33.5 MiB | 34.9 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.9986 | 2,131,918 | 2.4 | 1.5 | 79.5 MiB | 34.9 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.9989 | 2,132,609 | 1.9 | 1.6 | 115.9 MiB | 34.8 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0099 | 2,156,220 | 2.0 | 1.5 | 115.9 MiB | 34.8 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0001 | 2,135,257 | 1.2 | 1.6 | 56.3 MiB | 34.6 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0001 | 2,135,293 | 2.8 | 1.5 | 38.8 MiB | 30.9 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0004 | 2,135,781 | 2.7 | 1.6 | 39.8 MiB | 30.9 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.9988 | 2,132,406 | 2.7 | 1.5 | 38.8 MiB | 33.0 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.9988 | 2,132,406 | 2.7 | 1.6 | 39.8 MiB | 32.9 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.9984 (best) | 2,131,628 | 2.4 | 1.6 | 39.1 MiB | 32.8 MiB | 12.3 MiB | ok |
| xz-9e | 0.9988 | 2,132,368 | 4.3 | 19.7 | 87.9 MiB | 7.2 MiB | - | ok |
| zstd-ultra22 | 0.9984 | 2,131,682 | 3.4 | 9.9 | 14.0 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.9990 | 2,132,888 | 10.1 | 20.5 | 39.4 MiB | 10.6 MiB | 0.2 MiB | ok |

### vfa.py (62,266 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.2971 | 18,499 | 0.1 | 0.0 | 30.8 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.2746 | 17,097 | 0.1 | 0.0 | 28.3 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.2706 | 16,848 | 0.1 | 0.0 | 91.5 MiB | 26.8 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.2698 | 16,802 | 0.1 | 0.0 | 91.7 MiB | 26.8 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.2561 (best) | 15,946 | 0.1 | 0.0 | 30.3 MiB | 27.0 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0044 | 62,542 | 0.1 | 0.0 | 34.7 MiB | 26.8 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.6416 | 39,947 | 0.1 | 0.0 | 34.8 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.2958 | 18,421 | 0.1 | 0.0 | 34.6 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.2958 | 18,421 | 0.1 | 0.0 | 34.6 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.2951 | 18,377 | 0.1 | 0.0 | 34.8 MiB | 26.9 MiB | 12.3 MiB | ok |
| xz-9e | 0.2669 | 16,620 | 0.5 | 0.6 | 33.8 MiB | 5.1 MiB | - | ok |
| zstd-ultra22 | 0.2709 | 16,868 | 0.2 | 0.3 | 14.0 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.2681 | 16,693 | 0.6 | 0.6 | 9.9 MiB | 6.6 MiB | 0.2 MiB | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.

### M4 on Windows: reading (owner's machine, MSVC build)

- **Same output as Linux.** sample\ comes out at 16,523,530 bytes at level 6 on Windows, exactly the Linux size. The
  level 9 sizes also match: merged `main` built on Linux gives the same 187-byte offset at both levels against
  these rows, and that offset is from how the input folder is named. Same ratios, same codec output: the
  determinism goal holds across compilers and operating systems on real data.
- **Compression** speed matches Linux (27.6 MB/s at level 6). On this machine level 9 runs at 17.5 MB/s. These rows
  are from before the optimal parser; with it, level 9 will be slower and smaller.
- **Where VFA loses on Windows: decompression speed.** Every VFA row, VFA1 and VFA2 alike, extracts sample\ at
  about 25–29 MB/s, against 137–202 MB/s for xz/zstd/7z and 93–128 MB/s for the same VFA2 archive on Linux. The
  codec is not the limit (VFA1 zstd extracts at the same 27 MB/s). The fixed per-run cost seen in M3 (about 0.7 s:
  Python start-up plus imports on Windows) and per-file work while writing explain part of it. Not yet profiled.
- **vfa.py (text):** VFA2 0.2958 against xz 0.2669 and 7z 0.2681. The level 9 optimal parser closes part of this
  gap (Linux: 0.3012 → 0.2923); the rest needs a format change (see M4.1).

## 2026-10-12 21:21 M4.1 optimal parser, Windows

Machine: Windows-10-10.0.19045-SP0, AMD64 Family 25 Model 33 Stepping 0, AuthenticAMD, 16 logical CPUs. Tools: python 3.10.5; xz xz (XZ Utils) 5.2.6; zstd *** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***; 7z 7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29; python-zstandard 0.24.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9600 | 39,774,832 | 23.0 | 28.1 | 37.4 MiB | 44.3 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.8101 | 33,561,417 | 5.5 | 26.9 | 179.2 MiB | 144.9 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.3974 (best) | 16,465,674 | 5.5 | 25.6 | 518.0 MiB | 161.0 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.4003 | 16,585,458 | 5.6 | 20.2 | 518.1 MiB | 161.1 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.8153 | 33,778,173 | 0.7 | 26.5 | 173.5 MiB | 142.1 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 0.4587 | 19,003,385 | 45.4 | 29.0 | 73.0 MiB | 63.1 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.4508 | 18,678,012 | 36.5 | 28.5 | 97.9 MiB | 115.2 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.4158 | 17,226,935 | 28.4 | 28.4 | 87.9 MiB | 75.5 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.3988 | 16,523,530 | 26.5 | 28.8 | 97.6 MiB | 113.2 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.3981 | 16,494,918 | 3.7 | 28.7 | 124.4 MiB | 113.2 MiB | 12.3 MiB | ok |
| xz-9e | 0.3975 | 16,467,064 | 4.4 | 133.9 | 425.7 MiB | 44.7 MiB | - | ok |
| zstd-ultra22 | 0.3976 | 16,472,069 | 12.8 | 215.8 | 14.0 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.4488 | 18,594,869 | 11.0 | 170.3 | 391.5 MiB | 57.6 MiB | 0.2 MiB | ok |

### SfiDemoSetup.exe (18,046,052 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.9835 | 17,747,839 | 25.3 | 12.8 | 37.5 MiB | 44.1 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.9748 | 17,591,085 | 4.5 | 12.9 | 141.9 MiB | 86.7 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.8839 | 15,950,778 | 3.8 | 11.7 | 294.1 MiB | 93.5 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.8902 | 16,065,012 | 3.8 | 9.1 | 294.5 MiB | 93.5 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.9733 | 17,565,106 | 0.5 | 12.3 | 121.0 MiB | 82.5 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 0.9684 | 17,476,277 | 22.9 | 13.0 | 72.9 MiB | 60.7 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.9644 | 17,404,416 | 18.8 | 12.7 | 76.9 MiB | 76.6 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.8871 | 16,008,969 | 14.2 | 13.0 | 87.6 MiB | 75.1 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.8871 | 16,008,969 | 14.3 | 12.8 | 87.1 MiB | 75.3 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.8855 | 15,980,598 | 1.7 | 13.0 | 121.1 MiB | 75.2 MiB | 12.3 MiB | ok |
| xz-9e | 0.8840 | 15,952,108 | 4.2 | 66.0 | 224.6 MiB | 22.3 MiB | - | ok |
| zstd-ultra22 | 0.8844 | 15,959,910 | 6.3 | 94.9 | 14.0 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.8833 (best) | 15,939,476 | 18.5 | 100.6 | 236.5 MiB | 39.9 MiB | 0.2 MiB | ok |

### blob.bin (1,048,576 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.0006 | 606 | 1.6 | 0.8 | 31.7 MiB | 28.7 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.0006 | 592 | 1.6 | 0.8 | 45.3 MiB | 28.7 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.0007 | 746 | 1.5 | 0.8 | 102.0 MiB | 29.7 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.0007 | 702 | 1.6 | 0.8 | 102.1 MiB | 29.5 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.0004 | 452 | 1.5 | 0.8 | 38.0 MiB | 29.7 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 0.2503 | 262,482 | 1.5 | 0.8 | 36.0 MiB | 27.3 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.0008 | 808 | 1.5 | 0.8 | 36.0 MiB | 27.0 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.0007 | 687 | 1.6 | 0.8 | 36.2 MiB | 27.3 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.0007 | 687 | 1.5 | 0.8 | 36.1 MiB | 27.2 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.0007 | 687 | 1.5 | 0.8 | 36.1 MiB | 27.0 MiB | 12.3 MiB | ok |
| xz-9e | 0.0005 | 512 | 8.2 | 11.2 | 15.3 MiB | 6.1 MiB | - | ok |
| zstd-ultra22 | 0.0003 (best) | 359 | 3.6 | 5.6 | 14.1 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.0006 | 578 | 10.3 | 11.0 | 24.0 MiB | 7.6 MiB | 0.2 MiB | ok |

### random.bin (500,000 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0005 | 500,266 | 0.7 | 0.4 | 31.3 MiB | 28.6 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 1.0005 | 500,257 | 0.7 | 0.4 | 37.2 MiB | 28.7 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 1.0006 | 500,320 | 0.6 | 0.4 | 97.8 MiB | 28.5 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0142 | 507,095 | 0.6 | 0.4 | 97.8 MiB | 28.4 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0005 | 500,241 | 0.6 | 0.4 | 38.2 MiB | 28.6 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0006 | 500,280 | 0.7 | 0.4 | 35.9 MiB | 27.8 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0016 | 500,803 | 0.6 | 0.4 | 35.6 MiB | 27.8 MiB | 12.3 MiB | ok |
| vfa2-lz | 1.0012 | 500,620 | 0.7 | 0.4 | 36.1 MiB | 27.7 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 1.0012 | 500,620 | 0.7 | 0.4 | 36.1 MiB | 27.9 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 1.0012 | 500,620 | 0.6 | 0.4 | 35.9 MiB | 27.8 MiB | 12.3 MiB | ok |
| xz-9e | 1.0002 | 500,084 | 2.5 | 5.5 | 73.8 MiB | 5.5 MiB | - | ok |
| zstd-ultra22 | 1.0000 (best) | 500,022 | 1.1 | 2.6 | 14.0 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 1.0003 | 500,164 | 4.1 | 5.3 | 16.4 MiB | 7.5 MiB | 0.2 MiB | ok |

### app.ico (1,630,489 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0002 | 1,630,779 | 2.3 | 1.2 | 32.5 MiB | 32.5 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 1.0002 | 1,630,770 | 1.9 | 1.2 | 62.9 MiB | 32.3 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 1.0002 | 1,630,861 | 1.6 | 1.2 | 110.6 MiB | 32.9 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0110 | 1,648,440 | 1.6 | 1.1 | 110.5 MiB | 32.9 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0001 | 1,630,730 | 1.0 | 1.2 | 51.9 MiB | 32.9 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0002 | 1,630,766 | 2.4 | 1.2 | 37.9 MiB | 30.0 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0005 | 1,631,254 | 2.3 | 1.2 | 37.9 MiB | 29.9 MiB | 12.3 MiB | ok |
| vfa2-lz | 1.0004 | 1,631,145 | 2.1 | 1.2 | 38.1 MiB | 29.8 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 1.0004 | 1,631,145 | 2.1 | 1.2 | 38.1 MiB | 30.0 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 1.0000 | 1,630,553 | 1.9 | 1.2 | 43.8 MiB | 31.5 MiB | 12.3 MiB | ok |
| xz-9e | 1.0001 | 1,630,628 | 3.9 | 17.0 | 83.5 MiB | 6.7 MiB | - | ok |
| zstd-ultra22 | 1.0000 (best) | 1,630,538 | 3.0 | 8.3 | 13.9 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 1.0001 | 1,630,714 | 9.3 | 16.3 | 31.1 MiB | 9.7 MiB | 0.2 MiB | ok |

### payload.vfa (2,135,012 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 1.0001 | 2,135,319 | 2.9 | 1.6 | 33.4 MiB | 34.9 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.9986 | 2,131,918 | 2.4 | 1.6 | 79.6 MiB | 35.1 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.9989 | 2,132,609 | 2.0 | 1.6 | 115.9 MiB | 34.9 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 1.0099 | 2,156,220 | 2.0 | 1.5 | 115.9 MiB | 34.7 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 1.0001 | 2,135,257 | 1.1 | 1.6 | 56.3 MiB | 34.6 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0001 | 2,135,293 | 3.0 | 1.6 | 38.9 MiB | 30.9 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 1.0004 | 2,135,781 | 2.9 | 1.5 | 39.0 MiB | 30.9 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.9988 | 2,132,406 | 2.7 | 1.6 | 38.8 MiB | 32.9 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.9988 | 2,132,406 | 2.7 | 1.6 | 39.7 MiB | 33.0 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.9984 | 2,131,693 | 2.2 | 1.6 | 47.7 MiB | 32.8 MiB | 12.3 MiB | ok |
| xz-9e | 0.9988 | 2,132,368 | 4.0 | 20.3 | 87.8 MiB | 7.1 MiB | - | ok |
| zstd-ultra22 | 0.9984 (best) | 2,131,682 | 3.4 | 10.7 | 14.0 MiB | 14.0 MiB | - | ok |
| 7z-lzma2-mx9 | 0.9990 | 2,132,888 | 10.8 | 21.8 | 39.4 MiB | 10.6 MiB | 0.2 MiB | ok |

### vfa.py (62,266 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa-default | 0.2971 | 18,499 | 0.1 | 0.0 | 30.7 MiB | 26.8 MiB | 12.3 MiB | ok |
| vfa-zstd19-solid | 0.2746 | 17,097 | 0.1 | 0.0 | 28.2 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa-xz9-solid | 0.2706 | 16,848 | 0.1 | 0.0 | 91.7 MiB | 26.8 MiB | 12.3 MiB | ok |
| vfa-lzma9-solid | 0.2698 | 16,802 | 0.1 | 0.0 | 91.6 MiB | 26.8 MiB | 12.3 MiB | ok |
| vfa-brotli11-solid | 0.2561 (best) | 15,946 | 0.1 | 0.0 | 30.4 MiB | 27.1 MiB | 12.3 MiB | ok |
| vfa2-stored-solid | 1.0044 | 62,542 | 0.1 | 0.0 | 34.8 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa2-tans-solid | 0.6416 | 39,947 | 0.1 | 0.0 | 34.8 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa2-lz | 0.2958 | 18,421 | 0.1 | 0.0 | 34.8 MiB | 26.8 MiB | 12.3 MiB | ok |
| vfa2-lz-solid | 0.2958 | 18,421 | 0.1 | 0.0 | 34.7 MiB | 26.9 MiB | 12.3 MiB | ok |
| vfa2-lz9-solid | 0.2868 | 17,858 | 0.1 | 0.0 | 34.7 MiB | 26.9 MiB | 12.3 MiB | ok |
| xz-9e | 0.2669 | 16,620 | 0.6 | 0.7 | 33.9 MiB | 5.1 MiB | - | ok |
| zstd-ultra22 | 0.2709 | 16,868 | 0.2 | 0.3 | 13.9 MiB | 13.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.2681 | 16,693 | 0.6 | 0.7 | 9.9 MiB | 6.6 MiB | 0.2 MiB | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.

### M4.1 on Windows, and where Windows extraction time goes (measured)

- **Same output as Linux.** Level 9 gives sample\ in 16,494,918 bytes on Windows (MSVC), byte for byte the size of
  the Linux run. `test_vfa.py` on Windows confirms identical level-9 streams across MSVC /Od and /O2 and the
  gcc/clang builds.
- **Ratios:** sample\ 0.3981 (xz -9e 0.3975), vfa.py 0.2868, down from 0.2958 at level 6 (xz -9e 0.2669).
- **Level 9 is slow on big binaries here.** It compresses sample\ at 3.7 MB/s (xz -9e: 4.4), but SfiDemoSetup.exe
  only at 1.7 MB/s (xz -9e: 4.2). That run took 10.6 s for 18 MB, for a 0.2% gain over level 6. The default
  level 5 is unaffected.
- **Extraction on Windows: almost all of it is start-up, not decoding.** Every VFA row takes 1.36–1.5 s,
  whatever the size: 62 KB and 41 MB take nearly the same time. Measured on the owner's machine
  (`-X importtime`, `cProfile`, PowerShell `Measure-Command`) for `vfa x` of a small archive:

  | part | time |
  |---|---:|
  | Python interpreter start (`python -c pass`, no VFA code) | 0.99 s |
  | VFA's imports | 0.25 s |
  | …of which `import argon2` (runs `cmd /c ver` via `platform.win32_ver()` to pick its defaults) | 0.17 s |
  | extraction itself | ~0.01 s |
  | total | 1.36 s |

  The interpreter start (typically 30–60 ms) is a property of that machine's Python install (antivirus scanning,
  drive), outside VFA. The argon2 import was VFA's: it ran on every `vfa x`, and in the SFX stub, though only
  encrypted archives use it. Since this change, cryptography and argon2 load on first use (`vfa_extract._crypto`,
  `_argon2`). Expected saving is about 0.18 s per run on that machine; not yet re-measured on Windows.

## 2026-10-14 06:53 M5 vulp-cm, Linux

Machine: Linux-6.18.44-fc-v114-x86_64-with-glibc2.39, x86_64, 4 logical CPUs. Tools: python 3.13.16; xz xz (XZ Utils) 5.4.5; zstd *** Zstandard CLI (64-bit) v1.5.5, by Yann Collet ***; 7z 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20; python-zstandard 0.25.0

Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. Stub = size of the self-extractor the format needs ("-" = none exists for that tool).

### licenses.txt (303,076 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa2-lz9-solid | 0.1540 | 46,659 | 1.1 | 3.1 | 31.2 MiB | 24.9 MiB | - | ok |
| vfa2-cm-solid | 0.1125 | 34,086 | 0.5 | 0.5 | 81.1 MiB | 78.1 MiB | - | ok |
| vfa2-cm9-solid | 0.1123 (best) | 34,042 | 0.3 | 0.4 | 214.2 MiB | 213.5 MiB | - | ok |
| xz-9e | 0.1443 | 43,736 | 2.8 | 51.7 | 31.0 MiB | 2.3 MiB | - | ok |
| zstd-ultra22 | 0.1489 | 45,115 | 0.6 | 60.7 | 651.8 MiB | 2.9 MiB | - | ok |
| 7z-lzma2-mx9 | 0.1446 | 43,812 | 5.3 | 33.6 | 14.3 MiB | 5.8 MiB | - | ok |

### repo.txt (623,371 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa2-lz9-solid | 0.2428 | 151,371 | 1.5 | 6.4 | 33.2 MiB | 25.5 MiB | - | ok |
| vfa2-cm-solid | 0.1843 | 114,891 | 0.5 | 0.6 | 82.0 MiB | 79.6 MiB | - | ok |
| vfa2-cm9-solid | 0.1840 (best) | 114,694 | 0.4 | 0.5 | 225.1 MiB | 223.9 MiB | - | ok |
| xz-9e | 0.2291 | 142,808 | 2.1 | 53.0 | 62.2 MiB | 2.7 MiB | - | ok |
| zstd-ultra22 | 0.2349 | 146,403 | 1.0 | 117.6 | 652.7 MiB | 3.4 MiB | - | ok |
| 7z-lzma2-mx9 | 0.2291 | 142,791 | 7.1 | 42.5 | 18.1 MiB | 6.2 MiB | - | ok |

### stdlib.txt (4,590,540 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa2-lz9-solid | 0.2047 | 939,759 | 1.0 | 36.4 | 58.0 MiB | 34.0 MiB | - | ok |
| vfa2-cm-solid | 0.1494 | 685,901 | 0.6 | 0.7 | 88.4 MiB | 83.9 MiB | - | ok |
| vfa2-cm9-solid | 0.1485 (best) | 681,567 | 0.3 | 0.5 | 233.1 MiB | 228.8 MiB | - | ok |
| xz-9e | 0.1913 | 878,068 | 1.5 | 81.5 | 104.5 MiB | 6.4 MiB | - | ok |
| zstd-ultra22 | 0.1952 | 895,882 | 1.4 | 298.8 | 657.3 MiB | 7.8 MiB | - | ok |
| 7z-lzma2-mx9 | 0.1915 | 879,090 | 3.4 | 55.7 | 66.3 MiB | 10.6 MiB | - | ok |

### sample (41,430,058 bytes)

| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| vfa2-lz9-solid | 0.3981 | 16,494,918 | 3.5 | 102.4 | 128.0 MiB | 114.7 MiB | - | ok |
| vfa2-cm-solid | 0.3970 | 16,449,447 | 1.0 | 0.9 | 137.2 MiB | 114.4 MiB | - | ok |
| vfa2-cm9-solid | 0.3970 (best) | 16,447,439 | 0.7 | 0.8 | 292.6 MiB | 268.7 MiB | - | ok |
| xz-9e | 0.3975 | 16,466,920 | 2.6 | 127.6 | 422.5 MiB | 41.5 MiB | - | ok |
| zstd-ultra22 | 0.3975 | 16,469,958 | 8.2 | 827.4 | 707.9 MiB | 43.0 MiB | - | ok |
| 7z-lzma2-mx9 | 0.4488 | 18,595,617 | 6.8 | 117.4 | 390.2 MiB | 56.8 MiB | - | ok |

VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.

Text sets: licenses.txt = /usr/share/common-licenses concatenated; repo.txt = this repo's *.py + *.md; stdlib.txt = 155
Python 3.13 stdlib .py files concatenated (the same inputs as the M4.1 table above). vfa2-cm = `--method cm` (level 5,
2^22 tables), vfa2-cm9 = `--method cm --level 9` (2^24 tables).

### M5: what vulp-cm buys (measured)

- **Text and code:** 20–23% smaller than xz -9e (licenses 34,086 vs 43,736; repo 114,891 vs 142,808; stdlib 685,901 vs
  878,068) and 27% smaller than vulp-lz -9. That closes the M4 gap to xz and passes it by a wide margin. Level 9's
  bigger tables add only 0.1–0.6%, for 2.6× the memory.
- **sample\ (mostly compressed installers):** 0.3970, the smallest of all tools (xz -9e 0.3975), because the writer
  keeps vulp-cm only for chunks where it beats vulp-lz. Here that gain is 0.3%, and it costs the whole archive's
  decode speed: 0.9 MB/s instead of 102 MB/s. A minimum-gain rule (keep CM only if it saves, say, 1%) would avoid
  that trade on data like this. That is a policy choice, not a format change.
- **Cost:** about 0.5–1 MB/s to compress *and* to decompress (CM decodes by running the same model), and 80–90 MiB
  peak RSS at the default level (210–290 MiB at level 9). It is opt-in: `vfa c --format vfa2` still defaults to vulp-lz.
- **Determinism:** vulp-cm is in the cross-compiler digest. gcc and clang at -O0, -O3 and -O3 -march=native
  -ffast-math give identical output, it matches the _vulp extension, and the pure-Python reference agrees bit for
  bit. MSVC: not yet run.
