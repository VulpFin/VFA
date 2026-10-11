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
  order. Fixed after this run: VFA now sorts directory entries, so the same tree gives the same archive on every machine.
- **Small inputs:** every VFA row shows ~0.65 s to compress and ~1.34 s to extract regardless of size, which is
  interpreter and import start-up, so small-file MB/s figures say nothing about the codec. The ~0.7 s extra on
  extraction appears on Windows only (Linux: ~0.15 s for both) and has not been investigated yet.
- `zstd --ultra -22` did not run (CLI not installed); `zstd22-pylib` is the same library at level 22, labelled as a
  stand-in.
