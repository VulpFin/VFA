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
