# Experimental `--method neural` for VFA

This fork/copy adds a new compression method:

```bash
python3 vfa.py c archive.vfa input_folder --method neural --level 8
python3 vfa.py t archive.vfa
python3 vfa.py x archive.vfa -o extracted
```

## What is implemented now

`neural_codec.py` provides a stable VFA codec hook with:

- adaptive/content-defined chunking inside each VFA block
- long-range context features from prior segment shingles
- context-mixing style feature extraction/scoring
- per-segment entropy backend selection:
  - store
  - zlib
  - zstd, if installed
  - brotli, if installed
  - lzma/xz
  - bz2
  - lz4, if installed
- runtime/hardware detection reporting for native/GPU-capable libraries

This gives you a working experimental method today, while keeping a place to plug
in a real deterministic neural entropy coder later.

## Important reality check

A real neural-network entropy coder is a substantial research/engineering project.
It needs:

1. a deterministic trained model architecture,
2. quantized probability outputs,
3. range coding or ANS coding,
4. model version pinning inside the bitstream,
5. identical CPU/GPU numerical behavior or a carefully quantized inference path,
6. fallback paths when GPU acceleration is unavailable,
7. lots of corpus testing to avoid expanding normal data.

The current implementation is intentionally conservative: it does not require a
huge ML stack and is portable enough to use now.

## Recommended tests

```bash
mkdir -p /tmp/vfa-neural-test/in
printf 'hello hello hello hello\n' > /tmp/vfa-neural-test/in/a.txt
python3 vfa.py c /tmp/vfa-neural-test/test.vfa /tmp/vfa-neural-test/in --method neural --level 8 -v
python3 vfa.py t /tmp/vfa-neural-test/test.vfa
rm -rf /tmp/vfa-neural-test/out
python3 vfa.py x /tmp/vfa-neural-test/test.vfa -o /tmp/vfa-neural-test/out
cmp /tmp/vfa-neural-test/in/a.txt /tmp/vfa-neural-test/out/tmp/vfa-neural-test/in/a.txt
```

Note: VFA currently stores paths as provided. For cross-platform archives, create
from a parent folder using relative paths.
