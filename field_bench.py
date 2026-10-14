# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
#!/usr/bin/env python3
"""
field_bench.py - measure VFA's coders on your own files, privately.

    python field_bench.py D:\\Projects E:\\SteamLibrary C:\\Users\\me\\Documents --out field_results.md

Walks the given folders, sorts files into kinds (text, source code, Postgres data, raw / compressed images and audio,
video, executables, game data, archives, other), takes a repeatable sample of each kind (--budget-mb, default 200 MB
per kind), and compresses each sample with vulp-lz and vulp-cm (at one --level, default 9), xz -9e and zstd -19 in
64 MiB pieces, checking that every one decodes back exactly. The results file holds only totals per kind (bytes, file counts, compressed sizes,
speeds): no file names, paths or contents. Nothing is written anywhere else and nothing is sent anywhere.

It needs the _vulp extension (python build_vulp.py) and reads files only. vulp-cm is slow (about 0.5-1 MB/s each
way), so the default budget takes roughly 2-4 hours; --budget-mb 50 gives a first look in well under an hour.
A Postgres data folder is best read with the server stopped (a live one still works; pages may just be mid-write).
"""
import argparse, os, pathlib, platform, random, sys, time, lzma

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

KINDS = {
    "text": {".txt", ".md", ".log", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".yaml", ".yml", ".ini", ".cfg",
             ".conf", ".toml", ".rst", ".tex", ".srt", ".sql"},
    "source": {".py", ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".java", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs",
               ".rb", ".php", ".swift", ".kt", ".lua", ".sh", ".ps1", ".bat", ".css", ".scss", ".vue", ".gd", ".shader",
               ".hlsl", ".glsl"},
    "image-raw": {".bmp", ".tif", ".tiff", ".dng", ".cr2", ".cr3", ".nef", ".arw", ".psd", ".tga", ".dds", ".exr", ".hdr"},
    "image-compressed": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".heic"},
    "audio-raw": {".wav", ".aif", ".aiff", ".pcm"},
    "audio-compressed": {".mp3", ".ogg", ".opus", ".m4a", ".aac", ".flac", ".wma"},
    "video": {".mp4", ".mkv", ".avi", ".mov", ".webm", ".wmv", ".m4v", ".bk2", ".bik", ".usm"},
    "executable": {".exe", ".dll", ".so", ".dylib", ".sys", ".pyd", ".node"},
    "game-data": {".pak", ".vpk", ".assets", ".resource", ".ress", ".bundle", ".dat", ".bin", ".bsa", ".ba2", ".wad",
                  ".upk", ".uasset", ".umap", ".gcf", ".arc", ".big", ".pck", ".sav", ".esm", ".esp"},
    "archive": {".zip", ".7z", ".rar", ".gz", ".xz", ".zst", ".bz2", ".cab", ".msi", ".jar", ".apk", ".vfa"},
}
EXT_KIND = {e: k for k, exts in KINDS.items() for e in exts}
PIECE = 1 << 26                              # 64 MiB, the VFA2 default chunk size
SKIP_DIRS = {"$recycle.bin", "system volume information", ".git", "node_modules", "__pycache__", "windows", "winsxs"}

def kind_of(path: pathlib.Path, pg_roots) -> str:
    if any(r in path.parents for r in pg_roots): return "postgres"
    return EXT_KIND.get(path.suffix.lower(), "other")

def walk(roots, max_file):
    """(kind, real size, sampled size (capped at max_file), path) for every readable regular file; Postgres data
    folders (with PG_VERSION) are their own kind."""
    files = []; pg_roots = set()
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
            if "PG_VERSION" in filenames and "base" in dirnames: pg_roots.add(pathlib.Path(dirpath))
            for fn in filenames:
                p = pathlib.Path(dirpath) / fn
                try:
                    st = p.stat()
                    if not p.is_file() or st.st_size == 0: continue
                except OSError:
                    continue
                files.append((p, st.st_size))
    return [(kind_of(p, pg_roots), size, min(size, max_file), p) for p, size in files]

def sample(files, budget, seed=1):
    """Repeatable random sample per kind, up to budget bytes each (a large file contributes its first max_file bytes)."""
    by = {}
    for k, real, capped, p in files: by.setdefault(k, []).append((capped, real, p))
    rnd = random.Random(seed); picked = {}
    for k, lst in sorted(by.items()):
        lst.sort(key=lambda t: str(t[2])); rnd.shuffle(lst); total = 0; sel = []
        for capped, _real, p in lst:
            if total >= budget: break
            sel.append((p, min(capped, budget - total))); total += min(capped, budget - total)
        picked[k] = (sel, len(lst), sum(r for _, r, _ in lst))
    return picked

def read_blob(sel):
    """The sampled files back to back, the offset where each starts, and how many could be read."""
    out = bytearray(); n = 0; starts = []
    for p, take in sel:
        try:
            with open(p, "rb") as f: data = f.read(take)
        except OSError:
            continue
        if data: starts.append(len(out)); out += data; n += 1
    return bytes(out), starts, n

def codecs(level):
    """The coders at one --level, exactly as 'vfa c --format vfa2 --method cm --level N' runs them."""
    import _vulp as C, vfa2
    level_cm = vfa2.cm_bits(level)
    try: import zstandard as zs
    except Exception: zs = None
    # vulp codecs see the piece through the filter VFA's own router picked for it (r = (fid, fparams, filtered));
    # xz and zstd get the raw bytes
    unf = lambda r, d, n: vfa2.FILTERS[r[0]].decode(r[1], d, n)
    out = {
        "vulp-lz": (True, lambda d, r: C.lz_encode(r[2], level), lambda e, n, r: unf(r, C.lz_decode(e, n), n)),
        "vulp-cm": (True, lambda d, r: C.cm_encode(r[2], level_cm), lambda e, n, r: unf(r, C.cm_decode(e, n, level_cm), n)),
        "xz -9e": (False, lambda d, r: lzma.compress(d, preset=9 | lzma.PRESET_EXTREME), lambda e, n, r: lzma.decompress(e)),
    }
    if zs:
        out["zstd -19"] = (False, lambda d, r: zs.ZstdCompressor(level=19).compress(d),
                           lambda e, n, r: zs.ZstdDecompressor().decompress(e, max_output_size=n))
    return out

def route(piece, bounds):
    """The filter 'vfa c --format vfa2' would choose for this piece (vfa2.route with the files' boundaries, as the
    writer passes them, so mixed files can get a segmented filter), applied. Returns ((fid, fparams, filtered), s)."""
    import vfa2
    t = time.perf_counter()
    fid, fp, _ = vfa2.route(piece, bounds, vfa2.CODER_LZ)
    fparams, data = vfa2.FILTERS[fid].encode(piece, fp)
    return (fid, fparams, data), time.perf_counter() - t

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="+", help="folders to sample from (read only)")
    ap.add_argument("--budget-mb", type=int, default=200, help="sample size per kind of file (default 200 MB)")
    ap.add_argument("--max-file-mb", type=int, default=64, help="at most this much of any one file (default 64 MB)")
    ap.add_argument("--kinds", help="only these kinds, comma-separated (default: all found)")
    ap.add_argument("--level", type=int, default=9, choices=range(10), metavar="0-9",
                    help="the vfa --level both coders run at (default 9: vulp-lz -9 and vulp-cm with 2^24 tables, "
                         "about 220 MiB; 5 = VFA's default)")
    ap.add_argument("--out", default="field_results.md")
    a = ap.parse_args()
    try:
        import _vulp
        if getattr(_vulp, "VERSION", 0) < 4: raise ImportError("old")
    except ImportError:
        sys.exit("field_bench needs the current _vulp extension: python build_vulp.py")
    t0 = time.time()
    print("scanning ...", flush=True)
    files = walk(a.roots, a.max_file_mb << 20)
    picked = sample(files, a.budget_mb << 20)
    if a.kinds: picked = {k: v for k, v in picked.items() if k in a.kinds.split(",")}
    print(f"{len(files)} files in {len(picked)} kinds ({time.time() - t0:.0f} s); sampling up to {a.budget_mb} MB each", flush=True)
    cods = codecs(a.level)
    rows = []
    for k, (sel, nfiles, total) in picked.items():
        blob, starts, nread = read_blob(sel)
        if not blob: continue
        res = {}
        pieces, routed = [], []
        for off in range(0, len(blob), PIECE):         # filter choice + filtering count as vulp encode time
            pc = blob[off:off + PIECE]
            cuts = sorted({0} | {s - off for s in starts if off < s < off + len(pc)}) + [len(pc)]
            pieces.append(pc); routed.append(route(pc, [(a, b - a) for a, b in zip(cuts, cuts[1:]) if b > a]))
        for name, (filtered, enc, dec) in cods.items():
            sizes = []; te = td = 0.0; ok = True; decoded = 0
            for piece, (r, rt) in zip(pieces, routed):
                t = time.perf_counter(); e = enc(piece, r); te += time.perf_counter() - t + (rt if filtered else 0)
                if e is None or len(e) >= len(piece): sizes.append(None); continue   # VFA stores it
                t = time.perf_counter(); back = dec(e, len(piece), r); td += time.perf_counter() - t
                ok &= back == piece; sizes.append(len(e)); decoded += len(piece)
            size = sum(len(pc) if sz is None else sz for pc, sz in zip(pieces, sizes))
            res[name] = (size, te, td, ok, sizes, decoded)
            print(f"  {k:17} {name:11} {len(blob) >> 20:5} MB -> {size / len(blob):.4f}  "
                  f"{len(blob) / 1e6 / max(te, 1e-9):6.1f} / {rate(decoded, td)} MB/s  {'ok' if ok else 'MISMATCH'}", flush=True)
        rows.append((k, nfiles, total, nread, len(blob), res, vfa_cm_size(pieces, routed, res)))
        write(a.out, rows, time.time() - t0, a)
    write(a.out, rows, time.time() - t0, a)
    print(f"done in {(time.time() - t0) / 60:.0f} min -> {a.out}")

def rate(nbytes, secs) -> str:
    """MB/s over the bytes a decoder actually decoded; '-' when every piece was stored (nothing to decode)."""
    return f"{nbytes / 1e6 / max(secs, 1e-9):.1f}" if nbytes else "-"

def vfa_cm_size(pieces, routed, res):
    """What 'vfa c --method cm' writes for these pieces, by the writer's own rule (vfa2.Writer2._flush): written size
    = payload + params (2 + filter params + coder params, if there are any params); vulp-cm is kept only if it writes
    at least CM_MIN_GAIN_PCT % less than vulp-lz (or than the raw piece when vulp-lz cannot shrink it); a choice
    that is not smaller than the raw piece is stored."""
    import vfa2
    total = 0
    for i, (pc, (r, _)) in enumerate(zip(pieces, routed)):
        fparams = r[1]
        def written(payload_len, cparams_len):
            return payload_len + (2 + len(fparams) + cparams_len if (fparams or cparams_len) else 0)
        lz, cm = res["vulp-lz"][4][i], res["vulp-cm"][4][i]
        lz_w = written(lz, 0) if lz is not None else len(pc)
        pick = lz_w
        if cm is not None and written(cm, 2) * 100 <= lz_w * (100 - vfa2.CM_MIN_GAIN_PCT): pick = written(cm, 2)
        total += min(pick, len(pc))
    return total

def write(path, rows, secs, a):
    names = list(rows[0][5]) if rows else []
    lines = ["# VFA field benchmark", "",
             f"{time.strftime('%Y-%m-%d %H:%M')}, {platform.platform()}, {os.cpu_count()} CPUs, python {platform.python_version()}; "
             f"sample up to {a.budget_mb} MB per kind, files capped at {a.max_file_mb} MB, --level {a.level}; "
             f"{secs / 60:.0f} min. Only totals: no names or contents.", "",
             "Ratio = compressed / original (lower is better); the VFA cm column applies the writer's rule per 64 MiB piece: "
             "vulp-cm only where it writes at least 1% less than vulp-lz, params included, else vulp-lz or stored. MB/s = compress / decompress (decompress counts only pieces that were compressed; '-' = all stored). vulp-lz "
             "and vulp-cm see each piece through the filter VFA's own router picks for it (none, delta, bcj-x86, ...); "
             "xz and zstd see the raw bytes.", "",
             "| kind | files found | found GB | sampled MB | " + " | ".join(names) + " | VFA cm (best of lz, cm) | vs xz |",
             "|---|---:|---:|---:|" + "---:|" * len(names) + "---:|---:|"]
    for k, nfiles, total, nread, n, res, vfa_cm in rows:
        cells = []
        for nm in names:
            size, te, td, ok, _, decoded = res[nm]
            cells.append(f"{size / n:.4f} ({n / 1e6 / max(te, 1e-9):.1f} / {rate(decoded, td)}){'' if ok else ' MISMATCH'}")
        best = vfa_cm; xz = res["xz -9e"][0]
        lines.append(f"| {k} | {nfiles} | {total / 1e9:.1f} | {n / 1e6:.0f} | " + " | ".join(cells)
                     + f" | {best / n:.4f} | {(best - xz) * 100 / max(xz, 1):+.1f}% |")
    pathlib.Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
