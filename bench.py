# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
#!/usr/bin/env python3
"""
Benchmark VFA against xz -9e, zstd --ultra -22 and 7z LZMA2 on YOUR files.

    python bench.py D:\\data\\installer_payload  C:\\some\\big.csv  ...      # files and/or folders
    python bench.py --quick sample                                       # fast subset of configurations
    python bench.py --tools vfa-zstd19-solid,xz-9e  my_folder             # pick rows
    python bench.py                                                      # list tools and whether they are installed

Every input is measured on its own (a folder is one input). External tools get a single stream, so a folder is first
packed into an uncompressed .tar (tar time is not counted). 7z gets the folder directly.

Per row: ratio (compressed / original), compress MB/s and decompress MB/s (MB = 10^6 bytes of ORIGINAL data, wall
clock, best of --repeat runs), peak RSS of the compressing and decompressing process, and the size of the
self-extractor stub the result would need. Every decompression is verified byte-for-byte against the input; a row
that does not round-trip is reported as FAIL. A tool that is not installed is reported as "not run" with the reason -
never estimated.

Results are appended to BENCHMARKS.md (and a CSV next to it) with machine and tool versions.
"""
import argparse, csv, datetime, hashlib, os, pathlib, platform, shutil, subprocess, sys, tarfile, tempfile, time

HERE = pathlib.Path(__file__).resolve().parent
# In a Windows venv, Scripts\python.exe is a launcher that starts the real interpreter as a child, so timing and
# peak-RSS would measure the launcher. Run the base interpreter directly with the venv's packages on its path.
PY = getattr(sys, "_base_executable", sys.executable) or sys.executable
import site
CHILD_ENV = dict(os.environ, PYTHONPATH=os.pathsep.join([*site.getsitepackages(), str(HERE), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep))

# ---------------------------------------------------------------- process measurement

def run_measured(cmd, cwd=None, stdin=None, stdout=None):
    """Run cmd, return (seconds, peak_rss_bytes, returncode, stderr_tail)."""
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, cwd=cwd, stdin=stdin, stdout=stdout or subprocess.DEVNULL, stderr=subprocess.PIPE, env=CHILD_ENV)
    if os.name == "nt":
        _, err = p.communicate(); dt = time.perf_counter() - t0
        return dt, _peak_rss_win(p), p.returncode, err.decode(errors="replace")[-300:]
    # POSIX: wait4 gives this child's own rusage
    err = p.stderr.read(); _, status, ru = os.wait4(p.pid, 0); dt = time.perf_counter() - t0
    p.returncode = os.waitstatus_to_exitcode(status)
    rss = ru.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    return dt, rss, p.returncode, err.decode(errors="replace")[-300:]

# Linux: a child's ru_maxrss includes the high-water mark of the memory it was forked from (this Python process,
# ~50+ MiB), recorded at exec. GNU time forks the measured command from its own tiny process, so its %M is the
# command's real peak. Without it, RSS figures below that floor are not meaningful (the report says so).
GNU_TIME = "/usr/bin/time" if sys.platform.startswith("linux") and os.path.isfile("/usr/bin/time") else None
RSS_NOTE = ("" if os.name == "nt" or GNU_TIME or sys.platform == "darwin" else
            "RSS on this Linux run includes the benchmark's own forked Python image (~50 MiB floor): install GNU time "
            "(`apt install time`) for exact figures.")

if GNU_TIME:
    _run_measured_raw = run_measured
    def run_measured(cmd, cwd=None, stdin=None, stdout=None):
        fd, rf = tempfile.mkstemp(prefix="vfa-rss-"); os.close(fd)
        try:
            dt, _, rc, err = _run_measured_raw([GNU_TIME, "-q", "-f", "VFA_RSS_KB=%M", "-o", rf, *cmd], cwd, stdin, stdout)
            kb = [ln.split("=", 1)[1] for ln in pathlib.Path(rf).read_text().splitlines() if ln.startswith("VFA_RSS_KB=")]
            return dt, int(kb[-1]) * 1024 if kb else 0, rc, err
        finally:
            os.unlink(rf)

def _peak_rss_win(p):
    import ctypes, ctypes.wintypes as w
    class PMC(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("PageFaultCount", w.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
    ok = ctypes.windll.psapi.GetProcessMemoryInfo(w.HANDLE(int(p._handle)), ctypes.byref(pmc), pmc.cb)
    return pmc.PeakWorkingSetSize if ok else 0

def digest_tree(path: pathlib.Path):
    h = hashlib.sha256()
    if path.is_file():
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1 << 22), b""): h.update(b)
        return h.hexdigest()
    for p in sorted(x for x in path.rglob("*") if x.is_file()):
        h.update(p.relative_to(path).as_posix().encode() + b"\0")
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(1 << 22), b""): h.update(b)
    return h.hexdigest()

def size_of(path: pathlib.Path):
    return path.stat().st_size if path.is_file() else sum(p.stat().st_size for p in path.rglob("*") if p.is_file())

# ---------------------------------------------------------------- tools

def find_exe(name, extra=()):
    p = shutil.which(name)
    if p: return p
    for c in extra:
        if os.path.isfile(c): return c
    return None

XZ = find_exe("xz", [r"C:\Program Files\Git\mingw64\bin\xz.exe", r"C:\Program Files\Git\usr\bin\xz.exe"])
ZSTD = find_exe("zstd")
def _sevenz_registry():
    if os.name != "nt": return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\7-Zip") as k:
            p = os.path.join(winreg.QueryValueEx(k, "Path")[0], "7z.exe")
            return p if os.path.isfile(p) else None
    except Exception:
        return None
# the real 7z.exe first: package-manager shims (chocolatey) are launchers and would distort timing and RSS
SEVENZ = _sevenz_registry() or find_exe("7z", [r"C:\Program Files\7-Zip\7z.exe"])

def version_of(exe, args):
    try:
        r = subprocess.run([exe, *args], capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip().splitlines()[0][:80]
    except Exception as e:
        return f"? ({e})"

class Tool:
    """compress(src, single_stream_file, workdir) -> archive path; decompress(archive, workdir) -> restored path"""
    def __init__(self, name, desc, available, why, compress, decompress, stub_bytes):
        self.name, self.desc, self.available, self.why = name, desc, available, why
        self.compress, self.decompress, self.stub_bytes = compress, decompress, stub_bytes

def _stub_size(*cands):
    for c in cands:
        if c and os.path.isfile(c): return os.path.getsize(c)
    return None

VFA_SFX = HERE / "bin" / "windows" / "vfa_sfx.exe" if os.name == "nt" else HERE / "bin" / "linux" / "vfa_sfx"
def _sevenz_dirs():
    dirs = [pathlib.Path(SEVENZ).resolve().parent] if SEVENZ else []
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\7-Zip") as k: dirs.insert(0, pathlib.Path(winreg.QueryValueEx(k, "Path")[0]))
        except Exception: pass
    return dirs
SEVENZ_SFX = next((d / "7z.sfx" for d in _sevenz_dirs() if (d / "7z.sfx").is_file()), None)

def vfa_tool(name, method, level, solid, extra=()):
    def comp(src, stream, wd):
        arc = wd / "out.vfa"
        flags = ["--method", method, "--level", str(level), *(["--solid"] if solid else []), *extra]
        return arc, [PY, str(HERE / "vfa.py"), "c", str(arc), src.name, *flags], src.parent, None
    def decomp(arc, wd, src):
        out = wd / "restored"
        return out / src.name, [PY, str(HERE / "vfa.py"), "x", str(arc), "-o", str(out)], None, None
    desc = f"vfa {method} -{level}{' solid' if solid else ''}" + (" " + " ".join(extra) if extra else "")
    return Tool(name, desc, True, "", comp, decomp, _stub_size(VFA_SFX))

def stream_tool(name, desc, exe, cargs, dargs, ext, why):
    def comp(src, stream, wd):
        arc = wd / ("out" + ext)
        return arc, [exe, *cargs], None, ("pipe", stream, arc)
    def decomp(arc, wd, src):
        out = wd / ("restored_stream")
        return out, [exe, *dargs], None, ("pipe", arc, out)
    return Tool(name, desc, exe is not None, why, comp, decomp, None)

def sevenz_tool():
    def comp(src, stream, wd):
        arc = wd / "out.7z"
        return arc, [SEVENZ, "a", "-t7z", "-m0=lzma2", "-mx=9", "-bd", "-bso0", str(arc), src.name], src.parent, None
    def decomp(arc, wd, src):
        out = wd / "restored"
        return out / src.name, [SEVENZ, "x", "-bd", "-bso0", f"-o{out}", str(arc)], None, None
    return Tool("7z-lzma2-mx9", "7z a -t7z -m0=lzma2 -mx=9", SEVENZ is not None, "7z not found", comp, decomp,
                _stub_size(SEVENZ_SFX))

def all_tools():
    tools = [
        vfa_tool("vfa-default", "zstd", 5, False),
        vfa_tool("vfa-zstd19-solid", "zstd", 19, True),
        vfa_tool("vfa-xz9-solid", "xz", 9, True),
        vfa_tool("vfa-lzma9-solid", "lzma", 9, True),
        vfa_tool("vfa-brotli11-solid", "brotli", 11, True),
        vfa_tool("vfa2-stored-solid", "none", 0, True, ("--format", "vfa2")),     # VFA2 M1: container only, no compression
        vfa_tool("vfa2-tans-solid", "tans", 0, True, ("--format", "vfa2")),       # VFA2 M3: auto filter + order-0 tANS
        vfa_tool("vfa2-lz", "lz", 6, False, ("--format", "vfa2")),                 # VFA2 M4: vulp-lz + dedup (default)
        vfa_tool("vfa2-lz-solid", "lz", 6, True, ("--format", "vfa2")),
        vfa_tool("vfa2-lz9-solid", "lz", 9, True, ("--format", "vfa2")),
        vfa_tool("vfa2-cm-solid", "cm", 5, True, ("--format", "vfa2")),            # VFA2 M5: vulp-cm where it wins
        vfa_tool("vfa2-cm9-solid", "cm", 9, True, ("--format", "vfa2")),           # 2^24 tables (~220 MiB each way)
        stream_tool("xz-9e", "xz -9e -T1", XZ, ["-9e", "-T1", "-c"], ["-d", "-c"], ".xz", "xz not found on PATH"),
        stream_tool("zstd-ultra22", "zstd --ultra -22", ZSTD, ["--ultra", "-22", "-c", "-q"], ["-d", "-c", "-q"], ".zst",
                    "zstd CLI not found (install it, e.g. `winget install Facebook.zstd` or `choco install zstandard`)"),
        sevenz_tool(),
    ]
    if not ZSTD:   # same library the CLI uses; clearly labelled as NOT the CLI
        code_c = "import sys,zstandard as z; sys.stdout.buffer.write(z.ZstdCompressor(level=22).compress(sys.stdin.buffer.read()))"
        code_d = "import sys,zstandard as z; r=z.ZstdDecompressor().stream_reader(sys.stdin.buffer); o=sys.stdout.buffer\nwhile True:\n b=r.read(1<<22)\n if not b: break\n o.write(b)"
        try:
            import zstandard  # noqa
            tools.append(stream_tool("zstd22-pylib", "python-zstandard level 22 (stand-in: zstd CLI missing)", PY,
                                     ["-c", code_c], ["-c", code_d], ".zst", ""))
        except Exception:
            pass
    return tools

QUICK = {"vfa-default", "vfa2-lz", "vfa2-lz-solid", "vfa-zstd19-solid", "vfa-xz9-solid", "xz-9e", "zstd-ultra22", "zstd22-pylib", "7z-lzma2-mx9"}

# ---------------------------------------------------------------- run

def run_one(tool, src, stream, wd, repeat):
    best_c = best_d = None; rss_c = rss_d = 0; arc_size = None; ok = None; err = ""
    for _ in range(repeat):
        shutil.rmtree(wd, ignore_errors=True); wd.mkdir(parents=True)
        arc, cmd, cwd, pipe = tool.compress(src, stream, wd)
        if pipe:
            with open(pipe[1], "rb") as fi, open(pipe[2], "wb") as fo:
                dt, rss, rc, e = run_measured(cmd, cwd=cwd, stdin=fi, stdout=fo)
        else:
            dt, rss, rc, e = run_measured(cmd, cwd=cwd)
        if rc != 0: return {"status": "FAIL", "note": f"compress exit {rc}: {e}"}
        best_c = dt if best_c is None else min(best_c, dt); rss_c = max(rss_c, rss); arc_size = arc.stat().st_size
        restored, cmd, cwd, pipe = tool.decompress(arc, wd, src)
        if pipe:
            with open(pipe[1], "rb") as fi, open(pipe[2], "wb") as fo:
                dt, rss, rc, e = run_measured(cmd, cwd=cwd, stdin=fi, stdout=fo)
        else:
            dt, rss, rc, e = run_measured(cmd, cwd=cwd)
        if rc != 0: return {"status": "FAIL", "note": f"decompress exit {rc}: {e}"}
        best_d = dt if best_d is None else min(best_d, dt); rss_d = max(rss_d, rss)
        want = digest_tree(stream if pipe else src)
        ok = digest_tree(restored) == want
        if not ok: return {"status": "FAIL", "note": "round-trip mismatch"}
    return {"status": "ok", "arc": arc_size, "tc": best_c, "td": best_d, "rss_c": rss_c, "rss_d": rss_d}

def fmt_mb(n): return f"{n / 2**20:.1f} MiB" if n else "-"

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", help="files and/or folders to measure (each is one input)")
    ap.add_argument("--tools", help="comma-separated tool names (see --list-tools)")
    ap.add_argument("--quick", action="store_true", help="only the main configurations")
    ap.add_argument("--repeat", type=int, default=1, help="runs per row; the best time is kept")
    ap.add_argument("--out", default=str(HERE / "BENCHMARKS.md"))
    ap.add_argument("--label", default="", help="free text stored with the results (e.g. 'after M3')")
    a = ap.parse_args()
    tools = all_tools()
    if not a.inputs:
        for t in tools: print(f"{t.name:22s} {'ok ' if t.available else 'N/A'} {t.desc}{'' if t.available else '  - ' + t.why}")
        print("\nusage: python bench.py <file-or-folder> [...]"); return 0
    if a.tools: tools = [t for t in tools if t.name in set(a.tools.split(","))]
    elif a.quick: tools = [t for t in tools if t.name in QUICK]

    rows = []; tmp = pathlib.Path(tempfile.mkdtemp(prefix="vfa-bench-"))
    try:
        for inp in a.inputs:
            src = pathlib.Path(inp).resolve()
            if not src.exists(): print(f"skip {inp}: not found"); continue
            orig = size_of(src)
            stream = src
            if src.is_dir():
                stream = tmp / (src.name + ".tar")
                with tarfile.open(stream, "w", format=tarfile.PAX_FORMAT) as tf: tf.add(src, arcname=src.name)
            print(f"\n== {src}  ({orig:,} bytes{', folder -> tar for stream tools' if src.is_dir() else ''})")
            for t in tools:
                if not t.available:
                    r = {"status": "not run", "note": t.why}
                else:
                    print(f"   {t.name:22s} ...", end="", flush=True)
                    r = run_one(t, src, stream, tmp / "w", a.repeat)
                    print(f" {r['status']}" + (f"  ratio {r['arc']/max(orig,1):.4f}" if r["status"] == "ok" else f"  {r.get('note','')}"))
                rows.append({"input": src.name, "orig": orig, "tool": t.name, "desc": t.desc, "stub": t.stub_bytes, **r})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- write results
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    vers = {"python": platform.python_version(), "xz": version_of(XZ, ["--version"]) if XZ else "not found",
            "zstd": version_of(ZSTD, ["--version"]) if ZSTD else "not found",
            "7z": (version_of(SEVENZ, []) if SEVENZ else "not found")}
    try:
        import zstandard; vers["python-zstandard"] = zstandard.__version__
    except Exception: pass
    md = [f"\n## {now} {a.label}".rstrip(), "",
          f"Machine: {platform.platform()}, {platform.processor() or platform.machine()}, {os.cpu_count()} logical CPUs. "
          f"Tools: " + "; ".join(f"{k} {v}" for k, v in vers.items()), "",
          "Ratio = compressed / original (lower is better). MB/s are of original data. RSS = peak resident memory of the process. "
          "Stub = size of the self-extractor the format needs (\"-\" = none exists for that tool).", ""]
    for inp in dict.fromkeys(r["input"] for r in rows):
        rr = [r for r in rows if r["input"] == inp]; orig = rr[0]["orig"]
        md += [f"### {inp} ({orig:,} bytes)", "",
               "| tool | ratio | compressed | comp MB/s | decomp MB/s | RSS comp | RSS decomp | stub | status |",
               "|---|---:|---:|---:|---:|---:|---:|---:|---|"]
        oks = [r for r in rr if r["status"] == "ok"]
        best = min((r["arc"] for r in oks), default=None)
        for r in rr:
            if r["status"] != "ok":
                md.append(f"| {r['tool']} | | | | | | | {fmt_mb(r['stub'])} | **{r['status']}**: {r.get('note','')} |"); continue
            mark = " (best)" if r["arc"] == best else ""
            md.append(f"| {r['tool']} | {r['arc']/max(orig,1):.4f}{mark} | {r['arc']:,} | {orig/1e6/max(r['tc'],1e-9):.1f} | "
                      f"{orig/1e6/max(r['td'],1e-9):.1f} | {fmt_mb(r['rss_c'])} | {fmt_mb(r['rss_d'])} | {fmt_mb(r['stub'])} | ok |")
        md.append("")
    md.append("VFA rows include Python interpreter start-up (~0.3-1 s per run); on small inputs that dominates MB/s.\n")
    if RSS_NOTE: md.append(RSS_NOTE + "\n")
    outp = pathlib.Path(a.out)
    if not outp.exists(): outp.write_text("# VFA benchmarks\n\nMeasured by `bench.py` on the owner's data. Each section is one run.\n", encoding="utf-8")
    with open(outp, "a", encoding="utf-8") as f: f.write("\n".join(md))
    with open(outp.with_suffix(".csv"), "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["when", "label", "input", "orig", "tool", "desc", "status", "arc", "tc", "td", "rss_c", "rss_d", "stub", "note"])
        if f.tell() == 0: w.writeheader()
        for r in rows: w.writerow({"when": now, "label": a.label, **{k: r.get(k) for k in w.fieldnames if k not in ("when", "label")}})
    print(f"\nResults appended to {outp} and {outp.with_suffix('.csv')}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
