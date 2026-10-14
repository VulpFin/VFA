# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
#!/usr/bin/env python3
"""
release.py - build and test a full VFA release, for every Python version, on Windows and (via WSL) Linux.

    python release.py                      # this OS: tests + wheels on 3.10/3.12/3.13/3.14, executables with 3.13
    python release.py --wsl                # Windows: then the same again inside WSL for Linux
    python release.py --pythons 3.13 --tests none --no-exes     # just a 3.13 wheel

Per Python version X it keeps a private build environment in .buildenv/<os>-pyX (created on first use, with the
runtime packages from pyproject.toml plus the build tools), builds the _vulp C extension for X, runs test_vfa.py
(--quick by default) and builds a wheel. With the --exe-python version it then runs `build.py --matrix`
(portable, windowless, install folders, archives, installers). Results go to release/<version>/:

    release/<version>/windows/...  linux/...   the executables (see build.build_matrix)
    release/<version>/pypi/                     wheels for each OS and Python, plus the sdist
    release/<version>/RESULTS-<os>.md           which test runs passed, on which Python, and what was built

Finding Python X: Windows uses the py launcher (py -X), elsewhere pythonX on PATH, then `uv python find X`
(and `uv python install X` if uv is there and X is missing). Linux wheels are repaired with auditwheel to a
manylinux tag, which PyPI requires; the tag follows the glibc of the machine that builds them.
"""
import argparse, hashlib, os, pathlib, platform, re, shutil, subprocess, sys, tarfile, threading, time, zipfile

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build                       # this repo's build.py (TOOLS, arch_tag)
from vfa_version import __version__ as VERSION

IS_WIN = platform.system() == "Windows"; IS_LINUX = platform.system() == "Linux"
OS_TAG = "windows" if IS_WIN else "linux" if IS_LINUX else "macos"
OUT = ROOT / "release" / VERSION

def clock(t=None): return time.strftime("%H:%M:%S", time.localtime(t))

def log(msg): print(f"[{clock()}] [release] {msg}", flush=True)

def run(cmd, check=True, **kw):
    log("$ " + " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd], check=check, **kw)

VERBOSE = False     # --verbose: stream every command's output instead of the one-line status
LOGS = OUT / "logs"

class Status:
    """One self-rewriting console line: spinner, elapsed time, a progress bar when a total is known, a short note.
    Not a terminal (piped, redirected): a plain line every 30 s instead, so logs stay readable."""
    SPIN_U, SPIN_A = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", "|/-\\"
    def __init__(self, label):
        self.label, self.t0, self.note, self.done, self.total, self.i = label, time.time(), "", 0, 0, 0
        self.tty = sys.stdout.isatty(); self.lock = threading.Lock(); self.stop = threading.Event(); self.last = 0
        enc = sys.stdout.encoding or "ascii"
        def ok(t):
            try: t.encode(enc); return True
            except (UnicodeError, LookupError): return False
        fancy = ok("█░✓✗")
        # braille spinner where the font has it: not the classic Windows console (conhost), only Windows Terminal
        self.spin = self.SPIN_U if ok(self.SPIN_U) and (not IS_WIN or os.environ.get("WT_SESSION")) else self.SPIN_A
        self.full, self.empty = ("█", "░") if fancy else ("#", ".")
        self.ok_mark, self.bad_mark = ("✓", "✗") if fancy else ("ok", "FAILED")
        self.arrow = "→" if ok("→") else "->"
        self.thread = threading.Thread(target=self._tick, daemon=True)
    def __enter__(self): self.thread.start(); return self
    def __exit__(self, *exc): self.stop.set(); self.thread.join()
    def _elapsed(self):
        s = int(time.time() - self.t0); return f"{s // 60}:{s % 60:02d}".rjust(5)
    def _when(self, end=None):
        """[start → end], with the end blank while running so finished and running lines line up."""
        return f"[{clock(self.t0)} {self.arrow} {clock(end) if end else ' ' * 8}]"
    def _line(self):
        bar = ""
        if self.total:
            frac = min(1.0, self.done / self.total); n = 20
            bar = f" {self.full * int(frac * n)}{self.empty * (n - int(frac * n))} {frac * 100:3.0f}%"
        return f"{self._when()} {self._elapsed()}  {self.spin[self.i % len(self.spin)]} {self.label}{bar}  {self.note}"
    def _draw(self):
        width = shutil.get_terminal_size((100, 20)).columns - 1
        print("\r" + self._line()[:width].ljust(width), end="", flush=True)
    def _tick(self):
        while not self.stop.wait(0.15):
            with self.lock:
                self.i += 1
                if self.tty: self._draw()
                elif time.time() - self.last >= 30:
                    self.last = time.time(); print(self._line(), flush=True)
    def update(self, note=None, done=None):
        with self.lock:
            if note is not None: self.note = note
            if done is not None: self.done = done
    def say(self, text):
        """A line that stays (a failure), printed above the status line."""
        with self.lock:
            if self.tty: print("\r" + " " * (shutil.get_terminal_size((100, 20)).columns - 1) + "\r", end="")
            print(f"[{clock()}] {text.strip()}", flush=True)
    def finish(self, ok, note=""):
        with self.lock:
            self.stop.set()
            mark = self.ok_mark if ok else self.bad_mark
            text = f"{self._when(time.time())} {self._elapsed()}  {mark} {self.label}  {note}".rstrip()
            if self.tty: print("\r" + text.ljust(shutil.get_terminal_size((100, 20)).columns - 1), flush=True)
            else: print(text, flush=True)

def run_status(cmd, label, logname, cwd=None, env=None, on_line=None, total=0):
    """Run cmd with a one-line status instead of its output; the full output goes to release/<ver>/logs/<logname>.
    on_line(line, status) may update the status from the output. On failure the log's last lines are shown.
    Returns (returncode, list of non-empty output lines)."""
    LOGS.mkdir(parents=True, exist_ok=True); logf = LOGS / logname
    cmd = [str(c) for c in cmd]
    if VERBOSE: log("$ " + " ".join(cmd))
    env = dict(env or os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    lines = []
    with open(logf, "w", encoding="utf-8") as lf, Status(label) as st:
        st.total = total
        lf.write("$ " + " ".join(cmd) + "\n\n")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd, env=env,
                             text=True, encoding="utf-8", errors="replace")
        for raw in p.stdout:
            line = raw.rstrip(); lf.write(line + "\n")
            if VERBOSE: st.say("    " + line)
            if not line.strip(): continue
            lines.append(line)
            if on_line: on_line(line, st)
            else: st.update(note=line.strip())
        rc = p.wait()
        tail = f"log: {logf.relative_to(ROOT)}"
        st.finish(rc == 0, "" if rc == 0 else f"exit {rc}  ({tail})")
    if rc != 0 and not VERBOSE:
        for l in lines[-15:]: print("      " + l)
    return rc, lines

def run_quiet(cmd, label, logname, **kw):
    rc, lines = run_status(cmd, label, logname, **kw)
    if rc != 0: raise RuntimeError(f"{label} failed (exit {rc}); see release/{VERSION}/logs/{logname}")
    return lines

def runtime_requirements():
    """The dependencies list from pyproject.toml (one source of truth; tomllib is 3.11+, so a small regex)."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M).group(1)
    return re.findall(r'"([^"]+)"', block)

def find_python(ver):
    if IS_WIN:
        r = subprocess.run(["py", f"-{ver}", "-c", "import sys; print(sys.executable)"], capture_output=True, text=True)
        if r.returncode == 0: return r.stdout.strip()
    exe = shutil.which(f"python{ver}")
    if exe: return exe
    if shutil.which("uv"):
        r = subprocess.run(["uv", "python", "find", ver], capture_output=True, text=True)
        if r.returncode != 0:
            run_status(["uv", "python", "install", ver], f"py{ver}: download Python {ver} (uv)",
                       f"{OS_TAG}-py{ver}-uv.log")
            r = subprocess.run(["uv", "python", "find", ver], capture_output=True, text=True)
        if r.returncode == 0: return r.stdout.strip()
    return None

def env_python(ver, exe_python):
    """.buildenv/<os>-py<ver>: a venv with the runtime packages and the build tools. Returns its python."""
    env = ROOT / ".buildenv" / f"{OS_TAG}-py{ver}"
    py = env / ("Scripts/python.exe" if IS_WIN else "bin/python")
    if not py.exists():
        base = find_python(ver)
        if not base: raise RuntimeError(f"Python {ver} not found (Windows: install it for the py launcher; "
                                        f"elsewhere: python{ver} on PATH, or install uv)")
        run_quiet([base, "-m", "venv", env], f"py{ver}: create build environment", f"{OS_TAG}-py{ver}-venv.log")
    tools = ["pip", "setuptools>=77", "wheel", "build"]
    if ver == exe_python: tools.append("pyinstaller>=6.0")
    if IS_LINUX: tools += ["auditwheel", "patchelf"]
    run_quiet([py, "-m", "pip", "install", "--upgrade", "--progress-bar", "off", *tools, *runtime_requirements()],
              f"py{ver}: install build tools and dependencies", f"{OS_TAG}-py{ver}-pip.log")
    return py

def run_tests(py, mode, ver):
    """test_vfa.py with this Python; returns (ok, summary line). Shows a live count and, once a run of the same kind
    has finished before, a progress bar against that run's number of checks."""
    args = [py, ROOT / "test_vfa.py"] + (["--quick"] if mode == "quick" else [])
    logname = f"{OS_TAG}-py{ver}-tests-{mode}.log"
    total = 0
    for old in LOGS.glob(f"*-tests-{mode}.log") if LOGS.exists() else []:   # same mode on any Python or OS
        try: total = max(total, sum(1 for l in old.read_text(encoding="utf-8", errors="replace").splitlines()
                                    if l.startswith(("PASS ", "FAIL ", "SKIP "))))
        except OSError: pass
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    def on_line(line, st):
        word = line.split(" ", 1)[0]
        if word in counts:
            counts[word] += 1
            if word == "FAIL": st.say("    " + line)
            name = line[4:].strip()
            st.update(done=sum(counts.values()),
                      note=f"{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped   {name}")
        elif line.startswith("===="):
            st.update(note=f"{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped   "
                           f"{line.strip('= ')}")
    rc, lines = run_status(args, f"py{ver}: tests ({mode})", logname, cwd=ROOT, on_line=on_line, total=total)
    summary = next((l for l in reversed(lines) if "failed" in l and "skipped" in l), lines[-1] if lines else "no output")
    return rc == 0, summary.strip()

def build_wheel(py, pypi):
    """Wheel for this Python into release/<ver>/pypi (Linux: repaired to manylinux by auditwheel)."""
    tmp = ROOT / "build" / "wheels" / pathlib.Path(py).parent.parent.name
    shutil.rmtree(tmp, ignore_errors=True); tmp.mkdir(parents=True)
    tag = pathlib.Path(py).parent.parent.name          # <os>-pyX
    run_quiet([py, "-m", "pip", "wheel", ROOT, "--no-deps", "--no-build-isolation", "-w", tmp],
              f"{tag.split('-')[-1]}: wheel", f"{tag}-wheel.log", cwd=ROOT)
    whl = next(tmp.glob("*.whl"))
    if IS_LINUX:
        env = dict(os.environ, PATH=str(pathlib.Path(py).parent) + os.pathsep + os.environ.get("PATH", ""))  # patchelf
        run_quiet([py, "-m", "auditwheel", "repair", whl, "-w", pypi], f"{tag.split('-')[-1]}: manylinux repair",
                  f"{tag}-auditwheel.log", env=env)
        return max(pypi.glob(whl.name.split("-linux_")[0] + "-*manylinux*.whl"), key=lambda p: p.stat().st_mtime)
    dst = pypi / whl.name; shutil.copy2(whl, dst)
    return dst

def to_wsl_path(p):
    r = subprocess.run(["wsl", "wslpath", "-a", str(p).replace("\\", "/")], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None

def _zip_dir(src, zpath, top):
    """src folder -> zpath, its files under top/ in the archive."""
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(src.rglob("*")):
            if f.is_file(): z.write(f, f"{top}/{f.relative_to(src).as_posix()}")

def _tar_dir(src, tpath, top):
    """src folder -> tpath (.tar.gz), every file executable: the Linux binaries may be packed on Windows (after
    --wsl), where the file system has no execute bit to copy."""
    def fix(ti):
        ti.uid = ti.gid = 0; ti.uname = ti.gname = ""
        ti.mode = 0o755 if ti.isdir() or not ti.name.endswith((".txt", ".md")) else 0o644
        return ti
    with tarfile.open(tpath, "w:gz", compresslevel=9) as t:
        t.add(src, arcname=top, filter=fix)

def git_state():
    """'<commit>' for a clean checkout, '<commit>+dirty' with uncommitted changes to tracked files or untracked
    code files, None without git."""
    git = shutil.which("git")
    if not git: return None
    r = subprocess.run([git, "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode: return None
    dirty = subprocess.run([git, "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    # untracked code counts too: with the repo root on the import path, a stray module can end up in the tests
    # and the executables while git archive leaves it out (other untracked files, e.g. sample data, do not)
    stray = subprocess.run([git, "ls-files", "--others", "--exclude-standard", "--", "*.py", "*.c", "*.h"],
                           cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return r.stdout.strip() + ("+dirty" if dirty or stray else "")

def read_field(rep, name):
    """A 'Name: value' line of a RESULTS report (None if absent or 'unknown': reports from before it was recorded)."""
    m = re.search(rf"^{name}: (\S+)", rep.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m and m.group(1) != "unknown" else None

def read_commit(rep): return read_field(rep, "Commit")

def read_results(rep):
    """RESULTS-<os>.md -> [{"python", "tests", "wheel", "exes"}], one per Python row."""
    rows = []
    for line in rep.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and re.fullmatch(r"\d+\.\d+", cells[0]):
            rows.append(dict(zip(("python", "tests", "wheel", "exes"), cells)))
    return rows

def expected_executables(os_name, arch):
    """(portable files, install-folder archives, installers) that build.build_matrix makes for os_name."""
    exe = ".exe" if os_name == "windows" else ""
    suffixes = ("",) if os_name == "linux" else ("", "-windowless")     # build_matrix: no windowless on Linux
    portable = [f"{t}{s}{exe}" for t in build.TOOLS for s in suffixes]
    inst = [f"{t}{s}" for t, spec in build.TOOLS.items() if spec["install"] for s in suffixes]
    tag = f"{VERSION}-{os_name}-{arch}"
    archives = [f"{n}-{tag}.{'zip' if os_name == 'windows' else 'tar.gz'}" for n in inst]
    installers = [f"{n}-{tag}-setup{exe}" for n in inst]
    return portable, archives, installers

def assemble(out=OUT, commit=None):
    """release/<ver>/upload/: what goes where, taken only from what the RESULTS reports say the runs built.

        github/   one asset per download: each OS's portable archive (all its executables + LICENSE + README),
                  install-folder archives and installers, the source (zip, tar.gz), and vfa-<ver>-all.zip with
                  all of those plus the PyPI files
        pypi/     the wheels named in the reports, and the sdist (twine upload release/<ver>/upload/pypi/*)
        SHA256SUMS.txt  for every file in github/ and pypi/

    Complete means: a report for Windows and Linux (and macOS if it has one), the same Python versions in each,
    every row tested and PASS with its wheel present, each OS's full executable set, and one clean commit that
    every report was built from; the source archives are made from that commit, not from HEAD. `commit` (from
    --commit) stands in for reports that predate the Commit line. Returns the problems."""
    up = out / "upload"; gh = up / "github"; pp = up / "pypi"
    shutil.rmtree(up, ignore_errors=True); gh.mkdir(parents=True); pp.mkdir(parents=True)
    problems = []
    pypi_src = out / "pypi"

    oses = ["windows", "linux"] + (["macos"] if (out / "RESULTS-macos.md").exists() else [])
    reports = {o: read_results(out / f"RESULTS-{o}.md") for o in oses if (out / f"RESULTS-{o}.md").exists()}
    all_versions = sorted({r["python"] for rows in reports.values() for r in rows}, key=lambda v: tuple(map(int, v.split("."))))
    built = {o: read_commit(out / f"RESULTS-{o}.md") or commit for o in reports}
    for o, c in built.items():
        if not c: problems.append(f"{o}: RESULTS-{o}.md records no commit (re-run it, or pass --commit <sha> "
                                  f"if you know which commit it was built from)")
        elif c.endswith("+dirty"): problems.append(f"{o}: built with uncommitted changes (from {c[:-6][:12]})")
    commits = {c.removesuffix("+dirty") for c in built.values() if c}
    if len(commits) > 1:
        problems.append("built from different commits: " + ", ".join(f"{o} {c[:12]}" for o, c in built.items() if c))
    git = shutil.which("git")
    src = next(iter(commits)) if len(commits) == 1 and git else None
    if not git: problems.append("source: git not found, no source archives or bundled README/LICENSE")
    def at_commit(path):
        """A file's bytes at the build commit (README and LICENSE in the bundles match the binaries, not HEAD)."""
        r = subprocess.run([git, "show", f"{src}:{path}"], cwd=ROOT, capture_output=True)
        return r.stdout if r.returncode == 0 else None
    wheels = []
    for os_name in oses:
        rows = reports.get(os_name)
        if rows is None: problems.append(f"{os_name}: no RESULTS-{os_name}.md (run release.py there)"); continue
        have = {r["python"] for r in rows}
        for v in all_versions:
            if v not in have: problems.append(f"{os_name}: no result for Python {v} (the last {os_name} run skipped it)")
        for r in rows:
            where = f"{os_name} Python {r['python']}"
            if r["tests"] == "-": problems.append(f"{where}: not tested")
            elif not r["tests"].startswith("PASS"): problems.append(f"{where}: {r['tests'][:120]}")
            if r["wheel"] == "-": problems.append(f"{where}: no wheel")
            elif not (pypi_src / r["wheel"]).is_file(): problems.append(f"{where}: wheel {r['wheel']} missing from pypi/")
            else: wheels.append(pypi_src / r["wheel"])
        if not any(r["exes"] != "-" for r in rows):
            problems.append(f"{os_name}: no executables built in its last run"); continue

        d = out / os_name
        arch = read_field(out / f"RESULTS-{os_name}.md", "Arch")
        if not arch:   # a report from before the Arch line: only an unambiguous set of installers will do
            found = {mm.group(1) for f in (d / "installers").glob(f"*-{VERSION}-{os_name}-*-setup*")
                     if (mm := re.search(rf"-{re.escape(VERSION)}-{os_name}-(\w+)-setup", f.name))}
            if len(found) != 1:
                problems.append(f"{os_name}: report records no architecture and installers for "
                                f"{', '.join(sorted(found)) or 'none'} are present"); continue
            arch = found.pop()
        portable, archives, installers = expected_executables(os_name, arch)
        missing = [f"portable/{n}" for n in portable if not (d / "portable" / n).is_file()] + \
                  [f"archives/{n}" for n in archives if not (d / "archives" / n).is_file()] + \
                  [f"installers/{n}" for n in installers if not (d / "installers" / n).is_file()]
        if missing:
            problems.append(f"{os_name}: missing {', '.join(missing)}"); continue
        stage = ROOT / "build" / "upload" / os_name
        shutil.rmtree(stage, ignore_errors=True); stage.mkdir(parents=True)
        for n in portable: shutil.copy2(d / "portable" / n, stage / n)
        for name, dest in (("README.md", "README.md"), ("LICENSE", "LICENSE.txt")):
            data = at_commit(name) if src else None
            if data is None: problems.append(f"{os_name}: {name} not bundled (no single build commit to take it from)")
            else: (stage / dest).write_bytes(data)
        top = f"vfa-{VERSION}-{os_name}-{arch}-portable"
        if os_name == "windows": _zip_dir(stage, gh / f"{top}.zip", top)
        else: _tar_dir(stage, gh / f"{top}.tar.gz", top)
        for n in archives: shutil.copy2(d / "archives" / n, gh / n)
        for n in installers: shutil.copy2(d / "installers" / n, gh / n)

    sdist = pypi_src / f"vfvfa-{VERSION}.tar.gz"
    if sdist.is_file(): wheels.append(sdist)
    else: problems.append(f"pypi: no sdist (vfvfa-{VERSION}.tar.gz)")
    for f in wheels: shutil.copy2(f, pp / f.name)

    git = shutil.which("git")
    if src:
        for fmt, ext in (("zip", "zip"), ("tar.gz", "tar.gz")):
            r = subprocess.run([git, "archive", f"--format={fmt}", f"--prefix=vfa-{VERSION}/",
                                "-o", str(gh / f"vfa-{VERSION}-source.{ext}"), src], cwd=ROOT,
                               capture_output=True, text=True)
            if r.returncode: problems.append(f"source {ext}: git archive {src[:12]} failed: {r.stderr.strip()[:200]}")

    assets = sorted(f for f in gh.iterdir() if f.is_file())
    with zipfile.ZipFile(gh / f"vfa-{VERSION}-all.zip", "w", zipfile.ZIP_STORED) as z:   # already compressed
        for f in assets: z.write(f, f"vfa-{VERSION}/{f.name}")
        for f in sorted(pp.iterdir()): z.write(f, f"vfa-{VERSION}/pypi/{f.name}")

    def sha(f):
        h = hashlib.sha256()
        with open(f, "rb") as fh:
            for b in iter(lambda: fh.read(1 << 20), b""): h.update(b)
        return h.hexdigest()
    sums = [f"{sha(f)}  {f.parent.name}/{f.name}" for d in (gh, pp) for f in sorted(d.iterdir()) if f.is_file()]
    (up / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")

    log(f"{up} assembled:")
    for d in (gh, pp):
        for f in sorted(d.iterdir()): print(f"    {d.name}/{f.name}  ({f.stat().st_size / 1e6:.1f} MB)")
    if problems:
        log("NOT COMPLETE - do not publish yet:")
        for pr in problems: print("    - " + pr)
    else:
        log(f"complete: {', '.join(oses)}; Python {', '.join(all_versions)}; every row tested and PASS")
    return problems

def main(argv=None):
    ap = argparse.ArgumentParser(description="Build and test a full VFA release")
    ap.add_argument("--pythons", default="3.10,3.12,3.13,3.14", help="Python versions for tests and wheels")
    ap.add_argument("--exe-python", default="3.13", help="Python the executables are built with")
    ap.add_argument("--tests", choices=["quick", "full", "none"], default="quick", help="test_vfa.py per Python")
    ap.add_argument("--no-wheels", action="store_true"); ap.add_argument("--no-exes", action="store_true")
    ap.add_argument("--wsl", action="store_true", help="Windows: afterwards run the same release inside WSL (Linux)")
    ap.add_argument("--keep-going", action="store_true", help="Continue with the next Python if one fails")
    ap.add_argument("--verbose", action="store_true", help="Show every command's full output (always saved to "
                                                          "release/<version>/logs/ either way)")
    ap.add_argument("--no-assemble", action="store_true", help="Skip collecting release/<version>/upload/ at the end")
    ap.add_argument("--assemble-only", action="store_true",
                    help="Only (re)collect release/<version>/upload/ from what earlier runs built")
    ap.add_argument("--commit", help="With --assemble-only: the commit that reports without a Commit line were "
                                     "built from (they predate it)")
    ap.add_argument("--build-commit", help=argparse.SUPPRESS)   # set by the Windows side for the WSL run
    a = ap.parse_args(argv)
    if a.assemble_only: return 1 if assemble(commit=a.commit) else 0
    # the commit the binaries come from, taken before building; WSL gets it from Windows (its own git would see the
    # Windows checkout as foreign or, through line endings and file modes, as modified)
    commit = a.build_commit or git_state()
    global VERBOSE; VERBOSE = a.verbose

    pythons = [v.strip() for v in a.pythons.split(",") if v.strip()]
    if a.exe_python not in pythons and not a.no_exes: pythons.append(a.exe_python)
    pypi = OUT / "pypi"; pypi.mkdir(parents=True, exist_ok=True)
    rows, ok_all, t0 = [], True, time.time()
    for ver in pythons:
        row = {"python": ver, "tests": "-", "wheel": "-", "exes": "-"}
        try:
            py = env_python(ver, a.exe_python)
            run_quiet([py, ROOT / "build_vulp.py"], f"py{ver}: build _vulp", f"{OS_TAG}-py{ver}-vulp.log", cwd=ROOT)
            if a.tests != "none":
                ok, summary = run_tests(py, a.tests, ver); row["tests"] = ("PASS " if ok else "FAIL ") + summary
                if not ok:   # never package code that fails its tests (--keep-going moves on to the next Python)
                    raise RuntimeError(f"test_vfa.py failed on Python {ver}; not packaging it")
            if not a.no_wheels: row["wheel"] = build_wheel(py, pypi).name
            if ver == a.exe_python and not a.no_exes:
                if not a.no_wheels:   # not from ROOT: "-m build" would find this repo's build.py first
                    run_quiet([py, "-m", "build", "--sdist", "--no-isolation", "--outdir", pypi, ROOT],
                              f"py{ver}: sdist", f"{OS_TAG}-sdist.log", cwd=pypi)
                def step(line, st):   # build.py's own "[build] ..." lines say what it is doing
                    if line.startswith("[build]"): st.update(note=line[len("[build]"):].strip())
                shutil.rmtree(OUT / OS_TAG, ignore_errors=True)   # nothing left over from an earlier build
                run_quiet([py, ROOT / "build.py", "--matrix", "--out", OUT / OS_TAG],
                          f"py{ver}: executables, installers, archives", f"{OS_TAG}-exes.log", cwd=ROOT, on_line=step)
                row["exes"] = f"release/{VERSION}/{OS_TAG}"
        except Exception as e:
            row["tests"] = row["tests"] if row["tests"] != "-" else f"ERROR {e}"; ok_all = False
            log(f"Python {ver}: {e}")
            if not a.keep_going: rows.append(row); break
        rows.append(row)

    report = OUT / f"RESULTS-{OS_TAG}.md"
    lines = [f"# VFA {VERSION} release, {OS_TAG} ({platform.platform()}), {time.strftime('%Y-%m-%d %H:%M')}", "",
             f"Tests: test_vfa.py ({a.tests}). Executables built with Python {a.exe_python}.", "",
             f"Commit: {commit or 'unknown'}", f"Arch: {build.arch_tag()}", "",
             "| Python | tests | wheel | executables |", "|---|---|---|---|"]
    lines += [f"| {r['python']} | {r['tests']} | {r['wheel']} | {r['exes']} |" for r in rows]
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"{report.relative_to(ROOT)} written ({time.time() - t0:.0f} s)")
    print("\n".join(lines))

    if a.wsl:
        if not IS_WIN: log("--wsl only applies on Windows"); return 0 if ok_all else 1
        wp = to_wsl_path(ROOT)
        if not wp:
            log("WSL cannot see this folder. For a mapped or network drive, mount it in WSL first, e.g.\n"
                "          sudo mkdir -p /mnt/u && sudo mount -t drvfs U: /mnt/u")
            return 1
        rest = [x for x in (argv if argv is not None else sys.argv[1:]) if x != "--wsl"]
        if commit: rest += ["--build-commit", commit]
        quoted = " ".join("'" + x.replace("'", "'\\''") + "'" for x in rest)
        r = run(["wsl", "-e", "bash", "-lc", f"cd '{wp}' && python3 release.py {quoted} --no-assemble"], check=False)
        ok_all &= r.returncode == 0
    if not a.no_assemble and assemble(): ok_all = False
    return 0 if ok_all else 1

if __name__ == "__main__":
    sys.exit(main())
