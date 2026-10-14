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
import argparse, os, pathlib, platform, re, shutil, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from vfa_version import __version__ as VERSION

IS_WIN = platform.system() == "Windows"; IS_LINUX = platform.system() == "Linux"
OS_TAG = "windows" if IS_WIN else "linux" if IS_LINUX else "macos"
OUT = ROOT / "release" / VERSION

def log(msg): print(f"[release] {msg}", flush=True)

def run(cmd, check=True, **kw):
    log("$ " + " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd], check=check, **kw)

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
            run(["uv", "python", "install", ver], check=False)
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
        run([base, "-m", "venv", env])
    tools = ["pip", "setuptools>=77", "wheel", "build"]
    if ver == exe_python: tools.append("pyinstaller>=6.0")
    if IS_LINUX: tools += ["auditwheel", "patchelf"]
    run([py, "-m", "pip", "install", "-q", "--upgrade", *tools, *runtime_requirements()])
    return py

def run_tests(py, mode):
    """test_vfa.py with this Python; returns (ok, summary line)."""
    args = [py, ROOT / "test_vfa.py"] + (["--quick"] if mode == "quick" else [])
    r = run(args, check=False, capture_output=True, text=True, cwd=ROOT)
    lines = [l for l in (r.stdout + r.stderr).splitlines() if l.strip()]
    summary = next((l for l in reversed(lines) if "failed" in l and "skipped" in l), lines[-1] if lines else "no output")
    fails = [l for l in lines if l.startswith("FAIL ")]
    for l in fails[:20]: log("  " + l)
    return r.returncode == 0, summary.strip()

def build_wheel(py, pypi):
    """Wheel for this Python into release/<ver>/pypi (Linux: repaired to manylinux by auditwheel)."""
    tmp = ROOT / "build" / "wheels" / pathlib.Path(py).parent.parent.name
    shutil.rmtree(tmp, ignore_errors=True); tmp.mkdir(parents=True)
    run([py, "-m", "pip", "wheel", ROOT, "--no-deps", "--no-build-isolation", "-w", tmp], cwd=ROOT)
    whl = next(tmp.glob("*.whl"))
    if IS_LINUX:
        env = dict(os.environ, PATH=str(pathlib.Path(py).parent) + os.pathsep + os.environ.get("PATH", ""))  # patchelf
        run([py, "-m", "auditwheel", "repair", whl, "-w", pypi], env=env)
        return max(pypi.glob(whl.name.split("-linux_")[0] + "-*manylinux*.whl"), key=lambda p: p.stat().st_mtime)
    dst = pypi / whl.name; shutil.copy2(whl, dst)
    return dst

def to_wsl_path(p):
    r = subprocess.run(["wsl", "wslpath", "-a", str(p).replace("\\", "/")], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None

def main(argv=None):
    ap = argparse.ArgumentParser(description="Build and test a full VFA release")
    ap.add_argument("--pythons", default="3.10,3.12,3.13,3.14", help="Python versions for tests and wheels")
    ap.add_argument("--exe-python", default="3.13", help="Python the executables are built with")
    ap.add_argument("--tests", choices=["quick", "full", "none"], default="quick", help="test_vfa.py per Python")
    ap.add_argument("--no-wheels", action="store_true"); ap.add_argument("--no-exes", action="store_true")
    ap.add_argument("--wsl", action="store_true", help="Windows: afterwards run the same release inside WSL (Linux)")
    ap.add_argument("--keep-going", action="store_true", help="Continue with the next Python if one fails")
    a = ap.parse_args(argv)

    pythons = [v.strip() for v in a.pythons.split(",") if v.strip()]
    if a.exe_python not in pythons and not a.no_exes: pythons.append(a.exe_python)
    pypi = OUT / "pypi"; pypi.mkdir(parents=True, exist_ok=True)
    rows, ok_all, t0 = [], True, time.time()
    for ver in pythons:
        row = {"python": ver, "tests": "-", "wheel": "-", "exes": "-"}
        try:
            py = env_python(ver, a.exe_python)
            run([py, ROOT / "build_vulp.py"], cwd=ROOT)                    # _vulp for this Python, in place
            if a.tests != "none":
                ok, summary = run_tests(py, a.tests); row["tests"] = ("PASS " if ok else "FAIL ") + summary
                if not ok:   # never package code that fails its tests (--keep-going moves on to the next Python)
                    raise RuntimeError(f"test_vfa.py failed on Python {ver}; not packaging it")
            if not a.no_wheels: row["wheel"] = build_wheel(py, pypi).name
            if ver == a.exe_python and not a.no_exes:
                if not a.no_wheels:   # not from ROOT: "-m build" would find this repo's build.py first
                    run([py, "-m", "build", "--sdist", "--no-isolation", "--outdir", pypi, ROOT], cwd=pypi)
                run([py, ROOT / "build.py", "--matrix", "--out", OUT / OS_TAG], cwd=ROOT)
                row["exes"] = f"release/{VERSION}/{OS_TAG}"
        except Exception as e:
            row["tests"] = row["tests"] if row["tests"] != "-" else f"ERROR {e}"; ok_all = False
            log(f"Python {ver}: {e}")
            if not a.keep_going: rows.append(row); break
        rows.append(row)

    report = OUT / f"RESULTS-{OS_TAG}.md"
    lines = [f"# VFA {VERSION} release, {OS_TAG} ({platform.platform()}), {time.strftime('%Y-%m-%d %H:%M')}", "",
             f"Tests: test_vfa.py ({a.tests}). Executables built with Python {a.exe_python}.", "",
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
        quoted = " ".join("'" + x.replace("'", "'\\''") + "'" for x in rest)
        r = run(["wsl", "-e", "bash", "-lc", f"cd '{wp}' && python3 release.py {quoted}"], check=False)
        ok_all &= r.returncode == 0
    return 0 if ok_all else 1

if __name__ == "__main__":
    sys.exit(main())
