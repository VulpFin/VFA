# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
#!/usr/bin/env python3
"""
Build the _vulp C extension (vulp/vulp.c + vulp/vulpmodule.c) in place, next to vfa2.py.

    python build_vulp.py            # build for the Python running this script
    python build_vulp.py --check    # build, then import it and run a tiny round-trip

Windows: needs MSVC. If cl.exe is not on PATH, the VS 2022 developer environment (vcvars64.bat) is located with
vswhere or at the default Build Tools / Community paths and loaded automatically. The result needs only
python3X.dll, VCRUNTIME140.dll and the Windows CRT - all of which the PyInstaller stubs already ship.
Linux/macOS: the system C compiler.
"""
import argparse, os, pathlib, shutil, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC = [ROOT / "vulp" / "vulp.c", ROOT / "vulp" / "vulpmodule.c"]

def _vcvars_env():
    """Environment of an MSVC x64 developer prompt, or None."""
    cands = []
    vswhere = pathlib.Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    if vswhere.exists():
        try:
            out = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires",
                                  "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
                                 capture_output=True, text=True).stdout.strip()
            if out: cands.append(pathlib.Path(out) / "VC/Auxiliary/Build/vcvars64.bat")
        except OSError: pass
    for ed in ("Community", "BuildTools", "Professional", "Enterprise"):
        for pf in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            cands.append(pathlib.Path(pf) / "Microsoft Visual Studio/2022" / ed / "VC/Auxiliary/Build/vcvars64.bat")
    for bat in cands:
        if bat.exists():
            r = subprocess.run(f'cmd /s /c ""{bat}" >nul 2>&1 && set"', capture_output=True, text=True, shell=True)
            env = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
            if env: print(f"[vulp] using {bat}"); return env
    return None

def build():
    from setuptools import Extension, Distribution
    env = None
    if os.name == "nt" and not shutil.which("cl"):
        env = _vcvars_env()
        if env is None:
            raise SystemExit("[vulp] MSVC not found. Install 'Desktop development with C++' (VS 2022 Build Tools), or run from "
                             "an x64 Native Tools prompt (vcvars64.bat).")
        os.environ.update(env)
    if os.name == "nt": os.environ["DISTUTILS_USE_SDK"] = "1"; os.environ["MSSdk"] = "1"
    flags = ["/O2", "/W4"] if os.name == "nt" else ["-O2", "-std=c99", "-Wall", "-Wextra"]
    ext = Extension("_vulp", [str(p.relative_to(ROOT)) for p in SRC], include_dirs=["vulp"], extra_compile_args=flags)
    dist = Distribution({"name": "vulp", "ext_modules": [ext], "script_name": "build_vulp.py"})
    cmd = dist.get_command_obj("build_ext"); cmd.inplace = True; cmd.build_temp = str(ROOT / "build" / "vulp")
    cwd = os.getcwd(); os.chdir(ROOT)
    try:
        dist.run_command("build_ext")
    finally:
        os.chdir(cwd)
    built = list(ROOT.glob("_vulp*.pyd")) + list(ROOT.glob("_vulp*.so"))
    print(f"[vulp] built: {', '.join(p.name for p in built)}")
    return built

def check():
    sys.path.insert(0, str(ROOT))
    import importlib; m = importlib.import_module("_vulp")
    data = b"VFA2 tANS self-check " * 999
    enc = m.tans_encode(data)
    assert m.tans_decode(enc, len(data)) == data
    print(f"[vulp] import OK ({m.__file__}); {len(data)} -> {len(enc)} bytes round-trips")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); a = ap.parse_args()
    build()
    if a.check: check()
