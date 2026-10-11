# Copyright (C) 2025 TG11
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

#!/usr/bin/env python3
"""
Build script for VFA and SFX stub using PyInstaller.

- Windows: produces vfa.exe and vfa_sfx.exe
- Linux/macOS: produces vfa and vfa_sfx (ELF/Mach-O single-file binaries)

Usage:
  python build.py                   # normal build (onefile, clean)
  python build.py --no-clean        # keep build/dist between runs
  python build.py --debug           # PyInstaller debug build (bigger)
  python build.py --name-suffix _x  # append suffix to output names
  python build.py --noconsole-sfx   # build sfx without console window
"""

import argparse, os, sys, shutil, subprocess, pathlib, platform

ROOT = pathlib.Path(__file__).resolve().parent
PYI  = [sys.executable, "-m", "PyInstaller"]

def exists(p: pathlib.Path) -> bool:
    try: return p.exists()
    except Exception: return False

def which(cmd: str) -> bool:
    from shutil import which as _which
    return _which(cmd) is not None

def ensure_pyinstaller():
    try:
        import PyInstaller  # noqa: F401
    except Exception:
        print("[build] PyInstaller not found. Installing...", flush=True)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def is_windows(): return platform.system() == "Windows"
def is_linux():   return platform.system() == "Linux"
def is_macos():   return platform.system() == "Darwin"

def run(cmd, **kw):
    print("[build] $", " ".join(str(c) for c in cmd))
    subprocess.check_call(cmd, **kw)

def clean():
    for d in ("build", "dist", "__pycache__"):
        p = ROOT / d
        if exists(p):
            print(f"[build] Removing {p}")
            shutil.rmtree(p, ignore_errors=True)
    # old bin outputs
    for plat in ("windows", "linux", "macos"):
        p = ROOT / "bin" / plat
        p.mkdir(parents=True, exist_ok=True)  # ensure folder exists

def base_pyinstaller_args(debug=False):
    args = ["--onefile"]
    if not debug:
        args += ["--noconfirm"]
    else:
        args += ["--debug", "all"]
    # Helpful for smaller sizes on *nix
    if is_linux():
        args += ["--strip"]
    # Collect dynamic packages that sometimes need help
    args += [
        "--collect-all", "cryptography",
        "--collect-all", "zstandard",
        "--collect-all", "brotli",
        "--collect-all", "argon2",
        "--collect-all", "lz4",
        # one shared reader for every tool; xxhash so archives written by older builds (xxh64 digest) still verify
        "--paths", str(ROOT),
        "--hidden-import", "vfa_extract",
        "--hidden-import", "vfa2",
        "--hidden-import", "xxhash",
        # VFA2 codecs: the C extension (built by build_vulp.py) and the pure-Python reference it falls back to
        "--hidden-import", "_vulp",
        "--hidden-import", "vulp_ref",
    ]
    return args

def build_vfa(debug=False, name_suffix="", icon_path=None):
    entry = ROOT / "vfa.py"
    if not exists(entry):
        raise SystemExit("vfa.py not found next to build.py")

    name = f"vfa{name_suffix}"
    args = PYI + base_pyinstaller_args(debug=debug) + [
        "-n", name,
        str(entry),
    ]
    if icon_path and is_windows() and exists(icon_path):
        args += ["--icon", str(icon_path)]

    run(args)

    # Move artifact to bin/<platform>/
    out_dir = ROOT / "bin" / ("windows" if is_windows() else "linux" if is_linux() else "macos")
    out_dir.mkdir(parents=True, exist_ok=True)
    src = ROOT / "dist" / (name + (".exe" if is_windows() else ""))
    dst = out_dir / (name + (".exe" if is_windows() else ""))
    shutil.move(str(src), str(dst))
    print(f"[build] VFA => {dst}")

def build_sfx(debug=False, name_suffix="", icon_path=None, noconsole=False):
    entry = ROOT / "sfx_stub.py"
    if not exists(entry):
        raise SystemExit("sfx_stub.py not found next to build.py")

    name = f"vfa_sfx{name_suffix}"
    args = PYI + base_pyinstaller_args(debug=debug) + [
        "-n", name,
        str(entry),
    ]
    # For SFX, you may prefer console to keep debug logs. Allow override:
    if noconsole and is_windows():
        args += ["--noconsole"]
    # Icon
    if icon_path and is_windows() and exists(icon_path):
        args += ["--icon", str(icon_path)]

    run(args)

    # Move artifact to bin/<platform>/
    out_dir = ROOT / "bin" / ("windows" if is_windows() else "linux" if is_linux() else "macos")
    out_dir.mkdir(parents=True, exist_ok=True)
    src = ROOT / "dist" / (name + (".exe" if is_windows() else ""))
    dst = out_dir / (name + (".exe" if is_windows() else ""))
    shutil.move(str(src), str(dst))
    print(f"[build] SFX  => {dst}")

def build_sfi(debug=False, name_suffix="", icon_path=None, noconsole=False):
    """SFI = self-finishing installer stub (GUI + CLI + silent in one executable).
    Built as a console app: double-clicked it hides its own console and shows the wizard."""
    entry = ROOT / "sfi_stub.py"
    if not exists(entry):
        raise SystemExit("sfi_stub.py not found next to build.py")

    name = f"vfa_sfi{name_suffix}"
    args = PYI + base_pyinstaller_args(debug=debug) + [
        "-n", name,
        "--paths", str(ROOT),
        "--hidden-import", "vfa_extract",
        "--hidden-import", "vfa2",
        "--hidden-import", "sfi_gui",
        "--hidden-import", "tkinter",
        "--hidden-import", "xxhash",
        str(entry),
    ]
    if noconsole and is_windows():
        args += ["--noconsole"]
    if icon_path and is_windows() and exists(icon_path):
        args += ["--icon", str(icon_path)]

    run(args)

    out_dir = ROOT / "bin" / ("windows" if is_windows() else "linux" if is_linux() else "macos")
    out_dir.mkdir(parents=True, exist_ok=True)
    src = ROOT / "dist" / (name + (".exe" if is_windows() else ""))
    dst = out_dir / (name + (".exe" if is_windows() else ""))
    shutil.move(str(src), str(dst))
    print(f"[build] SFI  => {dst}")

def build_viewer(debug=False, name_suffix="", icon_path=None, noconsole=False):
    entry = ROOT / "vfa_viewer.py"
    if not exists(entry):
        raise SystemExit("vfa_viewer.py not found next to build.py")

    name = f"vfa_viewer{name_suffix}"
    args = PYI + base_pyinstaller_args(debug=debug) + [
        "-n", name,
        str(entry),
    ]
    # For SFX, you may prefer console to keep debug logs. Allow override:
    if noconsole and is_windows():
        args += ["--noconsole"]
    # Icon
    if icon_path and is_windows() and exists(icon_path):
        args += ["--icon", str(icon_path)]

    run(args)

    # Move artifact to bin/<platform>/
    out_dir = ROOT / "bin" / ("windows" if is_windows() else "linux" if is_linux() else "macos")
    out_dir.mkdir(parents=True, exist_ok=True)
    src = ROOT / "dist" / (name + (".exe" if is_windows() else ""))
    dst = out_dir / (name + (".exe" if is_windows() else ""))
    shutil.move(str(src), str(dst))
    print(f"[build] Viewer  => {dst}")

def check_build_deps():
    """PyInstaller silently skips packages it cannot import, producing a vfa.exe that dies at runtime
    ("zstandard not installed"). Fail early instead - usually this means the venv is not being used."""
    import importlib
    need = {"zstandard": "zstandard", "brotli": "brotli", "cryptography": "cryptography", "argon2": "argon2-cffi", "lz4": "lz4",
            "xxhash": "xxhash"}
    missing = []
    for mod, pipname in need.items():
        try: importlib.import_module(mod)
        except Exception: missing.append(pipname)
    if missing:
        raise SystemExit(
            "[build] Missing packages for the Python running build.py: " + ", ".join(missing) + "\n"
            f"        Python in use: {sys.executable}\n"
            "        Use your venv (e.g. venv\\Scripts\\python build.py) or: pip install -r requirements.txt\n"
            "        Building anyway would produce executables that fail at runtime.")

def main():
    ap = argparse.ArgumentParser(description="Build VFA and SFX with PyInstaller")
    ap.add_argument("--no-clean", action="store_true", help="Do not clean build/dist before building")
    ap.add_argument("--debug", action="store_true", help="Debug build (larger, verbose)")
    ap.add_argument("--name-suffix", default="", help="Append suffix to output binary names")
    ap.add_argument("--icon", default="VFA.ico", help="Windows icon (.ico). If missing, skip.")
    ap.add_argument("--noconsole-sfx", action="store_true", help="Build SFX without console on Windows")
    ap.add_argument("--noconsole-sfi", action="store_true", help="Build the SFI installer stub without a console window on Windows")
    ap.add_argument("--no-sfi", action="store_true", help="Skip building the SFI installer stub")
    ap.add_argument("--noconsole-viewer", action="store_true", help="Build SFX without console on Windows")
    ap.add_argument("--no-vulp", action="store_true",
                    help="Do not (re)build the _vulp C extension (VFA2 then decodes with the slow pure-Python reference)")
    args = ap.parse_args()

    check_build_deps()
    ensure_pyinstaller()

    # VFA2 codec core (C). Built before PyInstaller so every stub bundles it; see build_vulp.py.
    if not args.no_vulp:
        import build_vulp
        built = build_vulp.build()
        build_vulp.check()
        print(f"[build] _vulp: {', '.join(f'{b.name} ({b.stat().st_size // 1024} KiB)' for b in built)}")

    if not args.no_clean:
        clean()

    icon_path = ROOT / args.icon if args.icon else None

    # Build main CLI
    build_vfa(debug=args.debug, name_suffix=args.name_suffix, icon_path=icon_path)

    # Build SFX stub
    build_sfx(debug=args.debug, name_suffix=args.name_suffix, icon_path=icon_path, noconsole=args.noconsole_sfx)

    # Build SFI installer stub
    if not args.no_sfi:
        build_sfi(debug=args.debug, name_suffix=args.name_suffix, icon_path=icon_path, noconsole=args.noconsole_sfi)

    # Build Viewer
    build_viewer(debug=args.debug, name_suffix=args.name_suffix, icon_path=icon_path, noconsole=args.noconsole_viewer)

    print("\n[build] All done!")
    print("       Outputs in ./bin/windows or ./bin/linux (depending on your OS).")

if __name__ == "__main__":
    main()
