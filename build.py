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
  python build.py --matrix          # full release set for this OS (see build_matrix; release.py drives it)
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

# ---------------------------------------------------------------- release matrix (--matrix; driven by release.py)
#
# Per OS, into <out>/:
#   portable/<tool>[-windowless][.exe]      single-file builds of all four tools (unpack to a temp dir on each run)
#   install/<tool>[-windowless]/            folder builds of vfa and vfa_viewer (start faster: nothing to unpack)
#   archives/<tool>[-windowless]-<ver>-<os>-<arch>.zip|.tar.gz   each folder build, zipped
#   installers/<tool>[-windowless]-<ver>-<os>-<arch>-setup[.exe] each folder build as a VFA self-finishing installer
# The SFX/SFI stubs are portable only: a payload is appended to a single file, which a folder build cannot carry.
# "Windowless" (PyInstaller --noconsole) only means something on Windows and macOS; Linux builds skip it.

TOOLS = {
    "vfa":        {"entry": "vfa.py", "install": True, "extra": []},
    "vfa_viewer": {"entry": "vfa_viewer.py", "install": True, "extra": ["--hidden-import", "tkinter"]},
    "vfa_sfx":    {"entry": "sfx_stub.py", "install": False, "extra": []},
    "vfa_sfi":    {"entry": "sfi_stub.py", "install": False,
                   "extra": ["--hidden-import", "sfi_gui", "--hidden-import", "tkinter"]},
}

def os_tag():
    return "windows" if is_windows() else "linux" if is_linux() else "macos"

def arch_tag():
    m = platform.machine().lower()
    return {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64"}.get(m, m)

def pyi_build(tool, onedir, console, icon_path, debug=False):
    """One PyInstaller run; returns the produced file (onefile) or folder (onedir). Each OS gets its own
    work/dist folders, so a Windows build and a WSL build of the same checkout never share state."""
    spec = TOOLS[tool]; name = tool + ("" if console else "-windowless")
    base = ROOT / "build" / "pyi" / os_tag()
    args = PYI + base_pyinstaller_args(debug=debug)
    if onedir: args[args.index("--onefile")] = "--onedir"
    args += ["--paths", str(ROOT), *spec["extra"], "-n", name,
             "--distpath", str(base / "dist"), "--workpath", str(base / "work"), "--specpath", str(base / "spec")]
    if not console: args += ["--noconsole"]
    if icon_path and is_windows() and exists(icon_path): args += ["--icon", str(icon_path)]
    run(args + [str(ROOT / spec["entry"])])
    return base / "dist" / (name if onedir else name + (".exe" if is_windows() else ""))

def pack_folder(folder, out_base):
    """folder -> .zip on Windows, .tar.gz elsewhere (the folder's contents at the archive root, under its name)."""
    fmt = "zip" if is_windows() else "gztar"
    return pathlib.Path(shutil.make_archive(str(out_base), fmt, root_dir=str(folder.parent), base_dir=folder.name))

def make_installer(folder, tool, sfi_stub, out_file, version):
    """Folder build -> VFA2 archive (made by this checkout's vfa.py) -> pack_sfi with the portable SFI stub."""
    payload = ROOT / "build" / "pyi" / os_tag() / f"{folder.name}.payload.vfa"
    names = sorted(p.name for p in folder.iterdir())
    run([sys.executable, str(ROOT / "vfa.py"), "c", str(payload), *names, "--format", "vfa2", "--solid"], cwd=str(folder))
    exe = ".exe" if is_windows() else ""
    title = {"vfa": "VFA", "vfa_viewer": "VFA Viewer"}[tool]
    cmd = [sys.executable, str(ROOT / "pack_sfi.py"), "--stub", str(sfi_stub), "--archive", str(payload),
           "-o", str(out_file), "--name", title + (" (windowless)" if folder.name.endswith("-windowless") else ""),
           "--version", version, "--publisher", "TG11", "--license-file", str(ROOT / "LICENSE"),
           "--description", "VulpFin Archive tools" if tool == "vfa" else "VulpFin Archive viewer"]
    if tool == "vfa":
        cmd += ["--path-add", "."] if is_windows() else ["--bin-link", f"vfa:{folder.name}{exe}"]
    else:
        cmd += ["--shortcut", f"startmenu:{folder.name}{exe}:{title}"]
    run(cmd)
    payload.unlink()
    return out_file

def build_matrix(out, version, icon_path, debug=False):
    out = pathlib.Path(out); made = []
    for d in ("portable", "install", "archives", "installers"): (out / d).mkdir(parents=True, exist_ok=True)
    consoles = (True, False) if not is_linux() else (True,)
    if is_linux(): print("[build] Linux: no windowless variants (a Linux binary never opens a console window)")
    exe = ".exe" if is_windows() else ""; tag = f"{version}-{os_tag()}-{arch_tag()}"
    for tool in TOOLS:
        for console in consoles:
            src = pyi_build(tool, onedir=False, console=console, icon_path=icon_path, debug=debug)
            dst = out / "portable" / src.name; shutil.copy2(src, dst); made.append(dst)
    sfi_stub = out / "portable" / f"vfa_sfi{exe}"
    for tool in (t for t, spec in TOOLS.items() if spec["install"]):
        for console in consoles:
            src = pyi_build(tool, onedir=True, console=console, icon_path=icon_path, debug=debug)
            dst = out / "install" / src.name
            if dst.exists(): shutil.rmtree(dst)
            shutil.copytree(src, dst); made.append(dst)
            made.append(pack_folder(dst, out / "archives" / f"{src.name}-{tag}"))
            made.append(make_installer(dst, tool, sfi_stub, out / "installers" / f"{src.name}-{tag}-setup{exe}", version))
    return made

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
    ap.add_argument("--matrix", action="store_true",
                    help="Release set for this OS: portable + windowless + install folders, archives and installers "
                         "(see build_matrix; release.py runs this per OS)")
    ap.add_argument("--out", help="--matrix output folder (default release/<version>/<os>)")
    args = ap.parse_args()

    check_build_deps()
    ensure_pyinstaller()

    # VFA2 codec core (C). Built before PyInstaller so every stub bundles it; see build_vulp.py.
    if not args.no_vulp:
        import build_vulp
        built = build_vulp.build()
        build_vulp.check()
        print(f"[build] _vulp: {', '.join(f'{b.name} ({b.stat().st_size // 1024} KiB)' for b in built)}")

    icon_path = ROOT / args.icon if args.icon else None
    if args.matrix:
        from vfa_version import __version__ as version
        out = pathlib.Path(args.out) if args.out else ROOT / "release" / version / os_tag()
        made = build_matrix(out, version, icon_path, debug=args.debug)
        print(f"\n[build] {len(made)} artifact(s) in {out}")
        for m in made: print("   ", m.relative_to(out))
        return

    if not args.no_clean:
        clean()

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
