# 📦 VFA (VulpFin File Archive)

**VFA** is a custom archiver format and toolchain, designed as part of the **TG11 Ecosystem** (used also in Boundless and GridGoblin projects).
It blends the features of 7-Zip and RAR with a modern, Python-powered backend, plus a sleek fox-themed identity 🦊🐟.

## Features

* Multiple compression methods: **Zstandard, LZMA, zlib, Brotli**
* **Solid archives** with optional chunking and grouping by extension
* **Append support** (add files to existing archives)
* **Encryption**: AES-256-GCM with Argon2id / scrypt KDFs
* **Password protection**
* **Self-extracting (SFX) executables** on Windows
* Verbose/debug logging with aligned timestamps, ETA, ratios, and stats
* Metadata preservation:

  * Windows: hidden, system, ACLs, NTFS streams
  * Linux/Unix: permissions, ownership, symlinks, hardlinks, xattrs, ACLs, SELinux context
  * Optional sparse file support
* Cross-platform (Windows / Linux / macOS with Python 3.9+)

## Usage

Basic example:

```bash
# Create a compressed archive
vfa c mydata.vfa ./data --method zstd --level 19 --solid --solid-by ext

# Extract
vfa x mydata.vfa -o ./restore

# Create an encrypted archive
vfa c secret.vfa ./docs --method lzma --level 9 --solid --password

# Build executables for your platform.

# Windows (PowerShell)
py build.py
python build.py --debug
python build.py --name-suffix _beta --noconsole-sfx

# Linux / macOS
python3 build.py
python3 build.py --debug --name-suffix _beta
```

### Releases (all platforms, all Python versions)

`release.py` builds and tests a whole release into `release/<version>/` (version: `vfa_version.py`):

```bash
python release.py           # this OS
python release.py --wsl     # Windows: then the same again inside WSL, for Linux
```

For each Python (3.10, 3.12, 3.13, 3.14 by default; `--pythons`), it:
- creates a build environment in `.buildenv/` on first use;
- builds the C codec;
- runs `test_vfa.py --quick` (`--tests full|none`);
- builds a wheel for the `vfvfa` PyPI package. Linux wheels are repaired to manylinux.

With Python 3.13 (`--exe-python`), it then builds the executables:

| folder | contents |
|---|---|
| `portable/` | single-file `vfa`, `vfa_viewer`, `vfa_sfx`, `vfa_sfi`, each also `-windowless` (Windows) |
| `install/` | folder builds of `vfa` and `vfa_viewer` (faster start: nothing to unpack), console and windowless |
| `archives/` | each folder build as `.zip` (Windows) / `.tar.gz` (Linux) |
| `installers/` | each folder build as a VFA self-finishing installer (checked to start with `--info`) |
| `pypi/` | wheels for every OS and Python, plus the sdist (upload with `twine upload release/<version>/pypi/*`) |

Results per OS: `release/<version>/RESULTS-<os>.md`. Python versions come from the `py` launcher on Windows, and from
`pythonX.Y` on PATH or [uv](https://docs.astral.sh/uv/) elsewhere. With `--wsl`, WSL needs a `python3` and either the
Python versions or uv. A mapped network drive must first be mounted in WSL (`sudo mount -t drvfs U: /mnt/u`).

To pack your own SFX or installer, use `pack_sfi.py` (`--sfx` for a plain SFX) rather than `copy /b` when the payload
contains a PyInstaller program. It appends a copy of the stub's PyInstaller cookie, so the stub still starts.

---

## Current Features
- Multiple compression methods: Zstandard, LZMA, zlib, Brotli
- Solid archives with optional chunking and grouping by extension
- Archive append support
- AES-256-GCM encryption (Argon2id / scrypt KDFs)
- Password-protected archives
- Self-extracting (SFX) executables for Windows
- Verbose/debug logging with ETA, ratios, and per-file stats
- Metadata preservation:
  - Windows: hidden, system, ACLs, NTFS streams
  - Linux: permissions, ownership, symlinks, hardlinks, xattrs, ACLs, SELinux context
- Optional sparse file handling
- Cross-platform (Windows, Linux, macOS)

## Planned / Future Features
- Graphical user interface (GUI) for creating/extracting archives
- Built-in SFX creator (no need to manually append stub + archive)
- Recovery records / error correction
- Multi-threaded extraction (currently only compression benefits)
- Parallel solid block compression
- Integration with cloud storage backends (e.g. S3, WebDAV)
- Checkpoint/restart support for very large archives
- Plugin system for new compression/encryption methods
- Lightweight portable viewer to browse archive contents

---

Copyright © 2025 TG11 LLC
