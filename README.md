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
