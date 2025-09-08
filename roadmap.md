# VFA Roadmap

This roadmap tracks the progress of the **Vulpfin File Archive (VFA)** project — what’s done ✅, what’s in-progress, and what’s planned for the future.

---

## Core Features
- [x] Multiple compression methods (Zstandard, LZMA, Brotli, zlib)
- [x] Compression levels and tunables (dictionary size, word size, block size)
- [x] Solid archives
- [x] Solid chunking (configurable chunk exponent)
- [x] Grouping by extension (`--solid-by ext`)
- [x] Append files to existing archives
- [x] Archive listing (`l`), extraction (`x`), testing (`t`)
- [x] AES-256-GCM encryption
- [x] Password protection with Argon2id / scrypt KDFs
- [x] Self-extracting (SFX) executables
- [x] Verbose & debug logging with timestamps, ETA, ratios, stats
- [x] Metadata preservation  
  - Windows: hidden, system, ACLs, NTFS streams  
  - Linux: permissions, ownership, symlinks, hardlinks, xattrs, ACLs, SELinux  
- [x] Sparse file support
- [x] Cross-platform (Windows, Linux, macOS)

---

## Power-User Features (Next Steps)
- [ ] Recovery records / parity blocks (like RAR repair)
- [ ] Checksums per file in TOC (SHA-256)
- [ ] Multithreaded extraction (parallel block decode)
- [ ] Streaming mode (stdin/stdout support)
- [ ] File preview (`cat`/`dump` a single file without full extraction)
- [ ] GUI frontend (drag & drop interface)
- [ ] Built-in SFX creator (no manual `copy /b` step)
- [ ] Cloud storage integration (S3, WebDAV, etc.)
- [ ] Incremental archive updates (add/replace files without re-packing solid streams)

---

## Experimental / Future
- [ ] Deduplication across archives (store identical files once)
- [ ] New codec plugins (LZ4, Lizard, experimental compressors)
- [ ] Plugin system for custom encryption/compression
- [ ] Portable lightweight decompressor (mobile / embedded)
- [ ] Integration with CI/CD pipelines (artifact archiving)
- [ ] WebAssembly/WASM decompressor (for browser extraction)

---

### Notes
- VFA is already comparable to tools like **7-Zip** and **RAR**, with modern encryption and solid archiving.  
- Short-term focus: polish the **debug logging**, **per-file checksums**, and **parallel extraction**.  
- Mid-term: add **GUI** and **recovery records**.  
- Long-term: experiment with **deduplication** and **new codecs**.
