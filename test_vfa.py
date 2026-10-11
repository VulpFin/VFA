# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
#!/usr/bin/env python3
"""
VFA correctness harness (VFA1 and VFA2). No pytest needed:

    python test_vfa.py                  # both formats, everything except the 4 GiB tests (several minutes)
    python test_vfa.py --format vfa2    # one format: vfa1 | vfa2 | all (default)
    python test_vfa.py --quick          # smaller fuzz run
    python test_vfa.py --big            # also the >4 GiB single-file tests (needs ~13 GB free, slow)
    python test_vfa.py --fuzz 5000      # more fuzz cases per archive (default 600)
    python test_vfa.py --only fuzz,ra   # groups: roundtrip,sample,encrypt,append,ra,refuse,paths,fuzz,determinism,sfx,signed,
                                        #         codec,native,lz,dedup,big

What "pass" means:
  roundtrip     every file comes back byte-identical (all methods x solid/non-solid, multi-block, edge-case files)
  fuzz          a corrupted/truncated archive either raises VFAError or extracts byte-identical output:
                never another exception (crash), never a hang, never different bytes
  ra            one small member extracted from the middle of a large archive touches only its own blocks
  refuse        unknown version / flags / extension records / methods / entry types are refused by name
  determinism   same input + options -> byte-identical archive
  codec         (VFA2) C codec == pure-Python reference bit for bit; every filter round-trips; corrupt tANS data is
                refused by both decoders; the segmented filter is parsed strictly
  native        (VFA2) the C codec built by every available compiler at -O0 and -O3 (MSVC /Od and /O2 on Windows)
                gives identical output; no float/double in the codec source (C and Python, AST-checked); no
                floating-point instruction in the compiled object; sanitizer (ASan+UBSan) fuzz of the C decoder
Failing fuzz inputs are saved to ./fuzz_failures/ for reproduction.
"""
import os, re, sys, io, json, struct, shutil, hashlib, random, tempfile, subprocess, pathlib, time, contextlib, traceback, argparse
import multiprocessing as mp
from typing import Tuple

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vfa_extract as vx

PY = sys.executable
FAILS = []; SKIPS = []

def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"   {extra}" if extra and not cond else ""), flush=True)
    if not cond: FAILS.append(name)
    return cond

def skip(name, why):
    print(f"SKIP  {name}   ({why})", flush=True); SKIPS.append(name)

# ---------------------------------------------------------------- helpers

def vfa(*argv, cwd=None, env=None, expect=0):
    """Run vfa.py in a subprocess (exactly what a user runs). Returns CompletedProcess."""
    e = dict(os.environ); e.update(env or {})
    r = subprocess.run([PY, str(HERE / "vfa.py"), *map(str, argv)], capture_output=True, text=True, cwd=cwd, env=e)
    if expect is not None and r.returncode != expect:
        print(f"      vfa {' '.join(map(str, argv))} -> exit {r.returncode}\n      {r.stdout[-400:]}{r.stderr[-800:]}")
    return r

def tree(d):
    """{relative posix path: sha256} for files, plus '<dir>/' markers for directories."""
    d = pathlib.Path(d); out = {}
    for p in d.rglob("*"):
        rel = p.relative_to(d).as_posix()
        out[rel + "/" if p.is_dir() else rel] = "" if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest()
    return out

def same_tree(a, b):
    ta, tb = tree(a), tree(b)
    if ta == tb: return True, ""
    diff = sorted(set(ta.items()) ^ set(tb.items()))[:6]
    return False, f"differs: {diff}"

def make_corpus(root: pathlib.Path):
    """The edge-case corpus from the M2 list (the exe comes from the running Python)."""
    rnd = random.Random(1234)
    (root / "nested/deeper/deepest").mkdir(parents=True); (root / "emptydir").mkdir()
    (root / "empty.bin").write_bytes(b"")
    (root / "one.bin").write_bytes(b"\x7f")
    (root / "repetitive.txt").write_bytes(b"All work and no play makes VFA a dull archiver.\n" * 100_000)
    (root / "random.bin").write_bytes(rnd.randbytes(3 * 1024 * 1024))
    (root / "allbytes.bin").write_bytes(bytes(range(256)) * 257)
    text = ("Grüße aus Zürich - 日本語のテキスト - Ελληνικά - русский - العربية - emoji 🦊🐟\n"
            "The quick brown fox jumps over the lazy dog. 0123456789\n") * 3000
    (root / "utf8.txt").write_text(text, encoding="utf-8")
    (root / "utf16.txt").write_text(text, encoding="utf-16")
    rows = ["id,timestamp,sensor,value,flag"] + [f"{i},{1700000000 + i * 7},{'ABCD'[i % 4]},{rnd.gauss(20, 5):.4f},{i % 3 == 0}" for i in range(60_000)]
    (root / "data.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    shutil.copyfile(sys.executable, root / "program.exe")
    (root / "nested/deeper/deepest/note.txt").write_text("deep\n")
    (root / "nested/unicode_éè_日本.txt").write_text("unicode name\n", encoding="utf-8")
    (root / "block_exact.bin").write_bytes(rnd.randbytes(4096 * 3))       # exactly 3 blocks at --block-exp 12
    (root / "block_plus1.bin").write_bytes(rnd.randbytes(4096 * 3 + 1))
    return root

def extract_cmp(arc, src_dir, work, *extra, env=None, label=""):
    out = work / ("out_" + hashlib.md5(str(arc).encode()).hexdigest()[:8])
    shutil.rmtree(out, ignore_errors=True)
    r = vfa("x", arc, "-o", out, *extra, env=env)
    if r.returncode != 0: return False, r.stderr[-300:]
    return same_tree(src_dir, out / src_dir.name)

# ---------------------------------------------------------------- a tiny independent writer (follows VFA1.md)

def raw_archive(path, files, *, solid=False, method=0, frame_method=None, version=1, extra_flags=0, tocx=True,
                extra_tocx=(), entry_type=0, toc_trailing=b"", encrypt=None):
    """Write a VFA1 archive by hand from the spec, so tests can produce what vfa.py never would.
    files: list of (path, bytes). method 0 stores data as-is; frame_method overrides the method byte everywhere."""
    import vfa as V
    meth = method if frame_method is None else frame_method
    flags = (vx.F_SOLID if solid else 0) | (vx.F_TOCX if tocx else 0) | extra_flags
    hdr = V.HeaderV1(); hdr.version = version; hdr.flags = flags; hdr.default_method = meth
    out = bytearray(hdr.pack()); recs = []; toc = V.TOC()
    def put(data):
        comp = V.compress_block(method, 1, data) if frame_method is None else data
        recs.append((len(out), len(comp), len(data), meth, vx.crc32(data)))
        out.extend(struct.pack("<IB", len(comp), meth)); out.extend(comp)
        return (len(recs) - 1, len(data), len(comp), meth)
    if solid:
        stream = b"".join(d for _, d in files); pos = 0
        for p, d in files:
            toc.entries.append(V.FileEntry(p, 0o644, 1_700_000_000, len(d), [], pos, entry_type)); pos += len(d)
        if stream: put(stream)
    else:
        for p, d in files:
            e = V.FileEntry(p, 0o644, 1_700_000_000, len(d), [], 0, entry_type)
            if d: e.blocks.append(put(d))
            toc.entries.append(e)
    body = toc.pack(solid)
    if tocx:
        recs_b = struct.pack("<I", len(recs)) + b"".join(vx.BLOCK_REC.pack(o, c, u, m, vx.BF_CRC, k) for o, c, u, m, k in recs)
        rec_list = [(vx.TX_TOCCRC, vx.TXF_CRITICAL, struct.pack("<I", vx.crc32(body))),
                    (vx.TX_BLOCKS, vx.TXF_CRITICAL, recs_b), *extra_tocx]
        body += vx.TOCX_MAGIC + struct.pack("<I", len(rec_list)) + b"".join(struct.pack("<HHI", t, f, len(b)) + b for t, f, b in rec_list)
    body += toc_trailing
    toc_off = len(out); out += body
    digest = hashlib.sha256(bytes(out)).digest()
    out += struct.pack("<QIB", toc_off, len(body), vx.H_SHA256) + digest + vx.END_MAGIC
    pathlib.Path(path).write_bytes(bytes(out))
    return path

def open_extract(path, dest, password=None, verify=True, members=None):
    with vx.open_container(str(path)) as c:
        if verify and c.verify_digest() is False: raise vx.VFAError("digest mismatch")
        c.unlock(password)
        return c.extract(str(dest), members=members)

# ---------------------------------------------------------------- test groups

def t_roundtrip(work, corpus):
    import vfa as V
    for m in V.NAME_TO_METHOD:
        for solid in (False, True):
            arc = work / f"rt_{m}_{'s' if solid else 'n'}.vfa"
            flags = ["--solid", "--solid-chunk-exp", "20"] if solid else ["--block-exp", "16"]
            r = vfa("c", arc, corpus.name, "--method", m, "--level", "3", *flags, cwd=corpus.parent)
            if not check(f"roundtrip create {m} {'solid' if solid else 'non-solid'}", r.returncode == 0, r.stderr[-300:]): continue
            check(f"roundtrip test   {m} {'solid' if solid else 'non-solid'}", vfa("t", arc).returncode == 0)
            ok, why = extract_cmp(arc, corpus, work)
            check(f"roundtrip bytes  {m} {'solid' if solid else 'non-solid'}", ok, why)
    arc = work / "rt_blocks12.vfa"
    vfa("c", arc, corpus.name, "--method", "zstd", "--block-exp", "12", cwd=corpus.parent)
    with vx.Container(str(arc)) as c:
        c.unlock(None)
        e = next(e for e in c.entries if e["path"].replace("\\", "/").endswith("block_exact.bin"))
        e2 = next(e for e in c.entries if e["path"].replace("\\", "/").endswith("block_plus1.bin"))
        check("block boundaries: exact multiple -> 3 blocks, +1 byte -> 4 blocks", len(e["blocks"]) == 3 and len(e2["blocks"]) == 4,
              f"{len(e['blocks'])}/{len(e2['blocks'])}")
    ok, why = extract_cmp(arc, corpus, work); check("roundtrip bytes  4 KiB blocks", ok, why)

def t_sample(work):
    src = HERE / "sample"
    if not src.is_dir(): skip("sample\\ round-trips", f"{src} not found (put the sample folder next to vfa.py)"); return
    stage = work / "sample_copy"; shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(src, stage / "sample", ignore=shutil.ignore_patterns("__pycache__"))
    for m, flags in (("zstd", []), ("zstd", ["--solid"]), ("xz", ["--solid"]), ("none", [])):
        arc = work / f"sample_{m}_{len(flags)}.vfa"
        vfa("c", arc, "sample", "--method", m, *flags, cwd=stage)
        ok, why = extract_cmp(arc, stage / "sample", work)
        check(f"sample\\ round-trip ({m}{' solid' if flags else ''})", ok, why)

def t_encrypt(work, corpus):
    env = {"VFA_TEST_PW": "correct horse ☃"}; kdf = ["--kdf-mem-kib", "8192", "--kdf-time", "1", "--kdf-parallel", "1"]
    for solid in (False, True):
        arc = work / f"enc_{solid}.vfa"
        vfa("c", arc, corpus.name, "--password-env", "VFA_TEST_PW", *kdf, *(["--solid"] if solid else []), cwd=corpus.parent, env=env)
        ok, why = extract_cmp(arc, corpus, work, "--password-env", "VFA_TEST_PW", env=env)
        check(f"encrypted round-trip ({'solid' if solid else 'non-solid'})", ok, why)
        out = work / "wrongpw"; shutil.rmtree(out, ignore_errors=True)
        r = vfa("x", arc, "-o", out, "--password-env", "VFA_TEST_PW", env={"VFA_TEST_PW": "wrong"}, expect=None)
        check(f"wrong password -> exit 5, nothing written ({'solid' if solid else 'non-solid'})",
              r.returncode == 5 and not any(p.is_file() for p in out.rglob("*")), f"exit {r.returncode}")
        r = vfa("l", arc, expect=None)
        check("encrypted list without password refuses", r.returncode != 0)

def t_append(work, corpus):
    extra = work / "extra_in"; shutil.rmtree(extra, ignore_errors=True); (extra / "more").mkdir(parents=True)
    (extra / "more/a.txt").write_text("appended\n"); (extra / "more/b.bin").write_bytes(os.urandom(70_000))
    env = {"VFA_TEST_PW": "pw"}
    for solid in (False, True):
        for enc in (False, True):
            tag = f"{'solid' if solid else 'non-solid'}{' encrypted' if enc else ''}"
            arc = work / f"app_{solid}_{enc}.vfa"
            pwf = ["--password-env", "VFA_TEST_PW"] if enc else []
            vfa("c", arc, corpus.name, *pwf, "--kdf-mem-kib", "8192", "--kdf-time", "1", *(["--solid"] if solid else []), cwd=corpus.parent, env=env)
            r1 = vfa("a", arc, "more", *pwf, cwd=extra, env=env); r2 = vfa("a", arc, "more/a.txt", *pwf, cwd=extra, env=env)
            out = work / "app_out"; shutil.rmtree(out, ignore_errors=True)
            r = vfa("x", arc, "-o", out, *pwf, env=env)
            ok = r1.returncode == 0 and r2.returncode == 0 and r.returncode == 0 and same_tree(corpus, out / corpus.name)[0] \
                and (out / "more/b.bin").read_bytes() == (extra / "more/b.bin").read_bytes()
            check(f"append twice + full round-trip ({tag})", ok, r1.stderr[-200:] + r2.stderr[-200:] + r.stderr[-200:])
            check(f"append: archive still tests OK ({tag})", vfa("t", arc, *pwf, env=env).returncode == 0)
            if enc:
                with vx.Container(str(arc)) as c:
                    check(f"append: TOC nonce generation advanced to 2 ({tag})", c.header["toc_gen"] == 2, str(c.header["toc_gen"]))
    # a VFA 1.0 archive (no block table) is upgraded on append
    leg = raw_archive(work / "legacy10.vfa", [("l/a.txt", b"hello " * 1000), ("l/b.txt", b"world")], solid=True, method=vx.M_ZLIB, tocx=False)
    r = vfa("a", leg, "more/a.txt", cwd=extra)
    with vx.Container(str(leg)) as c:
        c.unlock(None); st = c.test()
        check("append upgrades a VFA 1.0 solid archive to a block table", r.returncode == 0 and c.has_tocx and st["blocks"] == 2)

def t_random_access(work):
    big = work / "ra_src"; shutil.rmtree(big, ignore_errors=True); (big / "d").mkdir(parents=True)
    rnd = random.Random(7); needle = b"NEEDLE-" + rnd.randbytes(5000)
    for i in range(24):
        (big / f"d/f{i:02d}.bin").write_bytes(rnd.randbytes(4 * 1024 * 1024))
        if i == 12: (big / "d/f12_needle.bin").write_bytes(needle)
    for solid in (False, True):
        arc = work / f"ra_{solid}.vfa"
        vfa("c", arc, big.name, "--method", "zstd", "--level", "1", *(["--solid", "--solid-chunk-exp", "22"] if solid else []), cwd=big.parent)
        with vx.Container(str(arc)) as c:
            c.unlock(None); calls = []; orig = c.block_data
            c.block_data = lambda i, limit=None: (calls.append(i), orig(i, limit=limit))[1]
            out = work / "ra_out"; shutil.rmtree(out, ignore_errors=True)
            t0 = time.perf_counter(); c.extract(str(out), members=["ra_src/d/f12_needle.bin"]); dt = time.perf_counter() - t0
            got = (out / "ra_src/d/f12_needle.bin").read_bytes()
            check(f"random access ({'solid' if solid else 'non-solid'}): member byte-identical", got == needle)
            check(f"random access ({'solid' if solid else 'non-solid'}): decoded {len(calls)} of {len(c.blocks)} blocks in {dt*1000:.0f} ms",
                  len(calls) <= 2 and len(c.blocks) >= 20, f"blocks {calls}")
            check(f"random access ({'solid' if solid else 'non-solid'}): nothing else written",
                  [p.name for p in out.rglob("*") if p.is_file()] == ["f12_needle.bin"])

def t_refuse(work):
    def refused(name, path, needle, verify=True):
        try:
            open_extract(path, work / "refuse_out", verify=verify)
            return check(name, False, "was accepted")
        except vx.VFAError as e:
            return check(name, needle.lower() in str(e).lower(), f"message: {e}")
        except Exception as e:
            return check(name, False, f"crashed: {e!r}")
    f = [("r/a.txt", b"payload " * 100)]
    refused("refuse: header version 2", raw_archive(work / "v2.vfa", f, version=2), "version 2")
    refused("refuse: unknown header flag", raw_archive(work / "flag.vfa", f, extra_flags=1 << 9), "feature flags")
    refused("refuse: unknown critical TOC extension", raw_archive(work / "crit.vfa", f, extra_tocx=[(77, vx.TXF_CRITICAL, b"x")]), "extension type 77")
    try:
        open_extract(raw_archive(work / "opt.vfa", f, extra_tocx=[(78, 0, b"future")]), work / "opt_out")
        check("accept: unknown optional TOC extension is ignored", (work / "opt_out/r/a.txt").read_bytes() == f[0][1])
    except Exception as e: check("accept: unknown optional TOC extension is ignored", False, repr(e))
    refused("refuse: unknown compression method 99", raw_archive(work / "m99.vfa", f, frame_method=99), "method 99")
    refused("refuse: unknown entry type 9", raw_archive(work / "et9.vfa", f, entry_type=9), "entry type 9")
    refused("refuse: trailing bytes after the TOC", raw_archive(work / "trail.vfa", f, tocx=False, toc_trailing=b"junk"), "trailing")
    p = raw_archive(work / "vfa2.vfa", f); b = bytearray(p.read_bytes()); b[-5:] = b"/VFA2"; p.write_bytes(bytes(b))
    try: vx.Container(str(p)); check("refuse: VFA1 reader names a /VFA2 file as a different format", False, "accepted")
    except vx.VFAError as e: check("refuse: VFA1 reader names a /VFA2 file as a different format", "different vfa format" in str(e).lower(), str(e))
    refused("refuse: a VFA1 body behind a /VFA2 end magic is rejected by the VFA2 reader", p, "")

def t_paths(work):
    bad = ["../evil.txt", "/abs_evil.txt", "C:/drive_evil.txt", "a/../../evil2.txt", "ok/../../../evil3.txt"]
    if os.name == "nt": bad += ["CON", "nested/aux.txt", "file.txt:ads"]
    for p in bad:
        arc = raw_archive(work / "bad.vfa", [("fine.txt", b"x"), (p, b"evil")])
        dest = work / "jail" / "inner"; shutil.rmtree(work / "jail", ignore_errors=True); dest.mkdir(parents=True)
        try:
            open_extract(arc, dest); check(f"path refused: {p!r}", False, "was extracted")
        except vx.VFAError:
            outside = [q for q in (work / "jail").rglob("*") if q.is_file()]
            check(f"path refused before writing anything: {p!r}", not outside, str(outside))
        except Exception as e:
            check(f"path refused: {p!r}", False, f"crashed: {e!r}")
    import vfa as V
    ok = all(not V._safe_ads_name(n) for n in (":..\\..\\evil", ":a/b", "x:y", None)) and V._safe_ads_name(":Zone.Identifier:$DATA")
    check("Windows ADS names with path separators are rejected", ok)

def t_determinism(work, corpus):
    for m, flags in (("zstd", []), ("xz", ["--solid"]), ("none", [])):
        a1, a2 = work / "det1.vfa", work / "det2.vfa"
        vfa("c", a1, corpus.name, "--method", m, *flags, cwd=corpus.parent); vfa("c", a2, corpus.name, "--method", m, *flags, cwd=corpus.parent)
        check(f"determinism: same input -> identical archive ({m}{' solid' if flags else ''})", a1.read_bytes() == a2.read_bytes())
    # VFA1 uses only library codecs (zlib/lzma/zstd/...); the native-codec determinism tests are VFA2's 'native' group

def t_sfx(work, corpus):
    arc = work / "sfx.vfa"; vfa("c", arc, corpus.name, "--solid", cwd=corpus.parent)
    exe = work / "fake_sfx.exe"; exe.write_bytes(b"MZ" + os.urandom(5000) + arc.read_bytes())
    out = work / "sfx_out"; shutil.rmtree(out, ignore_errors=True)
    r = subprocess.run([PY, str(HERE / "sfx_stub.py"), "--from-file", str(exe), "-o", str(out)], capture_output=True, text=True)
    check("SFX stub extracts stub+archive", r.returncode == 0 and same_tree(corpus, out / corpus.name)[0], r.stderr[-300:])
    b = bytearray(exe.read_bytes()); b[len(b) // 2] ^= 0x10; exe.write_bytes(bytes(b))
    out2 = work / "sfx_out2"; shutil.rmtree(out2, ignore_errors=True)
    r = subprocess.run([PY, str(HERE / "sfx_stub.py"), "--from-file", str(exe), "-o", str(out2)], capture_output=True, text=True)
    check("SFX stub refuses a corrupted file and writes nothing", r.returncode != 0 and (not out2.exists() or not any(out2.rglob("*"))))

# ---------------------------------------------------------------- fuzzing

def _fuzz_worker(job):
    """Runs in a pool process. Returns (kind, detail). kind in refused / identical / WRONG / CRASH."""
    data, verify, password, want = job
    import vfa_extract as vxw
    vxw.set_logger(vxw.VLog("quiet"))
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        p = os.path.join(td, "f.vfa"); open(p, "wb").write(data)
        dest = os.path.join(td, "out")
        try:
            with vxw.open_container(p) as c:
                if verify and c.verify_digest() is False: raise vxw.VFAError("digest mismatch")
                c.unlock(password); c.extract(dest)
        except vxw.VFAError as e:
            return ("refused", str(e)[:80])
        except Exception:
            return ("CRASH", traceback.format_exc()[-600:])
        stray = [n for n in os.listdir(td) if n not in ("f.vfa", "out")]
        if stray: return ("ESCAPE", str(stray))
        if want is None: return ("accepted", "")           # structure fuzz: any self-consistent result is fine
        got = {}
        for root, _, files in os.walk(dest):
            for fn in files:
                fp = os.path.join(root, fn)
                got[os.path.relpath(fp, dest).replace("\\", "/")] = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        return ("identical", "") if got == want else ("WRONG", f"{sorted(set(got.items()) ^ set(want.items()))[:3]}")

def mutate(data: bytes, rnd: random.Random) -> Tuple:
    b = bytearray(data); n = len(b); k = rnd.randrange(8)
    if k == 0: i = rnd.randrange(n); b[i] ^= 1 << rnd.randrange(8); d = f"bitflip@{i}"
    elif k == 1: i = rnd.randrange(n); b[i] = rnd.randrange(256); d = f"byte@{i}"
    elif k == 2: i = rnd.randrange(n); L = rnd.randint(2, 32); b[i:i + L] = rnd.randbytes(min(L, n - i)); d = f"run@{i}+{L}"
    elif k == 3: L = rnd.randrange(1, n); b = b[:L]; d = f"truncate@{L}"
    elif k == 4: i = rnd.randrange(n); L = rnd.randint(1, 64); del b[i:i + L]; d = f"delete@{i}+{L}"
    elif k == 5: i = rnd.randrange(n); b[i:i] = rnd.randbytes(rnd.randint(1, 64)); d = f"insert@{i}"
    elif k == 6: b += rnd.randbytes(rnd.randint(1, 64)); d = "append"
    else:   # aim at the footer/TOC end where the structure lives
        i = max(0, n - rnd.randint(1, 120)); b[i] ^= 1 << rnd.randrange(8); d = f"tailflip@{i}"
    return bytes(b), d

FAILDIR = HERE / "fuzz_failures"

def run_jobs(jobs, labels):
    """Run fuzz jobs in a process pool; a job that takes > 60 s is a HANG (the pool is replaced)."""
    ctx = mp.get_context("spawn")
    res = []; pool = ctx.Pool(min(4, os.cpu_count() or 2))
    try:
        pend = [pool.apply_async(_fuzz_worker, (j,)) for j in jobs]
        for i, a in enumerate(pend):
            try: res.append(a.get(timeout=60))
            except mp.TimeoutError:
                res.append(("HANG", labels[i])); pool.terminate(); pool = ctx.Pool(min(4, os.cpu_count() or 2))
                pend[i + 1:] = [pool.apply_async(_fuzz_worker, (j,)) for j in jobs[i + 1:]]
    finally:
        pool.terminate()
    return res

def run_fuzz(targets, want, n_cases, quick, rnd):
    """targets: (name, path, password, verify_modes). Every prefix truncation + n_cases random mutations each."""
    for name, path, pw, modes in targets:
        data = pathlib.Path(path).read_bytes()
        for verify in modes:
            jobs, labels = [], []
            for L in range(0, len(data), 1 if not quick else 7):
                jobs.append((data[:L], verify, pw, want)); labels.append(f"truncate@{L}")
            for _ in range(n_cases):
                m, d = mutate(data, rnd); jobs.append((m, verify, pw, want)); labels.append(d)
            t0 = time.perf_counter(); res = run_jobs(jobs, labels); dt = time.perf_counter() - t0
            bad = [(labels[i], r) for i, r in enumerate(res) if r[0] in ("WRONG", "CRASH", "HANG", "ESCAPE")]
            counts = {k: sum(1 for r in res if r[0] == k) for k in ("refused", "identical", "WRONG", "CRASH", "HANG", "ESCAPE")}
            tag = f"fuzz {name}, {'digest+CRC' if verify else 'CRC only (--no-verify)'}"
            if bad:
                FAILDIR.mkdir(exist_ok=True)
                for lab, r in bad[:20]:
                    j = labels.index(lab); fn = FAILDIR / f"{pathlib.Path(path).stem}_{'v' if verify else 'nv'}_{j}.vfa"
                    fn.write_bytes(jobs[j][0]); print(f"      {r[0]} {lab}: {r[1][:300]}  -> {fn.name}")
            check(f"{tag}: {len(jobs)} cases in {dt:.0f}s {counts}", not bad)

def t_fuzz(work, n_cases, quick):
    import vfa as V
    rnd = random.Random(20261011)
    files = [("z/a.txt", b"alpha " * 300), ("z/b.bin", bytes(range(256)) * 9), ("z/empty", b""), ("z/c.txt", b"gamma\n" * 50)]
    want = {p: hashlib.sha256(d).hexdigest() for p, d in files}
    targets = [
        ("stored, non-solid (CRC is the only check)", raw_archive(work / "fz_none.vfa", files, method=vx.M_NONE), None, (True, False)),
        ("zstd, non-solid", raw_archive(work / "fz_zstd.vfa", files, method=vx.M_ZSTD), None, (True, False)),
        ("xz, solid", raw_archive(work / "fz_xz.vfa", files, method=vx.M_XZ, solid=True), None, (True, False)),
        ("lz4, solid", raw_archive(work / "fz_lz4.vfa", files, method=vx.M_LZ4, solid=True), None, (True, False)),
        ("VFA 1.0 layout (no CRCs), zlib", raw_archive(work / "fz_legacy.vfa", files, method=vx.M_ZLIB, tocx=False), None, (True,)),
    ]
    zc = work / "fz_src"; shutil.rmtree(zc, ignore_errors=True)
    for p, d in files: (zc / p).parent.mkdir(parents=True, exist_ok=True); (zc / p).write_bytes(d)
    encp = work / "fz_enc.vfa"
    vfa("c", encp, "z", "--method", "zstd", "--password-env", "PW", "--kdf-mem-kib", "1024", "--kdf-time", "1", "--kdf-parallel", "1",
        cwd=zc, env={"PW": "pw"})
    targets.append(("AES-GCM encrypted, zstd", encp, "pw", (True,)))

    run_fuzz(targets, want, n_cases, quick, rnd)

    # documented limitation, measured: VFA 1.0 archives without --verify have no per-block check
    data = pathlib.Path(targets[4][1]).read_bytes(); jobs = []
    for _ in range(n_cases):
        m, d = mutate(data, rnd); jobs.append((m, False, None, want))
    res = run_jobs(jobs, ["legacy"] * len(jobs)); faildir = HERE / "fuzz_failures"
    wrong = sum(1 for r in res if r[0] == "WRONG"); crash = sum(1 for r in res if r[0] in ("CRASH", "HANG"))
    for j, r in enumerate(res):
        if r[0] in ("CRASH", "HANG"):
            faildir.mkdir(exist_ok=True); fn = faildir / f"legacy_nv_{j}.vfa"; fn.write_bytes(jobs[j][0])
            print(f"      {r[0]}: {r[1][-400:]}  -> {fn.name}")
    check(f"fuzz VFA 1.0 layout with --no-verify: no crash/hang (silently wrong output in {wrong}/{len(jobs)} cases - "
          "expected: 1.0 archives rely on the digest, never skip it for them)", crash == 0)

# ---------------------------------------------------------------- the 4 GiB+ file

def peak_rss_of(p: subprocess.Popen) -> int:
    """Peak resident memory of a finished child, in bytes (0 if unknown)."""
    if os.name == "nt":
        import ctypes, ctypes.wintypes as w
        class PMC(ctypes.Structure):
            _fields_ = [("cb", w.DWORD), ("PageFaultCount", w.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
        if ctypes.windll.psapi.GetProcessMemoryInfo(w.HANDLE(int(p._handle)), ctypes.byref(pmc), pmc.cb):
            return pmc.PeakWorkingSetSize
        return 0
    import resource
    return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024   # max over all children so far

def run_peak(cmd, cwd=None, env=None):
    """Run cmd; return its own peak RSS in bytes (0 if unknown). Linux: GNU time (a child's ru_maxrss would include
    this harness's forked memory, and RUSAGE_CHILDREN is a max over all children). Windows: PeakWorkingSetSize."""
    if sys.platform.startswith("linux") and os.path.isfile("/usr/bin/time"):
        fd, rf = tempfile.mkstemp(); os.close(fd)
        try:
            subprocess.run(["/usr/bin/time", "-q", "-f", "%M", "-o", rf, *cmd], cwd=cwd, env=env)
            kb = pathlib.Path(rf).read_text().split()
            return int(kb[-1]) * 1024 if kb else 0
        finally: os.unlink(rf)
    p = subprocess.Popen(cmd, cwd=cwd, env=env); p.wait()
    return peak_rss_of(p)

def t_big(work, fmt="vfa1"):
    size = (4 << 30) + 123_457                          # > 4 GiB and not block-aligned
    src = work / "big"; shutil.rmtree(src, ignore_errors=True); src.mkdir()
    f = src / "huge.bin"; rnd = random.Random(99); h = hashlib.sha256()
    text = (b"The quick brown fox jumps over the lazy dog. " * 12000)[: 1 << 19]
    with open(f, "wb") as fw:                           # every MiB: 512 KiB random + 512 KiB text -> roughly 2:1
        left = size; i = 0
        while left:
            blk = (os.urandom(1 << 19) + struct.pack("<Q", i) + text[8:])[:left]
            fw.write(blk); h.update(blk); left -= len(blk); i += 1
    want = h.hexdigest()
    # measure the real interpreter, not the venv launcher (which would report its own few MiB)
    import site
    real_py = getattr(sys, "_base_executable", PY) or PY
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([*site.getsitepackages(), str(HERE)]))
    for flags in ([], ["--solid"]):
        arc = work / "big.vfa"
        codec = ["--method", "zstd", "--level", "3"] if fmt == "vfa1" else ["--format", "vfa2"]
        rss_c = run_peak([real_py, str(HERE / "vfa.py"), "c", str(arc), "big", *codec, *flags], cwd=work, env=env)
        out = work / "big_out"; shutil.rmtree(out, ignore_errors=True)
        rss_x = run_peak([real_py, str(HERE / "vfa.py"), "x", str(arc), "-o", str(out)], env=env)
        g = hashlib.sha256()
        with open(out / "big/huge.bin", "rb") as fr:
            for b in iter(lambda: fr.read(1 << 24), b""): g.update(b)
        check(f"{fmt} 4 GiB+ file round-trip ({'solid' if flags else 'non-solid'}); archive {arc.stat().st_size / 2**20:.0f} MiB, "
              f"peak RSS create {rss_c / 2**20:.0f} MiB / extract {rss_x / 2**20:.0f} MiB", g.hexdigest() == want)
        shutil.rmtree(out, ignore_errors=True); arc.unlink()
    shutil.rmtree(src, ignore_errors=True)

# ================================================================ VFA2 (VFA2.md)

def build2(path, files, *, dirs=("z",), records=(), index_mut=None, extra_entries=(), **kw):
    """Write a VFA2 archive with vfa2.Writer2; index_mut(raw_index) lets a test hand-edit the index while every
    CRC and the digest stay valid (so the parser itself is exercised, not just the checksums)."""
    import vfa2 as V2
    class W(V2.Writer2):
        def _index_bytes(self, records=()):
            raw = super()._index_bytes(records)
            return index_mut(raw) if index_mut else raw
    with open(path, "wb") as f:
        w = W(f, **kw)
        for d in dirs: w.add_dir(d, 0o755, 1_700_000_000)
        for p, d in files: w.add_file(p, 0o644, 1_700_000_000, d)
        for et, p in extra_entries: w._entry(et, p, 0o644, 1_700_000_000)
        w.close(records)
    return pathlib.Path(path)

def refoot2(b) -> bytes:
    """Recompute the digest and footer CRC after a test edited bytes before the footer."""
    import vfa2 as V2
    b = bytearray(b); fs = len(b) - V2.FOOTER_SIZE
    off, ilen, alen, kind, _ = V2.FOOT.unpack(bytes(b[fs:fs + V2.FOOT.size]))
    body = V2.FOOT.pack(off, ilen, alen, kind, hashlib.sha256(bytes(b[:fs])).digest())
    b[fs:fs + V2.FOOT.size + 4] = body + struct.pack("<I", V2.crc32(body))
    return bytes(b)

def patch_frame2(path, frame_off, byte_index, value):
    """Set one byte of a frame header (0-based within the 26-byte body), fix that frame's CRC and the footer."""
    import vfa2 as V2
    b = bytearray(pathlib.Path(path).read_bytes())
    b[frame_off + byte_index] = value
    b[frame_off + V2.FRAME.size:frame_off + V2.FRAME_SIZE] = struct.pack("<I", V2.crc32(bytes(b[frame_off:frame_off + V2.FRAME.size])))
    pathlib.Path(path).write_bytes(refoot2(b))

def t2_roundtrip(work, corpus):
    for flags in ([], ["--solid"], ["--chunk-exp", "12"], ["--solid", "--chunk-exp", "12"]):
        tag = " ".join(flags) or "non-solid, 64 MiB chunks"
        arc = work / f"v2rt_{len(flags)}_{'s' if '--solid' in flags else 'n'}.vfa"
        r = vfa("c", arc, corpus.name, "--format", "vfa2", *flags, cwd=corpus.parent)
        if not check(f"vfa2 create ({tag})", r.returncode == 0, r.stderr[-300:]): continue
        check(f"vfa2 test   ({tag})", vfa("t", arc).returncode == 0)
        ok, why = extract_cmp(arc, corpus, work); check(f"vfa2 bytes  ({tag})", ok, why)
        if "12" in flags:
            with vx.open_container(str(arc)) as c:
                c.unlock(None)
                multi = max(len(e["extents"]) for e in c.entries if e["entry_type"] == vx.ET_FILE)
                check(f"vfa2 files span several 4 KiB chunks ({tag}): max {multi} extents, {len(c.chunks)} chunks", multi > 1)
    dup = build2(work / "v2dup.vfa", [("z/a", b"same bytes " * 900), ("z/b", b"same bytes " * 900), ("z/c", b"other")])
    with vx.open_container(str(dup)) as c:
        c.unlock(None); out = work / "v2dup_out"; shutil.rmtree(out, ignore_errors=True); c.extract(str(out))
        check("vfa2 dedup: two identical files share one chunk, both extract", len(c.chunks) == 2 and
              (out / "z/a").read_bytes() == (out / "z/b").read_bytes() == b"same bytes " * 900)
    with vx.open_container(str(build2(work / "v2emp.vfa", [], dirs=()))) as c:
        c.unlock(None); check("vfa2 empty archive (no chunks, no entries) is valid", c.entries == [] and c.chunks == [])

def t2_sample(work):
    if not (HERE / "sample").is_dir(): skip("vfa2 sample\\ round-trips", "sample folder not found"); return
    stage = work / "sample_copy2"; shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(HERE / "sample", stage / "sample", ignore=shutil.ignore_patterns("__pycache__"))
    for flags in ([], ["--solid"], ["--method", "stored"], ["--solid", "--filter", "bcj-x86"]):
        arc = work / f"v2sample_{len(flags)}.vfa"
        vfa("c", arc, "sample", "--format", "vfa2", *flags, cwd=stage)
        ok, why = extract_cmp(arc, stage / "sample", work)
        check(f"vfa2 sample\\ round-trip ({' '.join(flags) or 'non-solid'}; {arc.stat().st_size:,} bytes)", ok, why)

def t2_encrypt(work, corpus):
    env = {"VFA_TEST_PW": "correct horse ☃"}; kdf = ["--kdf-mem-kib", "8192", "--kdf-time", "1", "--kdf-parallel", "1"]
    for solid in (False, True):
        arc = work / f"v2enc_{solid}.vfa"
        vfa("c", arc, corpus.name, "--format", "vfa2", "--password-env", "VFA_TEST_PW", *kdf, *(["--solid"] if solid else []), cwd=corpus.parent, env=env)
        ok, why = extract_cmp(arc, corpus, work, "--password-env", "VFA_TEST_PW", env=env)
        check(f"vfa2 encrypted round-trip ({'solid' if solid else 'non-solid'})", ok, why)
        out = work / "v2wrongpw"; shutil.rmtree(out, ignore_errors=True)
        r = vfa("x", arc, "-o", out, "--password-env", "VFA_TEST_PW", env={"VFA_TEST_PW": "wrong"}, expect=None)
        check(f"vfa2 wrong password -> exit 5, nothing written ({'solid' if solid else 'non-solid'})",
              r.returncode == 5 and not any(p.is_file() for p in out.rglob("*")), f"exit {r.returncode}")
    check("vfa2 encrypted list without password refuses", vfa("l", work / "v2enc_True.vfa", expect=None).returncode != 0)
    # the cleartext frame header (coder/filter ids, sizes) is bound into AES-GCM as associated data:
    # decrypting with any header byte changed must fail
    arc = build2(work / "v2enc_aad.vfa", [("z/a", b"x" * 5000)], password=b"pw", kdf=(1, 1024, 1))
    with vx.open_container(str(arc)) as c:
        c.unlock("pw"); import vfa2 as V2
        fh = c._read_frame_header(c.chunks[0][0], V2.CHUNK_MAGIC, "chunk 0")
        results = []
        for i in range(V2.FRAME.size):
            t = dict(fh); h = bytearray(fh["hdr"]); h[i] ^= 1; t["hdr"] = bytes(h)
            try: c._frame_payload(t, c.data_key); results.append(False)
            except vx.VFAError as e: results.append("Decryption failed" in str(e))
        check(f"vfa2 every frame-header byte is authenticated by AES-GCM ({sum(results)}/{len(results)})", all(results))

def t2_random_access(work):
    big = work / "ra_src"
    if not big.exists():
        (big / "d").mkdir(parents=True); rnd = random.Random(7)
        for i in range(24):
            (big / f"d/f{i:02d}.bin").write_bytes(rnd.randbytes(4 * 1024 * 1024))
            if i == 12: (big / "d/f12_needle.bin").write_bytes(b"NEEDLE-" + rnd.randbytes(5000))
    needle = (big / "d/f12_needle.bin").read_bytes()
    for flags in ([], ["--solid"]):
        arc = work / f"v2ra_{len(flags)}.vfa"
        vfa("c", arc, big.name, "--format", "vfa2", "--chunk-exp", "22", *flags, cwd=big.parent)
        with vx.open_container(str(arc)) as c:
            c.unlock(None); seen = set(); orig = c.chunk_data
            c.chunk_data = lambda i: (seen.add(i), orig(i))[1]
            out = work / "v2ra_out"; shutil.rmtree(out, ignore_errors=True)
            t0 = time.perf_counter(); c.extract(str(out), members=["ra_src/d/f12_needle.bin"]); dt = time.perf_counter() - t0
            tag = "solid" if flags else "non-solid"
            check(f"vfa2 random access ({tag}): member byte-identical", (out / "ra_src/d/f12_needle.bin").read_bytes() == needle)
            check(f"vfa2 random access ({tag}): decoded {len(seen)} of {len(c.chunks)} chunks in {dt*1000:.0f} ms",
                  len(seen) <= 2 and len(c.chunks) >= 20, str(seen))

def t2_refuse(work):
    import vfa2 as V2
    f = [("z/a.txt", b"payload " * 100)]
    def refused(name, path, needle, verify=True):
        try:
            open_extract(path, work / "refuse2_out", verify=verify); return check(name, False, "was accepted")
        except vx.VFAError as e:
            return check(name, needle.lower() in str(e).lower(), f"message: {e}")
        except Exception as e:
            return check(name, False, f"crashed: {e!r}")
    def accepted(name, path):
        try:
            out = work / ("acc_" + path.stem); shutil.rmtree(out, ignore_errors=True); open_extract(path, out)
            check(name, (out / "z/a.txt").read_bytes() == f[0][1])
        except Exception as e: check(name, False, repr(e))
    refused("vfa2 refuse: min_reader_version 2", build2(work / "r_minr.vfa", f, min_reader=2), "reader of version 2")
    refused("vfa2 refuse: unknown required feature bit", build2(work / "r_feat.vfa", f, required_extra=1 << 7), "requires features")
    accepted("vfa2 accept: longer header (future optional fields)", build2(work / "r_hx.vfa", f, header_extra=b"\x01" * 22))
    p = build2(work / "r_flag.vfa", f)
    with vx.open_container(str(p)) as c: c.unlock(None); off = c.chunks[0][0]
    patch_frame2(p, off, 6, 0x80)
    refused("vfa2 refuse: unknown frame flag", p, "frame flags")
    for table, cid, needle, label in ((V2.CODERS, 2, "vulp-cm", "coder 2"), (V2.FILTERS, 5, "text", "filter 5")):
        # the test coder must shrink its input, or the writer (correctly) stores the chunk with coder 0 instead
        enc = (lambda raw, level=0: (b"", bytes(raw)[:8])) if table is V2.CODERS else (lambda raw, params=b"": (b"", bytes(raw)))
        table[cid] = V2.Codec(cid, "test-only", enc, None)
        try: p = build2(work / f"r_c{cid}.vfa", f, **({"coder": cid} if table is V2.CODERS else {"filt": cid}))
        finally: del table[cid]
        refused(f"vfa2 refuse: unimplemented {label} is named ({needle})", p, needle)
    # what an M1 build (stored only) does with an M3 archive: names the coder/filter it lacks, writes nothing
    p = build2(work / "r_m3.vfa", [("z/a.txt", b"payload " * 100), ("z/b.bin", bytes(range(256)) * 64)], coder=1, filt=(1, b"\x01"))
    saved = (V2.CODERS.pop(1), dict(V2.RESERVED_CODERS)); V2.RESERVED_CODERS[1] = "vulp-tans (M3)"
    try: refused("vfa2 refuse: a reader without vulp-tans names it (simulated M1 reader)", p, "coder id 1 (vulp-tans")
    finally: V2.CODERS[1] = saved[0]; V2.RESERVED_CODERS.clear(); V2.RESERVED_CODERS.update(saved[1])
    saved = V2.FILTERS.pop(1)
    try: refused("vfa2 refuse: a reader without the delta filter names it", p, "filter id 1")
    finally: V2.FILTERS[1] = saved
    refused("vfa2 refuse: unknown critical index record", build2(work / "r_crit.vfa", f, records=[(77, V2.XR_CRITICAL, b"x")]), "record type 77")
    accepted("vfa2 accept: unknown optional index record", build2(work / "r_opt.vfa", f, records=[(78, 0, b"future")]))
    refused("vfa2 refuse: unknown entry type 9", build2(work / "r_et.vfa", f, extra_entries=[(9, "z/odd")]), "entry type 9")
    refused("vfa2 refuse: trailing bytes in the index", build2(work / "r_trail.vfa", f, index_mut=lambda r: r + b"junk"), "trailing")
    p = build2(work / "r_v1.vfa", f)
    try: vx.Container(str(p)); check("VFA1 reader names a VFA2 file as a different format", False, "accepted")
    except vx.VFAError as e: check("VFA1 reader names a VFA2 file as a different format", "different vfa format" in str(e).lower(), str(e))

def t2_paths(work):
    bad = ["../evil.txt", "/abs_evil.txt", "C:/drive_evil.txt", "a/../../evil2.txt"]
    if os.name == "nt": bad += ["CON", "nested/aux.txt", "file.txt:ads", "what?.txt"]
    for p in bad:
        arc = build2(work / "bad2.vfa", [("fine.txt", b"x"), (p, b"evil")], dirs=())
        dest = work / "jail2" / "inner"; shutil.rmtree(work / "jail2", ignore_errors=True); dest.mkdir(parents=True)
        try:
            open_extract(arc, dest); check(f"vfa2 path refused: {p!r}", False, "was extracted")
        except vx.VFAError:
            outside = [q for q in (work / "jail2").rglob("*") if q.is_file()]
            check(f"vfa2 path refused before writing anything: {p!r}", not outside, str(outside))
        except Exception as e:
            check(f"vfa2 path refused: {p!r}", False, f"crashed: {e!r}")

def t2_determinism(work, corpus):
    for flags in ([], ["--solid", "--chunk-exp", "16"]):
        a1, a2 = work / "d2a.vfa", work / "d2b.vfa"
        vfa("c", a1, corpus.name, "--format", "vfa2", *flags, cwd=corpus.parent); vfa("c", a2, corpus.name, "--format", "vfa2", *flags, cwd=corpus.parent)
        check(f"vfa2 determinism: same input -> identical archive ({' '.join(flags) or 'non-solid'})", a1.read_bytes() == a2.read_bytes())
    # the archive must not depend on the order the filesystem lists directory entries in (NTFS sorts, ext4 does not)
    import vfa as V
    real_walk = os.walk
    def listing(walk):
        os.walk = walk
        try: return [(str(p), et) for p, _st, et in V.iter_tree([str(corpus)])]
        finally: os.walk = real_walk
    def reversed_walk(top, *a, **k):
        for r, d, f in real_walk(top, *a, **k):
            d.reverse(); f.reverse(); yield r, d, f
    check("vfa2 determinism: file order does not depend on directory listing order",
          listing(real_walk) == listing(reversed_walk))
    # the -O0/-O3 and cross-compiler check is the 'native' group (t2_native)

def t2_sfx(work, corpus):
    arc = work / "v2sfx.vfa"; vfa("c", arc, corpus.name, "--format", "vfa2", "--solid", cwd=corpus.parent)
    exe = work / "v2fake_sfx.exe"; exe.write_bytes(b"MZ" + os.urandom(5000) + arc.read_bytes())
    out = work / "v2sfx_out"; shutil.rmtree(out, ignore_errors=True)
    r = subprocess.run([PY, str(HERE / "sfx_stub.py"), "--from-file", str(exe), "-o", str(out)], capture_output=True, text=True)
    check("vfa2 SFX stub extracts stub+archive", r.returncode == 0 and same_tree(corpus, out / corpus.name)[0], r.stderr[-300:])
    sfi = work / "v2sfi.exe"
    r = subprocess.run([PY, str(HERE / "pack_sfi.py"), "--stub", str(exe), "--archive", str(arc), "--name", "T", "-o", str(sfi)], capture_output=True, text=True)
    with vx.open_container(str(sfi)) as c:
        c.unlock(None)
        check("vfa2 SFI container: pack_sfi accepts VFA2, manifest found, archive reads",
              r.returncode == 0 and (c.manifest or {}).get("name") == "T" and c.verify_digest() is True, r.stderr[-300:])
    b = bytearray(exe.read_bytes()); b[len(b) // 2] ^= 0x10; exe.write_bytes(bytes(b))
    out2 = work / "v2sfx_out2"; shutil.rmtree(out2, ignore_errors=True)
    r = subprocess.run([PY, str(HERE / "sfx_stub.py"), "--from-file", str(exe), "-o", str(out2)], capture_output=True, text=True)
    check("vfa2 SFX stub refuses a corrupted file and writes nothing", r.returncode != 0 and (not out2.exists() or not any(out2.rglob("*"))))

def t_signed(work, corpus, fmt):
    """Authenticode layout: [PE stub][archive][pad to 8][WIN_CERTIFICATE], PE security directory -> certificate.
    (A structural simulation: no real signtool run; the PE checksum is not updated.)"""
    arc = work / f"sig_{fmt}.vfa"; vfa("c", arc, corpus.name, "--format", fmt, cwd=corpus.parent)
    pe = bytearray(pathlib.Path(sys._base_executable if hasattr(sys, "_base_executable") else sys.executable).read_bytes())
    if pe[:2] != b"MZ":                             # not Windows: the interpreter is ELF/Mach-O -> a minimal PE32+ stub
        pe = bytearray(0x40); pe[0:2] = b"MZ"; pe[0x3C:0x40] = struct.pack("<I", 0x40)
        opt_hdr = bytearray(240); opt_hdr[0:2] = struct.pack("<H", 0x20B); opt_hdr[108:112] = struct.pack("<I", 16)
        pe += b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, len(opt_hdr), 0x22) + opt_hdr
        pe += bytes(1024 - len(pe))
    e_lfanew, = struct.unpack("<I", pe[0x3C:0x40]); opt = e_lfanew + 24
    dd = opt + (96 if struct.unpack("<H", pe[opt:opt + 2])[0] == 0x10B else 112)
    so, sl = struct.unpack("<II", pe[dd + 32:dd + 40])
    if (so, sl) != (0, 0):                          # the interpreter is signed itself: strip that signature first
        if so + sl != len(pe): skip(f"{fmt} Authenticode layout", "cannot strip the test PE's own signature"); return
        pe = pe[:so]; pe[dd + 32:dd + 40] = bytes(8)
    body = bytes(pe) + arc.read_bytes()
    pad = (-len(body)) % 8; blob = os.urandom(1500)
    cert = struct.pack("<IHH", 8 + len(blob), 0x0200, 2) + blob
    pe[dd + 32:dd + 40] = struct.pack("<II", len(body) + pad, len(cert))
    signed = work / f"signed_{fmt}.exe"; signed.write_bytes(bytes(pe) + arc.read_bytes() + b"\0" * pad + cert)
    out = work / f"signed_out_{fmt}"; shutil.rmtree(out, ignore_errors=True)
    r = subprocess.run([PY, str(HERE / "sfx_stub.py"), "--from-file", str(signed), "-o", str(out)], capture_output=True, text=True)
    check(f"{fmt}: archive found and verified behind an Authenticode certificate table (pad {pad})",
          r.returncode == 0 and same_tree(corpus, out / corpus.name)[0], r.stderr[-300:])

def t2_fuzz(work, n_cases, quick):
    rnd = random.Random(20261012)
    files = [("z/a.txt", b"alpha " * 300), ("z/b.bin", bytes(range(256)) * 9), ("z/empty", b""), ("z/c.txt", b"gamma\n" * 50)]
    # tANS targets add a big filterable file, so the solid chunk is split into segments with different filters
    tfiles = files + [("z/ramp.bin", bytes((i * 7) & 0xFF for i in range(300_000)))]
    twant = {p: hashlib.sha256(d).hexdigest() for p, d in tfiles}
    want = {p: hashlib.sha256(d).hexdigest() for p, d in files}
    targets = [
        ("vfa2 non-solid", build2(work / "fz2_n.vfa", files), None, (True, False)),
        ("vfa2 solid, 4 KiB chunks", build2(work / "fz2_s.vfa", files, solid=True, chunk_size=4096), None, (True, False)),
        ("vfa2 encrypted", build2(work / "fz2_e.vfa", files, password=b"pw", kdf=(1, 1024, 1)), "pw", (True, False)),
    ]
    run_fuzz(targets, want, n_cases, quick, rnd)
    import vfa2 as V2
    seg = build2(work / "fz2_g.vfa", tfiles, coder=1, filt=None, solid=True)
    with vx.open_container(str(seg)) as c:
        c.unlock(None)
        check("fuzz target really uses the segmented filter + tANS", any(ch[3] == 1 and ch[4] == V2.SEGMENTED for ch in c.chunks), str(c.chunks))
    run_fuzz([("vfa2 tANS + auto filter", build2(work / "fz2_t.vfa", tfiles, coder=1, filt=None), None, (True, False)),
              ("vfa2 tANS, solid, segmented filter", seg, None, (True, False)),
              ("vfa2 tANS + bitshuffle:4", build2(work / "fz2_b.vfa", tfiles, coder=1, filt=(2, b"\x04\x01")), None, (True, False)),
              ("vfa2 vulp-lz + auto filter", build2(work / "fz2_l.vfa", tfiles, coder=3, filt=None), None, (True, False))],
             twant, n_cases, quick, rnd)
    # dedup: a second copy of the ramp makes the writer reference earlier segments instead of storing them
    dfiles = tfiles + [("z/ramp2.bin", tfiles[-1][1])]
    dd = build2(work / "fz2_d.vfa", dfiles, coder=3, filt=None, solid=True, chunk_size=1 << 17, cdc=True)
    with vx.open_container(str(dd)) as c:
        c.unlock(None); ents = {e["path"]: e for e in c.entries}
        inside = lambda x, y: x[0] == y[0] and y[1] <= x[1] and x[1] + x[2] <= y[1] + y[2]
        check("fuzz target really uses dedup (part of ramp2.bin points into ramp.bin's stored bytes)",
              any(inside(x, y) for x in ents["z/ramp2.bin"]["extents"] for y in ents["z/ramp.bin"]["extents"]),
              str(ents["z/ramp2.bin"]["extents"])[:200])
    run_fuzz([("vfa2 vulp-lz, solid, dedup", dd, None, (True, False))],
             {p: hashlib.sha256(d).hexdigest() for p, d in dfiles}, n_cases, quick, rnd)
    # the oracle must be able to fail: an intact archive judged against the wrong expectation must read as WRONG
    bogus = dict(want); bogus["z/a.txt"] = "0" * 64
    check("fuzz oracle self-test: a wrong expectation is reported as WRONG",
          _fuzz_worker((targets[0][1].read_bytes(), True, None, bogus))[0] == "WRONG")
    # structure fuzz: mutate the index, keep every CRC and the digest valid -> exercises the parser and the
    # cross-checks, not just the checksums. Oracle: refuse or extract, never crash/hang/escape.
    jobs, labels = [], []
    for k in range(n_cases):
        def mut(raw, k=k):
            b = bytearray(raw); m, d = mutate(bytes(b), rnd)
            labels.append("index:" + d); return m
        p = build2(work / "fz2_struct.vfa", files, index_mut=mut)
        jobs.append((p.read_bytes(), True, None, None))
    res = run_jobs(jobs, labels)
    bad = [(labels[i], r) for i, r in enumerate(res) if r[0] in ("WRONG", "CRASH", "HANG", "ESCAPE")]
    for lab, r in bad[:10]: print(f"      {r[0]} {lab}: {r[1][:400]}")
    counts = {k: sum(1 for r in res if r[0] == k) for k in ("refused", "accepted", "CRASH", "HANG", "ESCAPE")}
    check(f"vfa2 structure fuzz (index mutated, CRCs+digest recomputed): {len(jobs)} cases {counts}", not bad)

# ================================================================ VFA2 codec (M3): C core vs reference, native builds

FILTER_CONFIGS = [(0, b""), (1, b"\x01"), (1, b"\x02"), (1, b"\x04"), (1, b"\x20"), (2, b"\x02\x00"), (2, b"\x04\x00"),
                  (2, b"\x08\x00"), (2, b"\x10\x00"), (2, b"\x02\x01"), (2, b"\x04\x01"), (2, b"\x08\x01"), (2, b"\x10\x01"),
                  (3, b""), (4, b"")]

def codec_cases(corpus):
    rnd = random.Random(31337); B = 1 << 17
    cases = {"empty": b"", "1 byte": b"\x00", "2 symbols": b"ab" * 3, "single symbol x B+1": b"z" * (B + 1),
             "all 256 values": bytes(range(256)) * 3, "random 5000": rnd.randbytes(5000), "block B-1": rnd.randbytes(B - 1),
             "skewed B+7": bytes(rnd.choice(b"aaaaaaab\x00\xff") for _ in range(B + 7)),
             "3 symbols 2B": bytes(rnd.randrange(3) for _ in range(2 * B)),
             "x86 calls": b"".join(b"\x55\xe8" + struct.pack("<i", rnd.randrange(-5000, 5000)) + b"\x90" for _ in range(3000)),
             "arm64 BL": b"".join(struct.pack("<I", 0x94000000 | rnd.randrange(1 << 26)) for _ in range(3000)),
             "int32 series": b"".join(struct.pack("<i", 1000 + i * 3 + rnd.randrange(4)) for i in range(9000))}
    for f in sorted(corpus.rglob("*")):
        if f.is_file(): cases[f"corpus/{f.name} (64 KiB)"] = f.read_bytes()[:1 << 16]
    return cases

def t2_codec(work, corpus):
    import vfa2 as V2, vulp_ref as R
    try:
        import _vulp as C
    except ImportError:
        check("vfa2 codec: the _vulp C extension is built (python build_vulp.py)", False, "not importable"); return
    check(f"vfa2 codec: vfa2 uses the C extension (NATIVE={V2.NATIVE})", V2.NATIVE)
    mism = []; n = 0
    for name, d in codec_cases(corpus).items():
        for fid, p in FILTER_CONFIGS:
            fc = C.filter_fwd(fid, p, d); n += 1
            if fc != R.filter_fwd(fid, p, d): mism.append(f"filter {fid}/{p.hex()} fwd on {name}")
            if C.filter_inv(fid, p, fc) != d or R.filter_inv(fid, p, fc) != d: mism.append(f"filter {fid}/{p.hex()} inverse on {name}")
            if C.cost(fc) != R.cost(fc): mism.append(f"cost on {name}")
        ec = C.tans_encode(d); n += 1
        if ec != R.tans_encode(d): mism.append(f"tans_encode on {name}")
        if C.tans_decode(ec, len(d)) != d or R.tans_decode(ec, len(d)) != d: mism.append(f"tans_decode on {name}")
    check(f"vfa2 codec: C == pure-Python reference, bit for bit ({n} encode/filter runs, every filter config)", not mism, str(mism[:5]))
    # adversarial: short strings dense in opcode/marker bytes, where overlapping candidates interact (this caught a
    # non-bijective BCJ-x86 rule that both implementations shared: corpus data alone did not)
    rnd = random.Random(808); bad = []
    for k in range(4000):
        x = bytes(rnd.choice(b"\xe8\xe9\x00\xff\x94\x97\x01\x34") for _ in range(rnd.randrange(1, 48)))
        for fid, p in ((3, b""), (4, b""), (1, b"\x01"), (2, b"\x02\x01"), (2, b"\x04\x00")):
            fc = C.filter_fwd(fid, p, x)
            if fc != R.filter_fwd(fid, p, x) or C.filter_inv(fid, p, fc) != x or R.filter_inv(fid, p, fc) != x: bad.append((fid, x.hex()))
    check("vfa2 codec: filters are bijective on 4000 adversarial marker-dense strings (C and reference)", not bad, str(bad[:3]))
    lg = [R.log2_q16(x) for x in (1, 2, 3, 1000, 65536, 2**32 - 1)]
    check("vfa2 codec: integer log2 (Q16) sane: log2(2)=1.0, log2(65536)=16.0, monotonic",
          lg[0] == 0 and lg[1] == 65536 and lg[4] == 16 << 16 and lg == sorted(lg))
    bad = []
    for fid, p in ((0, b"\x00"), (1, b""), (1, b"\x00"), (1, b"\x21"), (2, b"\x03\x00"), (2, b"\x04\x02"), (3, b"\x00"), (5, b""), (6, b""), (-1, b"")):
        for impl in (C, R):
            try: impl.filter_fwd(fid, p, b"abc"); bad.append((impl.__name__, fid, p))
            except ValueError: pass
            try: impl.filter_inv(fid, p, b"abc"); bad.append((impl.__name__, fid, p))
            except ValueError: pass
    check("vfa2 codec: malformed filter ids/params are refused by both implementations", not bad, str(bad))
    # corrupt tANS payloads: both decoders raise ValueError or return bytes; never anything else
    rnd = random.Random(99); src = codec_cases(corpus)["skewed B+7"][:40000] + b"tail" * 3000
    enc = C.tans_encode(src); stats = {"refused": 0, "identical": 0, "different": 0}; crash = []
    for k in range(3000):
        m, _ = mutate(enc, rnd); size = len(src) if k % 5 else rnd.randrange(len(src) + 2)
        for impl in ((C,) if k % 20 else (C, R)):
            try: out = impl.tans_decode(m, size); stats["identical" if out == src else "different"] += 1
            except ValueError: stats["refused"] += 1
            except Exception as e: crash.append(f"{impl.__name__}: {e!r}")
    check(f"vfa2 codec: corrupted tANS payloads never crash either decoder {stats} "
          "('different' output is caught by the chunk CRC32)", not crash, str(crash[:3]))
    agree = []
    for k in range(400):
        m, _ = mutate(enc, rnd)
        res = []
        for impl in (C, R):
            try: res.append(impl.tans_decode(m, len(src)))
            except ValueError: res.append("refused")
        if res[0] != res[1]: agree.append(k)
    check("vfa2 codec: C and reference decoders agree on every corrupted payload (accept/refuse and bytes)", not agree, str(agree[:5]))
    # segmented filter: strict parameters
    segbad = [b"", struct.pack("<I", 0), struct.pack("<I", 1) + V2.SEG.pack(0, 0, 0), struct.pack("<I", 1) + V2.SEG.pack(3, 6, 0),
              struct.pack("<I", 1) + V2.SEG.pack(3, 9, 0), struct.pack("<I", 1) + V2.SEG.pack(2, 0, 0),
              struct.pack("<I", 1) + V2.SEG.pack(3, 0, 0) + b"x", struct.pack("<I", 2) + V2.SEG.pack(3, 0, 0),
              struct.pack("<I", 1) + V2.SEG.pack(3, 1, 1), struct.pack("<I", 0xFFFFFFFF)]
    acc = []
    for prm in segbad:
        try: V2.FILTERS[V2.SEGMENTED].decode(prm, b"abc", 3); acc.append(prm.hex())
        except vx.VFAError: pass
    check("vfa2 codec: malformed segmented-filter parameters are refused", not acc, str(acc))
    # every filter, forced, through the real CLI (non-solid and solid)
    for spec in ("none", "delta:2", "shuffle:4", "bitshuffle:8", "bcj-x86", "bcj-arm64"):
        for solid in ([], ["--solid"]):
            arc = work / f"v2f_{spec.replace(':', '_')}_{len(solid)}.vfa"
            r = vfa("c", arc, corpus.name, "--format", "vfa2", "--filter", spec, *solid, cwd=corpus.parent)
            ok, why = extract_cmp(arc, corpus, work) if r.returncode == 0 else (False, r.stderr[-300:])
            check(f"vfa2 --filter {spec}{' --solid' if solid else ''}: round-trip", ok, why)
    # auto routing really chooses filters, records why, and the segmented filter appears in a mixed solid chunk
    mixed = work / "mixed"; shutil.rmtree(mixed, ignore_errors=True); (mixed / "m").mkdir(parents=True)
    (mixed / "m/ramp.bin").write_bytes(bytes((i * 3) & 0xFF for i in range(1 << 20)))
    (mixed / "m/noise.bin").write_bytes(random.Random(4).randbytes(1 << 20))
    (mixed / "m/ints.bin").write_bytes(b"".join(struct.pack("<I", 7 * i) for i in range(1 << 18)))
    arc = work / "v2mixed.vfa"; vfa("c", arc, "m", "--format", "vfa2", "--solid", cwd=mixed)
    ok, why = extract_cmp(arc, mixed / "m", work)
    with vx.open_container(str(arc)) as c:
        c.unlock(None); rt = c.routing()
        segs = rt[0].get("segments", []) if rt else []
        check(f"vfa2 auto routing: mixed solid chunk -> {rt[0]['filter'] if rt else '?'} "
              f"[{', '.join(sg['filter'] for sg in segs)}], round-trip", ok and len(segs) >= 2 and all(sg.get("why") for sg in segs), why)
    # a malformed (but checksummed) ROUTING record is ignored, never a crash: it is debug information only
    for i, bad in enumerate((b'{"chunks":1}', b'[1,2]', b'{"chunks":[1,"x",{"chunk":"0","filter":7,"stored":[1]}]}', b'{"chunks":[{"chunk":[]},{"chunk":{}},{"chunk":true}]}', b"\xff\xfe", b"null")):
        p = build2(work / f"v2badrt{i}.vfa", [("z/a.txt", b"routing " * 500)], records=[(V2.XR_ROUTING, 0, bad)])
        r = vfa("l", p, "--routing", expect=None)
        check(f"vfa2 malformed ROUTING record {bad[:40]!r} is ignored by 'vfa l --routing'", r.returncode == 0 and "Traceback" not in r.stderr, r.stderr[-300:])
    r = vfa("l", arc, "--routing")
    check("vfa2 'vfa l --routing' prints each chunk's filter and reason", r.returncode == 0 and "segments with different filters" in r.stdout, r.stdout[-300:])
    # incompressible data: tANS output would be larger -> stored, and the reason says so
    arc = work / "v2rand.vfa"; vfa("c", arc, "m/noise.bin", "--format", "vfa2", cwd=mixed)
    with vx.open_container(str(arc)) as c:
        c.unlock(None); rt = c.routing()
        check("vfa2 incompressible chunk falls back to 'stored', and the routing record says why",
              c.chunks[0][3] == 0 and rt and "stored instead" in rt[0]["why"], str(rt)[:300])
    # the pure-Python reference decoder reads what the C encoder wrote (the stub's fallback path)
    arc = build2(work / "v2ref.vfa", [("z/a.bin", codec_cases(corpus)["int32 series"]), ("z/b.txt", b"hello tans " * 900)], coder=1, filt=None, solid=True)
    saved = V2._native; V2._native = R
    try:
        out = work / "v2ref_out"; shutil.rmtree(out, ignore_errors=True); open_extract(arc, out)
        check("vfa2 pure-Python reference decoder extracts a C-encoded archive",
              (out / "z/b.txt").read_bytes() == b"hello tans " * 900 and (out / "z/a.bin").read_bytes() == codec_cases(corpus)["int32 series"])
    finally: V2._native = saved

# ---- native builds

NATIVE_SRC = ["vulp/vulp.c", "vulp/vulp_lz.c", "vulp/vulpcli.c"]
FP_TYPES = re.compile(r"\b(float|double|_Float\d+|__fp16|_Complex|fenv_t)\b|#\s*include\s*<(math|fenv|tgmath|complex)\.h>|\b(fabs|sqrt|pow|exp|log|log2|floor|ceil|round)\s*\(")
# x86 floating-point arithmetic/conversion (SSE/AVX scalar+packed, x87). Plain moves/bitwise (movaps, pxor) are integer-safe.
FP_INSN = re.compile(r"\b(v?(add|sub|mul|div|sqrt|min|max|rcp|rsqrt|round|cmp|comi|ucomi|h?addsub|hadd|hsub|dp)(ss|sd|ps|pd)|"
                     r"v?cvt\w+|vfn?m(add|sub)\w+|f(ld|st|stp|add|addp|sub|subp|subr|mul|mulp|div|divp|divr|ild|ist|istp|isttp|"
                     r"com|comp|ucom|ucomi|comi|sqrt|abs|chs|xch|init|ninit|ldz|ld1|rndint|scale|prem|sin|cos|patan|yl2x)\w*)\b")

def strip_c_comments(src: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", " ", src, flags=re.S)

def compilers():
    """[(label, argv-builder)] for every C compiler available here. MSVC needs a developer environment (vcvars64)."""
    out = []
    if os.name == "nt":
        try:
            import build_vulp; env = build_vulp.msvc_env()      # a working toolchain only (see msvc_env)
            cl = build_vulp.msvc_tool(env, "cl") if env else None
        except Exception: env = cl = None
        if env and cl:
            def msvc(srcs, exe, opt, env):
                objdir = pathlib.Path(str(exe) + "_obj"); objdir.mkdir(parents=True, exist_ok=True)
                if str(exe).endswith(".o"):           # object only (for the instruction scan)
                    return [cl, "/nologo", opt, "/W4", "/c", f"/Fo{exe}", *srcs], env
                return [cl, "/nologo", opt, "/W4", f"/Fe{exe}", f"/Fo{objdir}\\", *srcs], env
            for opt in ("/Od", "/O2"):
                out.append((f"msvc {opt}", lambda srcs, exe, opt=opt, env=env: msvc(srcs, exe, opt, env)))
    seen = set()
    for cc in ("gcc", "clang", "cc"):                  # 'cc' only if it is not one of the others
        path = shutil.which(cc)
        if not path or os.path.realpath(path) in seen: continue
        seen.add(os.path.realpath(path))
        for opt in ("-O0", "-O3", "-O3 -march=native -ffast-math"):
            def gnu(srcs, exe, cc=cc, opt=opt):
                if str(exe).endswith(".o"): return [cc, "-std=c99", *opt.split(), "-c", "-o", str(exe), *srcs], None
                return [cc, "-std=c99", *opt.split(), "-o", str(exe), *srcs], None
            out.append((f"{cc} {opt}", gnu))
    return out

def t2_native(work, corpus):
    srcs = [str(HERE / s) for s in NATIVE_SRC]
    # 1. source lint: no floating-point types or math in the codec (C) ...
    hits = []
    for f in ["vulp/vulp.c", "vulp/vulp_lz.c", "vulp/vulp.h", "vulp/vulpcli.c", "vulp/vulpmodule.c"]:
        for ln, line in enumerate(strip_c_comments((HERE / f).read_text()).splitlines(), 1):
            if FP_TYPES.search(line): hits.append(f"{f}:{ln}: {line.strip()}")
    check("native: no float/double/<math.h> in the C codec sources", not hits, str(hits[:5]))
    # the instruction scan must not count bitwise/move SSE ops (compilers zero registers with xorps etc.)
    check("native: FP-instruction scan ignores bitwise SSE ops (xorps, vxorps, andps, andnps, orps, blendvps, movaps)",
          not any(FP_INSN.search(f"\t{i} %xmm0,%xmm0") for i in ("xorps", "vxorps", "andps", "andnps", "orps", "vorpd", "blendvps", "movaps", "pxor")))
    # ... and none in the Python compress/decompress path (AST: no float literals, no true division, no float()/math)
    import ast
    targets = {"vulp_ref.py": None, "vfa2.py": {"classify", "route", "units", "_sample", "_hint", "seg_pack", "seg_unpack",
                                                "_seg_apply", "_tans_encode", "_tans_decode", "_filter_codec", "_stored_encode",
                                                "_stored_decode", "_flush", "chunk_data", "filter_label", "parse_filter",
                                                "_lz_encode", "_lz_decode", "_code_hints", "_segment", "_reference",
                                                "_append", "add_file"}}
    hits = []
    for fname, funcs in targets.items():
        tree = ast.parse((HERE / fname).read_text())
        nodes = []
        if funcs is None: nodes = [tree]
        else:
            found = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            missing = funcs - set(found)
            if missing: hits.append(f"{fname}: lint target functions not found: {sorted(missing)}")
            nodes = [found[k] for k in funcs if k in found]
        for root in nodes:
            for n in ast.walk(root):
                if isinstance(n, ast.Constant) and isinstance(n.value, float): hits.append(f"{fname}:{n.lineno} float literal")
                if isinstance(n, (ast.BinOp, ast.AugAssign)) and isinstance(n.op, ast.Div): hits.append(f"{fname}:{n.lineno} true division '/'")
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("float", "round", "pow"): hits.append(f"{fname}:{n.lineno} {n.func.id}()")
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "math": hits.append(f"{fname}:{n.lineno} math.{n.attr}")
    check("native: no floating point in the Python codec path (vulp_ref.py, vfa2 classifier/coder glue; AST-checked)", not hits, str(hits[:5]))
    # 2. build the standalone codec with every compiler at -O0 and -O3; all must print identical digests
    comps = compilers(); builds = []
    for label, mk in comps:
        exe = work / ("vulpcli_" + re.sub(r"\W+", "_", label) + (".exe" if os.name == "nt" else ""))
        argv, env = mk(srcs, exe)
        r = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=work)
        if r.returncode == 0 and exe.exists(): builds.append((label, exe, env))
        else: print(f"      build failed: {label}: {(r.stdout + r.stderr)[-300:]}")
    # inputs get plain ASCII names: vulpcli uses fopen(), which on Windows cannot open non-ASCII paths
    inputs = []; ind = work / "native_in"; ind.mkdir(parents=True, exist_ok=True)
    def add_input(data):
        dst = ind / f"in{len(inputs):03d}.bin"; dst.write_bytes(data); inputs.append(dst)
    for f in sorted(p for p in corpus.rglob("*") if p.is_file()):
        add_input(f.read_bytes()[:1 << 20])
    smp = HERE / "sample"
    if smp.is_dir():
        for f in sorted(p for p in smp.rglob("*") if p.is_file()):
            data = f.read_bytes(); add_input(data[:1 << 20] + data[len(data) // 2:len(data) // 2 + (1 << 20)])
    outs = {}
    for label, exe, env in builds:
        r = subprocess.run([str(exe), "digest", *map(str, inputs)], capture_output=True, text=True, env=env)
        outs[label] = (r.returncode, r.stdout)
        if r.returncode: print(f"      {label}: exit {r.returncode} {r.stdout[-300:]}{r.stderr[-300:]}")
    if len(builds) < 2:
        skip("native: identical output across compilers and -O0/-O3", f"only {len(builds)} working build(s): {[b[0] for b in builds]}")
    else:
        ref = next(iter(outs.values()))
        same = all(v == ref for v in outs.values()) and ref[0] == 0
        check(f"native: {len(builds)} builds ({', '.join(outs)}) give identical tANS/filter/cost output on {len(inputs)} inputs, all round-trip",
              same, str({k: v[1][:120] for k, v in outs.items()}))
        # and the Python extension (built by setuptools with its own flags) agrees with the standalone builds
        try:
            import _vulp as C, zlib
            lines = []
            for f in inputs:
                d = f.read_bytes(); h = 0; tl = 0
                for i, (fid, p) in enumerate([(0, b""), (1, b"\x01"), (1, b"\x02"), (1, b"\x04"), (2, b"\x02\x00"), (2, b"\x04\x00"), (2, b"\x08\x00"),
                                              (2, b"\x04\x01"), (2, b"\x08\x01"), (2, b"\x10\x01"), (3, b""), (4, b"")]):
                    fl = C.filter_fwd(fid, p, d); e = C.tans_encode(fl)
                    if i == 0: tl = len(e)
                    h = zlib.crc32(struct.pack("<Q", C.cost(fl)), h); h = zlib.crc32(fl, h); h = zlib.crc32(e, h)
                lz = C.lz_encode(d, 6)                 # None: did not fit in len+4096 -> the CLI uses the full bound
                if lz is None: lz = b""
                h = zlib.crc32(lz, h)
                cuts = C.cdc(d, 2048, 13, 65536)
                h = zlib.crc32(b"".join(struct.pack("<Q", c) for c in cuts), h)
                lines.append(f"size={len(d)} tans={tl} lz={len(lz)} cdc={len(cuts)} digest={h:08x}")
            check("native: the _vulp extension (as bundled into the stubs) matches the standalone builds", "\n".join(lines) + "\n" == ref[1],
                  f"{lines[:2]} vs {ref[1].splitlines()[:2]}")
        except ImportError:
            check("native: the _vulp extension is built", False, "not importable")
    # 3. no floating-point instructions in the compiled codec (objdump / dumpbin)
    objs = []
    for label, mk in comps:
        if "O0" in label or "Od" in label: continue
        for src in ("vulp/vulp.c", "vulp/vulp_lz.c"):
            obj = work / ("obj_" + re.sub(r"\W+", "_", label + "_" + src) + ".o")
            argv, env = mk([str(HERE / src)], obj)
            r = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=work)
            if r.returncode == 0: objs.append((label, obj, env, src))
            else: check(f"native: {src} compiles with {label}", False, (r.stdout + r.stderr)[-300:])
    scanned = 0
    for label, obj, env, src in objs:
        if label.startswith("msvc"):
            import build_vulp; db = build_vulp.msvc_tool(env, "dumpbin")
            if not db: continue
            cmd = [db, "/disasm", str(obj)]
        elif shutil.which("objdump"): cmd = ["objdump", "-d", "--no-show-raw-insn", str(obj)]
        else: continue
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if r.returncode != 0 or len(r.stdout) < 1000: continue
        found = sorted({m.group(0) for line in r.stdout.splitlines() if "\t" in line or label.startswith("msvc")
                        for m in [FP_INSN.search(line.split("\t", 2)[-1] if "\t" in line else line)] if m})
        scanned += 1
        check(f"native: no floating-point instructions in {src} compiled by {label}", not found, str(found[:10]))
    if not scanned: skip("native: floating-point instruction scan", "no disassembler (objdump / dumpbin) found")
    elif objs:
        # oracle self-test: the same scan must flag a function that really uses floating point
        label, _, env, _src = objs[0]; probe = work / "fp_probe.c"; pobj = work / "fp_probe.o"
        probe.write_text("double vfa_probe(double a, int b) { return a * 1.5 + (double)b; }\n")
        mk = dict(comps)[label]; argv, env = mk([str(probe)], pobj)
        subprocess.run(argv, capture_output=True, env=env, cwd=work)
        if label.startswith("msvc"):
            import build_vulp; cmd = [build_vulp.msvc_tool(env, "dumpbin") or "dumpbin", "/disasm", str(pobj)]
        else: cmd = ["objdump", "-d", "--no-show-raw-insn", str(pobj)]
        out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout if pobj.exists() else ""
        found = {m.group(0) for line in out.splitlines() for m in [FP_INSN.search(line.split("\t", 2)[-1] if "\t" in line else line)] if m}
        check(f"native: FP-instruction scan self-test flags real floating point ({label}: {sorted(found)[:4]})", bool(found))
        check("native: source lint self-test flags 'double' / <math.h>", bool(FP_TYPES.search("static double x;")) and
              bool(FP_TYPES.search("#include <math.h>")) and not FP_TYPES.search("uint32_t doubled_count;"))
    # 4. sanitizer build (gcc/clang -fsanitize=address,undefined): encoder digest + decoder fuzz must be clean
    san = None
    if os.name != "nt":
        for cc in ("gcc", "clang"):
            if not shutil.which(cc): continue
            exe = work / f"vulpcli_san_{cc}"
            r = subprocess.run([cc, "-std=c99", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                                "-fno-omit-frame-pointer", "-o", str(exe), *srcs], capture_output=True, text=True)
            if r.returncode == 0 and subprocess.run([str(exe)], capture_output=True).returncode == 2: san = (cc, exe); break
    if not san:
        skip("native: ASan+UBSan fuzz of the C decoder", "no compiler with working sanitizer runtimes (Windows: run on Linux/WSL)")
    else:
        cc, exe = san; logs = []
        r = subprocess.run([str(exe), "digest", *map(str, inputs[:12])], capture_output=True, text=True); logs.append(r)
        for i, f in enumerate([x for x in inputs if x.stat().st_size > 1000][:6]):
            logs.append(subprocess.run([str(exe), "fuzz", str(f), "4000", str(i + 1)], capture_output=True, text=True))
        ok = all(l.returncode == 0 and "runtime error" not in l.stderr and "Sanitizer" not in l.stderr for l in logs)
        summary = "; ".join(l.stdout.strip().split(": ", 1)[-1] for l in logs[1:3])
        check(f"native: {cc} ASan+UBSan build: encoder on {min(12, len(inputs))} inputs + {4000 * (len(logs) - 1)} corrupted "
              f"decodes, no sanitizer report ({summary} ...)", ok, "".join(l.stderr[-600:] for l in logs if l.returncode or l.stderr))


# ================================================================ VFA2 M4: vulp-lz + cross-chunk dedup

def t2_lz(work, corpus):
    import vfa2 as V2, vulp_ref as R
    try:
        import _vulp as C
    except ImportError:
        check("vfa2 lz: the _vulp C extension is built", False, "not importable"); return
    cases = codec_cases(corpus); rnd = random.Random(4242)
    a = rnd.randbytes(5 << 20)
    cases["long-range: 5 MiB, 1 MiB other, same 5 MiB again"] = a + rnd.randbytes(1 << 20) + a
    cases["3 MiB of zeros (one huge match)"] = bytes(3 << 20)
    mism = []; n = 0; ratios = {}
    for name, d in cases.items():
        for lvl in (0, 6, 9):
            e = C.lz_encode(d, lvl)
            if e is None: continue
            n += 1
            if C.lz_decode(e, len(d)) != d: mism.append(f"C decode L{lvl} {name}")
            if len(d) <= 300_000 and R.lz_decode(e, len(d)) != d: mism.append(f"reference decode L{lvl} {name}")
            if lvl == 6: ratios[name] = len(e) / max(1, len(d))
    check(f"vfa2 lz: {n} encodings decode byte-identically (C), and with the pure-Python reference where small", not mism, str(mism[:5]))
    lr = ratios.get("long-range: 5 MiB, 1 MiB other, same 5 MiB again", 9)      # 6 of 11 MiB are unique random bytes
    check(f"vfa2 lz: long-range match across a 1 MiB gap found (ratio {lr:.4f}; optimum 6/11 = 0.5455)", lr < 6 / 11 + 0.002)
    check(f"vfa2 lz: 3 MiB of zeros -> {ratios.get('3 MiB of zeros (one huge match)', 9) * 3145728:.0f} bytes",
          ratios.get("3 MiB of zeros (one huge match)", 9) * 3145728 < 200)
    check("vfa2 lz: empty input encodes to an empty payload that decodes", C.lz_encode(b"", 6) == b"" and C.lz_decode(b"", 0) == b""
          and R.lz_decode(b"", 0) == b"")
    cd = [(nm, d[:120_000]) for nm, d in list(cases.items())[:10]]
    check("vfa2 lz: content-defined cut points, C == reference", all(C.cdc(d, 512, 11, 8192) == R.cdc(d, 512, 11, 8192) for _, d in cd))
    # corrupted vulp-lz payloads: no crash in either decoder, and both agree
    src = cases["corpus/data.csv (64 KiB)"] if "corpus/data.csv (64 KiB)" in cases else cases["random 5000"]
    enc = C.lz_encode(src, 6); stats = {"refused": 0, "identical": 0, "different": 0}; crash = []; disagree = []
    for k in range(3000):
        m, _ = mutate(enc, rnd); size = len(src) if k % 5 else rnd.randrange(len(src) + 2)
        res = []
        for impl in ((C,) if k % 10 else (C, R)):
            try: out = impl.lz_decode(m, size); res.append(out); stats["identical" if out == src else "different"] += 1
            except ValueError: res.append("refused"); stats["refused"] += 1
            except Exception as e: crash.append(f"{impl.__name__}: {e!r}")
        if len(res) == 2 and res[0] != res[1]: disagree.append(k)
    check(f"vfa2 lz: corrupted payloads never crash either decoder {stats}", not crash, str(crash[:3]))
    check("vfa2 lz: C and reference decoders agree on corrupted payloads (accept/refuse and bytes)", not disagree, str(disagree[:5]))
    # a stale extension left over from an older build (API 1: no vulp-lz): refused cleanly, never half-used.
    # vfa.py's own folder (with the real module) comes first on sys.path, so run it through a launcher that puts
    # the stale module in front.
    stale = work / "stale_ext"; stale.mkdir(exist_ok=True)
    (stale / "_vulp.py").write_text("VERSION = 1\nfrom vulp_ref import tans_encode, tans_decode, filter_fwd, filter_inv, cost\n")
    (stale / "launch.py").write_text("import sys, runpy\nsys.path[:0] = [%r, %r]\nsys.argv = sys.argv[1:]\n"
                                     "runpy.run_path(sys.argv[0], run_name='__main__')\n" % (str(stale), str(HERE)))
    def stale_vfa(*argv, cwd=None):
        return subprocess.run([PY, str(stale / "launch.py"), str(HERE / "vfa.py"), *map(str, argv)], capture_output=True, text=True, cwd=cwd)
    src = work / "stale_src"; (src / "z").mkdir(parents=True, exist_ok=True); (src / "z/a.txt").write_bytes(b"stale extension " * 400)
    r = stale_vfa("c", work / "stale_new.vfa", "z", "--format", "vfa2", cwd=src)
    check("vfa2: a stale _vulp extension (API 1) makes 'vfa c' say it is out of date, not crash",
          r.returncode != 0 and "out of date" in (r.stdout + r.stderr) and "Traceback" not in r.stderr, (r.stdout + r.stderr)[-300:])
    lzarc = build2(work / "stale_lz.vfa", [("z/a.txt", b"stale extension " * 400)], coder=3, filt=(0, b""))
    out = work / "stale_out"; shutil.rmtree(out, ignore_errors=True)
    r = stale_vfa("x", lzarc, "-o", out)
    check("vfa2: with a stale extension, vulp-lz archives still extract (pure-Python fallback, with a warning)",
          r.returncode == 0 and (out / "z/a.txt").read_bytes() == b"stale extension " * 400 and "out of date" in r.stdout + r.stderr,
          (r.stdout + r.stderr)[-300:])
    # an older reader (M3: no vulp-lz) names what it lacks
    p = build2(work / "r_lz.vfa", [("z/a.txt", b"vulp-lz " * 2000)], coder=3, filt=(0, b""))
    saved = (V2.CODERS.pop(3), dict(V2.RESERVED_CODERS)); V2.RESERVED_CODERS[3] = "vulp-lz (M4)"
    try:
        try: open_extract(p, work / "r_lz_out"); check("vfa2 refuse: a reader without vulp-lz names it", False, "accepted")
        except vx.VFAError as e: check("vfa2 refuse: a reader without vulp-lz names it (simulated M3 reader)", "coder id 3 (vulp-lz" in str(e), str(e))
    finally:
        V2.CODERS[3] = saved[0]; V2.RESERVED_CODERS.clear(); V2.RESERVED_CODERS.update(saved[1])

def t2_dedup(work, corpus):
    import vfa2 as V2
    if not V2.NATIVE: skip("vfa2 dedup", "needs the _vulp extension"); return
    rnd = random.Random(77)
    base = rnd.randbytes(3 << 20)
    shifted = b"a different header " * 50 + base[:1 << 20] + rnd.randbytes(70_000) + base[1 << 20:]   # inserts move offsets
    d = work / "dd"; shutil.rmtree(d, ignore_errors=True); (d / "s").mkdir(parents=True)
    (d / "s/v100.bin").write_bytes(base); (d / "s/v110.bin").write_bytes(shifted)
    sizes = {}
    for flags in ([], ["--no-dedup"], ["--solid"]):
        arc = work / f"dd_{'_'.join(f.strip('-') for f in flags) or 'default'}.vfa"
        vfa("c", arc, "s", "--format", "vfa2", *flags, cwd=d)
        ok, why = extract_cmp(arc, d / "s", work); sizes[" ".join(flags) or "non-solid"] = arc.stat().st_size
        check(f"vfa2 dedup: shifted near-duplicate files round-trip ({' '.join(flags) or 'non-solid'})", ok, why)
    (d / "same").mkdir(exist_ok=True); (d / "same/a.bin").write_bytes(base[:1 << 20]); (d / "same/b.bin").write_bytes(base[:1 << 20])
    for flags, want in (([], 1), (["--no-dedup"], 2)):
        arc = work / f"dd_same_{len(flags)}.vfa"; vfa("c", arc, "same", "--format", "vfa2", *flags, cwd=d)
        with vx.open_container(str(arc)) as c:
            c.unlock(None)
            check(f"vfa2 dedup: two identical files -> {len(c.chunks)} chunk(s) {' '.join(flags) or '(default)'}", len(c.chunks) == want)
    check(f"vfa2 dedup: non-solid archive of two near-duplicates {sizes['non-solid']:,} B vs {sizes['--no-dedup']:,} B without dedup",
          sizes["non-solid"] < 0.6 * sizes["--no-dedup"])
    with vx.open_container(str(work / "dd_default.vfa")) as c:
        c.unlock(None)
        v110 = next(e for e in c.entries if e["path"].endswith("v110.bin")); v100 = next(e for e in c.entries if e["path"].endswith("v100.bin"))
        own = {ch for ch, _, _ in v100["extents"]}
        check(f"vfa2 dedup: v110.bin borrows extents from v100.bin's chunk ({len(v110['extents'])} extents)",
              any(ch in own for ch, _, _ in v110["extents"]))
        seen = []; orig = c.chunk_data
        c.chunk_data = lambda i: (seen.append(i), orig(i))[1]
        out = work / "dd_ra"; shutil.rmtree(out, ignore_errors=True)
        c.extract(str(out), members=["s/v110.bin"])
        check(f"vfa2 dedup: random access to the deduplicated member decodes {len(set(seen))} chunk(s), "
              f"({len(seen)} chunk requests, cache hits included)", (out / "s/v110.bin").read_bytes() == shifted and len(set(seen)) <= 2)
    p = build2(work / "dd_enc.vfa", [("z/a", base[:1 << 20]), ("z/b", base[:1 << 20])], password=b"pw", kdf=(1, 1024, 1), cdc=True)
    with vx.open_container(str(p)) as c:
        c.unlock("pw")
        check("vfa2 dedup is off when encrypting (identical files get separate chunks)", len(c.chunks) == 2)
    # duplicate paths whose extents span chunks (chunk-major extraction must not open one target twice)
    # the second entry shares the first one's bytes (dedup references back into its chunks) plus a new tail
    first = base[:300_000]; second = first + base[900_000:1_000_000]
    for solid in (False, True):
        p = build2(work / f"dd_dup_{solid}.vfa", [("z/a", first), ("z/a", second)], coder=3, filt=None,
                   solid=solid, chunk_size=1 << 16, cdc=True)
        out = work / "dd_dup_out"; shutil.rmtree(out, ignore_errors=True)
        try:
            open_extract(p, out)
            check(f"vfa2: duplicate paths spanning chunks extract, last entry wins ({'solid' if solid else 'non-solid'})",
                  (out / "z/a").read_bytes() == second and not list(out.rglob("*.vfapart")))
        except Exception as e:
            check(f"vfa2: duplicate paths spanning chunks extract, last entry wins ({'solid' if solid else 'non-solid'})", False, repr(e))
    # a chunk-boundary case: dedup references into the unflushed buffer and across flushes, small chunks
    files = [("z/a", base[:600_000]), ("z/b", base[:600_000]), ("z/c", base[100_000:700_000])]
    p = build2(work / "dd_small.vfa", files, cdc=True, solid=True, chunk_size=1 << 18, coder=3, filt=None)
    out = work / "dd_small_out"; shutil.rmtree(out, ignore_errors=True); open_extract(p, out)
    check("vfa2 dedup: solid, 256 KiB chunks, references into the current buffer and earlier chunks round-trip",
          all((out / pth).read_bytes() == dat for pth, dat in files))

# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--format", choices=["vfa1", "vfa2", "all"], default="all")
    ap.add_argument("--quick", action="store_true"); ap.add_argument("--big", action="store_true")
    ap.add_argument("--fuzz", type=int, default=None); ap.add_argument("--only"); ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    groups = set(a.only.split(",")) if a.only else {"roundtrip", "sample", "encrypt", "append", "ra", "refuse", "paths",
                                                     "fuzz", "determinism", "sfx", "signed", "codec", "native", "lz", "dedup"}
    if a.big: groups.add("big")
    n = a.fuzz if a.fuzz is not None else (150 if a.quick else 600)
    work = pathlib.Path(tempfile.mkdtemp(prefix="vfa-test-"))
    print(f"work dir: {work}")
    suites = {
        "vfa1": [("roundtrip", lambda c: t_roundtrip(work, c)), ("sample", lambda c: t_sample(work)),
                 ("encrypt", lambda c: t_encrypt(work, c)), ("append", lambda c: t_append(work, c)),
                 ("ra", lambda c: t_random_access(work)), ("refuse", lambda c: t_refuse(work)), ("paths", lambda c: t_paths(work)),
                 ("determinism", lambda c: t_determinism(work, c)), ("sfx", lambda c: t_sfx(work, c)),
                 ("signed", lambda c: t_signed(work, c, "vfa1")), ("fuzz", lambda c: t_fuzz(work, n, a.quick)),
                 ("big", lambda c: t_big(work, "vfa1"))],
        "vfa2": [("roundtrip", lambda c: t2_roundtrip(work, c)), ("sample", lambda c: t2_sample(work)),
                 ("encrypt", lambda c: t2_encrypt(work, c)), ("ra", lambda c: t2_random_access(work)),
                 ("refuse", lambda c: t2_refuse(work)), ("paths", lambda c: t2_paths(work)),
                 ("determinism", lambda c: t2_determinism(work, c)), ("sfx", lambda c: t2_sfx(work, c)),
                 ("signed", lambda c: t_signed(work, c, "vfa2")), ("codec", lambda c: t2_codec(work, c)),
                 ("native", lambda c: t2_native(work, c)), ("lz", lambda c: t2_lz(work, c)),
                 ("dedup", lambda c: t2_dedup(work, c)), ("fuzz", lambda c: t2_fuzz(work, n, a.quick)),
                 ("big", lambda c: t_big(work, "vfa2"))],
    }
    try:
        corpus = make_corpus(work / "corpus")
        t0 = time.perf_counter()
        for fmt in (["vfa1", "vfa2"] if a.format == "all" else [a.format]):
            print(f"\n==== {fmt}")
            for g, fn in suites[fmt]:
                if g in groups: fn(corpus)
        print(f"\n{len(FAILS)} failed, {len(SKIPS)} skipped, in {time.perf_counter() - t0:.0f}s")
        for f in FAILS: print("  FAILED:", f)
    finally:
        if not a.keep: shutil.rmtree(work, ignore_errors=True)
    return 1 if FAILS else 0

if __name__ == "__main__":
    sys.exit(main())
