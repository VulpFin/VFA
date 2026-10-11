# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
#!/usr/bin/env python3
"""
Regression tests for the SFI installer. No pytest needed:   python test_sfi.py

Builds a sample tree, archives it with the real vfa.py, glues it to a dummy stub with pack_sfi.py and drives the
unfrozen sfi_stub.py headless in a throw-away HOME. POSIX only for the install tests (Windows-only paths -
shortcuts, registry, PATH - need a manual run; see SFI.md).
"""
import os, sys, json, shutil, subprocess, tempfile, filecmp, pathlib

HERE = pathlib.Path(__file__).resolve().parent
PY = sys.executable
fails = []

def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"   {extra}" if extra and not cond else ""))
    if not cond: fails.append(name)

def run(args, env=None, **kw):
    e = dict(os.environ); e.update(env or {})
    return subprocess.run([PY, *map(str, args)], capture_output=True, text=True, env=e, **kw)

def same_tree(a, b, ignore=("uninstall", "uninstall.json")):
    a, b = pathlib.Path(a), pathlib.Path(b)
    fa = {p.relative_to(a).as_posix() for p in a.rglob("*") if p.is_file()}
    fb = {p.relative_to(b).as_posix() for p in b.rglob("*") if p.is_file() and p.name not in ignore}
    return fa == fb and all(filecmp.cmp(a / f, b / f, shallow=False) for f in fa)

def main():
    if os.name == "nt": print("install tests are POSIX-only; skipping"); return 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="sfi-test-"))
    try:
        app = tmp / "app"; (app / "bin").mkdir(parents=True); (app / "data/sub").mkdir(parents=True); (app / "data/emptydir").mkdir()
        (app / "bin/tool").write_text('#!/bin/sh\n[ -n "$SFI_MARKER" ] && echo launched > "$SFI_MARKER"\necho ok\n'); os.chmod(app / "bin/tool", 0o755)
        (app / "data/blob.bin").write_bytes(os.urandom(200_000)); (app / "README.txt").write_text("hi\n"); (app / "data/sub/a.txt").write_text("a")
        (tmp / "stub").write_bytes(b"dummy-stub")
        for name, flags in (("solid", ["--method", "zstd", "--solid"]), ("plain", ["--method", "lzma"])):
            r = run([HERE / "vfa.py", "c", tmp / f"{name}.vfa", ".", *flags], cwd=app); assert r.returncode == 0, r.stderr
            r = run([HERE / "pack_sfi.py", "--stub", tmp / "stub", "--archive", tmp / f"{name}.vfa", "--name", "Test App", "--version", "1.0",
                     "--publisher", "TG11", "--shortcut", "startmenu:bin/tool", "--shortcut", "desktop:bin/tool", "--bin-link", "tool:bin/tool", "--run-after", "bin/tool",
                     "-o", tmp / f"{name}.setup"]); assert r.returncode == 0, r.stderr
        home = tmp / "home"; home.mkdir(); env = {"HOME": str(home), "XDG_DATA_HOME": ""}
        env["XDG_DATA_HOME"] = str(home / ".local/share"); env["SFI_MARKER"] = str(tmp / "marker")
        inst = lambda f, *a: run([HERE / "sfi_stub.py", "--from-file", tmp / f, "--silent", *a], env=env)
        dest = home / ".local/share/test-app"

        r = inst("solid.setup", "--desktop", "--path"); check("silent install (solid) exits 0", r.returncode == 0, r.stderr + r.stdout)
        check("installed tree identical", same_tree(app, dest))
        check("exec bit preserved", os.access(dest / "bin/tool", os.X_OK))
        check("empty dir recreated", (dest / "data/emptydir").is_dir())
        check("install dir is not 0700", (dest.stat().st_mode & 0o055) == 0o055, oct(dest.stat().st_mode))
        check("desktop + menu entries written", (home / "Desktop/test-app.desktop").exists() and (home / ".local/share/applications/test-app.desktop").exists())
        check("bin link created", (home / ".local/bin/tool").is_symlink())

        (dest / "stale.txt").write_text("x"); rec = json.load(open(dest / "uninstall.json")); rec["files"].append("stale.txt"); json.dump(rec, open(dest / "uninstall.json", "w"))
        r = inst("plain.setup"); check("upgrade (non-solid over solid) exits 0", r.returncode == 0, r.stderr)
        check("upgrade removed stale tracked file", not (dest / "stale.txt").exists())
        check("upgrade kept earlier shortcuts/links in record", {"shortcuts", "links"} <= set(json.load(open(dest / "uninstall.json"))) and
              len(json.load(open(dest / "uninstall.json"))["shortcuts"]) >= 2 and len(json.load(open(dest / "uninstall.json"))["links"]) >= 1)

        # --- what to do when it is already installed ---
        (dest / "my_user_file.txt").write_text("keep me"); (dest / "stale.txt").write_text("x")
        rec = json.load(open(dest / "uninstall.json")); rec["files"].append("stale.txt"); json.dump(rec, open(dest / "uninstall.json", "w"))
        before = (dest / "uninstall.json").read_text()
        r = inst("solid.setup", "--existing", "abort"); check("--existing abort: exit 4, install untouched", r.returncode == 4 and (dest / "uninstall.json").read_text() == before, r.stdout + r.stderr)
        r = inst("solid.setup", "--existing", "clean", "-v"); out = r.stdout + r.stderr
        check("--existing clean: removes old first, then installs", r.returncode == 0 and "Removing existing installation" in out, out)
        check("clean: tracked stale file gone, untracked user file kept, tree complete",
              not (dest / "stale.txt").exists() and (dest / "my_user_file.txt").read_text() == "keep me" and (dest / "bin/tool").exists())
        os.remove(dest / "my_user_file.txt")
        r = inst("solid.setup", "--existing", "remove"); left2 = [p for p in dest.rglob("*")] if dest.exists() else []
        check("--existing remove: uninstalls and installs nothing", r.returncode == 0 and not left2 and not (home / ".local/bin/tool").exists(), str(left2))
        r = inst("plain.setup", "--desktop", "--path"); check("fresh install after remove works", r.returncode == 0 and same_tree(app, dest), r.stderr)

        # --- launch after install (CLI/silent --launch), and never without the flag ---
        import time
        r = inst("plain.setup"); time.sleep(0.5); check("no launch without --launch", r.returncode == 0 and not (tmp / "marker").exists())
        r = inst("plain.setup", "--launch"); ok = False
        for _ in range(30):
            if (tmp / "marker").exists(): ok = True; break
            time.sleep(0.1)
        check("--launch starts run_after", r.returncode == 0 and ok, r.stderr + r.stdout)

        # --- permission problems must turn into an elevation request, not a crash ---
        sys.path.insert(0, str(HERE)); import sfi_stub as S, vfa_extract as vx0
        def fake_extract(self, *a, **k): raise PermissionError("denied")
        c = vx0.Container(str(tmp / "plain.setup")); c.unlock(None)
        m = S.load_manifest(c, "x"); o = S.Options(dir=str(tmp / "denied_dest")); pre = S.preflight(c, m, o)
        orig_ext, orig_adm = vx0.Container.extract, S.is_admin
        vx0.Container.extract = fake_extract; S.is_admin = lambda: False
        try: S.do_install(c, m, o, pre); raised = None
        except S.NeedAdmin: raised = "NeedAdmin"
        except Exception as e: raised = type(e).__name__
        S.is_admin = lambda: True
        try: S.do_install(c, m, o, pre); raised2 = None
        except PermissionError: raised2 = "PermissionError"
        except Exception as e: raised2 = type(e).__name__
        vx0.Container.extract, S.is_admin = orig_ext, orig_adm; c.close()
        check("PermissionError while unelevated -> NeedAdmin (triggers UAC/sudo)", raised == "NeedAdmin", str(raised))
        check("PermissionError while already admin -> real error, no elevation loop", raised2 == "PermissionError", str(raised2))
        check("no stage folder left after denied install", not list(tmp.glob(".vfi-stage-*")) and not (tmp / "denied_dest").exists())
        # regression: tempfile.mkstemp/mkdtemp retry ~10,000x on Windows when a folder denies writes (froze the wizard on Program Files)
        import tempfile as tf, builtins
        calls = {"n": 0}; real_open = S.os.open
        def deny(*a, **k): calls["n"] += 1; raise PermissionError(13, "denied")
        def boom(*a, **k): raise AssertionError("tempfile retry-loop helper used in the install path")
        om, od = tf.mkstemp, tf.mkdtemp; tf.mkstemp = boom; tf.mkdtemp = boom; S.os.open = deny
        try: denied_result = S.can_write_dir(str(tmp)); one_attempt = calls["n"] == 1
        finally: S.os.open = real_open
        try:
            c2 = vx0.Container(str(tmp / "plain.setup")); c2.unlock(None); o2 = S.Options(dir=str(tmp / "no_tempfile_dest")); p2 = S.preflight(c2, m, o2)
            S.do_install(c2, m, o2, p2); c2.close(); fresh_ok = (tmp / "no_tempfile_dest/README.txt").exists()
        except AssertionError as e: fresh_ok = False
        finally: tf.mkstemp, tf.mkdtemp = om, od
        check("write probe: denied folder -> False after exactly ONE attempt (no retry loop)", denied_result is False and one_attempt, str(calls))
        check("fresh install never touches tempfile.mkstemp/mkdtemp", fresh_ok)
        check("can_write_dir really probes (writable tmp / missing parent / file)", S.can_write_dir(str(tmp / "new/sub")) and not S.can_write_dir("/proc/nope/x"))

        r = inst("plain.setup", "--uninstall", "--dir", str(dest)); check("uninstall exits 0", r.returncode == 0, r.stderr)
        left = [p for p in home.rglob("*") if p.is_file() or p.is_symlink()]
        check("uninstall leaves nothing behind", not left and not dest.exists(), str(left))

        # a previous uninstall that could not delete its own exe leaves only 'uninstall[.exe]' behind: reinstall must work
        lo = tmp / "leftover"; lo.mkdir(); (lo / "uninstall").write_bytes(b"stub")
        r = inst("plain.setup", "--dir", str(lo)); check("folder holding only a leftover uninstaller is reused", r.returncode == 0 and same_tree(app, lo), r.stderr + r.stdout)
        inst("plain.setup", "--uninstall", "--dir", str(lo))

        foreign = tmp / "foreign"; foreign.mkdir(); (foreign / "mine.txt").write_text("keep")
        r = inst("plain.setup", "--dir", str(foreign)); check("refuses non-empty foreign dir (exit 2)", r.returncode == 2 and (foreign / "mine.txt").exists())

        bad = bytearray((tmp / "solid.setup").read_bytes()); bad[len(bad) // 2] ^= 0xFF; (tmp / "bad.setup").write_bytes(bad)
        r = inst("bad.setup", "--dir", str(tmp / "bad_out")); check("corrupted payload rejected, nothing written", r.returncode == 1 and not (tmp / "bad_out").exists(), r.stdout + r.stderr)

        sys.path.insert(0, str(HERE)); import vfa_extract as vx
        evil = ["../evil", "a/../../evil", "/etc/passwd", "C:\\Windows\\x", "..\\evil", "a\x00b"]
        def rejected(p):
            try: vx.safe_join(str(tmp / "dst"), p); return False
            except vx.VFAError: return True
        check("path traversal strings rejected", all(rejected(p) for p in evil))
        with vx.Container(str(tmp / "solid.setup")) as c:
            c.unlock(None); c.entries[1]["path"] = "../../escape.txt"
            try: c.extract(str(tmp / "dst2")); ok = False
            except vx.VFAError: ok = True
        check("malicious TOC entry aborts extraction", ok and not (tmp / "escape.txt").exists())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}"); return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
