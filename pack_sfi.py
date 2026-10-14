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
#
#!/usr/bin/env python3
"""
pack_sfi - glue a VFA archive and an install manifest onto the SFI stub.

    python pack_sfi.py --stub bin/windows/vfa_sfi.exe --archive app.vfa --manifest app.json -o AppSetup.exe
    python pack_sfi.py --stub bin/linux/vfa_sfi --archive app.vfa --name MyApp --version 1.0 \
        --shortcut startmenu:bin/myapp --shortcut desktop:bin/myapp -o myapp-setup

Output layout:  [stub][manifest JSON][u32 len]["/VFIM1"][VFA archive]
This is the SFI counterpart of `copy /b vfa_sfx.exe + payload.vfa MySFX.exe`. With --sfx it builds that SFX
instead; prefer it over copy /b when the payload contains a PyInstaller program (see pyi_trailer).
"""
import argparse, json, os, shutil, struct, sys

MANIFEST_MAGIC = b"/VFIM1"
# PyInstaller stubs find their own bundled data by searching backwards from the end of the file for this cookie.
# A payload that contains a PyInstaller program (e.g. an installer for a PyInstaller app, or for VFA itself) has
# the same cookie inside it, closer to the end, and the stub then fails to start. So a copy of the stub's own
# cookie goes after the archive, its length field adjusted so it still points at the stub's data; VFA readers skip
# it (vfa_extract.effective_end). Layout: struct "!8sIIII64s" = magic, package length (counted back from the end of
# the cookie), TOC offset, TOC length, Python version, libpython name.
PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYI_COOKIE_LEN = 88

def pyi_trailer(stub: bytes, at: int) -> bytes:
    """The stub's PyInstaller cookie, re-based to sit at file offset `at`; b"" for a stub that is not PyInstaller.
    Raises ValueError when the re-based length does not fit the cookie's 32-bit field (the stub's launcher could not
    reach its data past a payload that large anyway)."""
    i = stub.rfind(PYI_MAGIC)
    if i < 0 or i + PYI_COOKIE_LEN > len(stub): return b""
    cookie = bytearray(stub[i:i + PYI_COOKIE_LEN])
    (length,) = struct.unpack(">I", cookie[8:12])
    if length + (at - i) > 0xFFFFFFFF:
        raise ValueError(f"payload too large ({at - i:,} bytes after the stub's data) for a PyInstaller stub whose "
                         f"payload contains another PyInstaller program; split the payload below 4 GiB")
    cookie[8:12] = struct.pack(">I", length + (at - i))
    return bytes(cookie)

def contains_pyi_magic(path: str) -> bool:
    """Does the file contain PyInstaller's cookie magic? Only then is a trailer needed (streamed, so a multi-GiB
    archive is not read into memory)."""
    tail = b""
    with open(path, "rb") as f:
        while True:
            block = f.read(1 << 20)
            if not block: return False
            if PYI_MAGIC in tail + block: return True
            tail = block[-(len(PYI_MAGIC) - 1):]
ARCHIVE_MAGICS = {b"VFA1": b"/VFA1", b"VFA2": b"/VFA2"}   # head -> tail

def main(argv=None):
    ap = argparse.ArgumentParser(description="Create a VFA self-finishing installer (SFI)")
    ap.add_argument("--stub", required=True, help="Built vfa_sfi stub (vfa_sfi.exe on Windows)")
    ap.add_argument("--archive", required=True, help="Payload .vfa archive")
    ap.add_argument("--manifest", help="JSON manifest file (see sfi_stub.DEFAULT_MANIFEST)")
    ap.add_argument("-o", "--output", required=True)
    q = ap.add_argument_group("quick manifest fields (override --manifest)")
    q.add_argument("--name"); q.add_argument("--version"); q.add_argument("--publisher"); q.add_argument("--description")
    q.add_argument("--license-file", help="Text file embedded as the license")
    q.add_argument("--default-location", choices=["user", "public", "system", "system86"])
    q.add_argument("--icon", help="Icon path inside the archive (used for shortcuts)")
    q.add_argument("--shortcut", action="append", default=[], metavar="TYPE:TARGET[:NAME]",
                   help="startmenu|desktop shortcut to a path inside the archive (repeatable)")
    q.add_argument("--bin-link", action="append", default=[], metavar="NAME:TARGET", help="POSIX command link (repeatable)")
    q.add_argument("--path-add", action="append", default=[], metavar="RELDIR", help="Windows PATH entry inside the install dir (repeatable)")
    q.add_argument("--run-after")
    ap.add_argument("--sfx", action="store_true",
                    help="Plain SFX (stub = vfa_sfx): no manifest, just the archive and the PyInstaller cookie trailer")
    a = ap.parse_args(argv)

    m = {}
    if a.manifest:
        with open(a.manifest, "r", encoding="utf-8") as f: m = json.load(f)
    for k in ("name", "version", "publisher", "description", "icon", "run_after", "default_location"):
        v = getattr(a, k)
        if v: m[k] = v
    if a.license_file:
        with open(a.license_file, "r", encoding="utf-8") as f: m["license"] = f.read()
    for s in a.shortcut:
        parts = s.split(":", 2)
        if len(parts) < 2 or parts[0] not in ("startmenu", "desktop"): ap.error(f"bad --shortcut {s!r}")
        sc = {"type": parts[0], "target": parts[1]}
        if len(parts) == 3: sc["name"] = parts[2]
        m.setdefault("shortcuts", []).append(sc)
    for b in a.bin_link:
        n, _, t = b.partition(":")
        if not t: ap.error(f"bad --bin-link {b!r}")
        m.setdefault("bin_links", []).append({"name": n, "target": t})
    if a.path_add: m.setdefault("path_add", []).extend(a.path_add)
    if not m.get("name") and not a.sfx: ap.error("a name is required (--name or manifest 'name')")

    with open(a.archive, "rb") as f:
        head = f.read(4); f.seek(-5, os.SEEK_END); tail = f.read(5)
    if ARCHIVE_MAGICS.get(head) != tail:
        ap.error(f"{a.archive} is not a VFA archive (bad magic).")
    blob = json.dumps(m, ensure_ascii=False).encode("utf-8")
    with open(a.stub, "rb") as f: stub = f.read()
    trailer = b""
    if contains_pyi_magic(a.archive):     # only then would the stub's launcher find the wrong cookie
        at = len(stub) + (0 if a.sfx else len(blob) + 4 + len(MANIFEST_MAGIC)) + os.path.getsize(a.archive)
        try: trailer = pyi_trailer(stub, at)
        except ValueError as e: ap.error(str(e))          # before anything is written
    with open(a.output, "wb") as out:
        out.write(stub)
        if not a.sfx: out.write(blob); out.write(struct.pack("<I", len(blob))); out.write(MANIFEST_MAGIC)
        with open(a.archive, "rb") as f: shutil.copyfileobj(f, out, 1 << 20)
        if trailer and out.tell() != at: raise RuntimeError(f"archive changed while packing ({out.tell()} != {at})")
        out.write(trailer)
    if os.name != "nt": os.chmod(a.output, 0o755)
    print(f"[pack_sfi] {a.output}  ({os.path.getsize(a.output):,} bytes)" + (f"  name={m['name']!r}" if not a.sfx else "  (sfx)"))
    return 0

if __name__ == "__main__":
    sys.exit(main())
