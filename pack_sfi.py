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
This is the SFI counterpart of `copy /b vfa_sfx.exe + payload.vfa MySFX.exe`.
"""
import argparse, json, os, shutil, struct, sys

MANIFEST_MAGIC = b"/VFIM1"
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
    if not m.get("name"): ap.error("a name is required (--name or manifest 'name')")

    with open(a.archive, "rb") as f:
        head = f.read(4); f.seek(-5, os.SEEK_END); tail = f.read(5)
    if ARCHIVE_MAGICS.get(head) != tail:
        ap.error(f"{a.archive} is not a VFA archive (bad magic).")
    blob = json.dumps(m, ensure_ascii=False).encode("utf-8")
    with open(a.output, "wb") as out:
        with open(a.stub, "rb") as f: shutil.copyfileobj(f, out, 1 << 20)
        out.write(blob); out.write(struct.pack("<I", len(blob))); out.write(MANIFEST_MAGIC)
        with open(a.archive, "rb") as f: shutil.copyfileobj(f, out, 1 << 20)
    if os.name != "nt": os.chmod(a.output, 0o755)
    print(f"[pack_sfi] {a.output}  ({os.path.getsize(a.output):,} bytes)  name={m['name']!r}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
