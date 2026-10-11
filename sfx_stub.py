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
# Self-extracting stub for .vfa archives appended to this EXE
# Build:
#   python build.py            (or: pyinstaller --onefile --clean --name vfa_sfx sfx_stub.py)
# Pack:
#   copy /b .\dist\vfa_sfx.exe + .\payload.vfa MySFX.exe
#
# Usage:
#   MySFX.exe [-o OUTPUT_DIR] [--password] [--quiet|--log-level debug] [--from-file PATH] [--no-verify]
#
# All archive reading is done by vfa_extract.Container (shared with vfa.py, the SFI installer and the
# viewer): digest check before anything is written, block size/CRC checks, and path validation.

import sys, argparse, getpass

import vfa_extract as vx
from vfa_extract import VFAError, VLog

LOGGER = VLog("warning")

def extract_self(output_dir:str, need_password:bool=False, quiet:bool=False, from_file:str=None,
                 log_level:str="warning", verify:bool=True):
    global LOGGER
    LOGGER = VLog(log_level); vx.set_logger(LOGGER)
    exe_path = from_file or sys.executable
    LOGGER.info(f"Opening container file: {exe_path}")
    with vx.open_container(exe_path) as c:          # VFA1 or VFA2
        LOGGER.info(f"VFA payload: {getattr(c, 'format', 'VFA1')} solid={c.solid} encrypted={c.encrypted}")
        if verify:
            if c.verify_digest() is False:
                raise VFAError("Integrity check FAILED: this file is corrupted or was modified.")
            LOGGER.info("Integrity check OK")
        elif not c.has_tocx:
            LOGGER.warning("VFA 1.0 payload without block CRCs: with --no-verify, corruption can go undetected.")
        pw = None
        if c.encrypted:
            if not need_password: LOGGER.info("Encrypted payload detected; prompting for password.")
            pw = getpass.getpass("Password: ")
        c.unlock(pw)
        LOGGER.info(f"Extracting to: {output_dir}")
        files, dirs = c.extract(output_dir)
    LOGGER.info(f"Extraction complete: {len(files)} file(s).")

# ---------------- CLI ----------------

def main():
    ap = argparse.ArgumentParser(description="Self-extracting VFA archive")
    ap.add_argument("-o", "--output", default="./_extracted", help="Output directory (default: ./_extracted)")
    ap.add_argument("--password", action="store_true", help="Prompt for password if archive is encrypted (if omitted, we'll still prompt when needed).")
    ap.add_argument("--log-level", choices=["quiet","error","warning","info","debug","trace"], default="warning")
    ap.add_argument("-v","--verbose", action="store_true", help="Shortcut for --log-level info")
    ap.add_argument("--from-file", help="Debug: read container bytes from this path instead of sys.executable")
    ap.add_argument("--no-verify", action="store_true", help="Skip the whole-file digest check (blocks are still checked)")
    args = ap.parse_args()

    if args.verbose and args.log_level == "warning":
        args.log_level = "info"

    try:
        extract_self(args.output, need_password=args.password, quiet=(args.log_level=="quiet"),
                     from_file=args.from_file, log_level=args.log_level, verify=not args.no_verify)
    except VFAError as e:
        LOGGER.error(str(e))
        sys.exit(e.code or 1)

if __name__ == "__main__":
    main()
