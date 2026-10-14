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
SFI - Self-Finishing Installer stub for VFA payloads.

Build:   python build.py            (produces vfa_sfi / vfa_sfi.exe)
Pack:    python pack_sfi.py --stub bin/<plat>/vfa_sfi[.exe] --archive app.vfa \
                            --manifest app.json -o MyAppSetup[.exe]

Modes (one executable does all of them):
    (no flags)   GUI wizard when a display is available, otherwise interactive CLI
    --cli        interactive terminal installer (flags prefill answers)
    --silent     fully unattended; uses manifest defaults + flags, never prompts
    --uninstall  remove a previous install (also: run as uninstall[.exe])
"""

import sys, os, json, shutil, argparse, subprocess, tempfile, time, re, platform, stat, random, traceback
from typing import Dict, List, Optional

import vfa_extract as vx
from vfa_extract import Container, VFAError, VLog

IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")
FROZEN = getattr(sys, "frozen", False)

RECORD_NAME = "uninstall.json"
UNINSTALLER_NAME = "uninstall.exe" if IS_WIN else "uninstall"

EXIT_OK, EXIT_ERR, EXIT_ARGS, EXIT_ELEV, EXIT_CANCEL, EXIT_PASSWORD = 0, 1, 2, 3, 4, 5

# ---------------- Manifest ----------------

DEFAULT_MANIFEST = {
    "name": None, "version": "", "publisher": "", "description": "", "url": "",
    "app_id": None,
    "default_location": "user",                 # user | public | system | system86 | custom
    "allow_locations": ["user", "public", "system", "system86", "custom"],
    "subdir": None,                             # folder name under the location (default: name)
    "license": "",                              # license text shown in GUI / --accept-license in CLI
    "shortcuts": [],                            # {type: startmenu|desktop, name, target, args, icon, comment, terminal, categories}
    "bin_links": [],                            # POSIX: [{name, target}] -> ~/.local/bin or /usr/local/bin
    "path_add": [],                             # Windows: relative dirs appended to PATH
    "run_after": None,                          # relative path launched after install (if enabled)
    "defaults": {"desktop": False, "startmenu": True, "path": False, "launch": False},
    "uninstaller": True,
}

def load_manifest(c: Optional[Container], exe_path: str) -> dict:
    m = json.loads(json.dumps(DEFAULT_MANIFEST))
    if c is not None and c.manifest:
        for k, v in c.manifest.items():
            if k == "defaults" and isinstance(v, dict): m["defaults"].update(v)
            else: m[k] = v
    if not m.get("name"):
        base = os.path.splitext(os.path.basename(exe_path))[0]
        m["name"] = re.sub(r"(?i)[-_ ]?(setup|installer|sfi)$", "", base) or "Application"
    return m

def _safe_name(s: str) -> str:
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", s).strip(" .")
    return s or "App"

def app_id_of(m: dict) -> str:
    return _safe_name(m.get("app_id") or ((m.get("publisher", "") + "." if m.get("publisher") else "") + m["name"]))

# ---------------- Privileges ----------------

def is_admin() -> bool:
    if IS_WIN:
        try:
            import ctypes; return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception: return False
    return hasattr(os, "geteuid") and os.geteuid() == 0

def can_write_dir(path: str) -> bool:
    """True if we can really create files at (or below) path. os.access(W_OK) is useless on Windows - it ignores ACLs and
    says yes for C:\\Program Files - so probe by creating one file in the nearest existing folder.
    Do NOT use tempfile.mkstemp here: on Windows it treats 'access denied' as 'name taken' and retries 10,000 times,
    which froze the wizard for minutes on Program Files."""
    p = os.path.abspath(path)
    while p and not os.path.isdir(p):
        parent = os.path.dirname(p)
        if parent == p: return False
        p = parent
    probe = os.path.join(p, f".vfi-probe-{os.getpid()}-{random.getrandbits(32):08x}")
    try:
        fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        return False
    try:
        os.close(fd)
    finally:
        try: os.remove(probe)
        except OSError: pass
    return True

def make_staging_dir(parent: str) -> str:
    """Create a uniquely named staging folder next to the destination with ONE attempt per name
    (tempfile.mkdtemp has the same Windows retry-on-PermissionError problem, and is 0700). Mode follows the umask."""
    for _ in range(8):
        d = os.path.join(parent, f".vfi-stage-{random.getrandbits(48):012x}")
        try:
            os.mkdir(d, 0o777)
            return d
        except FileExistsError:
            continue
    raise FileExistsError(f"could not create a staging folder in {parent}")

class NeedAdmin(Exception):
    """Extraction hit a permission error while not elevated: the caller should relaunch elevated."""

# ---------------- Install locations ----------------

def location_table(m: dict) -> Dict[str, dict]:
    """id -> {label, path, admin}. Paths are platform specific."""
    sub = _safe_name(m.get("subdir") or m["name"])
    t: Dict[str, dict] = {}
    if IS_WIN:
        lad = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        t["user"] = {"label": "Current user (AppData\\Local\\Programs)", "path": os.path.join(lad, "Programs", sub), "admin": False}
        pub = os.environ.get("PUBLIC") or r"C:\Users\Public"
        t["public"] = {"label": "Shared (Users\\Public)", "path": os.path.join(pub, sub), "admin": False}
        pf = os.environ.get("ProgramFiles") or r"C:\Program Files"
        t["system"] = {"label": "Program Files", "path": os.path.join(pf, sub), "admin": True}
        pf86 = os.environ.get("ProgramFiles(x86)")
        if pf86:
            t["system86"] = {"label": "Program Files (x86)", "path": os.path.join(pf86, sub), "admin": True}
    elif IS_MAC:
        t["user"] = {"label": "Current user (~/Applications)", "path": os.path.join(os.path.expanduser("~"), "Applications", sub), "admin": False}
        t["public"] = {"label": "Shared (/Users/Shared)", "path": os.path.join("/Users/Shared", sub), "admin": False}
        t["system"] = {"label": "Applications (/Applications)", "path": os.path.join("/Applications", sub), "admin": True}
    else:
        xdg = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
        low = _safe_name(sub).lower().replace(" ", "-")
        t["user"] = {"label": f"Current user ({xdg})", "path": os.path.join(xdg, low), "admin": False}
        t["public"] = {"label": "All users (/usr/local/share)", "path": os.path.join("/usr/local/share", low), "admin": True}
        t["system"] = {"label": "System (/opt)", "path": os.path.join("/opt", low), "admin": True}
    allow = m.get("allow_locations") or list(t)
    return {k: v for k, v in t.items() if k in allow}

def resolve_dir(m: dict, location: Optional[str], custom_dir: Optional[str]) -> dict:
    """Returns {id, path, admin}. custom_dir wins and implies location 'custom'."""
    table = location_table(m)
    if custom_dir:
        p = os.path.abspath(os.path.expandvars(os.path.expanduser(custom_dir)))
        return {"id": "custom", "path": p, "admin": not can_write_dir(p)}
    loc = location or m.get("default_location") or "user"
    if loc not in table:
        raise VFAError(f"Location '{loc}' is not available here. Choose from: {', '.join(table) or 'custom (--dir)'}", EXIT_ARGS)
    e = table[loc]
    return {"id": loc, "path": e["path"], "admin": e["admin"] and not can_write_dir(e["path"])}

# ---------------- Elevation ----------------

def _self_cmd() -> List[str]:
    return [sys.executable] if FROZEN else [sys.executable, os.path.abspath(sys.argv[0])]

def relaunch_elevated(extra_args: List[str], wait=True) -> int:
    """Re-run this program with admin rights. Returns the child's exit code."""
    cmd = _self_cmd() + extra_args
    vx.LOGGER.info("Requesting administrator privileges...")
    if IS_WIN:
        import ctypes
        from ctypes import wintypes
        class SEI(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                        ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                        ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                        ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                        ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]
        sei = SEI(); sei.cbSize = ctypes.sizeof(sei); sei.fMask = 0x40  # SEE_MASK_NOCLOSEPROCESS
        sei.lpVerb = "runas"; sei.lpFile = cmd[0]
        sei.lpParameters = subprocess.list2cmdline(cmd[1:]); sei.nShow = 1
        if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
            return EXIT_ELEV  # user declined UAC
        if not wait: return EXIT_OK
        ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 0xFFFFFFFF)
        code = wintypes.DWORD(); ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(sei.hProcess)
        return int(code.value)
    if IS_MAC:
        vx.LOGGER.error("Administrator rights needed. Re-run with: sudo " + " ".join(cmd)); return EXIT_ELEV
    gui = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and "--cli" not in extra_args and "--silent" not in extra_args
    if gui and shutil.which("pkexec"):
        env = ["env"] + [f"{k}={os.environ[k]}" for k in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR") if k in os.environ]
        full = ["pkexec"] + env + cmd
    elif shutil.which("sudo"):
        full = ["sudo"] + cmd
    else:
        vx.LOGGER.error("Administrator rights needed but neither pkexec nor sudo found."); return EXIT_ELEV
    return subprocess.call(full)

# ---------------- Windows helpers ----------------

def _std_kw() -> dict:
    """Windowless (GUI-subsystem) builds have no std handles; child processes then fail with 'invalid handle' unless we pass explicit ones."""
    kw = {}
    if sys.stdin is None:  kw["stdin"] = subprocess.DEVNULL
    if sys.stdout is None: kw["stdout"] = subprocess.DEVNULL
    if sys.stderr is None: kw["stderr"] = subprocess.DEVNULL
    return kw

def attach_parent_console():
    """Windowless Windows build started from a terminal: reattach to that terminal so --info / -v / errors are visible there.
    (Double-clicked there is no parent console; AttachConsole fails and everything stays silent, as intended.)"""
    if not IS_WIN or sys.stdout is not None: return
    try:
        import ctypes
        if ctypes.windll.kernel32.AttachConsole(0xFFFFFFFF):           # ATTACH_PARENT_PROCESS
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
            sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
            sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
    except Exception:
        pass

def _ps(script: str, env_extra: Optional[dict] = None) -> str:
    env = dict(os.environ); env.update(env_extra or {})
    flags = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                       capture_output=True, text=True, env=env, creationflags=flags, stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"powershell exit {r.returncode}")
    return r.stdout.strip()

def win_special_dir(kind: str, scope: str) -> str:
    """kind: startmenu|desktop ; scope: user|all"""
    name = {("startmenu", "user"): "Programs", ("startmenu", "all"): "CommonPrograms",
            ("desktop", "user"): "Desktop", ("desktop", "all"): "CommonDesktopDirectory"}[(kind, scope)]
    return _ps(f"[Environment]::GetFolderPath('{name}')")

def win_make_shortcut(link_path: str, target: str, args: str, workdir: str, icon: str, desc: str):
    os.makedirs(os.path.dirname(link_path), exist_ok=True)
    script = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:VFI_LNK);"
              "$s.TargetPath=$env:VFI_TARGET;$s.Arguments=$env:VFI_ARGS;$s.WorkingDirectory=$env:VFI_WD;"
              "if($env:VFI_ICON){$s.IconLocation=$env:VFI_ICON};$s.Description=$env:VFI_DESC;$s.Save()")
    _ps(script, {"VFI_LNK": link_path, "VFI_TARGET": target, "VFI_ARGS": args or "", "VFI_WD": workdir,
                 "VFI_ICON": icon or "", "VFI_DESC": desc or ""})

UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

def _winreg_root(scope: str):
    import winreg
    return winreg.HKEY_LOCAL_MACHINE if scope == "all" else winreg.HKEY_CURRENT_USER

def win_register_uninstall(m: dict, scope: str, install_dir: str, size_kb: int) -> str:
    import winreg
    key = UNINSTALL_KEY + "\\" + app_id_of(m)
    un = os.path.join(install_dir, UNINSTALLER_NAME)
    with winreg.CreateKeyEx(_winreg_root(scope), key, 0, winreg.KEY_WRITE) as k:
        def sv(n, v, t=winreg.REG_SZ): winreg.SetValueEx(k, n, 0, t, v)
        sv("DisplayName", m["name"]); sv("DisplayVersion", m.get("version", ""))
        sv("Publisher", m.get("publisher", "")); sv("InstallLocation", install_dir)
        sv("UninstallString", f'"{un}" --uninstall'); sv("QuietUninstallString", f'"{un}" --uninstall --silent')
        sv("NoModify", 1, winreg.REG_DWORD); sv("NoRepair", 1, winreg.REG_DWORD)
        sv("EstimatedSize", int(size_kb), winreg.REG_DWORD)
        if m.get("url"): sv("URLInfoAbout", m["url"])
        icon = os.path.join(install_dir, m["icon"]) if m.get("icon") else un
        sv("DisplayIcon", icon)
    return ("HKLM\\" if scope == "all" else "HKCU\\") + key

def win_delete_uninstall_key(m: dict, scope: str):
    import winreg
    try: winreg.DeleteKey(_winreg_root(scope), UNINSTALL_KEY + "\\" + app_id_of(m))
    except FileNotFoundError: pass

def _env_key(scope: str):
    import winreg
    if scope == "all":
        return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", 0,
                              winreg.KEY_READ | winreg.KEY_WRITE)
    return winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE)

def _broadcast_env():
    try:
        import ctypes
        ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x2, 5000, None)
    except Exception: pass

def win_path_edit(scope: str, entry: str, add: bool) -> bool:
    import winreg
    with _env_key(scope) as k:
        try: cur, typ = winreg.QueryValueEx(k, "Path")
        except FileNotFoundError: cur, typ = "", winreg.REG_EXPAND_SZ
        parts = [p for p in cur.split(";") if p]
        low = [p.rstrip("\\").lower() for p in parts]
        e = entry.rstrip("\\")
        if add:
            if e.lower() in low: return False
            parts.append(e)
        else:
            if e.lower() not in low: return False
            parts = [p for p in parts if p.rstrip("\\").lower() != e.lower()]
        winreg.SetValueEx(k, "Path", 0, winreg.REG_EXPAND_SZ if typ != winreg.REG_SZ else winreg.REG_SZ, ";".join(parts))
    _broadcast_env(); return True

# ---------------- POSIX helpers ----------------

def posix_desktop_dir() -> str:
    try:
        r = subprocess.run(["xdg-user-dir", "DESKTOP"], capture_output=True, text=True, timeout=3)
        if r.returncode == 0 and r.stdout.strip(): return r.stdout.strip()
    except Exception: pass
    return os.path.join(os.path.expanduser("~"), "Desktop")

def posix_app_dir(scope: str) -> str:
    if scope == "all": return "/usr/share/applications"
    return os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"), "applications")

def posix_bin_dir(scope: str) -> str:
    return "/usr/local/bin" if scope == "all" else os.path.join(os.path.expanduser("~"), ".local", "bin")

def write_desktop_entry(path: str, name: str, exec_path: str, args: str, icon: str, comment: str,
                        terminal: bool, categories: str, workdir: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    q = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
    lines = ["[Desktop Entry]", "Type=Application", f"Name={name}", f"Exec={q(exec_path)} {args}".rstrip(),
             f"Path={workdir}", f"Terminal={'true' if terminal else 'false'}"]
    if comment: lines.append(f"Comment={comment}")
    if icon: lines.append(f"Icon={icon}")
    if categories: lines.append(f"Categories={categories}")
    with open(path, "w", encoding="utf-8") as f: f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o755)

# ---------------- Install ----------------

class Options:
    def __init__(self, **kw):
        self.location = None; self.dir = None; self.all_users = None
        self.desktop = False; self.startmenu = True; self.path = False; self.launch = False
        self.force = False; self.dry_run = False; self.from_temp = None
        self.existing = "upgrade"   # what to do if already installed: upgrade | clean | remove | abort
        self.__dict__.update(kw)

UNINSTALLER_NAMES = ("uninstall.exe", "uninstall")

def _dir_nonempty(p: str) -> bool:
    """True if p holds anything besides a leftover uninstaller (a previous uninstall that could not delete itself)."""
    return os.path.isdir(p) and any(e.name.lower() not in UNINSTALLER_NAMES for e in os.scandir(p))

def _clear_leftover_uninstaller(p: str) -> bool:
    """Remove stray uninstall[.exe] from an otherwise empty folder. Returns True if the folder is now empty/absent."""
    if not os.path.isdir(p): return True
    for e in list(os.scandir(p)):
        try: os.remove(e.path)
        except OSError: return False
    return True

def read_record(install_dir: str) -> Optional[dict]:
    try:
        with open(os.path.join(install_dir, RECORD_NAME), "r", encoding="utf-8") as f: return json.load(f)
    except Exception: return None

def scope_for(target: dict, opts: Options) -> str:
    if opts.all_users is True: return "all"
    if opts.all_users is False: return "user"
    return "all" if (target["admin"] or (not IS_WIN and target["id"] in ("public", "system"))) else "user"

def launch_app(m: dict, install_dir: str) -> Optional[str]:
    """Start m['run_after'] the way a user double-click would. Returns None on success or an error message.
    Windows uses ShellExecute (handles .exe/.cmd/.bat/documents, creates a normal console for console programs);
    never launched from an elevated installer helper (callers pass --no-launch to those)."""
    rel = m.get("run_after")
    if not rel: return None
    try:
        exe = vx.safe_join(install_dir, rel)
        if not os.path.exists(exe): return f"'{rel}' was not found in {install_dir}"
        wd = os.path.dirname(exe)
        if IS_WIN:
            try: os.startfile(exe, cwd=wd)            # Python 3.10+
            except TypeError: os.startfile(exe)       # older Python: no cwd argument
        elif IS_MAC:
            subprocess.Popen(["open", exe], cwd=wd, start_new_session=True, **{**_std_kw(), "stdin": subprocess.DEVNULL})
        else:
            cmd = [exe] if os.access(exe, os.X_OK) else ["xdg-open", exe]
            subprocess.Popen(cmd, cwd=wd, start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        vx.LOGGER.info(f"Launched {exe}")
        return None
    except Exception as e:
        return f"{type(e).__name__}: {e}"

def preflight(c: Container, m: dict, opts: Options) -> dict:
    """Validate choices before touching disk. Returns dict(target, scope, existing)."""
    t = resolve_dir(m, opts.location, opts.dir)
    existing = read_record(t["path"])
    if _dir_nonempty(t["path"]) and not existing and not opts.force:
        raise VFAError(f"Destination '{t['path']}' exists and is not empty (not a previous install). Use --force to install anyway.", EXIT_ARGS)
    parent = t["path"]
    while parent and not os.path.exists(parent):
        nxt = os.path.dirname(parent)
        if nxt == parent: break
        parent = nxt
    try:
        free = shutil.disk_usage(parent).free
        need = int(c.total_bytes * 1.1) + (1 << 20)
        if free < need:
            raise VFAError(f"Not enough disk space on '{parent}': need ~{need // (1<<20)} MiB, have {free // (1<<20)} MiB.")
    except OSError: pass
    scope = scope_for(t, opts)
    if existing and existing.get("scope") == "all": t["admin"] = True   # removing/replacing an all-users install needs admin
    if scope == "all": t["admin"] = True   # shortcuts/registry/links for all users need admin; call sites skip elevation if already admin
    return {"target": t, "scope": scope, "existing": existing}

def _remove_old_files(old: dict, new_files: set, install_dir: str):
    for rel in old.get("files", []):
        if rel not in new_files and rel != RECORD_NAME:
            try:
                p = vx.safe_join(install_dir, rel)
                if os.path.isfile(p): os.remove(p)
            except Exception: pass

def do_install(c: Container, m: dict, opts: Options, pre: dict, progress=None, cancel=None,
               exe_path: Optional[str] = None) -> dict:
    L = vx.LOGGER
    target, scope, existing = pre["target"], pre["scope"], pre["existing"]
    dest = target["path"]
    L.info(f"Installing {m['name']} {m.get('version','')} -> {dest} (scope={scope})")
    if opts.dry_run:
        L.info(f"[dry-run] would extract {c.total_files} files ({c.total_bytes} bytes)")
        return {"install_dir": dest, "files": [], "dirs": [], "shortcuts": [], "links": [], "path_entries": [], "registry": []}

    if existing:
        mode = opts.existing
        if mode == "abort":
            raise VFAError(f"{m['name']} v{existing.get('version','?')} is already installed in '{dest}' (--existing abort).", EXIT_CANCEL)
        if mode in ("clean", "remove"):
            L.info(f"Removing existing installation v{existing.get('version','?')} first")
            do_uninstall(dest, Options())
            existing = None
            if mode == "remove":
                L.info("Uninstalled; nothing new installed (--existing remove).")
                return {"install_dir": dest, "removed": True, "files": [], "dirs": [], "shortcuts": [], "links": [], "path_entries": [], "registry": [], "warnings": []}

    parent = os.path.dirname(dest.rstrip("\\/")) or dest
    try:
        os.makedirs(parent, exist_ok=True)
    except PermissionError as e:
        if not is_admin(): raise NeedAdmin(str(e)) from e
        raise
    fresh = existing is None and not _dir_nonempty(dest)
    if fresh and os.path.isdir(dest) and not _clear_leftover_uninstaller(dest):
        fresh = False  # leftover is locked; extract in place instead of renaming over the folder
    staging = None
    try:
        if fresh:
            staging = make_staging_dir(parent)
            files, dirs = c.extract(staging, progress, cancel)
            if os.path.isdir(dest): os.rmdir(dest)  # empty dir; rename needs it absent on Windows
            os.replace(staging, dest); staging = None
        else:
            files, dirs = c.extract(dest, progress, cancel)
            if existing: _remove_old_files(existing, set(files), dest)
    except PermissionError as e:
        if not is_admin(): raise NeedAdmin(str(e)) from e
        raise
    finally:
        if staging: shutil.rmtree(staging, ignore_errors=True)

    rec = {"app_id": app_id_of(m), "name": m["name"], "version": m.get("version", ""),
           "publisher": m.get("publisher", ""), "install_dir": dest, "scope": scope,
           "installed": time.strftime("%Y-%m-%dT%H:%M:%S"), "files": sorted(set(files)),
           "dirs": sorted(set(dirs), key=lambda d: -d.count("/")), "shortcuts": [], "links": [],
           "path_entries": [], "registry": [], "uninstaller": None}
    warnings = []

    # uninstaller = stub only (no payload)
    if m.get("uninstaller", True):
        try:
            up = os.path.join(dest, UNINSTALLER_NAME)
            with open(up, "wb") as f: f.write(c.stub_bytes)
            if not IS_WIN: os.chmod(up, 0o755)
            rec["uninstaller"] = UNINSTALLER_NAME
        except Exception as e: warnings.append(f"uninstaller: {e}")

    # shortcuts
    for sc in m.get("shortcuts", []):
        kind = sc.get("type")
        if kind == "startmenu" and not opts.startmenu: continue
        if kind == "desktop" and not opts.desktop: continue
        if kind not in ("startmenu", "desktop"): continue
        try:
            target_abs = vx.safe_join(dest, sc["target"])
            name = _safe_name(sc.get("name") or m["name"])
            icon_rel = sc.get("icon") or m.get("icon")
            icon_abs = vx.safe_join(dest, icon_rel) if icon_rel else ""
            if IS_WIN:
                folder = win_special_dir(kind, scope)
                if kind == "startmenu" and sc.get("folder", True) and m.get("publisher"):
                    folder = os.path.join(folder, _safe_name(m["publisher"]))
                link = os.path.join(folder, name + ".lnk")
                win_make_shortcut(link, target_abs, sc.get("args", ""), os.path.dirname(target_abs),
                                  icon_abs or target_abs, sc.get("comment", m.get("description", "")))
            elif IS_MAC:
                if kind == "startmenu": continue
                link = os.path.join(posix_desktop_dir(), name)
                if os.path.lexists(link): os.remove(link)
                os.symlink(target_abs, link)
            else:
                folder = posix_desktop_dir() if kind == "desktop" else posix_app_dir(scope)
                link = os.path.join(folder, re.sub(r"\s+", "-", name.lower()) + ".desktop")
                write_desktop_entry(link, name, target_abs, sc.get("args", ""), icon_abs, sc.get("comment", m.get("description", "")),
                                    bool(sc.get("terminal")), sc.get("categories", "Utility;"), os.path.dirname(target_abs))
            rec["shortcuts"].append(link); L.info(f"Shortcut: {link}")
        except Exception as e:
            warnings.append(f"shortcut {sc.get('name')}: {e}")

    # PATH / bin links
    if opts.path:
        if IS_WIN:
            for rel in m.get("path_add", []):
                try:
                    ent = vx.safe_join(dest, rel)
                    if win_path_edit(scope, ent, True):
                        rec["path_entries"].append({"scope": scope, "value": ent}); L.info(f"Added to PATH: {ent}")
                except Exception as e: warnings.append(f"PATH {rel}: {e}")
        else:
            for bl in m.get("bin_links", []):
                try:
                    tgt = vx.safe_join(dest, bl["target"]); bd = posix_bin_dir(scope)
                    os.makedirs(bd, exist_ok=True)
                    lp = os.path.join(bd, _safe_name(bl["name"]))
                    if os.path.lexists(lp): os.remove(lp)
                    os.symlink(tgt, lp); rec["links"].append(lp); L.info(f"Link: {lp} -> {tgt}")
                except Exception as e: warnings.append(f"link {bl.get('name')}: {e}")
            if m.get("path_add") or m.get("bin_links"):
                bd = posix_bin_dir(scope)
                if scope == "user" and bd not in os.environ.get("PATH", "").split(os.pathsep):
                    warnings.append(f"{bd} is not on your PATH; add it to your shell profile to use the installed commands.")

    # Windows Apps & Features entry
    if IS_WIN and rec["uninstaller"]:
        try:
            size_kb = sum(os.path.getsize(os.path.join(dest, f)) for f in rec["files"] if os.path.isfile(os.path.join(dest, f))) // 1024
            rec["registry"].append(win_register_uninstall(m, scope, dest, size_kb))
        except Exception as e: warnings.append(f"registry: {e}")

    if existing:  # keep everything the previous install created so uninstall still removes it
        for k in ("shortcuts", "links", "registry"):
            rec[k] = list(dict.fromkeys(existing.get(k, []) + rec[k]))
        seen = {(p["scope"], p["value"]) for p in rec["path_entries"]}
        rec["path_entries"] += [p for p in existing.get("path_entries", []) if (p["scope"], p["value"]) not in seen]
    with open(os.path.join(dest, RECORD_NAME), "w", encoding="utf-8") as f: json.dump(rec, f, indent=1)
    rec["warnings"] = warnings
    for w in warnings: L.warning(w)

    if opts.launch and m.get("run_after"):
        err = launch_app(m, dest)
        if err: L.warning(f"Could not launch: {err}")
    L.info("Installation complete.")
    return rec

# ---------------- Uninstall ----------------

def _allowed_shortcut_parents(scope: str) -> List[str]:
    out = []
    try:
        if IS_WIN:
            for k in ("startmenu", "desktop"): out.append(os.path.normcase(win_special_dir(k, scope)))
        else:
            out += [posix_app_dir(scope), posix_desktop_dir()]
    except Exception: pass
    return out

def schedule_delete(files, dirs):
    """Windows: delete files that are in use right now (this process, or the uninstaller that launched us).
    A hidden batch retries for up to ~60 s until the owners exit, then removes the (empty) folders and itself.
    Also queues a delete-at-reboot as insurance when we are admin. Never shows a window."""
    q = lambda x: x.replace("%", "%%")
    flist = " ".join(f'"{q(f)}"' for f in files)
    lines = ["@echo off", "set n=0", ":retry",
             f"for %%F in ({flist}) do if exist \"%%~F\" del /f /q \"%%~F\" >nul 2>&1",
             "set left=",
             f"for %%F in ({flist}) do if exist \"%%~F\" set left=1",
             "if not defined left goto done", "set /a n+=1", "if %n% GEQ 60 goto done",
             "ping -n 2 127.0.0.1 >nul", "goto retry", ":done"]
    lines += [f'rmdir "{q(d)}" >nul 2>&1' for d in dirs]
    lines += ['(goto) 2>nul & del /f /q "%~f0"']
    bat = os.path.join(tempfile.gettempdir(), f"vfi-clean-{os.getpid()}.bat")
    with open(bat, "w", encoding="mbcs" if IS_WIN else "utf-8", errors="replace", newline="") as f:
        f.write("\r\n".join(lines) + "\r\n")   # newline="" so the explicit CRLFs are written exactly once
    si = subprocess.STARTUPINFO(); si.dwFlags |= subprocess.STARTF_USESHOWWINDOW; si.wShowWindow = 0  # SW_HIDE
    subprocess.Popen(["cmd.exe", "/d", "/c", bat], startupinfo=si, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=0x08000000 | 0x00000200)  # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP (NOT DETACHED_PROCESS: that re-opens a console)
    if is_admin():
        try:
            import ctypes
            for f in files: ctypes.windll.kernel32.MoveFileExW(f, None, 0x4)  # MOVEFILE_DELAY_UNTIL_REBOOT
        except Exception: pass

def do_uninstall(install_dir: str, opts: Options) -> dict:
    """Remove exactly what uninstall.json says this program created. Paths from the record are re-validated:
    files stay inside install_dir; shortcuts/links must live in the standard folders."""
    L = vx.LOGGER
    rec = read_record(install_dir)
    if not rec: raise VFAError(f"No {RECORD_NAME} in '{install_dir}'; nothing to uninstall.")
    if os.path.normcase(os.path.abspath(rec["install_dir"])) != os.path.normcase(os.path.abspath(install_dir)):
        raise VFAError("Install record does not match this folder; refusing to uninstall.")
    scope = rec.get("scope", "user")
    if scope == "all" and not is_admin():
        raise VFAError("This was an all-users install; administrator rights are required.", EXIT_ELEV)
    removed = 0; left = []
    m = {"name": rec["name"], "app_id": rec["app_id"]}
    if opts.dry_run: L.info("[dry-run] would uninstall"); return rec

    # shortcuts
    ok_parents = _allowed_shortcut_parents(scope)
    for s in rec.get("shortcuts", []):
        try:
            par = os.path.normcase(os.path.dirname(s))
            if not any(par == p or par.startswith(p.rstrip(os.sep) + os.sep) for p in ok_parents):
                L.warning(f"Ignoring shortcut outside standard folders: {s}"); continue
            if os.path.lexists(s): os.remove(s); removed += 1
            d = os.path.dirname(s)
            if IS_WIN and os.path.normcase(d) not in ok_parents:
                try: os.rmdir(d)
                except OSError: pass
        except Exception as e: L.warning(f"shortcut {s}: {e}")
    # links
    for lp in rec.get("links", []):
        try:
            if os.path.dirname(lp) == posix_bin_dir(scope) and os.path.islink(lp) \
               and os.path.realpath(lp).startswith(os.path.realpath(install_dir) + os.sep):
                os.remove(lp); removed += 1
        except Exception as e: L.warning(f"link {lp}: {e}")
    # PATH + registry
    if IS_WIN:
        for pe in rec.get("path_entries", []):
            try:
                v = pe["value"]
                if os.path.normcase(v).startswith(os.path.normcase(os.path.abspath(install_dir))): win_path_edit(scope, v, False)
            except Exception as e: L.warning(f"PATH: {e}")
        try: win_delete_uninstall_key(m, scope)
        except Exception as e: L.warning(f"registry: {e}")
    # files + dirs (confined to install_dir)
    for rel in rec.get("files", []):
        try:
            p = vx.safe_join(install_dir, rel)
            if os.path.lexists(p): os.remove(p); removed += 1
        except Exception as e: left.append(rel); L.warning(f"{rel}: {e}")
    for rel in sorted(rec.get("dirs", []), key=lambda d: -d.count("/")):
        try: os.rmdir(vx.safe_join(install_dir, rel))
        except Exception: pass
    # record + uninstaller last
    try: os.remove(os.path.join(install_dir, RECORD_NAME))
    except Exception: pass
    pending = []   # files that are locked right now (the running exe / the original uninstaller we were launched from)
    un = os.path.join(install_dir, rec.get("uninstaller") or UNINSTALLER_NAME)
    for victim in (un, opts.from_temp):
        if victim and os.path.exists(victim):
            try: os.remove(victim)
            except OSError: pending.append(victim)
    own = os.path.abspath(sys.executable) if FROZEN else None
    dirs_after = [install_dir]
    if IS_WIN and FROZEN and opts.from_temp and own:         # we are the temp copy: remove ourselves + our folder too
        pending.append(own); dirs_after.append(os.path.dirname(own))
    elif IS_WIN and own and os.path.normcase(os.path.dirname(own)) == os.path.normcase(os.path.abspath(install_dir)):
        pending.append(own)                                   # legacy: running straight from the install folder
    if IS_WIN and pending:
        schedule_delete(sorted(set(pending)), dirs_after)
    else:
        try: os.rmdir(install_dir)
        except OSError:
            if os.path.isdir(install_dir) and _dir_nonempty(install_dir):
                L.info(f"Left in place (not installed by this program): {install_dir}")
    L.info(f"Uninstall complete ({removed} items removed).")
    return rec

# ---------------- CLI ----------------

def build_parser():
    from vfa_version import __version__, version_text
    ap = argparse.ArgumentParser(description=f"VFA self-finishing installer (VFA {__version__}; --info shows the "
                                             f"version of what it installs)", add_help=True)
    ap.add_argument("-V", "--version", action="version", version=version_text("vfa-sfi"))
    g = ap.add_argument_group("mode")
    g.add_argument("--gui", action="store_true", help="Force the graphical wizard")
    g.add_argument("--cli", action="store_true", help="Interactive terminal installer")
    g.add_argument("-s", "--silent", "--quiet", action="store_true", dest="silent", help="Unattended: never prompt; use defaults + flags")
    g.add_argument("--uninstall", action="store_true", help="Uninstall a previous installation")
    g.add_argument("--info", action="store_true", help="Show installer info and exit")
    g.add_argument("--list", action="store_true", help="List payload contents and exit")
    g.add_argument("--dry-run", action="store_true", help="Resolve everything, change nothing")
    w = ap.add_argument_group("where / what")
    w.add_argument("--location", choices=["user", "public", "system", "system86"], help="Named install location")
    w.add_argument("-d", "--dir", help="Custom install directory (overrides --location)")
    sc = w.add_mutually_exclusive_group()
    sc.add_argument("--all-users", dest="all_users", action="store_const", const=True, default=None)
    sc.add_argument("--user", dest="all_users", action="store_const", const=False)
    w.add_argument("--desktop", action=argparse.BooleanOptionalAction, default=None, help="Desktop shortcut")
    w.add_argument("--startmenu", action=argparse.BooleanOptionalAction, default=None, help="Start Menu / applications entry")
    w.add_argument("--path", action=argparse.BooleanOptionalAction, default=None, help="Add to PATH / ~/.local/bin")
    w.add_argument("--launch", action=argparse.BooleanOptionalAction, default=None, help="Launch after install")
    w.add_argument("--force", action="store_true", help="Install into a non-empty folder that is not a previous install")
    w.add_argument("--existing", choices=["upgrade", "clean", "remove", "abort"],
                   help="If already installed: upgrade in place (default), clean = uninstall the old version first then install, "
                        "remove = uninstall only, abort = do nothing and exit 4")
    w.add_argument("--accept-license", action="store_true", help="Accept the license (required with --silent if one is shown)")
    p = ap.add_argument_group("encrypted payloads")
    p.add_argument("--password-file", help="Read the password from this file (first line)")
    p.add_argument("--password-env", help="Read the password from this environment variable")
    p.add_argument("--password-stdin", action="store_true", help="Read the password from stdin")
    p.add_argument("--password", action="store_true", help="Prompt for the password (default if encrypted)")
    l = ap.add_argument_group("logging")
    l.add_argument("--log", help="Also write the log to this file")
    l.add_argument("--log-level", choices=["quiet", "error", "warning", "info", "debug", "trace"], default=None)
    l.add_argument("-v", "--verbose", action="store_true", help="Shortcut for --log-level info")
    ap.add_argument("--from-file", help="Debug: read container from this path instead of this executable")
    ap.add_argument("--autostart", action="store_true", help=argparse.SUPPRESS)  # GUI after elevation
    ap.add_argument("--from-temp", help=argparse.SUPPRESS)  # uninstall: path of the original uninstaller we were copied from
    return ap

def get_password(args, interactive: bool) -> Optional[str]:
    if args.password_env:
        v = os.environ.get(args.password_env)
        if v is None: raise VFAError(f"Environment variable {args.password_env} is not set.", EXIT_PASSWORD)
        return v
    if args.password_file:
        try:
            with open(args.password_file, "r", encoding="utf-8") as f: return f.readline().rstrip("\r\n")
        except OSError as e: raise VFAError(f"Cannot read password file: {e}", EXIT_PASSWORD)
    if args.password_stdin: return sys.stdin.readline().rstrip("\r\n")
    if interactive: return vx.prompt_password("Password: ")
    return None

def make_options(args, m: dict) -> Options:
    d = m["defaults"]
    pick = lambda a, k: a if a is not None else bool(d.get(k))
    o = Options(location=args.location, dir=args.dir, all_users=args.all_users,
                desktop=pick(args.desktop, "desktop"), startmenu=pick(args.startmenu, "startmenu"),
                path=pick(args.path, "path"), launch=pick(args.launch, "launch"),
                force=args.force, dry_run=args.dry_run, existing=args.existing or "upgrade")
    return o

def display_available() -> bool:
    if IS_WIN or IS_MAC: return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))

def hide_owned_console():
    """Double-clicked console exe on Windows: hide the console window if we are its only process."""
    if not IS_WIN: return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        buf = (ctypes.c_uint * 4)()
        if k.GetConsoleProcessList(buf, 4) <= 1:
            hwnd = k.GetConsoleWindow()
            if hwnd: ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception: pass

def _ask(prompt: str, default: str = "") -> str:
    r = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return r or default

def _yn(prompt: str, default: bool) -> bool:
    r = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not r else r.startswith("y")

def run_cli(c: Container, m: dict, args, opts: Options, interactive: bool) -> int:
    L = vx.LOGGER
    pw = get_password(args, interactive and c.encrypted) if c.encrypted else None
    if c.encrypted and pw is None:
        raise VFAError("Payload is encrypted. Supply --password-file, --password-env or --password-stdin (or run interactively).", EXIT_PASSWORD)
    c.unlock(pw)
    if m.get("license"):
        if interactive:
            print("\n" + m["license"] + "\n")
            if not _yn("Do you accept the license?", False): raise VFAError("License not accepted.", EXIT_CANCEL)
        elif not args.accept_license:
            raise VFAError("A license must be accepted: pass --accept-license.", EXIT_ARGS)
    if interactive:
        print(f"\n{m['name']} {m.get('version','')}  -  {m.get('publisher','')}\n{m.get('description','')}\n")
        if not args.dir and not args.location:
            tbl = location_table(m); keys = list(tbl)
            for i, k in enumerate(keys, 1): print(f"  {i}) {tbl[k]['label']:<48} {tbl[k]['path']}" + ("  [admin]" if tbl[k]['admin'] else ""))
            print(f"  {len(keys)+1}) Custom folder")
            dflt = keys.index(m["default_location"]) + 1 if m["default_location"] in keys else 1
            ch = _ask("Install location", str(dflt))
            if ch.isdigit() and 1 <= int(ch) <= len(keys): opts.location = keys[int(ch) - 1]
            else: opts.dir = _ask("Folder path")
        if args.desktop is None and any(s.get("type") == "desktop" for s in m["shortcuts"]): opts.desktop = _yn("Create a desktop shortcut?", opts.desktop)
        if args.startmenu is None and any(s.get("type") == "startmenu" for s in m["shortcuts"]): opts.startmenu = _yn("Create a Start Menu / applications entry?", opts.startmenu)
        if args.path is None and (m["path_add"] or m["bin_links"]): opts.path = _yn("Add to PATH?", opts.path)
        if args.launch is None and m.get("run_after"): opts.launch = _yn("Launch after install?", opts.launch)
    pre = preflight(c, m, opts)
    if pre["existing"] and interactive and not args.existing:
        print(f"\n{m['name']} v{pre['existing'].get('version','?')} is already installed in {pre['target']['path']}")
        print("  [U] Upgrade - replace it with this version (default)")
        print("  [C] Clean   - uninstall the old version first, then install this one")
        print("  [R] Remove  - just uninstall the old version, install nothing")
        print("  [A] Abort")
        ch = _ask("Choice", "U").strip().lower()[:1]
        if ch == "a": raise VFAError("Cancelled.", EXIT_CANCEL)
        opts.existing = {"c": "clean", "r": "remove"}.get(ch, "upgrade")
    if pre["existing"]: L.info(f"Existing install v{pre['existing'].get('version','?')} found; mode: {opts.existing}")
    if pre["target"]["admin"] and not is_admin() and not opts.dry_run:
        code = relaunch_elevated(_elev_args(args, opts, pre))
        if code == EXIT_OK and opts.launch and m.get("run_after"):
            err = launch_app(m, pre["target"]["path"])
            if err: L.warning(f"Could not launch: {err}")
        return code
    r = c.verify_digest()
    if r is False: raise VFAError("Integrity check FAILED: the installer is corrupted or was modified.")
    L.info({True: "Integrity check OK", None: "Integrity check skipped"}[r])
    last = {"t": 0.0}
    def prog(df, tf, db, tb, name):
        if interactive and sys.stdout and time.time() - last["t"] > 0.1:
            last["t"] = time.time(); print(f"\r  {df}/{tf} files  {db*100//max(tb,1)}%   ", end="", flush=True)
    try:
        rec = do_install(c, m, opts, pre, progress=prog)
    except NeedAdmin:
        if interactive: print()
        L.info("Permission denied; retrying with administrator rights.")
        pre["target"]["admin"] = True
        code = relaunch_elevated(_elev_args(args, opts, pre))
        if code == EXIT_OK and opts.launch and m.get("run_after"):
            err = launch_app(m, pre["target"]["path"])
            if err: L.warning(f"Could not launch: {err}")
        return code
    if interactive: print()
    return EXIT_OK

def _elev_args(args, opts: Options, pre: dict) -> List[str]:
    """Rebuild a command line for the elevated child from the resolved choices."""
    a = []
    if args.from_file: a += ["--from-file", args.from_file]
    for flag in ("silent", "cli", "gui"):
        if getattr(args, flag, False): a.append("--" + flag)
    if args.gui or not (args.silent or args.cli): a += ["--gui"] if "--gui" not in a else []; a.append("--autostart")
    a += ["--dir", pre["target"]["path"]]
    if pre["scope"] == "all": a.append("--all-users")
    for n in ("desktop", "startmenu", "path"):
        a.append(("--" if getattr(opts, n) else "--no-") + n)
    a.append("--no-launch")   # never start the app from an elevated helper; the original (unelevated) process does it
    if opts.force: a.append("--force")
    if pre.get("existing"): a += ["--existing", opts.existing]
    if args.accept_license: a.append("--accept-license")
    for n in ("password_file", "password_env"):
        v = getattr(args, n, None)
        if v: a += ["--" + n.replace("_", "-"), v]
    if args.log: a += ["--log", args.log]
    if args.log_level: a += ["--log-level", args.log_level]
    return a

def main(argv=None) -> int:
    attach_parent_console()
    ap = build_parser(); args = ap.parse_args(argv)
    level = args.log_level or ("info" if args.verbose else ("error" if args.silent else "warning"))
    logf = None
    if args.log:
        logf = open(args.log, "a", encoding="utf-8")
        sink = lambda line: (logf.write(line + "\n"), logf.flush())
        if not args.log_level and level in ("quiet", "error"): level = "info"
    else: sink = None
    vx.set_logger(VLog(level, tag="SFI", sink=sink))
    L = vx.LOGGER
    exe = args.from_file or sys.executable
    try:
        opts_dry = args.dry_run
        base = os.path.basename(exe).lower()
        # ---- uninstall ----
        if args.uninstall or (base.startswith("uninstall") and read_record(os.path.dirname(os.path.abspath(exe)))):
            idir = args.dir or os.path.dirname(os.path.abspath(exe))
            rec = read_record(idir)
            own = os.path.abspath(sys.executable)
            if IS_WIN and FROZEN and not args.from_temp and not args.dry_run and rec \
               and os.path.normcase(os.path.dirname(own)) == os.path.normcase(os.path.abspath(idir)) \
               and not (rec.get("scope") == "all" and not is_admin()):
                # run from a temp copy so the install folder (including this very exe) can be deleted
                if not args.silent and not args.cli and display_available(): hide_owned_console()
                tdir = tempfile.mkdtemp(prefix="vfi-un-"); tcopy = os.path.join(tdir, UNINSTALLER_NAME)
                shutil.copy2(own, tcopy)
                return subprocess.call([tcopy] + sys.argv[1:] + (["--uninstall"] if "--uninstall" not in sys.argv else [])
                                       + ["--dir", idir, "--from-temp", own], **_std_kw())
            if rec and rec.get("scope") == "all" and not is_admin() and not args.dry_run:
                return relaunch_elevated([a for a in sys.argv[1:]] + (["--uninstall"] if "--uninstall" not in sys.argv else []))
            if not args.silent and not args.cli:
                if display_available():
                    try:
                        import sfi_gui
                    except ImportError:
                        sfi_gui = None
                    if sfi_gui:
                        hide_owned_console()
                        return sfi_gui.run_uninstall(sys.modules[__name__], idir, rec, Options(from_temp=args.from_temp))
                if not _yn(f"Uninstall {rec['name'] if rec else 'this application'} from {idir}?", False): return EXIT_CANCEL
            do_uninstall(idir, Options(dry_run=args.dry_run, from_temp=args.from_temp)); return EXIT_OK

        # ---- everything else needs the payload ----
        with vx.open_container(exe) as c:
            m = load_manifest(c, exe)
            if args.info or args.list:
                print(f"{m['name']} {m.get('version','')}  {m.get('publisher','')}")
                fmt = c.summary() if hasattr(c, "summary") else f"VFA1 method={c.header['default_method']}"
                print(f"payload: {fmt} solid={c.solid} encrypted={c.encrypted}")
                print("locations:"); [print(f"  {k:<9} {v['path']}" + ("  [admin]" if v["admin"] else "")) for k, v in location_table(m).items()]
                if args.list:
                    c.unlock(get_password(args, c.encrypted and not args.silent) if c.encrypted else None)
                    for e in c.entries:
                        if not e["path"].startswith(vx.MANIFEST_RESERVED_PREFIX): print(f"  {e['size']:>12}  {e['path']}")
                return EXIT_OK
            opts = make_options(args, m)
            interactive = not args.silent
            use_gui = (args.gui or (not args.cli and not args.silent)) and display_available()
            if use_gui:
                try:
                    import sfi_gui
                except ImportError as e:
                    L.warning(f"GUI unavailable ({e}); falling back to CLI."); use_gui = False
            if use_gui:
                hide_owned_console()
                return sfi_gui.run_wizard(sys.modules[__name__], c, m, args, opts)
            if not sys.stdin or not sys.stdin.isatty(): interactive = False if (not args.cli or not sys.stdin) else interactive
            return run_cli(c, m, args, opts, interactive)
    except Exception as e:
        if not isinstance(e, VFAError):
            L.error("Unexpected error:\n" + traceback.format_exc())
            if IS_WIN and not args.silent and not args.cli:
                try:
                    import tkinter, tkinter.messagebox as mb; r = tkinter.Tk(); r.withdraw()
                    mb.showerror("Installer", f"Unexpected error: {type(e).__name__}: {e}\n\nDetails are in the log if you used --log."); r.destroy()
                except Exception: pass
            return EXIT_ERR
        L.error(str(e))
        if IS_WIN and not args.silent and not args.cli:  # double-clicked: nobody sees the console
            try:
                import tkinter, tkinter.messagebox as mb; r = tkinter.Tk(); r.withdraw(); mb.showerror("Installer", str(e)); r.destroy()
            except Exception: pass
        return e.code
    finally:
        if logf: logf.close()

if __name__ == "__main__":
    sys.exit(main())
