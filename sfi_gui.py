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
"""tkinter wizard for the SFI stub. Pure stdlib so the stub stays a single file.

The stub module is passed in as `S` (avoids a circular import when the stub runs as __main__).
"""

import os, sys, threading, queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

import vfa_extract as vx
from vfa_extract import VFAError


def _fmt_bytes(n):
    for u in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or u == "GiB": return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


class ExistingDialog(tk.Toplevel):
    """Modal: what to do about an installation that is already there. .result is upgrade|clean|remove or None (cancel)."""
    def __init__(self, parent, name, version, path):
        super().__init__(parent); self.title("Existing installation"); self.resizable(False, False)
        self.result = None; self.var = tk.StringVar(value="upgrade")
        f = ttk.Frame(self, padding=16); f.pack(fill="both", expand=True)
        ttk.Label(f, text=f"{name} {('v' + version) if version else ''} is already installed in:", wraplength=420, justify="left").pack(anchor="w")
        ttk.Label(f, text=path, foreground="#555", wraplength=420, justify="left").pack(anchor="w", pady=(0, 10))
        for val, txt in (("upgrade", "Upgrade - replace it with this version"),
                         ("clean", "Remove the old version first, then install fresh"),
                         ("remove", "Just uninstall the old version (install nothing)")):
            ttk.Radiobutton(f, text=txt, value=val, variable=self.var).pack(anchor="w", pady=2)
        ttk.Label(f, text="Only files, shortcuts and entries created by the old install are removed.", foreground="#555").pack(anchor="w", pady=(8, 0))
        b = ttk.Frame(f); b.pack(fill="x", pady=(14, 0))
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(b, text="Continue", command=self.ok).pack(side="right", padx=6)
        self.transient(parent); self.grab_set(); self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2; y = parent.winfo_rooty() + 60
        self.geometry(f"+{max(x,0)}+{max(y,0)}")
    def ok(self): self.result = self.var.get(); self.destroy()


class Wizard(tk.Tk):
    def __init__(self, S, c, m, args, opts):
        super().__init__()
        self.S, self.c, self.m, self.args, self.opts = S, c, m, args, opts
        self.title(f"{m['name']} Setup"); self.geometry("560x420"); self.minsize(520, 380)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.cancelled = False; self.exit_code = S.EXIT_CANCEL; self.worker = None; self.q = queue.Queue()
        self.password = None; self.unlocked = False; self.install_dir = None
        self.removed = False; self.done_title = None

        # variables
        tbl = S.location_table(m)
        self.loc_var = tk.StringVar(value=opts.location or ("custom" if opts.dir else (m["default_location"] if m["default_location"] in tbl else next(iter(tbl), "custom"))))
        self.custom_var = tk.StringVar(value=opts.dir or "")
        self.desktop_var = tk.BooleanVar(value=opts.desktop); self.start_var = tk.BooleanVar(value=opts.startmenu)
        self.path_var = tk.BooleanVar(value=opts.path); self.launch_var = tk.BooleanVar(value=opts.launch)
        self.accept_var = tk.BooleanVar(value=bool(args.accept_license))
        self.pw_var = tk.StringVar()

        # chrome
        head = ttk.Frame(self, padding=(16, 12)); head.pack(fill="x")
        self.h_title = ttk.Label(head, font=("TkDefaultFont", 14, "bold")); self.h_title.pack(anchor="w")
        self.h_sub = ttk.Label(head, foreground="#555"); self.h_sub.pack(anchor="w")
        ttk.Separator(self).pack(fill="x")
        self.body = ttk.Frame(self, padding=16); self.body.pack(fill="both", expand=True)
        ttk.Separator(self).pack(fill="x")
        foot = ttk.Frame(self, padding=(16, 10)); foot.pack(fill="x")
        self.btn_cancel = ttk.Button(foot, text="Cancel", command=self.on_cancel); self.btn_cancel.pack(side="right")
        self.btn_next = ttk.Button(foot, text="Next >", command=self.on_next); self.btn_next.pack(side="right", padx=6)
        self.btn_back = ttk.Button(foot, text="< Back", command=self.on_back); self.btn_back.pack(side="right")

        self.pages = ["welcome"] + (["license"] if m.get("license") else []) + ["where", "options", "progress", "done"]
        self.idx = 0
        if args.autostart:
            self.after(50, self.autostart)
        else:
            self.show()

    def report_callback_exception(self, exc, val, tb):
        """tkinter swallows errors in callbacks (they only go to a console nobody sees); log them and tell the user."""
        import traceback
        vx.LOGGER.error("Unexpected error in wizard:\n" + "".join(traceback.format_exception(exc, val, tb)))
        try: messagebox.showerror("Unexpected error", f"{exc.__name__}: {val}\n\nDetails are in the log if you used --log.")
        except Exception: pass

    # ---------- navigation ----------
    def clear(self):
        for w in self.body.winfo_children(): w.destroy()

    def show(self):
        page = self.pages[self.idx]; self.clear()
        getattr(self, "page_" + page)()
        self.btn_back.state(["!disabled"] if page in ("license", "where", "options") else ["disabled"])
        self.btn_next.configure(text={"options": "Install", "done": "Finish"}.get(page, "Next >"))
        self.btn_next.state(["!disabled"] if page not in ("progress",) else ["disabled"])
        self.btn_cancel.state(["disabled"] if page == "done" else ["!disabled"])
        if page == "license": self.update_license_btn()

    def on_back(self):
        if self.idx > 0: self.idx -= 1; self.show()

    def on_next(self):
        page = self.pages[self.idx]
        if page == "where" and not self.validate_where(): return
        if page == "options": self.begin_install(); return
        if page == "done": self.finish(); return
        self.idx += 1; self.show()

    def finish(self):
        """Finish button: optionally launch the app (from this normal, unelevated process), then close."""
        if self.exit_code == self.S.EXIT_OK and self.launch_var.get() and self.m.get("run_after") and self.install_dir \
           and not self.removed and not self.args.autostart:
            err = self.S.launch_app(self.m, self.install_dir)
            if err:
                messagebox.showerror("Launch", f"Could not start {self.m['name']}:\n{err}"); return
        self.destroy()

    def on_cancel(self):
        page = self.pages[self.idx]
        if page == "progress" and self.worker and self.worker.is_alive():
            if messagebox.askyesno("Cancel", "Stop the installation? Nothing will be left half-installed."):
                self.cancelled = True
            return
        if page == "done": self.destroy(); return
        if messagebox.askyesno("Exit", f"Exit {self.m['name']} setup?"): self.destroy()

    def header(self, title, sub=""):
        self.h_title.configure(text=title); self.h_sub.configure(text=sub)

    # ---------- pages ----------
    def page_welcome(self):
        m = self.m
        self.header(f"Welcome to {m['name']}", " ".join(x for x in (f"Version {m['version']}" if m.get("version") else "", f"by {m['publisher']}" if m.get("publisher") else "") if x))
        ttk.Label(self.body, text=m.get("description") or f"This wizard will install {m['name']} on your computer.", wraplength=500, justify="left").pack(anchor="w")
        info = f"\nPayload: {self.c.size // 1024:,} KiB" + ("   (password protected)" if self.c.encrypted else "")
        ttk.Label(self.body, text=info, foreground="#555").pack(anchor="w")
        existing = None
        try:
            t = self.S.resolve_dir(m, self.opts.location, self.opts.dir); existing = self.S.read_record(t["path"])
        except Exception: pass
        if existing:
            ttk.Label(self.body, text=f"\nAn existing installation (v{existing.get('version','?')}) was found. You will be asked whether to upgrade or remove it.", foreground="#a60", wraplength=500, justify="left").pack(anchor="w")

    def page_license(self):
        self.header("License Agreement", "Please read and accept to continue.")
        t = tk.Text(self.body, wrap="word", height=10); t.insert("1.0", self.m["license"]); t.configure(state="disabled")
        sb = ttk.Scrollbar(self.body, command=t.yview); t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); t.pack(fill="both", expand=True)
        ttk.Checkbutton(self.body, text="I accept the terms of the license", variable=self.accept_var,
                        command=self.update_license_btn).pack(side="bottom", anchor="w", pady=(8, 0))

    def update_license_btn(self):
        if self.pages[self.idx] == "license":
            self.btn_next.state(["!disabled"] if self.accept_var.get() else ["disabled"])

    def page_where(self):
        S = self.S
        self.header("Install location", "Choose where to install.")
        tbl = S.location_table(self.m)
        for k, v in tbl.items():
            f = ttk.Frame(self.body); f.pack(fill="x", pady=2)
            ttk.Radiobutton(f, text=v["label"] + ("   (administrator)" if v["admin"] else ""), value=k, variable=self.loc_var, command=self.refresh_where).pack(anchor="w")
            ttk.Label(f, text=v["path"], foreground="#555").pack(anchor="w", padx=22)
        if "custom" in (self.m.get("allow_locations") or ["custom"]):
            f = ttk.Frame(self.body); f.pack(fill="x", pady=2)
            ttk.Radiobutton(f, text="Custom folder", value="custom", variable=self.loc_var, command=self.refresh_where).pack(anchor="w")
            r = ttk.Frame(f); r.pack(fill="x", padx=22)
            self.custom_entry = ttk.Entry(r, textvariable=self.custom_var); self.custom_entry.pack(side="left", fill="x", expand=True)
            self.browse_btn = ttk.Button(r, text="Browse...", command=self.browse); self.browse_btn.pack(side="left", padx=(6, 0))
        if self.c.encrypted:
            ttk.Separator(self.body).pack(fill="x", pady=8)
            r = ttk.Frame(self.body); r.pack(fill="x")
            ttk.Label(r, text="Password:").pack(side="left")
            ttk.Entry(r, textvariable=self.pw_var, show="*").pack(side="left", fill="x", expand=True, padx=6)
        self.space_lbl = ttk.Label(self.body, foreground="#555"); self.space_lbl.pack(anchor="w", pady=(8, 0))
        self.refresh_where()

    def refresh_where(self):
        custom = self.loc_var.get() == "custom"
        if hasattr(self, "custom_entry"):
            st = "normal" if custom else "disabled"
            try: self.custom_entry.configure(state=st); self.browse_btn.configure(state=st)
            except tk.TclError: pass
        try:
            p = self.current_target()["path"]
            import shutil
            q = p
            while q and not os.path.exists(q):
                n = os.path.dirname(q)
                if n == q: break
                q = n
            self.space_lbl.configure(text=f"Needs about {_fmt_bytes(self.c.size)} (installed size may be larger). Free space: {_fmt_bytes(shutil.disk_usage(q).free)}")
        except Exception: self.space_lbl.configure(text="")

    def browse(self):
        d = filedialog.askdirectory(title="Choose install folder", initialdir=self.custom_var.get() or os.path.expanduser("~"))
        if d: self.custom_var.set(os.path.join(d, self.S._safe_name(self.m.get("subdir") or self.m["name"])) if os.listdir(d) else d)

    def current_target(self):
        if self.loc_var.get() == "custom":
            return self.S.resolve_dir(self.m, None, self.custom_var.get() or None) if self.custom_var.get() else {"id": "custom", "path": "", "admin": False}
        return self.S.resolve_dir(self.m, self.loc_var.get(), None)

    def validate_where(self):
        try:
            t = self.current_target()
            if not t["path"]: raise VFAError("Choose a folder.")
        except VFAError as e:
            messagebox.showerror("Install location", str(e)); return False
        if self.c.encrypted and not self.unlocked:
            self.config(cursor="watch"); self.update_idletasks()
            try:
                self.c.unlock(self.pw_var.get()); self.password = self.pw_var.get(); self.unlocked = True
            except VFAError as e:
                self.config(cursor=""); messagebox.showerror("Password", str(e)); return False
            self.config(cursor="")
        elif not self.c.encrypted and not self.unlocked:
            self.c.unlock(None); self.unlocked = True
        return True

    def page_options(self):
        S, m = self.S, self.m
        self.header("Options", "Choose what to set up.")
        kinds = {s.get("type") for s in m.get("shortcuts", [])}
        if "desktop" in kinds: ttk.Checkbutton(self.body, text="Create a desktop shortcut", variable=self.desktop_var).pack(anchor="w", pady=3)
        if "startmenu" in kinds:
            ttk.Checkbutton(self.body, text="Create a Start Menu entry" if S.IS_WIN else "Add to the applications menu", variable=self.start_var).pack(anchor="w", pady=3)
        if m.get("path_add") or m.get("bin_links"):
            ttk.Checkbutton(self.body, text="Add to PATH" if S.IS_WIN else "Add commands to your PATH", variable=self.path_var).pack(anchor="w", pady=3)
        t = self.current_target()
        ttk.Separator(self.body).pack(fill="x", pady=10)
        ttk.Label(self.body, text=f"Install to:\n{t['path']}" + ("\n(administrator permission will be requested)" if t["admin"] and not S.is_admin() else ""),
                  justify="left", wraplength=500).pack(anchor="w")

    def page_progress(self):
        self.header(f"Installing {self.m['name']}", "Please wait...")
        self.pbar = ttk.Progressbar(self.body, maximum=100); self.pbar.pack(fill="x", pady=(20, 6))
        self.status = ttk.Label(self.body, text="Preparing...", foreground="#555"); self.status.pack(anchor="w")

    def page_done(self):
        ok = self.exit_code == self.S.EXIT_OK
        self.header((self.done_title or "Installation complete") if ok else "Installation failed", "" if ok else "Nothing was changed.")
        txt = self.done_text
        ttk.Label(self.body, text=txt, wraplength=500, justify="left").pack(anchor="w")
        if ok and self.m.get("run_after") and not self.args.autostart and not self.removed:
            ttk.Separator(self.body).pack(fill="x", pady=10)
            ttk.Checkbutton(self.body, text=f"Launch {self.m['name']}", variable=self.launch_var).pack(anchor="w")

    # ---------- install ----------
    def collect(self):
        o = self.opts
        t = self.current_target()
        if self.loc_var.get() == "custom": o.dir, o.location = t["path"], None
        else: o.dir, o.location = None, self.loc_var.get()
        o.desktop, o.startmenu, o.path = (v.get() for v in (self.desktop_var, self.start_var, self.path_var))
        o.launch = False   # launching happens on the Finish page, from this unelevated process
        return o

    def autostart(self):
        """Elevated relaunch: options came from flags; only ask for the password."""
        S, c = self.S, self.c
        try:
            if c.encrypted:
                pw = S.get_password(self.args, False) or simpledialog.askstring("Password", f"Password for {self.m['name']}:", show="*", parent=self)
                if pw is None: self.exit_code = S.EXIT_CANCEL; self.destroy(); return
                c.unlock(pw)
            else: c.unlock(None)
            self.unlocked = True
        except VFAError as e:
            messagebox.showerror("Password", str(e)); self.exit_code = e.code; self.destroy(); return
        self.idx = self.pages.index("progress"); self.show(); self.start_worker(self.opts)

    def begin_install(self):
        o = self.collect()
        self.removed = False; self.done_title = None
        try:
            pre = self.S.preflight(self.c, self.m, o)
        except VFAError as e:
            messagebox.showerror("Cannot install", str(e)); return
        if pre["existing"] and not self.args.existing:
            d = ExistingDialog(self, self.m["name"], pre["existing"].get("version", ""), pre["target"]["path"])
            self.wait_window(d)
            if d.result is None: return
            o.existing = d.result
        if pre["target"]["admin"] and not self.S.is_admin() and not o.dry_run:
            self.elevate(o, pre); return
        self.idx = self.pages.index("progress"); self.show(); self.start_worker(o, pre)

    def elevate(self, o, pre):
        """Run the install in an elevated copy of this program (UAC). Shows the result on the Finish page."""
        self.withdraw()
        code = self.S.relaunch_elevated(self.S._elev_args(self.args, o, pre))
        self.install_dir = pre["target"]["path"]
        self.exit_code = code; self.deiconify()
        removing = o.existing == "remove" and bool(pre.get("existing"))
        if code == self.S.EXIT_OK and removing:
            self.removed = True; self.done_title = "Uninstall complete"
            self.done_text = f"The previous installation of {self.m['name']} was removed from:\n{self.install_dir}"
        else:
            self.done_text = "Finished with administrator permission." if code == self.S.EXIT_OK else \
            f"The elevated installer did not finish (exit code {code}). If you declined the permission prompt, nothing was installed."
        self.idx = self.pages.index("done"); self.show()

    def start_worker(self, o, pre=None):
        def work():
            try:
                p = pre or self.S.preflight(self.c, self.m, o)
                self.q.put(("status", "Verifying integrity..."))
                if self.c.verify_digest() is False: raise VFAError("Integrity check FAILED: the installer is corrupted or modified.")
                def prog(df, tf, db, tb, name): self.q.put(("prog", (df, tf, db, tb, name)))
                rec = self.S.do_install(self.c, self.m, o, p, progress=prog, cancel=lambda: self.cancelled)
                self.q.put(("ok", rec))
            except self.S.NeedAdmin: self.q.put(("needadmin", (o, p)))
            except VFAError as e: self.q.put(("err", (str(e), e.code)))
            except Exception as e: self.q.put(("err", (f"{type(e).__name__}: {e}", 1)))
        self.worker = threading.Thread(target=work, daemon=True); self.worker.start(); self.after(50, self.poll)

    def poll(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "status": self.status.configure(text=val)
                elif kind == "prog":
                    df, tf, db, tb, name = val; self.pbar["value"] = db * 100 / max(tb, 1)
                    self.status.configure(text=f"{df}/{tf} files  -  {name}"[:90])
                elif kind == "needadmin":
                    o, p = val; p["target"]["admin"] = True; self.elevate(o, p); return
                elif kind == "ok":
                    self.exit_code = self.S.EXIT_OK; self.install_dir = val.get("install_dir")
                    w = val.get("warnings") or []
                    self.removed = bool(val.get("removed"))
                    if self.removed:
                        self.done_title = "Uninstall complete"
                        self.done_text = f"The previous installation of {self.m['name']} was removed from:\n{val['install_dir']}"
                    else:
                        self.done_text = f"{self.m['name']} was installed to:\n{val['install_dir']}" + ("\n\nNotes:\n- " + "\n- ".join(w) if w else "")
                    self.idx = self.pages.index("done"); self.show()
                    if self.args.autostart: self.after(1500, self.destroy)
                    return
                elif kind == "err":
                    msg, code = val; self.exit_code = code if code else 1
                    self.done_text = ("Installation cancelled." if code == self.S.EXIT_CANCEL else msg)
                    self.idx = self.pages.index("done"); self.show(); return
        except queue.Empty: pass
        self.after(50, self.poll)


def run_wizard(S, c, m, args, opts) -> int:
    vx.LOGGER.info(f"Wizard opened for {m['name']} {m.get('version','')}")
    w = Wizard(S, c, m, args, opts)
    w.mainloop()
    return w.exit_code


def run_uninstall(S, install_dir, rec, opts=None) -> int:
    root = tk.Tk(); root.withdraw()
    name = rec["name"] if rec else "this application"
    if not rec:
        messagebox.showerror("Uninstall", f"No installation record found in\n{install_dir}"); root.destroy(); return S.EXIT_ERR
    if not messagebox.askyesno(f"Uninstall {name}", f"Remove {name} from\n{install_dir}?"):
        root.destroy(); return S.EXIT_CANCEL
    try:
        S.do_uninstall(install_dir, opts or S.Options())
        messagebox.showinfo("Uninstall", f"{name} was removed."); code = S.EXIT_OK
    except VFAError as e:
        messagebox.showerror("Uninstall", str(e)); code = e.code
    root.destroy(); return code
