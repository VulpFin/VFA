#!/usr/bin/env python3
# Tiny VFA Viewer / Extractor (Tkinter)
# Features: open .vfa, prompt password if encrypted, list entries, test, extract selected/all.
# Requires: cryptography, zstandard, brotli (depending on methods used in your archives)

import os, io, sys, struct, time, json, stat, hashlib
try:                                          # optional until the window opens: --version works without Tk
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    _TK_PROBLEM = None
except ImportError as _e:                     # e.g. a headless Linux without the python3-tk package
    tk = ttk = filedialog = messagebox = None
    _TK_PROBLEM = _e

from vfa_version import __version__, version_text, show
import vfa_extract as vx                      # the shared, validated reader (also used by vfa.py and the stubs)
from vfa_extract import METHOD_NAMES, VFAError

class VFAArchive:
    """GUI-facing wrapper around vfa_extract.Container."""
    def __init__(self, path:str):
        self.path = path
        self.header=None
        self.entries=[]
        self.encrypted=False; self.solid=False
        self._c=None

    def open(self, password:str|None=None):
        c = vx.open_container(self.path)     # VFA1 or VFA2
        try:
            self.header, self.encrypted, self.solid = c.header, c.encrypted, c.solid
            if self.encrypted and password is None:
                raise RuntimeError("Password required")
            self.entries = c.unlock(password)
        except Exception:
            c.close(); raise
        if self._c: self._c.close()
        self._c = c

    def describe(self)->str:
        if hasattr(self._c, "summary"): return self._c.summary()          # VFA2
        return f"method={METHOD_NAMES.get(self.header['default_method'])} lvl={self.header['default_level']}"

    def test(self)->str:
        """Full check: footer digest, then every block (size, and CRC32 when the archive has them)."""
        ok = self._c.verify_digest()
        if ok is False:
            raise RuntimeError("Integrity check FAILED: the archive is corrupted or was modified.")
        st = self._c.test()
        crc = "CRC32 verified" if self._c.has_tocx else "no block CRCs (VFA 1.0 archive)"
        return (f"{'Solid' if self.solid else 'Non-solid'} OK. Blocks checked={st['blocks']}, data={st['bytes']} bytes, "
                f"digest={'OK' if ok else 'none stored'}, {crc}.")

    def extract_selected(self, outdir:str, selected_paths:list[str]):
        # a selected directory brings everything below it; every path is validated before writing
        self._c.extract(outdir, members=selected_paths)

class Viewer(ttk.Frame if ttk else object):
    def __init__(self, master):
        super().__init__(master)
        self.pack(fill="both", expand=True)
        self.master.title(f"VFA Viewer {__version__}")
        self.archive = None
        self.create_widgets()

    def create_widgets(self):
        # Toolbar
        tb = ttk.Frame(self); tb.pack(side="top", fill="x")
        ttk.Button(tb, text="Open", command=self.on_open).pack(side="left", padx=4, pady=4)
        ttk.Button(tb, text="Test", command=self.on_test, state="disabled").pack(side="left", padx=4)
        ttk.Button(tb, text="Extract Selected", command=self.on_extract_sel, state="disabled").pack(side="left", padx=4)
        ttk.Button(tb, text="Extract All", command=self.on_extract_all, state="disabled").pack(side="left", padx=4)
        ttk.Label(tb, text="Filter:").pack(side="left", padx=(12,4))
        self.filter_var = tk.StringVar()
        e = ttk.Entry(tb, textvariable=self.filter_var, width=30); e.pack(side="left", padx=4)
        e.bind("<KeyRelease>", lambda ev: self.apply_filter())

        # Info
        self.info = tk.StringVar(value="Open a .vfa to view contents.")
        ttk.Label(self, textvariable=self.info, anchor="w").pack(side="top", fill="x", padx=8)

        # Table
        cols=("path","size","type","mtime")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c, command=lambda c=c: self.sort_by(c, False))
            self.tree.column(c, stretch=True, width=220 if c=="path" else 100)
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        # Status
        self.status = tk.StringVar(value="")
        sb = ttk.Label(self, textvariable=self.status, anchor="w")
        sb.pack(side="bottom", fill="x")

        # save buttons for enabling/disabling
        self.btn_test = self.children[self.children_keys()[0]].winfo_children()[1]
        self.btn_ex_sel = self.children[self.children_keys()[0]].winfo_children()[2]
        self.btn_ex_all = self.children[self.children_keys()[0]].winfo_children()[3]

    def children_keys(self):
        return list(self.children.keys())

    def on_open(self):
        path = filedialog.askopenfilename(title="Open VFA", filetypes=[("VFA archives","*.vfa"),("All files","*.*")])
        if not path: return
        arc = VFAArchive(path)
        password=None
        try:
            arc.open(password=None)
        except Exception as e:
            # If encrypted, prompt
            if "Password required" in str(e):
                pw = self.prompt_password()
                if pw is None: return
                arc.open(password=pw)
            else:
                messagebox.showerror("Error", f"Failed to open archive:\n{e}")
                return
        self.archive = arc
        self.populate_table()
        total_files = sum(1 for e in arc.entries if e["entry_type"]==0)
        total_bytes = sum(e["size"] for e in arc.entries if e["entry_type"]==0)
        self.info.set(f"Archive: {os.path.basename(path)} | {arc.describe()} | solid={arc.solid} | enc={arc.encrypted} "
                      f"| files={total_files} | size={self.hbytes(total_bytes)}")
        self.btn_test.config(state="normal")
        self.btn_ex_all.config(state="normal")
        self.btn_ex_sel.config(state="normal")
        self.status.set("Ready.")

    def prompt_password(self):
        top = tk.Toplevel(self); top.title("Password"); top.grab_set()
        ttk.Label(top, text="Enter password:").pack(padx=10, pady=8)
        var = tk.StringVar()
        ent = ttk.Entry(top, show="*", textvariable=var); ent.pack(padx=10, pady=4)
        ent.focus_set()
        res = {"ok": False}
        def ok():
            res["ok"]=True; top.destroy()
        def cancel():
            top.destroy()
        btns = ttk.Frame(top); btns.pack(pady=8)
        ttk.Button(btns, text="OK", command=ok).pack(side="left", padx=4)
        ttk.Button(btns, text="Cancel", command=cancel).pack(side="left", padx=4)
        top.wait_window()
        return var.get() if res["ok"] else None

    def populate_table(self):
        self.tree.delete(*self.tree.get_children())
        if not self.archive: return
        for e in self.archive.entries:
            kind = ["file","dir","symlink","hardlink"][e["entry_type"]]
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["mtime"]))
            size = e["size"]
            self.tree.insert("", "end", values=(e["path"], size, kind, mtime))
        self.apply_filter()

    def apply_filter(self):
        pat = self.filter_var.get().lower().strip()
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            visible = (pat in vals[0].lower()) if pat else True
            if visible:
                self.tree.reattach(iid, "", "end")
            else:
                self.tree.detach(iid)

    def on_test(self):
        if not self.archive: return
        self.status.set("Testing…")
        self.update_idletasks()
        try:
            msg = self.archive.test()
            self.status.set(f"Test: {msg}")
        except Exception as e:
            self.status.set(f"Test failed: {e}")
            messagebox.showerror("Test failed", str(e))

    def on_extract_sel(self):
        if not self.archive: return
        sel = [self.tree.item(i,"values")[0] for i in self.tree.selection()]
        if not sel:
            messagebox.showinfo("Nothing selected", "Select one or more files/dirs in the list.")
            return
        out = filedialog.askdirectory(title="Extract to…")
        if not out: return
        try:
            # treat trailing slash to indicate "directory selection"
            # also pass exactly selected file paths
            # (viewer supports both file exact matches and dir-prefix selection)
            self.archive.extract_selected(out, sel)
            self.status.set(f"Extracted {len(sel)} item(s) to {out}")
        except Exception as e:
            self.status.set(f"Extract failed: {e}")
            messagebox.showerror("Extract failed", str(e))

    def on_extract_all(self):
        if not self.archive: return
        out = filedialog.askdirectory(title="Extract all to…")
        if not out: return
        try:
            all_paths = [e["path"] for e in self.archive.entries if e["entry_type"] in (0,1)]
            self.archive.extract_selected(out, all_paths)
            self.status.set(f"Extracted all to {out}")
        except Exception as e:
            self.status.set(f"Extract failed: {e}")
            messagebox.showerror("Extract failed", str(e))

    def sort_by(self, col, descending):
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children("")]
        if col in ("size",):
            data.sort(key=lambda t: int(t[0]), reverse=descending)
        else:
            data.sort(key=lambda t: t[0].lower(), reverse=descending)
        for idx, item in enumerate(data):
            self.tree.move(item[1], "", idx)
        self.tree.heading(col, command=lambda c=col: self.sort_by(c, not descending))

    @staticmethod
    def hbytes(n:int):
        units=["B","KiB","MiB","GiB","TiB"]; v=float(n); i=0
        while v>=1024 and i<len(units)-1:
            v/=1024.0; i+=1
        return f"{v:.2f} {units[i]}"

# ... keep the rest of vfa_viewer.py as-is ...

def main():
    if sys.argv[1:2] in (["--version"], ["-V"]):
        show(version_text("vfa-viewer"), "VFA Viewer"); return
    if tk is None:
        show(f"vfa-viewer needs Tk, which this Python does not have ({_TK_PROBLEM}). On Linux install it with your "
             "package manager (e.g. python3-tk).", "VFA Viewer")
        raise SystemExit(1)
    root = tk.Tk()
    root.geometry("900x520")
    app = Viewer(root)

    # NEW: open file passed on CLI (e.g., when launched via file association)
    if len(sys.argv) > 1:
        candidate = sys.argv[1]
        if os.path.isfile(candidate):
            try:
                arc = VFAArchive(candidate)
                try:
                    arc.open(password=None)
                except Exception as e:
                    if "Password required" in str(e):
                        pw = app.prompt_password()
                        if pw is None:
                            # user cancelled – just show the window idle
                            root.mainloop(); return
                        arc.open(password=pw)
                    else:
                        tk.messagebox.showerror("Error", f"Failed to open archive:\n{e}")
                        root.mainloop(); return
                app.archive = arc
                app.populate_table()
                total_files = sum(1 for e in arc.entries if e["entry_type"]==0)
                total_bytes = sum(e["size"] for e in arc.entries if e["entry_type"]==0)
                app.info.set(
                    f"Archive: {os.path.basename(candidate)} | "
                    f"{arc.describe()} | "
                    f"solid={arc.solid} | enc={arc.encrypted} | "
                    f"files={total_files} | size={app.hbytes(total_bytes)}"
                )
                app.btn_test.config(state="normal")
                app.btn_ex_all.config(state="normal")
                app.btn_ex_sel.config(state="normal")
                app.status.set("Ready.")
            except Exception as e:
                tk.messagebox.showerror("Error", f"Failed to open {candidate}:\n{e}")

    root.mainloop()

if __name__=="__main__":
    main()
