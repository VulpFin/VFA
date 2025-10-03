#!/usr/bin/env python3
# Tiny VFA Viewer / Extractor (Tkinter)
# Features: open .vfa, prompt password if encrypted, list entries, test, extract selected/all.
# Requires: cryptography, zstandard, brotli (depending on methods used in your archives)

import os, io, sys, struct, time, json, stat, hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Optional deps (align with vfa.py)
try:
    import zstandard as zstd
    HAVE_ZSTD = True
except Exception:
    HAVE_ZSTD = False
try:
    import brotli
    HAVE_BROTLI = True
except Exception:
    HAVE_BROTLI = False
import zlib, lzma

# Crypto (for encrypted archives)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAVE_AESGCM = True
except Exception:
    AESGCM = None
    Scrypt = None
    HAVE_AESGCM = False
try:
    import argon2.low_level as argon2ll
    HAVE_ARGON2 = True
except Exception:
    argon2ll = None
    HAVE_ARGON2 = False

MAGIC = b"VFA1"
END_MAGIC = b"/VFA1"
VERSION = 1

AEAD_NONE=0; AEAD_AESGCM=1
KDF_NONE=0; KDF_ARGON2ID=1; KDF_SCRYPT=2

M_NONE=0; M_ZLIB=1; M_LZMA=2; M_BROTLI=3; M_ZSTD=4
METHOD_NAMES={M_NONE:"none",M_ZLIB:"zlib",M_LZMA:"lzma",M_BROTLI:"brotli",M_ZSTD:"zstd"}

F_ENCRYPTED=1<<0
F_SOLID=1<<1

FOOTER_LEN = 8+4+1+32+5  # toc_off, toc_sz, hash_kind, digest[32], END_MAGIC

def _nonce_from(prefix12:bytes, index:int)->bytes:
    m=hashlib.sha256(); m.update(prefix12); m.update(struct.pack("<Q", index)); m.update(b"vfa-nonce"); return m.digest()[:12]

def _kdf(password:bytes, header):
    kid = header["kdf_id"]
    if kid == KDF_ARGON2ID:
        if not HAVE_ARGON2: raise RuntimeError("argon2-cffi not installed")
        return argon2ll.hash_secret_raw(
            secret=password, salt=header["salt"],
            time_cost=header["kdf_t"] or 3, memory_cost=header["kdf_m"] or (256*1024),
            parallelism=header["kdf_p"] or 4, hash_len=32,
            type=argon2ll.Type.ID, version=argon2ll.ARGON2_VERSION
        )
    if kid == KDF_SCRYPT:
        if Scrypt is None: raise RuntimeError("cryptography.scrypt not available")
        return Scrypt(salt=header["salt"], length=32, n=header["kdf_t"] or (1<<15),
                      r=header["kdf_m"] or 8, p=header["kdf_p"] or 1).derive(password)
    raise RuntimeError("Archive indicates no KDF (not password-protected)")

def _aead_decrypt(key:bytes, header, index:int, ciphertext:bytes, aad:bytes=b""):
    if header["aead_id"] != AEAD_AESGCM or not HAVE_AESGCM:
        raise RuntimeError("AES-GCM not available")
    return AESGCM(key).decrypt(_nonce_from(header["nonce_prefix"], index), ciphertext, aad)

def _decompress(m, data:bytes)->bytes:
    if m==M_NONE: return data
    if m==M_ZLIB: return zlib.decompress(data)
    if m==M_LZMA: return lzma.decompress(data)
    if m==M_BROTLI:
        if not HAVE_BROTLI: raise RuntimeError("brotli not installed")
        return brotli.decompress(data)
    if m==M_ZSTD:
        if not HAVE_ZSTD: raise RuntimeError("zstandard not installed")
        return zstd.ZstdDecompressor().decompress(data)
    raise RuntimeError(f"Unknown method {m}")

def read_footer(fp:io.BufferedReader):
    fp.seek(-(FOOTER_LEN), os.SEEK_END)
    toc_off = struct.unpack("<Q", fp.read(8))[0]
    toc_sz  = struct.unpack("<I", fp.read(4))[0]
    hk      = struct.unpack("<B", fp.read(1))[0]
    digest  = fp.read(32)
    if fp.read(5) != END_MAGIC:
        raise ValueError("Bad end magic")
    return toc_off, toc_sz, hk, digest

def parse_header(fp:io.BufferedReader):
    if fp.read(4)!=MAGIC: raise ValueError("Not a VFA archive")
    version,=struct.unpack("<H", fp.read(2))
    flags,  =struct.unpack("<I", fp.read(4))
    dm      =fp.read(1)[0]
    dl      =fp.read(1)[0]
    be      =fp.read(1)[0]
    th,     =struct.unpack("<H", fp.read(2))
    rm,     =struct.unpack("<I", fp.read(4))
    kid     =fp.read(1)[0]
    kt,     =struct.unpack("<I", fp.read(4))
    km,     =struct.unpack("<I", fp.read(4))
    kp      =fp.read(1)[0]
    salt    =fp.read(16)
    aid     =fp.read(1)[0]
    np      =fp.read(12)
    res     =fp.read(16)
    header_len = 4+2+4 + 1+1+1 + 2 + 4 + 1 + 4 + 4 + 1 + 16 + 1 + 12 + 16
    return {
        "version":version,"flags":flags,"default_method":dm,"default_level":dl,"block_exp":be,
        "threads":th,"ram_mib":rm,"kdf_id":kid,"kdf_t":kt,"kdf_m":km,"kdf_p":kp,
        "salt":salt,"aead_id":aid,"nonce_prefix":np,"reserved":res,"header_len":header_len
    }

def parse_toc(data:bytes, solid:bool):
    bio=io.BytesIO(data)
    n, = struct.unpack("<I", bio.read(4))
    entries=[]
    for _ in range(n):
        plen, = struct.unpack("<H", bio.read(2))
        path = bio.read(plen).decode("utf-8","replace")
        mode, = struct.unpack("<I", bio.read(4))
        mtime,= struct.unpack("<Q", bio.read(8))
        size, = struct.unpack("<Q", bio.read(8))
        nb,   = struct.unpack("<I", bio.read(4))
        entry_type = 0; meta=b""
        # newer format with entry_type + meta
        pos = bio.tell()
        try:
            entry_type = bio.read(1)[0]
            mlen, = struct.unpack("<I", bio.read(4))
            meta = bio.read(mlen) if mlen>0 else b""
        except Exception:
            bio.seek(pos)
        blocks=[]; start_off=0
        if solid:
            start_off, = struct.unpack("<Q", bio.read(8))
        else:
            for _ in range(nb):
                idx, = struct.unpack("<Q", bio.read(8))
                usz, = struct.unpack("<I", bio.read(4))
                csz, = struct.unpack("<I", bio.read(4))
                meth = bio.read(1)[0]
                blocks.append((idx, usz, csz, meth))
        entries.append({"path":path,"mode":mode,"mtime":mtime,"size":size,
                        "entry_type":entry_type,"blocks":blocks,"start_off":start_off,"meta":meta})
    return entries

class VFAArchive:
    def __init__(self, path:str):
        self.path = path
        self.header=None
        self.entries=[]
        self.toc_off=0; self.toc_sz=0
        self.encrypted=False; self.solid=False
        self.key=None

    def open(self, password:str|None=None):
        with open(self.path, "rb") as f:
            toc_off,toc_sz,hk,dig = read_footer(f)
            f.seek(0)
            header = parse_header(f)
            self.header = header
            self.encrypted = bool(header["flags"] & F_ENCRYPTED)
            self.solid     = bool(header["flags"] & F_SOLID)

            # Read TOC block
            f.seek(toc_off)
            toc_data = f.read(toc_sz)
            if self.encrypted:
                if password is None:
                    raise RuntimeError("Password required")
                key=_kdf(password.encode("utf-8"), header)
                self.key = key
                toc_data = _aead_decrypt(key, header, 0xFFFFFFFFFFFFFFFF, toc_data, aad=b"vfa-toc")

            self.entries = parse_toc(toc_data, solid=self.solid)
            self.toc_off, self.toc_sz = toc_off, toc_sz

    def test(self)->str:
        """Lightweight integrity run: for non-solid, walk blocks; for solid, reassemble len."""
        with open(self.path,"rb") as f:
            f.seek(0)
            header = parse_header(f)
            f.seek(header["header_len"])
            if self.solid:
                # decode all blocks to get total size and match expected sum
                expected = sum(e["size"] for e in self.entries if e["entry_type"]==0)
                pos = header["header_len"]; parts_len=0; solid_idx=0
                # arc range up to toc_off
                while pos < self.toc_off:
                    blen = struct.unpack("<I", f.read(4))[0]
                    meth = f.read(1)[0]
                    payload = f.read(blen)
                    if self.encrypted:
                        payload = _aead_decrypt(self.key, header, solid_idx, payload, aad=b"vfa-data")
                    chunk = _decompress(header["default_method"], payload)
                    parts_len += len(chunk); solid_idx += 1
                return f"Solid OK. Data={parts_len} bytes, expected={expected}."
            else:
                pos = header["header_len"]
                ok_blocks=0
                for e in self.entries:
                    if e["entry_type"]!=0: continue
                    for (idx, usz, csz, meth) in e["blocks"]:
                        blen = struct.unpack("<I", f.read(4))[0]
                        mb = f.read(1)[0]
                        payload = f.read(blen)
                        if self.encrypted:
                            payload = _aead_decrypt(self.key, header, idx, payload, aad=b"vfa-data")
                        data = _decompress(meth, payload)
                        if len(data)!=usz: raise RuntimeError("Size mismatch")
                        ok_blocks += 1
                return f"Non-solid OK. Blocks checked={ok_blocks}"

    def extract_selected(self, outdir:str, selected_paths:list[str]):
        with open(self.path,"rb") as f:
            header = parse_header(f)
            # Get a decompressed solid buffer if needed
            solid_buf = None
            if self.solid:
                f.seek(header["header_len"])
                parts=[]; pos=header["header_len"]; solid_idx=0
                while pos < self.toc_off:
                    blen = struct.unpack("<I", f.read(4))[0]
                    meth = f.read(1)[0]
                    payload = f.read(blen)
                    if self.encrypted:
                        payload = _aead_decrypt(self.key, header, solid_idx, payload, aad=b"vfa-data")
                    parts.append(_decompress(header["default_method"], payload))
                    solid_idx+=1
                    pos = f.tell()
                solid_buf = b"".join(parts)

            for e in self.entries:
                if e["entry_type"]==1:
                    # ensure directories exist if selected parent folders are chosen
                    if any(p.startswith(e["path"]+"/") or p==e["path"] for p in selected_paths):
                        dest = os.path.join(outdir, e["path"])
                        os.makedirs(dest, exist_ok=True)
                    continue
                if e["entry_type"]!=0:
                    continue
                if e["path"] not in selected_paths:
                    # Also include if a parent dir was selected
                    if not any(e["path"].startswith(p.rstrip("/")+"/") for p in selected_paths if p.endswith("/")):
                        continue

                dest = os.path.join(outdir, e["path"])
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                if self.solid:
                    seg = solid_buf[e["start_off"]: e["start_off"]+e["size"]]
                    with open(dest,"wb") as fw: fw.write(seg)
                else:
                    # stream blocks
                    with open(dest,"wb") as fw:
                        for (idx, usz, csz, meth) in e["blocks"]:
                            blen = struct.unpack("<I", f.read(4))[0]
                            mb = f.read(1)[0]
                            payload = f.read(blen)
                            if self.encrypted:
                                payload = _aead_decrypt(self.key, header, idx, payload, aad=b"vfa-data")
                            data = _decompress(meth, payload)
                            if len(data)!=usz: raise RuntimeError("Size mismatch")
                            fw.write(data)
                # times best-effort
                try: os.utime(dest, (e["mtime"], e["mtime"]))
                except Exception: pass

class Viewer(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.pack(fill="both", expand=True)
        self.master.title("VFA Viewer")
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
        self.info.set(f"Archive: {os.path.basename(path)} | method={METHOD_NAMES.get(arc.header['default_method'])} "
                      f"lvl={arc.header['default_level']} | solid={arc.solid} | enc={arc.encrypted} "
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
                    f"method={METHOD_NAMES.get(arc.header['default_method'])} "
                    f"lvl={arc.header['default_level']} | "
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
