# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
"""The VFA release version: one place for the PyPI package (vfvfa), release.py file names and installers.
Not the archive format version (VFA1 / VFA2 and the VFA2 spec revision live in the readers)."""
__version__ = "2.0.0a4"

def version_text(tool: str) -> str:
    """The `--version` text every tool prints: release, the VFA2 spec revision it writes and reads, and whether the
    C codec is in use (without it VFA2 decodes with the slow pure-Python reference)."""
    try:
        import vfa2
        native = f"C codec API {vfa2.NATIVE_API}" if vfa2.NATIVE else "pure-Python codec (C codec not available)"
        return f"{tool} {__version__} (VFA2 spec {vfa2.SPEC_VERSION}, {native})"
    except Exception:
        return f"{tool} {__version__}"

def show(text: str, title: str = "VFA") -> None:
    """Print text; a windowless build (PyInstaller --noconsole: no stdout or stderr) shows it in a message box
    (Windows) or an AppleScript dialog (macOS)."""
    import sys
    out = sys.stdout or sys.stderr
    if out is not None:
        out.write(text if text.endswith("\n") else text + "\n"); out.flush(); return
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, text.rstrip("\n"), title, 0x40)   # MB_ICONINFORMATION
        except Exception:
            pass
    elif sys.platform == "darwin":                   # macOS --noconsole builds have no stdio either: AppleScript dialog
        try:
            import subprocess
            q = lambda t: '"' + t.replace("\\", "\\\\").replace('"', '\\"') + '"'
            subprocess.run(["osascript", "-e", f"display dialog {q(text.rstrip())} with title {q(title)} buttons {{\"OK\"}} "
                            "default button 1"], capture_output=True, timeout=600)
        except Exception:
            pass

def route_output(ap, title: str) -> None:
    """Send everything argparse prints (--help, --version, usage errors) through show(), so a windowless build
    answers them in a message box instead of saying nothing. Call it before add_subparsers(): subcommand parsers
    are made from the parent's class, so they route their output too."""
    import sys
    if sys.stdout is None and sys.stderr is None:
        class Routed(type(ap)):
            def _print_message(self, message, file=None):
                if message: show(message, title)
        ap.__class__ = Routed
