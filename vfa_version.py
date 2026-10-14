# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
"""The VFA release version: one place for the PyPI package (vfvfa), release.py file names and installers.
Not the archive format version (VFA1 / VFA2 and the VFA2 spec revision live in the readers)."""
__version__ = "2.0.0a1"

def version_text(tool: str) -> str:
    """The `--version` text every tool prints: release, the VFA2 spec revision it writes and reads, and whether the
    C codec is in use (without it VFA2 decodes with the slow pure-Python reference)."""
    try:
        import vfa2
        native = f"C codec API {vfa2.NATIVE_API}" if vfa2.NATIVE else "pure-Python codec (C codec not available)"
        return f"{tool} {__version__} (VFA2 spec {vfa2.SPEC_VERSION}, {native})"
    except Exception:
        return f"{tool} {__version__}"
