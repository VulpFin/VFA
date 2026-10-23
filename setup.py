# Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
"""Builds the _vulp C extension into the vfvfa wheel. Everything else is in pyproject.toml.
Flags match build_vulp.py (the in-place developer build): the codec is integer-only and test_vfa.py checks that
-O0/-O3/MSVC builds give identical output, so wheels and local builds encode the same bytes."""
import os
from setuptools import Extension, setup

flags = ["/W4"] if os.name == "nt" else ["-O2", "-std=c99"]
setup(ext_modules=[Extension("_vulp", ["vulp/vulp.c", "vulp/vulp_lz.c", "vulp/vulp_cm.c", "vulp/vulpmodule.c"],
                             include_dirs=["vulp"], extra_compile_args=flags)],
      options={"egg_info": {"egg_base": os.environ.get("VFA_EGG_BASE", ".")}})
