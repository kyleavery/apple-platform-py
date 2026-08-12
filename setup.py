"""Build integration for the Rust cdylib.

Everything declarative lives in pyproject.toml. This file exists only to:

1. Build crates/apple-platform-ffi as a plain cdylib (no Python bindings in the
   Rust code, hence Binding.NoBinding) and place it inside the package.
2. Tag wheels as ``py3-none-<platform>``: the library is loaded via ctypes, so
   there is no CPython ABI dependency and one wheel per platform covers all
   supported Python versions.
"""

import os
import sys

# Without this, setuptools names the artifact after the *build* interpreter
# (e.g. `_native_lib.cpython-312-darwin.so`), which is misleading inside a
# py3-none wheel and makes the filename vary by build machine. The library has
# no CPython ABI dependency, so pin a plain, deterministic suffix.
os.environ.setdefault(
    "SETUPTOOLS_EXT_SUFFIX", ".dll" if sys.platform == "win32" else ".so"
)

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.dist import Distribution

from setuptools_rust import Binding, RustExtension


class BDistWheel(bdist_wheel):
    def get_tag(self):
        _py, _abi, plat = super().get_tag()
        return "py3", "none", plat


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True

    def is_pure(self):
        return False


setup(
    rust_extensions=[
        RustExtension(
            "apple_platform._native_lib",
            path="crates/apple-platform-ffi/Cargo.toml",
            binding=Binding.NoBinding,
            features=["notarize"],
            debug=False,
        )
    ],
    distclass=BinaryDistribution,
    cmdclass={"bdist_wheel": BDistWheel},
)
