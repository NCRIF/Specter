"""
top-level package metadata for specter
"""

import os
import sys

# when running as root (e.g. sudo for a SYN scan, or inside an agent), don't
# write .pyc files. otherwise root-owned __pycache__ ends up inside a
# user-owned (pipx) install and later breaks `pipx` ops run as the normal user.
if os.geteuid() == 0:
    sys.dont_write_bytecode = True

from importlib.metadata import PackageNotFoundError, version

_PKG_NAME = "specter"

try:
    __version__ = version(_PKG_NAME)
except PackageNotFoundError:
    __version__ = "2.3.0"

__all__ = ["__version__"]
