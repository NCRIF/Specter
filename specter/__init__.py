"""
top-level package metadata for specter
"""

from importlib.metadata import PackageNotFoundError, version

_PKG_NAME = "x3r0day-specter"

try:
    __version__ = version(_PKG_NAME)
except PackageNotFoundError:
    __version__ = "2.1.0"

__all__ = ["__version__"]
