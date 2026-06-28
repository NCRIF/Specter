"""
top-level package metadata for specter
"""

from importlib.metadata import PackageNotFoundError, version

_PKG_NAME = "specter"

try:
    __version__ = version(_PKG_NAME)
except PackageNotFoundError:
    __version__ = "2.2.1"

__all__ = ["__version__"]
