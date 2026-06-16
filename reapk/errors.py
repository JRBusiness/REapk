"""Exception hierarchy for reapk.

Library code raises these (never ``SystemExit``); the CLI catches
:class:`REapkError` at the top level and turns it into a clean exit code.
"""
from __future__ import annotations


class REapkError(Exception):
    """Base class for every error raised by reapk."""


class AxmlError(REapkError):
    """Malformed or unsupported binary XML / ``resources.arsc``."""


class BundleError(REapkError):
    """Problem reading an APK / XAPK / split bundle."""


class ZipError(REapkError):
    """Problem reading or writing the APK zip container."""


class DexError(REapkError):
    """Malformed DEX or an unsupported DEX operation."""


class AssembleError(DexError):
    """A smali instruction could not be assembled (also used to skip)."""


class SignError(REapkError):
    """APK signing failed or prerequisites are missing."""


class EngineError(REapkError):
    """An external engine (apktool / APKEditor) is missing or failed."""


__all__ = [
    "REapkError", "AxmlError", "BundleError", "ZipError", "DexError",
    "AssembleError", "SignError", "EngineError",
]
