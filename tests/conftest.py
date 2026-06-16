"""Shared fixtures. Integration tests need a real APK.

Provide one via the ``REAPK_TEST_APK`` environment variable (or drop a file at
``tests/sample.apk``); otherwise the integration tests are skipped.
"""
import os

import pytest

_CANDIDATES = [
    os.environ.get("REAPK_TEST_APK"),
    os.path.join(os.path.dirname(__file__), "sample.apk"),
]


@pytest.fixture(scope="session")
def apk_path():
    for c in _CANDIDATES:
        if c and os.path.isfile(c):
            return c
    pytest.skip("set REAPK_TEST_APK to run integration tests")
