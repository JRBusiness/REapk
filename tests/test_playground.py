"""Tests for the playground display helpers.

These cover the pure helpers (`hexdump`, `show_smali`) and `dump_dex` against a
tiny fake DEX-like object, so the suite runs with no APK and no sample DEX.
"""
from reapk.playground import hexdump, show_smali, dump_dex


def test_hexdump_format():
    out = hexdump(b"AB\x00\xff", 0, 4)
    # one row: offset, hex bytes, ASCII gutter (non-printables shown as '.')
    assert out.startswith("00000000  ")
    assert "41 42 00 ff" in out
    assert out.rstrip().endswith("AB..")


def test_show_smali_joins_lines():
    assert show_smali(["a", "b", "c"]) == "a\nb\nc"


class _FakeDex:
    """Minimal duck-typed DEX: one public class with one abstract method."""

    def classes(self):
        return [{"name": "Lp/C;", "access": 0x1, "cdata": 1}]

    def class_methods(self, cdata):
        # code_off == 0 -> abstract/native, so dump_dex won't disassemble
        return [{"name": "m", "proto": "()V", "access": 0x401, "code_off": 0}]


def test_dump_dex_renders_class_and_method():
    dump = dump_dex(_FakeDex())
    assert ".class public Lp/C;" in dump
    assert ".method public abstract m()V" in dump
    assert "# no code (abstract/native)" in dump
    assert ".end method" in dump


def test_dump_dex_caps_are_honored():
    dump = dump_dex(_FakeDex(), max_classes=0)
    assert "more class(es)" in dump
    assert ".method" not in dump
