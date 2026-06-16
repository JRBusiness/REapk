# REapk DEX Playground

A single hands-on notebook for the REapk DEX engine, run against a real app. Point it at your own APK with the `REAPK_TEST_APK` environment variable. Every cell is guarded, so the notebook still executes top to bottom without one (it just prints a reminder).

## Setup

```bash
pip install -e .[playground]
REAPK_TEST_APK=/path/to/app.apk jupyter lab examples/notebooks/playground.ipynb
```

If `import reapk` fails inside the notebook, install it into the kernel from a cell with `%pip install -e "<path-to-repo>"`, then restart the kernel.

## What's inside `playground.ipynb`

1. Load an APK and read its manifest attack surface.
2. Disassemble a method to smali.
3. Hex-dump the raw DEX header.
4. Render a full smali listing with `dump_dex` (capped for real apps).

The display helpers (`dump_dex`, `hexdump`, `show_smali`) live in `reapk.playground`.
