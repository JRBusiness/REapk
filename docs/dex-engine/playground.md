# Playground

The repository ships a runnable Jupyter notebook that walks the whole engine against a real app: [`examples/notebooks/playground.ipynb`](https://github.com/JRBusiness/REapk/blob/main/examples/notebooks/playground.ipynb).

## Run it

```bash
pip install -e .[playground]
REAPK_TEST_APK=/path/to/app.apk jupyter lab examples/notebooks/playground.ipynb
```

Point `REAPK_TEST_APK` at an app you are authorized to test. Every cell is guarded, so the notebook still runs top to bottom without one (it just prints a reminder).

## What it covers

1. What a DEX is, read live from the app's header and pools.
2. The constant pools.
3. Disassembling a method to smali.
4. A byte-identical assemble round trip, scanned across real methods.
5. Force-return patching a method.
6. SSL-pinning bypass across every dex, then repackage and re-sign.
7. Interning a new string with a whole-DEX rewrite.
8. A full smali listing with `dump_dex`.

If `import reapk` fails inside the notebook, install it into the kernel from a cell with `%pip install -e "<path-to-repo>"`, then restart the kernel.
