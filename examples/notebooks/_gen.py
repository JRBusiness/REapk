# examples/notebooks/_gen.py
import json
import sys


def notebook(cells):
    out = {"cells": [], "metadata": {"kernelspec":
           {"display_name": "Python 3", "language": "python", "name": "python3"},
           "language_info": {"name": "python"}},
           "nbformat": 4, "nbformat_minor": 5}
    for i, (kind, src) in enumerate(cells):
        lines = src.strip("\n").splitlines(keepends=True)
        if kind == "md":
            out["cells"].append({"cell_type": "markdown", "id": "c%d" % i,
                                 "metadata": {}, "source": lines})
        else:
            out["cells"].append({"cell_type": "code", "id": "c%d" % i,
                                 "metadata": {}, "execution_count": None,
                                 "outputs": [], "source": lines})
    return out


def write(path, cells):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(notebook(cells), f, indent=1)
        f.write("\n")
    print("wrote", path)


if __name__ == "__main__":
    print("import this module and call write(path, cells)", file=sys.stderr)
