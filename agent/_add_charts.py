"""One-off helper: print actual YAML labels for chart mapping."""

import yaml
import pathlib

path = pathlib.Path("builtin_hunts.yaml")
data = yaml.safe_load(path.read_text())
for entry in data:
    print(repr(entry.get("label", "?")))
