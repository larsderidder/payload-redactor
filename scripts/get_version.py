"""Print project version from pyproject.toml."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = pyproject.read_text()
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover
        print("tomllib is required (Python 3.11+).", file=sys.stderr)
        return 1
    version = tomllib.loads(data)["project"]["version"]
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
