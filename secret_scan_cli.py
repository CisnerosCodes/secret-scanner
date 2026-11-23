"""Launcher: run the scanner from this flat folder.

    python secret_scan_cli.py ./test_repo --format json

The modules use package-relative imports, so this loads the folder as the
package "secret_scan" without moving or renaming any file.
"""

import importlib.util
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "secret_scan", here / "__init__.py", submodule_search_locations=[str(here)]
)
pkg = importlib.util.module_from_spec(spec)
sys.modules["secret_scan"] = pkg
spec.loader.exec_module(pkg)

from secret_scan.cli import Cli  # noqa: E402

if __name__ == "__main__":
    sys.exit(Cli().run())
