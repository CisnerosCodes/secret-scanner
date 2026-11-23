from pathlib import Path
import sys

# /.../Secret Scanner/secret_scanner/test/conftest.py -> parent.parent.parent is /.../Secret Scanner
WORKSPACE_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)
    