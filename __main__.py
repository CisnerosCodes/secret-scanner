"""Entry point for running the secret scanner package with `python -m`."""

import sys

from .cli import Cli


def main() -> int:
    return Cli().run()


if __name__ == "__main__":
    sys.exit(main())