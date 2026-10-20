"""Program entry point.

Run with:   python -m secret_scan [PATH] [options]

RUN ORDER: the program starts at STEP 1 below and ends at STEP 27.
Every other file is labelled with the STEP numbers where its code runs.
See RUN_ORDER.md for the order of steps on each command-line flag path.
"""

import sys

from .cli import Cli


def main() -> None:
    # STEP 1  The shell starts the program here.
    #         Next: STEP 2, Cli.run()  (cli.py)
    exit_code = Cli().run()

    # STEP 27 Hand the exit code to the shell, Git hook or CI pipeline.
    #         0 = no findings, 1 = findings, 2 = usage or runtime error (3.4.4)
    #         END OF PROGRAM.
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
