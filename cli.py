"""Cli: turns the command line into a Config, runs the scan, prints the report.

RUN ORDER
  STEP 2   run() starts            (called by __main__.main at STEP 1)
  STEP 3   parse_args()            --help / --version / invalid arguments END here
  STEP 4   Config created
  STEP 5   path check              missing path ENDS here
  STEP 6-22  Scanner does the work (scanner.py)
  STEP 23  pick a Reporter         --format json changes this step
  STEP 24  render the report
  STEP 25  write it out            write failure ENDS here
  STEP 26  exit code               back to __main__.main at STEP 27
"""

import argparse
import sys
from pathlib import Path

from .config import Config, OutputFormat
from .reporters import JsonReporter, TextReporter
from .scanner import Scanner

VERSION = "0.1.0"


class Cli:
    def run(self) -> int:
        # STEP 2  Called by __main__.main().  Returns the exit code.

        # STEP 3  Read sys.argv into a Config.
        #         PATH --help / --version: argparse prints and exits 0 INSIDE this call.
        #                                  Nothing below runs. END.
        #         PATH invalid argument:   argparse prints an error and exits 2
        #                                  INSIDE this call (4.3). END.
        config = self.parse_args()

        # STEP 5  The target path must exist (UC-1 exception flow).
        if not config.path.exists():
            # PATH missing path: print a clear error, exit code 2. END.
            print(f"secret-scan: error: path not found: {config.path}", file=sys.stderr)
            return 2

        # STEP 6-7   Build the scanner. Its constructor compiles every rule once.
        scanner = Scanner(config)

        # STEP 8-22  Walk the files, read each line, match rules, build the report.
        report = scanner.scan(config)

        # STEP 23 Pick the Reporter from config.format.
        #         PATH --format json: JsonReporter instead of TextReporter.
        if config.format is OutputFormat.JSON:
            reporter = JsonReporter()
        else:
            reporter = TextReporter()

        # STEP 24 Turn the report into text or JSON.  Next: reporters.py
        output = reporter.render(report)

        # STEP 25 Write to standard output.
        try:
            sys.stdout.write(output)
        except OSError as err:
            # PATH write failure (closed pipe, full disk; UC-3 exception): exit 2. END.
            print(f"secret-scan: error: {err}", file=sys.stderr)
            return 2

        # STEP 26 0 = no findings, 1 = findings (3.4.4).  Next: STEP 27 in __main__.py
        return report.exit_code()

    def parse_args(self, argv: list[str] | None = None) -> Config:
        # STEP 3  Define every option from Needs Statement 4.2, then parse.
        parser = argparse.ArgumentParser(
            prog="secret-scan",
            description="Find hardcoded API keys, tokens and credentials in project files.",
        )
        parser.add_argument("path", nargs="?", default=".",
                            help="file or directory to scan (default: current directory)")
        parser.add_argument("--format", choices=["text", "json"], default="text")
        parser.add_argument("--entropy-threshold", type=float, default=4.5)
        parser.add_argument("--max-file-size", type=int, default=1_000_000, metavar="BYTES")
        parser.add_argument("--ignore", action="append", default=[], metavar="GLOB")
        parser.add_argument("--no-entropy", action="store_true")
        parser.add_argument("--no-injection", action="store_true")
        parser.add_argument("--version", action="version", version=f"secret-scan {VERSION}")
        # --help is added by argparse automatically.

        # STEP 3a argparse handles --help, --version and unknown options here.
        args = parser.parse_args(argv)

        # STEP 3b Range checks argparse cannot do (4.3: clear error, exit 2).
        # TODO: reject --max-file-size <= 0 and --entropy-threshold <= 0
        #       with parser.error("..."), which prints the message and exits 2.

        # STEP 4  Build the Config.  Next: back to run() at STEP 5.
        return Config(
            path=Path(args.path),
            format=OutputFormat(args.format),
            entropy_threshold=args.entropy_threshold,
            max_file_size=args.max_file_size,
            ignore_globs=args.ignore,
            no_entropy=args.no_entropy,
            no_injection=args.no_injection,
        )
