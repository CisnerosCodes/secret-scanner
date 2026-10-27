"""ScanReport: everything the scan found, handed from Scanner to the reporters.

RUN ORDER
  STEP 22  created at the end of Scanner.scan()
  STEP 24  by_type()     called by the reporter for the summary
  STEP 26  exit_code()   called by Cli.run()
"""

from collections import Counter
from dataclasses import dataclass

from .finding import Finding, Warning


@dataclass
class ScanReport:
    findings: list[Finding]
    warnings: list[Warning]
    files_scanned: int
    files_skipped: int
    elapsed: float  # seconds

    def by_type(self) -> dict[str, int]:
        # STEP 24 Count of findings per finding_type for the summary (3.4.2).
        # TODO: collections.Counter(f.finding_type for f in self.findings)
        return dict(Counter(f.finding_type for f in self.findings))

    def exit_code(self) -> int:
        # STEP 26 1 if any findings, else 0 (3.4.4).  Errors (2) are returned by Cli.
        # TODO
        return 1 if self.findings else 0
