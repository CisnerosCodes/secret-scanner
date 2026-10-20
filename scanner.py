"""Scanner: the centre of the program. Owns the walker, rules, entropy and suppression.

RUN ORDER
  STEP 6   __init__()        build the helpers   (--no-entropy, --no-injection act here)
  STEP 7   RuleEngine.compile() runs once from __init__
  STEP 8   scan() starts
  STEP 9-12  FileWalker.walk() yields the next file      (file_walker.py)
  STEP 13  scan_file() for that file
  STEP 14-21 open, read each line, check suppression, match rules, entropy
  ... back to STEP 9 for the next file ...
  STEP 22  build the ScanReport, return to Cli.run()

IMPORTANT: walk() is a GENERATOR, so the run-time order ALTERNATES per file:
    walk finds file A (9-12) -> scan_file(A) (13-21)
    -> walk resumes, finds file B (9-12) -> scan_file(B) (13-21) -> ...
It does NOT list every file first and then scan them.
"""

import time
from pathlib import Path

from .config import Config
from .entropy import EntropyAnalyzer
from .file_walker import FileWalker
from .finding import Finding, Warning
from .line_reader import LineReader
from .report import ScanReport
from .rule_engine import RuleEngine
from .rules import RULE_TABLE, RuleKind
from .suppression import SuppressionFilter


class Scanner:
    def __init__(self, config: Config) -> None:
        # STEP 6  Called by Cli.run().  Build every helper once.
        self.walker = FileWalker()
        self.suppression = SuppressionFilter()
        self.warnings: list[Warning] = []
        self.files_scanned = 0
        self.files_skipped = 0

        # STEP 6a PATH --no-entropy: no EntropyAnalyzer, so STEPS 19-21 never run.
        #         PATH --entropy-threshold X: X becomes the base64 threshold here.
        self.entropy = None if config.no_entropy else EntropyAnalyzer(
            base64_threshold=config.entropy_threshold
        )

        # STEP 6b PATH --no-injection: drop injection rules, so STEP 17a never runs.
        table = [
            rule for rule in RULE_TABLE
            if not (config.no_injection and rule.kind is RuleKind.INJECTION)
        ]

        # STEP 7  Compile every regex ONCE, not per line (3.1.5).  Next: rule_engine.py
        self.engine = RuleEngine.compile(table)

    def scan(self, config: Config) -> ScanReport:
        # STEP 8  Called by Cli.run().  Start the clock for the summary (3.4.2).
        start = time.perf_counter()
        findings: list[Finding] = []

        # STEP 9  Ask the walker for the next file (generator; see note at top).
        for path in self.walker.walk(config.path, config):
            # STEP 13 Scan this one file, then loop back to STEP 9.
            findings.extend(self.scan_file(path))

        # STEP 22 Every file done.  Build the report.  Next: back to Cli.run() STEP 23.
        return ScanReport(
            findings=findings,
            warnings=self.warnings,
            files_scanned=self.files_scanned,
            files_skipped=self.files_skipped + self.walker.skipped,
            elapsed=time.perf_counter() - start,
        )

    def scan_file(self, path: Path) -> list[Finding]:
        # STEP 13 Called from scan() for each file the walker yields.
        reader = LineReader()

        # STEP 14 Open the file.
        try:
            reader.open(path)
        except OSError as err:
            # PATH unreadable file (permission denied, broken symlink; 2.5, UC-5):
            #      record a warning, count it skipped, return to STEP 9. Scan continues.
            self.warnings.append(Warning(path=path, reason=str(err)))
            self.files_skipped += 1
            return []
        self.files_scanned += 1

        findings: list[Finding] = []
        line_number = 0

        # STEP 15 Read ONE line at a time (2.3).  Loops back here for every line.
        while (line := reader.next_line()) is not None:
            line_number += 1  # 1-based (2.4)

            # STEP 16 Inline marker check (3.4.5, 3.3.7).
            if self.suppression.is_suppressed(line):
                # PATH suppressed line: skip STEPS 17-21, back to STEP 15.
                continue

            # STEP 17-18 Known-pattern and injection rules.  Next: rule_engine.py
            matched = self.engine.match_line(line, path.suffix)

            # STEP 19-21 Entropy check (skipped with --no-entropy).  Next: entropy.py
            if self.entropy is not None:
                matched.extend(self.entropy.analyze(line, matched))

            # match_line and analyze only see one line, so the file and line
            # number are filled in here.
            for finding in matched:
                finding.file = path
                finding.line_number = line_number
            findings.extend(matched)

        # End of file.  Back to scan() and STEP 9 for the next file.
        return findings
