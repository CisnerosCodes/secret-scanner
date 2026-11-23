import copy
import time
from pathlib import Path

from .config import Config
from .entropy import EntropyAnalyzer
from .fileWalkerV1 import FileWalker
from .finding import Finding, Warning
from .lineReader import LineReader
from .report import ScanReport
from .rule_engine import RuleEngine
from .rules import RuleTable, RuleType
from .suppression import SuppressionFilter


class Scanner:
    def __init__(self, config: Config) -> None:
        # STEP 6a Entropy analyzer, unless --no-entropy.
        self.entropy = (
            None if config.no_entropy
            else EntropyAnalyzer(base64_threshold=config.entropy_threshold)
        )
        # STEP 6b Drop injection rules when --no-injection is set.
        # Copy so compiling never mutates the shared module-level table.
        rules = [copy.copy(r) for r in RuleTable
                 if not (config.no_injection and r.type is RuleType.INJECTION)]
        # STEP 7  Compile every pattern once.
        self.engine = RuleEngine.compile(rules)
        self.walker = FileWalker()
        self.suppression = SuppressionFilter()

    def scan(self, config: Config) -> ScanReport:
        # STEP 8
        start = time.perf_counter()
        findings: list[Finding] = []
        warnings: list[Warning] = []
        scanned = 0

        for path in self.walker.walk(config.path, config):          # STEP 9
            file_findings, warning = self.scan_file(path)           # STEP 13
            if warning is not None:
                warnings.append(warning)
                continue
            scanned += 1
            findings.extend(file_findings)

        # STEP 22
        return ScanReport(
            findings=findings,
            warnings=warnings,
            files_scanned=scanned,
            files_skipped=self.walker.skipped,
            elapsed=time.perf_counter() - start,
        )

    def scan_file(self, path: Path) -> tuple[list[Finding], Warning | None]:
        # STEP 13 Returns (findings, warning). A warning means the file was unreadable.
        reader = LineReader()
        try:
            reader.open(path)                                       # STEP 14
        except OSError as err:
            return [], Warning(path=path, reason=f"unreadable file: {err.strerror or err}")

        findings: list[Finding] = []
        ext = path.suffix.lower()
        line_number = 0
        try:
            while (line := reader.next_line()) is not None:         # STEP 15
                line_number += 1
                line = line.rstrip("\r\n")
                if self.suppression.is_suppressed(line):            # STEP 16
                    continue
                line_findings = self.engine.match_line(line, ext)   # STEP 17
                if self.entropy is not None:
                    line_findings += self.entropy.analyze(line, line_findings)  # STEP 19
                for f in line_findings:
                    f.file = path
                    f.line_number = line_number
                findings.extend(line_findings)
        except OSError as err:  # read failure mid-file
            return findings, Warning(path=path, reason=f"read error: {err.strerror or err}")
        finally:
            reader.close()
        return findings, None
