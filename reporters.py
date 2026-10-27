"""Reporters: turn a ScanReport into text or JSON.

RUN ORDER
  STEP 23  Cli.run picks one:  TextReporter (default) or JsonReporter (--format json)
  STEP 24  render()            builds the whole output string
  STEP 25  Cli.run writes it to standard output
"""

import json
from abc import ABC, abstractmethod

from .report import ScanReport


class Reporter(ABC):
    @abstractmethod
    def render(self, report: ScanReport) -> str:
        """STEP 24"""


class TextReporter(Reporter):
    def render(self, report: ScanReport) -> str:
        # STEP 24 (default path)  3.4.2:
        #   1. findings grouped by file: line number, finding type, redacted preview
        #      (plus confidence for injection findings, 3.3.4)
        #   2. one line per warning
        #   3. summary: files scanned, files skipped, report.by_type(), elapsed time
        # TODO
        lines = []
        current_file = None
        # Scanner adds findings one file at a time, so same-file findings are already together.
        for f in report.findings:
            if f.file != current_file:
                current_file = f.file
                lines.append(str(f.file))
            confidence = f" ({f.confidence.value} confidence)" if f.confidence else ""
            lines.append(f"  line {f.line_number}: {f.finding_type}: {f.redacted_preview}{confidence}")
        for w in report.warnings:
            lines.append(f"warning: {w.path}: {w.reason}")
        lines.append(f"Scanned {report.files_scanned} files, skipped {report.files_skipped}, "
                     f"in {report.elapsed:.2f}s")
        for finding_type, count in report.by_type().items():
            lines.append(f"  {finding_type}: {count}")
        return "\n".join(lines) + "\n"


class JsonReporter(Reporter):
    def render(self, report: ScanReport) -> str:
        # STEP 24 (PATH --format json)  3.4.3: same data as TextReporter, as JSON.
        # TODO: build a dict from report (paths and enums as strings) and
        #       return json.dumps(data, indent=2)
        data = {
            "findings": [{
                "file": str(f.file),
                "line": f.line_number,
                "column": f.span.start,
                "type": f.finding_type,
                "severity": f.severity.value,
                "confidence": f.confidence.value if f.confidence else None,
                "preview": f.redacted_preview,
            } for f in report.findings],
            "warnings": [{"path": str(w.path), "reason": w.reason} for w in report.warnings],
            "summary": {
                "files_scanned": report.files_scanned,
                "files_skipped": report.files_skipped,
                "by_type": report.by_type(),
                "elapsed": round(report.elapsed, 3),
            },
        }
        return json.dumps(data, indent=2) + "\n"
