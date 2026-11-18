"""Reporters: turn a ScanReport into text or JSON.

RUN ORDER
  STEP 23  Cli.run picks one:  TextReporter (default) or JsonReporter (--format json)
  STEP 24  render()            builds the whole output string
  STEP 25  Cli.run writes it to standard output
"""

import json
from abc import ABC, abstractmethod
from itertools import groupby

from .report import ScanReport


class Reporter(ABC):
    @abstractmethod
    def render(self, report: ScanReport) -> str:
        """STEP 24"""


def _sorted_findings(report: ScanReport):
    return sorted(report.findings, key=lambda f: (str(f.file), f.line_number, f.span.start))


class TextReporter(Reporter):
    def render(self, report: ScanReport) -> str:
        # STEP 24 (default path)  3.4.2
        out: list[str] = []

        # 1. findings grouped by file
        for file, group in groupby(_sorted_findings(report), key=lambda f: f.file):
            out.append(str(file))
            for f in group:
                conf = f" (confidence: {f.confidence.value})" if f.confidence else ""
                out.append(
                    f"  line {f.line_number}: [{f.severity.value.upper()}] "
                    f"{f.finding_type}{conf}  {f.redacted_preview}"
                )
            out.append("")

        # 2. one line per warning
        for w in report.warnings:
            out.append(f"warning: {w.path}: {w.reason}")
        if report.warnings:
            out.append("")

        # 3. summary
        out.append("Summary")
        out.append(f"  files scanned: {report.files_scanned}")
        out.append(f"  files skipped: {report.files_skipped}")
        out.append(f"  findings:      {len(report.findings)}")
        for name, count in sorted(report.by_type().items()):
            out.append(f"    {name}: {count}")
        out.append(f"  elapsed:       {report.elapsed:.2f}s")
        return "\n".join(out) + "\n"


class JsonReporter(Reporter):
    def render(self, report: ScanReport) -> str:
        # STEP 24 (PATH --format json)  3.4.3: same data as TextReporter, as JSON.
        data = {
            "findings": [
                {
                    "file": str(f.file),
                    "line": f.line_number,
                    "type": f.finding_type,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value if f.confidence else None,
                    "span": {"start": f.span.start, "end": f.span.end},
                    "preview": f.redacted_preview,
                }
                for f in _sorted_findings(report)
            ],
            "warnings": [{"path": str(w.path), "reason": w.reason} for w in report.warnings],
            "summary": {
                "files_scanned": report.files_scanned,
                "files_skipped": report.files_skipped,
                "total_findings": len(report.findings),
                "by_type": report.by_type(),
                "elapsed_seconds": round(report.elapsed, 3),
            },
        }
        return json.dumps(data, indent=2) + "\n"
