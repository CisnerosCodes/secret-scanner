"""Data classes passed between steps.  No logic runs here.

  Finding  created at STEP 18; file and line_number filled in by Scanner.scan_file
  Span     where the match sits in the line (2.4)
  Warning  created at STEP 14 when a file cannot be read (2.5).
           NOTE: Warning is not in the class diagram yet; ScanReport.warnings needs it.
"""

from dataclasses import dataclass
from pathlib import Path

from .rules import Confidence, Severity


@dataclass
class Span:
    start: int
    end: int


@dataclass
class Finding:
    finding_type: str
    severity: Severity
    span: Span
    redacted_preview: str
    confidence: Confidence | None = None  # injection rules only (3.3.4)
    file: Path | None = None              # set by Scanner.scan_file
    line_number: int = 0                  # 1-based, set by Scanner.scan_file


@dataclass
class Warning:
    path: Path
    reason: str
