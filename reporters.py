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
        raise NotImplementedError


class JsonReporter(Reporter):
    def render(self, report: ScanReport) -> str:
        # STEP 24 (PATH --format json)  3.4.3: same data as TextReporter, as JSON.
        # TODO: build a dict from report (paths and enums as strings) and
        #       return json.dumps(data, indent=2)
        raise NotImplementedError
