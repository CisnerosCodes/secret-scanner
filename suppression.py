"""SuppressionFilter: lets a developer silence one line on purpose.

RUN ORDER
  STEP 16  is_suppressed()  once per line, BEFORE any rule runs.
           True -> the line is skipped (STEPS 17-21 do not run for it).
"""


class SuppressionFilter:
    # 3.4.5 secret marker; 3.3.7 says it also silences injection findings.
    MARKERS = ("// secret-scan:ignore",)
    # TEAM DECISION: add "# secret-scan:ignore" for Python files?

    def is_suppressed(self, line: str) -> bool:
        # STEP 16
        # TODO: return True if any marker appears in the line.
        raise NotImplementedError
