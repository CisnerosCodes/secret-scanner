"""EntropyAnalyzer: finds unknown secrets by how random a string looks (1.3, 3.2).

RUN ORDER (skipped entirely with --no-entropy)
  STEP 19  analyze()              once per line, after RuleEngine
  STEP 19a   pull out candidate strings (quoted or assigned, 20+ characters)
  STEP 19b   skip candidates RuleEngine already matched (3.2.3)
  STEP 20    shannon()            entropy of the candidate
  STEP 21    Allowlist.is_false_positive()   UUIDs, hashes, placeholders
  STEP 18    Redactor.redact()    then build the Finding
"""

from .finding import Finding, Span
from .redactor import Redactor
from .rules import Severity


class Allowlist:
    def is_false_positive(self, s: str) -> bool:
        # STEP 21 True for UUIDs, lockfile hashes, and placeholders such as
        #         YOUR_API_KEY_HERE (3.2.4).
        # TODO: regex checks for a UUID shape and a placeholder list.
        raise NotImplementedError


class EntropyAnalyzer:
    def __init__(self, base64_threshold: float = 4.5, hex_threshold: float = 3.0) -> None:
        # Built at STEP 6a.  PATH --entropy-threshold X sets base64_threshold (3.2.2).
        self.base64_threshold = base64_threshold
        self.hex_threshold = hex_threshold
        self.allowlist = Allowlist()

    def analyze(self, line: str, matched: list[Finding]) -> list[Finding]:
        # STEP 19 Called by Scanner.scan_file after match_line.
        findings: list[Finding] = []
        for start, end, candidate in self._candidates(line):          # STEP 19a
            if any(f.span.start <= start < f.span.end for f in matched):
                continue                                               # STEP 19b
            threshold = self.hex_threshold if self._is_hex(candidate) else self.base64_threshold
            if self.shannon(candidate) <= threshold:                   # STEP 20
                continue
            if self.allowlist.is_false_positive(candidate):            # STEP 21
                continue
            findings.append(Finding(                                   # STEP 18
                finding_type="High-entropy string",
                severity=Severity.MEDIUM,
                span=Span(start, end),
                redacted_preview=Redactor.redact(candidate),
            ))
        # Next: back to Scanner.scan_file, then STEP 15 for the next line.
        return findings

    def shannon(self, s: str) -> float:
        # STEP 20 H(s) = -sum p(c) * log2 p(c), p(c) = count(c) / len(s)   (3.2)
        # TODO: count characters with collections.Counter, apply the formula.
        raise NotImplementedError

    def _candidates(self, line: str) -> list[tuple[int, int, str]]:
        # STEP 19a Quoted or assigned tokens of 20+ base64 or hex characters (3.2.1).
        # TODO: regex for the token; return (start, end, text) for each.
        raise NotImplementedError

    def _is_hex(self, s: str) -> bool:
        # TODO: all characters in 0-9a-fA-F.
        raise NotImplementedError
