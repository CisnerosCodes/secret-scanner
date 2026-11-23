"""EntropyAnalyzer: finds unknown secrets by how random a string looks (1.3, 3.2).

RUN ORDER (skipped entirely with --no-entropy)
  STEP 19  analyze()              once per line, after RuleEngine
  STEP 19a   pull out candidate strings (quoted or assigned, 20+ characters)
  STEP 19b   skip candidates RuleEngine already matched (3.2.3)
  STEP 20    shannon()            entropy of the candidate
  STEP 21    Allowlist.is_false_positive()   UUIDs, hashes, placeholders
  STEP 18    Redactor.redact()    then build the Finding
"""
import math
import re
from collections import Counter

from .finding import Finding, Span
from .redactor import Redactor
from .rules import Severity


_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# Lockfile integrity hashes, e.g. "sha512-AbC...==" (npm, yarn, pip).
_INTEGRITY = re.compile(r"^sha(1|256|384|512)-", re.IGNORECASE)
_PLACEHOLDER_WORDS = (
    "YOUR_", "_HERE", "EXAMPLE", "PLACEHOLDER", "CHANGEME", "CHANGE_ME",
    "REPLACE_ME", "REPLACEME", "INSERT_", "<", "XXXX",
)
# 20+ base64/hex-ish characters right after a quote or an '=' / ':' assignment.
_CANDIDATE = re.compile(r"""(?:["']|[=:]\s*)([A-Za-z0-9+/=_\-]{20,})""")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


class Allowlist:
    def is_false_positive(self, s: str) -> bool:
        # STEP 21 True for UUIDs, lockfile hashes, and placeholders such as
        #         YOUR_API_KEY_HERE (3.2.4).
        if _UUID.match(s) or _INTEGRITY.match(s):
            return True
        upper = s.upper()
        if any(word in upper for word in _PLACEHOLDER_WORDS):
            return True
        # One repeated character, e.g. "0000000000000000000000".
        return len(set(s)) == 1


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
        if not s:
            return 0.0
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())

    def _candidates(self, line: str) -> list[tuple[int, int, str]]:
        # STEP 19a Quoted or assigned tokens of 20+ base64 or hex characters (3.2.1).
        return [(m.start(1), m.end(1), m.group(1)) for m in _CANDIDATE.finditer(line)]

    def _is_hex(self, s: str) -> bool:
        return bool(_HEX.match(s))
