"""RuleEngine: runs every compiled rule against one line (UC-2).

RUN ORDER
  STEP 7   compile()      ONCE, from Scanner.__init__
  STEP 17  match_line()   once per line, from Scanner.scan_file
  STEP 17a   InjectionRule.applies_to(ext)   skip rules for other languages
  STEP 17b   regex search on the line
  STEP 18    Redactor.redact() + build a Finding for each match
"""

from __future__ import annotations

from .finding import Finding, Span
from .redactor import Redactor
from .rules import InjectionRule, Rule, RuleKind


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def compile(cls, table: list[Rule]) -> RuleEngine:
        # STEP 7  Compile every pattern exactly once (3.1.5, 3.3.2).
        # TODO: for rule in table: rule.regex = re.compile(rule.pattern)
        #       then return cls(table)
        raise NotImplementedError

    def match_line(self, line: str, ext: str) -> list[Finding]:
        # STEP 17 Called once per line.  Returns every finding on this line.
        findings: list[Finding] = []
        for rule in self.rules:
            # STEP 17a PATH injection rule on a non-matching file type: skip (3.3.5).
            if isinstance(rule, InjectionRule) and not rule.applies_to(ext):
                continue

            # STEP 17b Every match of this rule on the line.
            for match in rule.regex.finditer(line):
                # STEP 18 Redact BEFORE the value goes anywhere (3.4.1).
                #         Injection findings show code, not a secret, so they are
                #         not redacted.  TEAM DECISION: confirm this.
                if rule.kind is RuleKind.KNOWN_SECRET:
                    preview = Redactor.redact(match.group())
                else:
                    preview = match.group()

                findings.append(Finding(
                    finding_type=rule.name,
                    severity=rule.severity,
                    confidence=getattr(rule, "confidence", None),
                    span=Span(match.start(), match.end()),  # 2.4
                    redacted_preview=preview,
                ))
        # Next: back to Scanner.scan_file, STEP 19.
        return findings
