"""Rule table: detection rules are DATA, not scanner logic (3.1.6, 3.3.2).
Adding a provider = adding one entry to RULE_TABLE.  Nothing else changes.

RUN ORDER
  Loaded at import time.
  STEP 6b  Scanner drops INJECTION rules when --no-injection is set.
  STEP 7   RuleEngine.compile() compiles every `pattern` once.
  STEP 17a InjectionRule.applies_to() runs per line, per injection rule.

Patterns are copied from the Needs Statement and are marked illustrative there;
verify them against provider documentation before finalizing.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class RuleKind(Enum):
    KNOWN_SECRET = "KnownSecret"
    INJECTION = "Injection"


class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Confidence(Enum):  # 3.3.4: injection findings are heuristic
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class Rule:
    name: str
    pattern: str                         # source text of the regex
    severity: Severity
    kind: RuleKind = RuleKind.KNOWN_SECRET
    regex: re.Pattern | None = None      # filled at STEP 7, never per line


@dataclass
class InjectionRule(Rule):
    kind: RuleKind = RuleKind.INJECTION
    confidence: Confidence = Confidence.LOW
    languages: list[str] = field(default_factory=list)  # file extensions (3.3.5)

    def applies_to(self, ext: str) -> bool:
        # STEP 17a Only run this rule on matching file extensions (3.3.5).
        # TODO: return ext in self.languages
        raise NotImplementedError


RULE_TABLE: list[Rule] = [
    # 3.1 Known secret patterns
    Rule("AWS access key ID", r"AKIA[0-9A-Z]{16}", Severity.HIGH),
    Rule("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36,}", Severity.HIGH),
    Rule("OpenAI API key", r"sk-[A-Za-z0-9_-]{20,}", Severity.HIGH),
    Rule("JWT", r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+", Severity.MEDIUM),

    # 3.3.1 Injection patterns.  TEAM DECISION: confidence and languages per rule.
    InjectionRule("SQL injection",
                  r"(?i)(SELECT|INSERT|UPDATE|DELETE)\b.*(\+\s*\w+|\$\{.+\}|%s|\{\})",
                  Severity.HIGH, confidence=Confidence.MEDIUM,
                  languages=[".py", ".java", ".js", ".rs"]),
    InjectionRule("OS command injection",
                  r"(?i)(os\.system|subprocess\.\w+|Runtime\.getRuntime\(\)\.exec|Command::new)\(.*\+",
                  Severity.HIGH, confidence=Confidence.MEDIUM,
                  languages=[".py", ".java", ".rs"]),
    InjectionRule("Code injection", r"\b(eval|exec)\s*\(\s*[^\"')]",
                  Severity.HIGH, confidence=Confidence.MEDIUM,
                  languages=[".py", ".js"]),
    InjectionRule("Path traversal", r"\.\./|open\(.*\+",
                  Severity.MEDIUM, confidence=Confidence.LOW,
                  languages=[".py", ".java", ".js", ".rs"]),
    InjectionRule("XSS", r"innerHTML\s*=|document\.write\(",
                  Severity.MEDIUM, confidence=Confidence.MEDIUM,
                  languages=[".js", ".html"]),
]
