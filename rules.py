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


class RuleType(Enum):
    INJECTION = "injection"  # STEP 17a
    KNOWN_SECRET = "KnownSecret"


class Severity(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    
class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    

@dataclass
class Rule:
    name: str
    pattern: str        # source text of the regex
    severity: Severity
    type: RuleType = RuleType.KNOWN_SECRET
    regex: re.Pattern | None = None     # filled at STEP 7, never per line
    

@dataclass
class InjectionRule(Rule):
    type: RuleType = RuleType.INJECTION
    confidence: Confidence = Confidence.LOW  # STEP 17a
    languages: list[str] = field(default_factory=list)  # file extensions (3.3.5)
    
    def applies_to(self, line: str, file_extension: str) -> bool:
        # STEP 17a Return True if this rule applies to the given line and file extension.
        return file_extension in self.languages
    

RuleTable: list[Rule] = [
    # --- KNOWN SECRET RULES ---
    Rule("AWS Access Key", r"AKIA[0-9A-Z]{16}",  Severity.HIGH),
    Rule("GitHub Token", r"ghp_[a-zA-Z0-9]{36}", Severity.HIGH),
    Rule("OpenAI API Key", r"sk-[a-zA-Z0-9]{48}",Severity.HIGH),
    Rule("JWT", r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+", Severity.MEDIUM),

    # --- INJECTION RULES ---
    InjectionRule("SQL Injection",
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