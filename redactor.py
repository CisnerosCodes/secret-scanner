"""Redactor: masks secret values so the report never becomes a leak (3.4.1).

RUN ORDER
  STEP 18  redact()  for every known-secret finding (from RuleEngine)
                     and every high-entropy finding (from EntropyAnalyzer)
"""


class Redactor:
    VISIBLE_PREFIX = 4  # keep "AKIA", "ghp_", "sk-p" so the type is still readable

    @staticmethod
    def redact(value: str) -> str:
        # STEP 18 Example: "AKIAIOSFODNN7EXAMPLE" -> "AKIA****************"
        n = Redactor.VISIBLE_PREFIX
        if len(value) <= n:
            return "*" * len(value)
        return value[:n] + "*" * (len(value) - n)
