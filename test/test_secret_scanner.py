import io
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch
import pytest

from secret_scanner.cli import Cli
from secret_scanner.config import Config, OutputFormat
from secret_scanner.entropy import Allowlist, EntropyAnalyzer
from secret_scanner.fileWalkerV1 import FileWalker
from secret_scanner.finding import Finding, Span, Warning
from secret_scanner.lineReader import LineReader
from secret_scanner.redactor import Redactor
from secret_scanner.report import ScanReport
from secret_scanner.reporters import JsonReporter, TextReporter
from secret_scanner.rule_engine import RuleEngine
from secret_scanner.rules import (
    Confidence,
    InjectionRule,
    Rule,
    RuleTable,
    RuleType,
    Severity,
)
from secret_scanner.ScannerV1 import Scanner
from secret_scanner.suppression import SuppressionFilter


# =====================================================================
# 1. Redactor Tests (Needs Statement 3.4.1)
# =====================================================================

def test_redactor_masks_aws_and_short_strings():
    assert Redactor.redact("AKIAIOSFODNN7EXAMPLE") == "AKIA****************"
    assert len(Redactor.redact("AKIAIOSFODNN7EXAMPLE")) == 20
    assert Redactor.redact("abcd") == "****"
    assert Redactor.redact("ab") == "**"
    assert Redactor.redact("") == ""


# =====================================================================
# 2. SuppressionFilter Tests (Needs Statement 3.3.7, 3.4.5)
# =====================================================================

def test_suppression_filter():
    sf = SuppressionFilter()
    assert sf.is_suppressed('token = "ghp_' + "a" * 36 + '" // secret-scan:ignore') is True
    assert sf.is_suppressed('token = "ghp_' + "a" * 36 + '"') is False


# =====================================================================
# 3. EntropyAnalyzer & Allowlist Tests (Needs Statement 1.3, 3.2)
# =====================================================================

def test_shannon_entropy_math():
    ea = EntropyAnalyzer()
    assert ea.shannon("") == 0.0
    assert ea.shannon("aaaaaaaaaaaaaaaaaaaa") == 0.0
    # Equal two-character split ("ab" repeated 10 times) has entropy 1.0
    assert ea.shannon("abababababababababab") == pytest.approx(1.0)
    # High-entropy random-looking string exceeds default 4.5
    assert ea.shannon("x9P2mK7vL4qR8wZ1tY6nB3cF5gH0jD8s") > 4.5


def test_allowlist_false_positives():
    al = Allowlist()
    assert al.is_false_positive("550e8400-e29b-41d4-a716-446655440000") is True
    assert al.is_false_positive("sha512-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=") is True
    assert al.is_false_positive("YOUR_API_KEY_HERE_1234567890") is True
    assert al.is_false_positive("EXAMPLE_TOKEN_VALUE_1234567890") is True
    assert al.is_false_positive("1111111111111111111111") is True
    assert al.is_false_positive("x9P2mK7vL4qR8wZ1tY6nB3cF5gH0jD8s") is False


def test_entropy_deduplicates_matched_spans_and_respects_threshold():
    line = 'AWS = "AKIAIOSFODNN7EXAMPLE" EXTRA = "x9P2mK7vL4qR8wZ1tY6nB3cF5gH0jD8s"'
    aws_finding = Finding(
        finding_type="AWS Access Key",
        severity=Severity.HIGH,
        span=Span(7, 27),
        redacted_preview="AKIA****************",
    )
    ea = EntropyAnalyzer(base64_threshold=4.5)
    findings = ea.analyze(line, [aws_finding])
    assert len(findings) == 1
    assert findings[0].finding_type == "High-entropy string"
    assert findings[0].redacted_preview.startswith("x9P2")


# =====================================================================
# 4. RuleEngine & RuleTable Tests (Needs Statement 3.1, 3.3)
# =====================================================================

def test_rule_engine_compiles_and_matches_known_secrets():
    rules = [Rule(r.name, r.pattern, r.severity, r.type) for r in RuleTable if r.type is RuleType.KNOWN_SECRET]
    engine = RuleEngine.compile(rules)

    assert all(r.regex is not None for r in engine.rules)

    aws_line = 'aws_key: "AKIAIOSFODNN7EXAMPLE",'
    gh_line = 'github_token: "ghp_' + "a" * 36 + '",'
    oa_line = 'openai_key: "sk-' + "b" * 48 + '",'
    jwt_line = 'jwt_token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",'

    assert [f.finding_type for f in engine.match_line(aws_line, ".rs")] == ["AWS Access Key"]
    assert [f.finding_type for f in engine.match_line(gh_line, ".rs")] == ["GitHub Token"]
    assert [f.finding_type for f in engine.match_line(oa_line, ".rs")] == ["OpenAI API Key"]
    assert [f.finding_type for f in engine.match_line(jwt_line, ".rs")] == ["JWT"]

    # Redaction check on known secrets
    aws_match = engine.match_line(aws_line, ".rs")[0]
    assert aws_match.redacted_preview == "AKIA****************"
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_match.redacted_preview


def test_rule_table_extensible_without_scanner_changes():
    custom_rule = Rule("Custom Internal Key", r"INT_[A-Z0-9]{10}", Severity.HIGH)
    engine = RuleEngine.compile([custom_rule])
    matches = engine.match_line('key = "INT_ABCDEF1234"', ".py")
    assert len(matches) == 1
    assert matches[0].finding_type == "Custom Internal Key"


def test_rule_engine_injection_rule_language_filter():
    inj_rule = InjectionRule(
        name="XSS",
        pattern=r"innerHTML\s*=",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        languages=[".js"],
    )
    engine = RuleEngine.compile([inj_rule])
    assert len(engine.match_line("el.innerHTML = x;", ".js")) == 1
    assert len(engine.match_line("el.innerHTML = x;", ".py")) == 0


# =====================================================================
# 5. LineReader Tests (Needs Statement 2.3, 2.5)
# =====================================================================

def test_line_reader_streams_lines_and_handles_invalid_utf8(tmp_path: Path):
    f = tmp_path / "data.txt"
    f.write_bytes(b"line one\n\xff\xfe bad bytes\nline three\n")

    reader = LineReader()
    reader.open(f)
    try:
        got = []
        while (line := reader.next_line()) is not None:
            got.append(line)
    finally:
        reader.close()

    assert len(got) == 3
    assert got[0] == "line one\n"
    assert "bad bytes" in got[1]
    assert got[2] == "line three\n"
    assert reader.next_line() is None


def test_line_reader_raises_oserror_on_missing_file(tmp_path: Path):
    reader = LineReader()
    with pytest.raises(OSError):
        reader.open(tmp_path / "does_not_exist.txt")


# =====================================================================
# 6. FileWalker Tests (Needs Statement 2.1, 2.2, 2.5)
# =====================================================================

def test_file_walker_too_large_handles_oserror_gracefully(tmp_path: Path):
    walker = FileWalker()
    cfg = Config(path=tmp_path, max_file_size=10)
    small = tmp_path / "small.txt"
    small.write_text("hi", encoding="utf-8")
    large = tmp_path / "large.txt"
    large.write_text("0123456789abcdef", encoding="utf-8")

    assert walker.too_large(small, cfg) is False
    assert walker.too_large(large, cfg) is True
    assert walker.too_large(tmp_path / "broken_link", cfg) is False


def test_file_walker_excludes_and_binary_detection(tmp_path: Path):
    walker = FileWalker()
    cfg = Config(path=tmp_path, ignore_globs=["*.secret.txt"])

    assert walker.is_excluded(tmp_path / ".git", cfg) is True
    assert walker.is_excluded(tmp_path / "target", cfg) is True
    assert walker.is_excluded(tmp_path / "node_modules", cfg) is True
    assert walker.is_excluded(tmp_path / "foo.secret.txt", cfg) is True
    assert walker.is_excluded(tmp_path / "main.rs", cfg) is False

    bin_file = tmp_path / "sample.bin"
    bin_file.write_bytes(b"\x00\x01\x02\x03")
    text_file = tmp_path / "sample.rs"
    text_file.write_text("fn main() {}\n", encoding="utf-8")

    assert walker.is_binary(bin_file) is True
    assert walker.is_binary(text_file) is False


# =====================================================================
# 7. Scanner.scan_file Tests (including uploaded vulnerable_sample.rs)
# =====================================================================

def test_scanner_scan_file_on_vulnerable_sample_rs():
    sample_path = Path(__file__).resolve().parent.parent / "vulnerable_sample.rs"
    if not sample_path.exists():
        sample_path = Path("vulnerable_sample.rs")
    assert sample_path.exists(), "vulnerable_sample.rs not found"

    cfg = Config(path=sample_path, no_entropy=True, no_injection=True)
    scanner = Scanner(cfg)
    findings, warning = scanner.scan_file(sample_path)

    assert warning is None
    types = {f.finding_type for f in findings}
    assert "AWS Access Key" in types
    assert "GitHub Token" in types
    assert "JWT" in types
    assert all(f.line_number > 0 and f.file == sample_path for f in findings)
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.redacted_preview for f in findings)


def test_scanner_scan_file_unreadable_returns_warning(tmp_path: Path):
    missing = tmp_path / "missing.py"
    cfg = Config(path=missing, no_entropy=True, no_injection=True)
    scanner = Scanner(cfg)
    findings, warning = scanner.scan_file(missing)

    assert findings == []
    assert warning is not None
    assert warning.path == missing


# =====================================================================
# 8. ScanReport & Reporters Tests (Needs Statement 3.4)
# =====================================================================

def test_scan_report_and_reporters(tmp_path: Path):
    f = Finding(
        finding_type="AWS Access Key",
        severity=Severity.HIGH,
        span=Span(10, 30),
        redacted_preview="AKIA****************",
        file=tmp_path / "app.py",
        line_number=5,
    )
    w = Warning(path=tmp_path / "locked.txt", reason="unreadable file: Permission denied")
    report = ScanReport(findings=[f], warnings=[w], files_scanned=2, files_skipped=1, elapsed=0.123)

    assert report.exit_code() == 1
    assert report.by_type() == {"AWS Access Key": 1}

    text = TextReporter().render(report)
    assert str(tmp_path / "app.py") in text
    assert "line 5: [HIGH] AWS Access Key  AKIA****************" in text
    assert "warning:" in text
    assert "files scanned: 2" in text
    assert "files skipped: 1" in text

    payload = json.loads(JsonReporter().render(report))
    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["files_scanned"] == 2
    assert payload["summary"]["files_skipped"] == 1
    assert payload["findings"][0]["line"] == 5
    assert payload["findings"][0]["preview"] == "AKIA****************"


# =====================================================================
# 9. CLI Argument Parsing & Error Handling Tests (Needs Statement 3.4.4, 4)
# =====================================================================

def test_cli_parse_args_defaults_and_options():
    cli = Cli()
    default_cfg = cli.parse_args([])
    assert default_cfg.path == Path(".")
    assert default_cfg.format is OutputFormat.TEXT
    assert default_cfg.max_file_size == 1_000_000
    assert default_cfg.entropy_threshold == 4.5
    assert default_cfg.no_entropy is False
    assert default_cfg.no_injection is False

    cfg = cli.parse_args([
        "my_dir",
        "--format", "json",
        "--entropy-threshold", "3.2",
        "--max-file-size", "4096",
        "--ignore", "*.bak",
        "--no-entropy",
        "--no-injection",
    ])
    assert cfg.path == Path("my_dir")
    assert cfg.format is OutputFormat.JSON
    assert cfg.entropy_threshold == 3.2
    assert cfg.max_file_size == 4096
    assert cfg.ignore_globs == ["*.bak"]
    assert cfg.no_entropy is True
    assert cfg.no_injection is True


@pytest.mark.parametrize("bad_args", [["--max-file-size", "0"], ["--entropy-threshold", "0"], ["--format", "yaml"]])
def test_cli_invalid_args_exit_2(bad_args: list[str]):
    cli = Cli()
    with pytest.raises(SystemExit) as exc:
        cli.parse_args(bad_args)
    assert exc.value.code == 2


def test_cli_run_missing_path_returns_2(tmp_path: Path):
    cli = Cli()
    missing = tmp_path / "no_such_dir"
    with patch.object(sys, "argv", ["secret-scan", str(missing)]):
        assert cli.run() == 2


def test_cli_run_stdout_write_error_returns_2(tmp_path: Path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n", encoding="utf-8")
    cli = Cli()

    class BrokenStdout:
        def write(self, _s: str) -> int:
            raise OSError("Broken pipe")

    with patch.object(sys, "argv", ["secret-scan", "--no-entropy", "--no-injection", str(clean)]), \
         patch.object(sys, "stdout", BrokenStdout()):
        assert cli.run() == 2