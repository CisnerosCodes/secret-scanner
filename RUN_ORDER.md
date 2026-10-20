# Secret Scanner: Run-Time Order

Every function in `secret_scan/` is a stub with `# STEP n` comments.
The steps are numbered in the order they run. Read the files in this order:

| Steps | File | Function |
|---|---|---|
| 1, 27 | `__main__.py` | `main()` |
| 2, 5, 23, 25, 26 | `cli.py` | `Cli.run()` |
| 3, 4 | `cli.py`, `config.py` | `Cli.parse_args()`, `Config` |
| 6, 7 | `scanner.py` | `Scanner.__init__()` |
| 7 | `rule_engine.py` | `RuleEngine.compile()` |
| 8, 22 | `scanner.py` | `Scanner.scan()` |
| 9 to 12 | `file_walker.py` | `walk()`, `is_excluded()`, `is_binary()`, `too_large()` |
| 13 | `scanner.py` | `Scanner.scan_file()` |
| 14, 15 | `line_reader.py` | `open()`, `next_line()` |
| 16 | `suppression.py` | `is_suppressed()` |
| 17 | `rule_engine.py`, `rules.py` | `match_line()`, `InjectionRule.applies_to()` |
| 18 | `redactor.py` | `Redactor.redact()` |
| 19 to 21 | `entropy.py` | `analyze()`, `shannon()`, `Allowlist.is_false_positive()` |
| 22, 24, 26 | `report.py` | `ScanReport`, `by_type()`, `exit_code()` |
| 23, 24 | `reporters.py` | `TextReporter.render()` / `JsonReporter.render()` |

**The loops.** Steps 9 to 21 repeat. `walk()` is a generator, so the order
alternates per file: find file A (9-12), scan file A (13-21), find file B
(9-12), scan file B (13-21). Inside one file, steps 15 to 21 repeat per line.

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8
  ┌─► 9 → 10 → 11 → 12 → 13 → 14 ─┐            one pass per file
  │      ┌─► 15 → 16 → 17 → 18 → 19 → 20 → 21 ─┐   one pass per line
  │      └──────────────────────────────────────┘
  └──────────────────────────────────────────────┘
22 → 23 → 24 → 25 → 26 → 27
```

## One real run, traced step by step

Command: `secret-scan ./demo`. The folder holds four files (os.walk may visit
them in another order):

| File | Contents |
|---|---|
| `app.py` | line 1 `import os`, line 2 `AWS_KEY = "AKIAIOSFODNN7EXAMPLE"` |
| `logo.png` | binary |
| `keys.pem` | no read permission |
| `web.js` | line 1 `const k = "sk-test..."; // secret-scan:ignore` |

```
 1  main()
 2  Cli.run()
 3  parse_args()            no flags, so every default
 4  Config(path=./demo, format=TEXT, entropy on, injection on)
 5  ./demo exists
 6  Scanner.__init__()      EntropyAnalyzer built, injection rules kept
 7  RuleEngine.compile()    9 regexes compiled, once
 8  Scanner.scan()          clock starts

    ── app.py ──
 9  walk() finds app.py
10  not excluded
11  not binary
12  under 1 MB              → yield
13  scan_file(app.py)
14  open() ok
15    line 1 "import os"
16    no marker
17    match_line(".py"): injection rules for .py run, nothing matches
19    analyze(): no 20+ character token
15    line 2 'AWS_KEY = "AKIA..."'
16    no marker
17    match_line(): AWS rule matches at columns 11-31
18    redact() → "AKIA****************"  → Finding #1
19    analyze(): candidate "AKIA..." already matched (19b), skipped
15    next_line() → None, end of file

    ── logo.png ──
 9  walk() finds logo.png
10  not excluded
11  binary → skipped += 1, not yielded

    ── keys.pem ──
 9  walk() finds keys.pem
10, 11, 12  passes            → yield
13  scan_file(keys.pem)
14  open() raises PermissionError → Warning, skipped += 1

    ── web.js ──
 9  walk() finds web.js
10, 11, 12  passes            → yield
13  scan_file(web.js)
14  open() ok
15    line 1
16    "// secret-scan:ignore" found → skip 17-21
15    next_line() → None

22  ScanReport(1 finding, 1 warning, 2 scanned, 2 skipped)
23  TextReporter chosen
24  render() calls by_type() → {"AWS access key ID": 1}
25  written to the terminal
26  exit_code() → 1
27  sys.exit(1)
```

## Every flag path

Each row starts from the default run above and lists only what changes.

| Command | Steps that change | Ends with |
|---|---|---|
| `secret-scan --help` | Step 3: argparse prints usage and exits inside `parse_args()`. Steps 4-26 never run. | exit 0 |
| `secret-scan --version` | Same as `--help`, prints the version. | exit 0 |
| `secret-scan --format xml` (any invalid argument) | Step 3a: argparse prints an error and exits. | exit 2 |
| `secret-scan --max-file-size -5` | Step 3b: `parser.error()` (range check). | exit 2 |
| `secret-scan ./missing` | Step 5: path not found, error printed. Steps 6-26 never run. | exit 2 |
| `secret-scan` (no path) | Step 4: `path` defaults to `.` | as default |
| `secret-scan app.py` (one file) | Step 9: `walk()` yields that one file, no directory loop. | as default |
| `secret-scan --format json` | Step 23: `JsonReporter` instead of `TextReporter`. Step 24: JSON. | exit 0 or 1 |
| `secret-scan --format json > /dev/full` (write fails) | Step 25: `OSError`, error printed. | exit 2 |
| `secret-scan --no-entropy` | Step 6a: no `EntropyAnalyzer`. Steps 19-21 never run. | as default |
| `secret-scan --entropy-threshold 5.0` | Step 4 stores 5.0. Step 6a passes it on. Step 20 compares against 5.0. | as default |
| `secret-scan --no-injection` | Step 6b: injection rules removed. Step 17a never runs. | as default |
| `secret-scan --ignore "*.lock"` | Step 10: matching files dropped, not counted. | as default |
| `secret-scan --max-file-size 500` | Step 12: larger files skipped and counted. | as default |
| A binary file in the tree | Step 11: skipped and counted. | as default |
| An unreadable file or broken symlink | Step 14: `Warning`, skipped, scan continues at step 9. | as default |
| A line with `// secret-scan:ignore` | Step 16: steps 17-21 skipped for that line. | as default |
| A non-UTF-8 line | Step 15: bad bytes replaced, scan continues. | as default |
| No findings anywhere | Step 26: `exit_code()` returns 0. | exit 0 |
