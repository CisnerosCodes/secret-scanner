"""Config: one object holding every command-line option.

RUN ORDER
  Created at STEP 4 (end of Cli.parse_args).
  Read later at:
    STEP 5   Cli.run          -> path
    STEP 6   Scanner.__init__ -> no_entropy, no_injection, entropy_threshold
    STEP 10  FileWalker       -> ignore_globs
    STEP 12  FileWalker       -> max_file_size
    STEP 23  Cli.run          -> format
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class OutputFormat(Enum):
    TEXT = "text"   # default (3.4.2)
    JSON = "json"   # --format json (3.4.3)


@dataclass
class Config:
    # STEP 4  Filled in by Cli.parse_args(). Each field is one CLI option (4.2).
    path: Path = Path(".")                     # PATH argument; none given -> current directory (4.1)
    format: OutputFormat = OutputFormat.TEXT   # --format text|json
    entropy_threshold: float = 4.5             # --entropy-threshold FLOAT (3.2.2, base64 default)
    max_file_size: int = 1_000_000             # --max-file-size BYTES, default 1 MB (2.2)
    ignore_globs: list[str] = field(default_factory=list)  # --ignore GLOB, repeatable (2.1)
    no_entropy: bool = False                   # --no-entropy: known patterns only (4.2)
    no_injection: bool = False                 # --no-injection (3.3.8)
