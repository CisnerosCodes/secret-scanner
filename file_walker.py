"""FileWalker: decides which files get read (UC-4).

RUN ORDER
  STEP 9   walk() resumes and looks at the next entry
  STEP 10  is_excluded()   .git/, target/, node_modules/, --ignore globs
  STEP 11  is_binary()     binary files are skipped and counted
  STEP 12  too_large()     files over --max-file-size are skipped and counted
  then     yield the path  -> control jumps to Scanner.scan_file() at STEP 13
"""

import os
from collections.abc import Iterator
from pathlib import Path

from .config import Config


class FileWalker:
    DEFAULT_EXCLUDES = {".git", "target", "node_modules"}  # 2.1

    def __init__(self) -> None:
        self.skipped = 0  # binary + oversized, shown in the summary (2.2)

    def walk(self, path: Path, config: Config) -> Iterator[Path]:
        # STEP 9  Generator: each `yield` pauses here and runs STEP 13 for that file.

        # PATH single file (UC-1 alternate): check it and yield just that one.
        if path.is_file():
            if self._should_read(path, config):
                yield path
            return

        # PATH directory: recursive walk (2.1).
        for root, dirs, files in os.walk(path):
            # STEP 10 Prune excluded directories so os.walk never enters them.
            dirs[:] = [d for d in dirs if not self.is_excluded(Path(root, d), config)]
            for name in files:
                file_path = Path(root, name)
                if self._should_read(file_path, config):
                    yield file_path  # -> STEP 13, then resumes on the next line

    def _should_read(self, path: Path, config: Config) -> bool:
        # STEP 10 PATH --ignore GLOB: matching files are dropped (not counted).
        if self.is_excluded(path, config):
            return False
        # STEP 11 PATH binary file: skipped and counted (2.2).
        if self.is_binary(path):
            self.skipped += 1
            return False
        # STEP 12 PATH --max-file-size: larger files skipped and counted (2.2).
        if self.too_large(path, config):
            self.skipped += 1
            return False
        return True

    def is_excluded(self, path: Path, config: Config) -> bool:
        # STEP 10
        # TODO: True if path.name is in DEFAULT_EXCLUDES, or if the path matches
        #       any glob in config.ignore_globs (fnmatch).
        raise NotImplementedError

    def is_binary(self, path: Path) -> bool:
        # STEP 11
        # TODO: read the first few KB; a NUL byte (b"\x00") means binary.
        #       If the file cannot be opened, return False and let STEP 14 report it.
        raise NotImplementedError

    def too_large(self, path: Path, config: Config) -> bool:
        # STEP 12
        # TODO: path.stat().st_size > config.max_file_size.
        #       A broken symlink fails stat(); return False and let STEP 14 report it.
        raise NotImplementedError
