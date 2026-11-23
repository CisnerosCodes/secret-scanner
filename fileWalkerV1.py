"""FileWalker: finds the files to scan and drops binary / oversized ones (2.1, 2.2).

RUN ORDER
  STEP 9   walk()          generator, called by Scanner.scan()
  STEP 10  is_excluded()   default excludes + --ignore globs
  STEP 11  is_binary()
  STEP 12  too_large()
"""

from collections.abc import Iterator
from fnmatch import fnmatch
import os
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
        # STEP 10 True if path.name is in DEFAULT_EXCLUDES, or if the path matches
        #         any glob in config.ignore_globs (fnmatch).
        if path.name in self.DEFAULT_EXCLUDES:
            return True
        path_str = path.as_posix()
        for pattern in config.ignore_globs:
            # "dir/**" and "dir/*" exclude everything under dir.
            glob = pattern.rstrip("/")
            if glob.endswith("/**"):
                glob = glob[:-3]
            elif glob.endswith("/*"):
                glob = glob[:-2]
            if (fnmatch(path.name, glob) or fnmatch(path_str, glob)
                    or fnmatch(path_str, f"*/{glob}") or fnmatch(path_str, f"{glob}/*")
                    or fnmatch(path_str, f"*/{glob}/*")):
                return True
        return False

    def is_binary(self, path: Path) -> bool:
        # STEP 11 Read the first few KB; a NUL byte (b"\x00") means binary.
        #         If the file cannot be opened, return False and let STEP 14 report it.
        try:
            with open(path, "rb") as f:
                chunk = f.read(4096)
            return b"\x00" in chunk
        except OSError:
            return False

    def too_large(self, path: Path, config: Config) -> bool:
        # STEP 12 path.stat().st_size > config.max_file_size.
        #         A broken symlink fails stat(); return False and let STEP 14 report it.
        try:
            return path.stat().st_size > config.max_file_size
        except OSError:
            return False