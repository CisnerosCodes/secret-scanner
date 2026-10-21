"""LineReader: reads one line at a time so large files never sit in memory (2.3).

RUN ORDER
  STEP 14  open()        called once per file by Scanner.scan_file()
  STEP 15  next_line()   called in a loop, once per line, until it returns None
"""

from pathlib import Path


class LineReader:
    def __init__(self) -> None:
        self._file = None

    def open(self, path: Path) -> None:
        # STEP 14 Raise OSError if the file cannot be read; Scanner turns that
        #         into a warning (PATH unreadable file, 2.5).
        # TODO: self._file = open(path, encoding="utf-8", errors="replace")
        try:
            self._file = open(path, encoding="utf-8", errors="replace")
        except (OSError, IOError) as e:
            raise e
        #       errors="replace" keeps non-UTF-8 lines from crashing the scan (2.3).
        raise NotImplementedError

    def next_line(self) -> str | None:
        # STEP 15 Return the next line, or None at end of file (then close the file).
        # TODO: line = self._file.readline(); "" means end of file.
        line = self._file.readline()
        if line == "":
            self._file.close()
            return None
        return line
