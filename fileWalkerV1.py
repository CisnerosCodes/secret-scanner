# 2 tasks: 1) find all files in a given directory and its subdirectories, 2) filter out files that are binary or exceed a certain size limit.

import os
import numpy as np
import pandas as pd
import sys
from pathlib import Path
from collections.abc import Iterator
from .config import Config


def validFiles(path):#gets the files that need to be scanned
  parent_dir = os.path.abspath(path)
  results = []
  if os.path.isfile(path):
    results.append(path)
  else:
    # Determine the base depth of the root directory
    base_depth = parent_dir.rstrip(os.path.sep).count(os.path.sep)
    
    for root, dirs, files in os.walk(parent_dir):
      # Calculate current depth relative to parent
      current_depth = root.count(os.path.sep) - base_depth
      
      # Level 1 or Level 2 files/folders inside the current root
      for name in dirs + files:
        full_path = os.path.join(root, name)
        results.append(full_path)
          
      # Prevent os.walk from diving into Level 3
      if current_depth >= 1:
        dirs.clear()  # This stops os.walk from recursing deeper
            
    return results



# Example run: python script.py arg1 arg2
print("Script name:", sys.argv[0])
print("All arguments:", sys.argv[1:])

#client runs CLI command and provides a path to either a folder or exact file to be scanned
# script path 
try:
    Target_DIR = sys.argv[1]
except IndexError:
    Target_DIR = os.getcwd()
    
print(Target_DIR)

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
    if path.name in self.DEFAULT_EXCLUDES:
      return True
    for glob in config.ignore_globs:
      if path.match(glob):
        return True
    return False
  
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

      
