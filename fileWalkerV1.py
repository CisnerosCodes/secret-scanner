#proof of concept file

import os
import numpy as np
import pandas as pd
import sys

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



      
