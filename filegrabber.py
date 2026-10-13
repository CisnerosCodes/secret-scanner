#proof of concept file

import os
import numpy as np
import pandas as pd
import sys


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
    
