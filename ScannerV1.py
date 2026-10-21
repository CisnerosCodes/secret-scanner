import os
import numpy as np
import pandas as pd
import sys
import fileWalkerV1

"""
summery: 
main script that the client would run

takes up to 7 arguments: target path, output format, entropy threshold, max file size, file types to ignore, check entropy (toggle), check injection (toggle)

code timeline: 
  1. get the files to be scanned
  1.1. filter for criteria 
  2. scan the files:
  2.1.api
  2.2.entropy strings 
  2.3.injection
  3.process results
  4.return findings
"""
"""  outdated:
TargetFiles = fileWalkerV1.validFiles(sys.argv[1:])


class APIKeyScanner:

class EntropyStringScanner:

class InjectionScanner:

# base linereader 
#ToDo: convert to our needs
def process_file_lines(file_path):
    # 'with' automatically handles opening and closing the file safely
    with open(file_path, 'r', encoding='utf-8') as file:
        # Iterating directly over the file object reads line-by-line (memory efficient)
        for line in file:
            # .rstrip("\n") removes the trailing newline character from each line
            clean_line = line.rstrip("\n")
            
            # Perform your logic here
            print(clean_line)
"""