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
TargetFiles = fileWalkerV1.validFiles(arg[*1])
