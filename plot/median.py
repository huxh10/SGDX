#! /usr/bin/python

import sys
from statistics import median

if len(sys.argv) != 2:
    print "please input latency files: ./plot.py [file1]"
    exit(0)

with open(sys.argv[1], 'r') as f:
    data = map(lambda x: int(x[:-1].split(' ')[1]), f.readlines())

print median(data)
