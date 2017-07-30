#! /usr/bin/python

import sys, os

count = 0

with open('%s' % sys.argv[1]) as infile:
    for line in infile:
        if line.startswith('TIME'):
            count += 1

print count
