#! /usr/bin/python

import sys, os
from collections import defaultdict

time_counts = defaultdict(lambda: 0)
totol_updates = 0

with open('%s' % sys.argv[1]) as infile:
    for line in infile:
        if line.startswith('TIME'):
            time = line.split("\n")[0].split(": ")[1]
        if line.startswith('TYPE'):
            if 'Update' == line.split("\n")[0].split(": ")[1].split("/")[-1]:
                time_counts[time] += 1
                totol_updates += 1

max_count = 0
max_time = 0
for k, v in time_counts.iteritems():
    print k, v
    if v > max_count:
        max_count = v
        max_time = k

print "max:"
print max_time, max_count
print "total:"
print totol_updates
