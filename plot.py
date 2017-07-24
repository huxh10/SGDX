#! /usr/bin/python

import sys
import matplotlib.pyplot as plt

if len(sys.argv) == 1:
    print "please input latency files: ./plot.py [file1] [file2] .."
    exit(0)

data = []
labels = []

for i in range(1, len(sys.argv)):
    print sys.argv[i]
    with open(sys.argv[i], 'r') as f:
        data.append(map(lambda x: int(x[:-1].split(' ')[1]), f.readlines()))
        labels.append(sys.argv[i])

# plot
f = plt.figure()
plt.boxplot(data, notch = 0, sym = '', vert = 1, whis = 1.4, labels = labels)
plt.gca().yaxis.grid(True)
plt.yscale('log')
#plt.show()

f.savefig('result_box.pdf', bbox_inches='tight')
