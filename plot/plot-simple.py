#! /usr/bin/python

import sys
import matplotlib.pyplot as plt

if len(sys.argv) == 1:
    print "please input latency files: ./plot.py [file1] [label1] [file2] [label2] .."
    exit(0)

data = []
labels = []

for i in range(1, len(sys.argv)):
    if i % 2 != 0:
        with open(sys.argv[i], 'r') as f:
            data.append(map(lambda x: int(x[:-1].split(' ')[1]), f.readlines()))
    else:
        labels.append(sys.argv[i])

f = plt.figure()

plt.boxplot(data, notch = 0, sym = '', vert = 1, whis = 1.4, labels = labels)

# plot
#plt.boxplot(data, notch = 0, sym = '', vert = 1, whis = 1.4, labels = labels)
plt.gca().yaxis.grid(True)
plt.yscale('log')
#plt.legend(prop={'size':6})

plt.xlabel('RIB Entry Number')
plt.ylabel('Time (us)')
plt.title('SIX-PACK compute time for BGP updates')
#plt.show()

f.savefig('result_box.pdf', bbox_inches='tight')
