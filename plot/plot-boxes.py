#! /usr/bin/python

import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.artist import setp

groups = 3

def setBoxColors(bp):
    setp(bp['boxes'][0], color='blue')
    setp(bp['caps'][0], color='blue')
    setp(bp['caps'][1], color='blue')
    setp(bp['whiskers'][0], color='blue')
    setp(bp['whiskers'][1], color='blue')
    setp(bp['medians'][0], color='blue')

    setp(bp['boxes'][1], color='red')
    setp(bp['caps'][2], color='red')
    setp(bp['caps'][3], color='red')
    setp(bp['whiskers'][2], color='red')
    setp(bp['whiskers'][3], color='red')
    setp(bp['medians'][1], color='red')

    setp(bp['boxes'][2], color='darkgreen')
    setp(bp['caps'][4], color='darkgreen')
    setp(bp['caps'][5], color='darkgreen')
    setp(bp['whiskers'][4], color='darkgreen')
    setp(bp['whiskers'][5], color='darkgreen')
    setp(bp['medians'][2], color='darkgreen')


if len(sys.argv) == 1:
    print "please input latency files: ./plot.py [file1] [file2] [file3] [label1] ..."
    exit(0)

data = []
labels = []

assert (len(sys.argv) - 1) % (groups + 1) == 0
group_num = (len(sys.argv) -1) / (groups + 1)

for i in range(1, len(sys.argv)):
    if i % (groups + 1) != 0:
        with open(sys.argv[i], 'r') as f:
            data.append(map(lambda x: int(x[:-1].split(' ')[1]), f.readlines()))
    else:
        labels.append(sys.argv[i])

f = plt.figure()

for i in range(0, group_num):
    k = i * groups
    t = k + 1
    r = k + 2
    p = i * (groups + 1) + 1
    q = p + 1
    s = p + 2
    bp = plt.boxplot([data[k], data[t], data[r]], positions = [p, q, s], widths = 0.6, notch = 0, sym = '', vert = 1, whis = 1.4)
    setBoxColors(bp)

# plot
#plt.boxplot(data, notch = 0, sym = '', vert = 1, whis = 1.4, labels = labels)
plt.gca().yaxis.grid(True)
plt.yscale('log')
plt.plot([], c='darkgreen', label='SIXPACK')
plt.plot([], c='red', label='SGRS')
plt.plot([], c='blue', label='Baseline')
plt.legend(loc=2, prop={'size':10})
#plt.legend(prop={'size':6})

plt.xticks(xrange(2, group_num * (groups + 1), (groups + 1)), labels)
plt.xlim(-2, group_num * (groups + 1) + 2)
plt.xlabel('RIB Entry Number (million)')
plt.ylabel('Time (us)')
#plt.title('Per BGP announcement compute time')
#plt.show()

f.savefig('result_box.pdf', bbox_inches='tight')
