#! /usr/bin/python

import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.artist import setp

groups = 2

def setBoxColors(bp, c):
    setp(bp['boxes'][0], color=c)
    setp(bp['caps'][0], color=c)
    setp(bp['caps'][1], color=c)
    setp(bp['whiskers'][0], color=c)
    setp(bp['whiskers'][1], color=c)
    setp(bp['medians'][0], color=c)

if len(sys.argv) == 1:
    print "please input latency files: ./plot.py [file1] [file2] [label1] ..."
    exit(0)

data1 = []
data2 = []
labels = []

assert (len(sys.argv) - 1) % (groups + 1) == 0
group_num = (len(sys.argv) -1) / (groups + 1)

for i in range(1, len(sys.argv)):
    if i % (groups + 1) == 1:
        with open(sys.argv[i], 'r') as f:
            data1.append(map(lambda x: float(x[:-1].split(' ')[1]) / 1000, f.readlines()))
    elif i % (groups + 1) == 2:
        with open(sys.argv[i], 'r') as f:
            data2.append(map(lambda x: float(x[:-1].split(' ')[1]) / 1000, f.readlines()))
    else:
        labels.append(sys.argv[i])


f, (ax1, ax2) = plt.subplots(2, sharex=True, sharey=False)

for i in range(0, group_num):
    p = i * groups + 1
    bp1 = ax1.boxplot([data2[i]], positions = [p], widths = 0.6, notch = 0, sym = '', vert = 1, whis = 1.4)
    bp2 = ax2.boxplot([data1[i]], positions = [p], widths = 0.6, notch = 0, sym = '', vert = 1, whis = 1.4)
    setBoxColors(bp1, 'darkgreen')
    setBoxColors(bp2, 'red')

# Fine-tune figure; make subplots close to each other and hide x ticks for
# all but bottom plot.
ax1.plot([], c='darkgreen', label='SIXPACK')
ax1.legend(loc=2, prop={'size':10})
#ax1.set_xlim(-2, group_num * 2 + 2)
ax1.set_ylim(10, 200)
ax1.yaxis.grid(True)
ax2.plot([], c='red', label='SGRS')
ax2.legend(loc=2, prop={'size':10})
ax2.set_xlim(-2, group_num * 2 + 1)
ax2.set_ylim(0, 10)
ax2.yaxis.grid(True)
ax2.set_ylabel('Time (ms)')
ax2.yaxis.set_label_coords(-0.07, 1)
#ax2.set_xticks(xrange(1, group_num * 2, 2), labels)
f.subplots_adjust(hspace=0)
#plt.gca().yaxis.grid(True)
plt.setp([a.get_xticklabels() for a in f.axes[:-1]], visible=False)
plt.xticks(xrange(1, group_num * 2, 2), labels)
#plt.xlim(-2, group_num * 2 + 1)


# plot
#plt.boxplot(data, notch = 0, sym = '', vert = 1, whis = 1.4, labels = labels)
#plt.legend(prop={'size':6})

plt.xlabel('Updates Per Second')
#plt.ylabel('Time (ms)')
#plt.title('Per BGP announcement compute time')
#plt.show()

f.savefig('result_box.pdf', bbox_inches='tight')
