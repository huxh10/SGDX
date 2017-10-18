#! /usr/bin/python

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

isdx = [0.010897, 0.029618, 0.056102, 0.091818, 0.134134]
w_sgx = [0.023137, 0.028914, 0.039269, 0.052020, 0.062375]
wo_sgx = [0.022891, 0.023537, 0.027715, 0.036196, 0.045230]
x_axis = [0.2, 0.4, 0.6, 0.8, 1.0]

def show_ms(times):
    return map(lambda x: 1000 * x, times)

f = plt.figure()

p_wo_sgx, = plt.plot(x_axis, show_ms(wo_sgx), 'b+-', label='SGDX*')
p_w_sgx, = plt.plot(x_axis, show_ms(w_sgx), 'r|-', label='SGDX')
p_isdx, = plt.plot(x_axis, show_ms(isdx), 'yx-', label='iSDX')

plt.gca().yaxis.grid(True)
#plt.yscale('log')

#for x, y in zip(x_axis, wo_sgx):
#    plt.annotate("%0.1f" % (y * 1000), xy=(x - 0.01, y * 1000 - 3), fontsize = 8)
#
#for x, y in zip(x_axis, w_sgx):
#    plt.annotate("%0.1f" % (y * 1000), xy=(x - 0.01, y * 1000), fontsize = 8)
#
#for x, y in zip(x_axis, isdx):
#    plt.annotate("%0.1f" % (y * 1000), xy=(x - 0.01, y * 1000 + 2), fontsize = 8)



plt.legend(handles = [p_isdx, p_w_sgx, p_wo_sgx], loc=2, prop={'size': 10})

plt.xticks(x_axis, x_axis)
plt.xlabel('Fraction of Peerings')
plt.ylabel('Time (ms)')
#plt.title('Per BGP announcement compute time')

plt.xlim(0, 1.1)

f.savefig('result_line.pdf', bbox_inches='tight')
