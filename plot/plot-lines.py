#! /usr/bin/python

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

isdx = [0.239595, 0.631698, 1.137534]
w_sgx = [0.023106, 0.034906, 0.058749, 0.085820]
wo_sgx = [0.022861, 0.028084, 0.046305, 0.068643]
ix_axis = [0.2, 0.4, 0.6]
x_axis = [0.2, 0.4, 0.6, 0.8]

def show_ms(times):
    return map(lambda x: 1000 * x, times)

f = plt.figure()

p_wo_sgx, = plt.plot(x_axis, show_ms(wo_sgx), 'b+-', label='w/o SGX')
p_w_sgx, = plt.plot(x_axis, show_ms(w_sgx), 'rx-', label='w/ SGX')
p_isdx, = plt.plot(ix_axis, show_ms(isdx), 'y|-', label='iSDX')

plt.gca().yaxis.grid(True)
plt.yscale('log')

for x, y in zip(x_axis, wo_sgx):
    plt.annotate(str(int(y * 1000)), xy=(x - 0.02, y * 1000 - 5))

for x, y in zip(x_axis, w_sgx):
    plt.annotate(str(int(y * 1000)), xy=(x - 0.02, y * 1000 + 2))

for x, y in zip(ix_axis, isdx):
    plt.annotate(str(int(y * 1000)), xy=(x - 0.02, y * 1000 - 5))



plt.legend(handles = [p_isdx, p_w_sgx, p_wo_sgx], loc=2, prop={'size': 10})

plt.xticks(x_axis, x_axis)
plt.xlabel('Fraction of ASes')
plt.ylabel('Time (ms)')
plt.title('Per BGP announcement compute time')

plt.xlim(0, 0.9)

f.savefig('result_line.pdf', bbox_inches='tight')
