#! /usr/bin/python

import argparse
from random import choice, shuffle
from collections import defaultdict

MAX_AS_NUM = 1000
BASE_FILTER_FILE = '../bgp_policies/peers'      # filtering for export/import policies
BASE_RANK_FILE = '../bgp_policies/prefer'       # local preference for selection policies


class BGPPolicyGenerator(object):
    def __init__(self, as_num):
        self.as_num = as_num
        self.base_filter_name = BASE_FILTER_FILE
        self.base_rank_name = BASE_RANK_FILE
        self.as_peers = defaultdict(lambda: defaultdict(lambda: 0))
        self.as_peer_num = defaultdict(lambda: 0)

    def generate_uni_filter_policies(self, fraction):
        peer_num = int(self.as_num * fraction)
        rand_range = self.as_num - 1
        lists = [range(i+1, self.as_num) for i in range(0, self.as_num-1)]
        for i in range(0, self.as_num-1):
            while self.as_peer_num[i] < peer_num:
                if len(lists[i]) == 0:
                    break
                r = choice(lists[i])
                if self.as_peer_num[r] == peer_num:
                    lists[i].remove(r)
                    continue
                self.as_peers[i][r] = 1
                self.as_peers[r][i] = 1
                self.as_peer_num[i] += 1
                self.as_peer_num[r] += 1
                lists[i].remove(r)
        with open(self.base_filter_name + '_uni_%d_0%d.cfg' % (self.as_num, int(fraction * 100)), 'w+') as policy_file:
            lines = ['%d\n' % self.as_num]
            for i in range(0, self.as_num):
                lines.append('%d' % self.as_peer_num[i])
                if self.as_peer_num[i] != peer_num:
                    print i, self.as_peer_num[i]
                    #exit(1)
                for j in range(0, self.as_num):
                    if self.as_peers[i][j]:
                        lines.append(' %d' % j)
                lines.append('\n')
            policy_file.writelines(lines)

    def generate_rand_rank_policies(self):
        lists = [range(0, self.as_num) for i in range(0, self.as_num)]
        for i in range(0, self.as_num):
            shuffle(lists[i])
            # i should have lowest number (highest priority)
            for j in range(0, self.as_num):
                if lists[i][j] == 0:
                    lists[i][j] = lists[i][i]
                    break
            lists[i][i] = 0
        with open(self.base_rank_name + '_rand_%d.cfg' % self.as_num, 'w+') as policy_file:
            lines = ['%d\n' % self.as_num]
            for i in range(0, self.as_num):
                for j in range(0, self.as_num):
                    lines.append(' %d' % lists[i][j])
                lines.append('\n')
            policy_file.writelines(lines)


def restricted_float(x):
    x = float(x)
    if x > 0.0 and x < 1.0:
        return x
    else:
        raise argparse.ArgumentTypeError("fraction %r should in range (0, 1)" % x)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('as_num', type=int, help='AS member number')
    parser.add_argument('--rank_policies', action='store_true', help='generate random preference policies')
    parser.add_argument('--filter_policies', action='store_true', help='generate random filtering policies')
    parser.add_argument('-d', '--distribution', choices=['uni'], default='uni', help='the distribution of AS peering number: [uni] (the uniform peering number is specified by -f parameter, default is 0.2*AS_NUM)')
    parser.add_argument('-f', '--fraction', type=restricted_float, default=0.2, help='the fraction is the uniform peering number divided by the as number')
    args = parser.parse_args()

    bgp_policy_gen = BGPPolicyGenerator(args.as_num)
    if args.rank_policies:
        bgp_policy_gen.generate_rand_rank_policies()
    if args.filter_policies:
        if args.distribution == 'uni':
            bgp_policy_gen.generate_uni_filter_policies(args.fraction)
