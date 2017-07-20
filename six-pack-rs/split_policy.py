#! /usr/bin/python

import argparse
import json
import os
import random


FILTER_SHARE1 = 'filter_share1.json'
FILTER_SHARE2 = 'filter_share2.json'
RANK_SHARE1 = 'rank_share1.json'
RANK_SHARE2 = 'rank_share2.json'

def xor_string(s_x, s_y):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s_x, s_y))

def split_policy(filter_file, rank_file):
    with open(filter_file, 'r') as f:
        as_num = int(f.readline()[:-1])
        export_policies = [[False for i in range(0, as_num)] for j in range(0, as_num)]
        i = 0
        for line in f:
            for asn in line[:-1].split(' ')[1:]:
                export_policies[i][int(asn)] = True
            i += 1
        assert i == as_num

    export_policies_1 = [map(lambda x: random.random() > 0.5, [0] * as_num) for i in range(0, as_num)]
    export_policies_2 = [map(lambda x, y: x ^y, export_policies_1[i], export_policies[i]) for i in range(0, as_num)]

    with open(FILTER_SHARE1, 'w+') as f:
        json.dump(export_policies_1, f)
    with open(FILTER_SHARE2, 'w+') as f:
        json.dump(export_policies_2, f)

    # priority is 16 bits long
    with open(rank_file, 'r') as f:
        assert as_num == int(f.readline()[:-1])
        selection_policies = [[] for i in range(0, as_num)]
        i = 0
        for line in f:
            # in six-pack the bigger value the higher priority, reverse the value
            selection_policies[i] = map(lambda x: "{0:0{1}x}".format(as_num-int(x), 4), line[:-1].split(' '))
            i += 1
        assert i == as_num

    selection_policies_1 = [map(lambda x: os.urandom(2).encode('hex'), [0] * as_num) for i in range(0, as_num)]
    selection_policies_2 = [map(xor_string, selection_policies_1[i], selection_policies[i]) for i in range(0, as_num)]

    with open(RANK_SHARE1, 'w+') as f:
        json.dump(selection_policies_1, f)
    with open(RANK_SHARE2, 'w+') as f:
        json.dump(selection_policies_2, f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--filter_file', type=str, help='specify the filtering policy file')
    parser.add_argument('--rank_file', type=str, help='specify the ranking policy file')
    args = parser.parse_args()

    if args.filter_file and args.rank_file:
        split_policy(args.filter_file, args.rank_file)
    else:
        print 'please specify policy files'
