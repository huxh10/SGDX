#! /usr/bin/python

import json


FILTER_SHARE1 = 'filter_share1.json'
FILTER_SHARE2 = 'filter_share2.json'
RANK_SHARE1 = 'rank_share1.json'
RANK_SHARE2 = 'rank_share2.json'


def merge_policy():
    with open(FILTER_SHARE1, 'r') as f:
        export_policies_1 = json.load(f)
    with open(FILTER_SHARE2, 'r') as f:
        export_policies_2 = json.load(f)

    as_num = len(export_policies_1)
    print [map(lambda x, y: x ^ y, export_policies_1[i], export_policies_2[i]) for i in range(0, as_num)]

    with open(RANK_SHARE1, 'r') as f:
        selection_policies_1 = json.load(f)
    with open(RANK_SHARE2, 'r') as f:
        selection_policies_2 = json.load(f)

    print [map(lambda s_x, s_y: as_num - int("".join(chr(ord(x) ^ ord(y)) for x, y in zip(s_x, s_y)), 16), selection_policies_1[i], selection_policies_2[i]) for i in range(0, as_num)]

if __name__ == "__main__":
    merge_policy()
