#! /usr/bin/python

import json
import argparse

ORIGINAL_RIB_FILE = '../ribs/bview'
BASE_RIB_FILE = '../ribs/rib_'


def duplicate_and_filter_ribs(asn_2_id_json_file, filter_policy_file):
    with open(filter_policy_file, 'r') as f:
        as_num = int(f.readline()[:-1])
        export_policies = []
        for line in f:
            export_policies.append(map(int, line[:-1].split(' '))[1:])

    with open(asn_2_id_json_file, 'r') as f:
        asn_2_id = json.load(f)
        asn_2_id = {int(k):v for k,v in asn_2_id.items()}
    id_2_asn = {}
    for asn in asn_2_id:
        id_2_asn[asn_2_id[asn]] = asn
    ribs = [[] for i in range(0, as_num)]
    tmp_entry = []
    tmp_asn = 0

    with open(ORIGINAL_RIB_FILE, 'r') as original_rib_file:
        for line in original_rib_file:
            tmp_entry.append(line)
            if line.startswith("FROM"):
                tmp_asn = int(line[:-1].split(" ")[-1][2:])
            if line.startswith('\n'):
                ribs[asn_2_id[tmp_asn]] += tmp_entry
                for dest_as_id in export_policies[asn_2_id[tmp_asn]]:
                    ribs[dest_as_id] += tmp_entry
                tmp_entry = []

    for i in range(0, as_num):
        with open(BASE_RIB_FILE + '%d' % i, 'w+') as rib_file:
            rib_file.writelines(ribs[i])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--filter_policy', type=str, help='specify the filtering policy file')
    parser.add_argument('--asn_2_id_json', type=str, help='specify the asn_2_id json file')
    args = parser.parse_args()

    if args.asn_2_id_json and args.filter_policy:
        duplicate_and_filter_ribs(args.asn_2_id_json, args.filter_policy)
