#! /usr/bin/python

import json
import argparse


def truncate_rib(rib_file, factor):
    rib = []
    tmp_entry = []
    tmp_asn = 0
    entry_size = 0

    with open(rib_file, 'r') as original_rib_file:
        for line in original_rib_file:
            tmp_entry.append(line)
            if line.startswith("FROM"):
                tmp_asn = int(line[:-1].split(" ")[-1][2:])
            if line.startswith('\n'):
                if tmp_asn == 0:
                    tmp_entry = []
                    continue
                rib += tmp_entry
                entry_size += 1
                tmp_entry = []

    line_counter = 0
    entry_counter = 0
    for line in rib:
        line_counter += 1
        if line.startswith('\n'):
            entry_counter += 1
            if entry_counter > entry_size / factor:
                break
    rib = rib[:line_counter]

    with open(rib_file, 'w+') as rib_file:
        rib_file.writelines(rib)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rib_file', type=str, help='specify the rib file, e.g. ../ribs/bview')
    parser.add_argument('factor', type=float, help='specify the truncation factor')
    args = parser.parse_args()

    truncate_rib(args.rib_file, args.factor)
