#! /usr/bin/python

import json
import random
import socket
import struct
import argparse
from collections import defaultdict


def generate_as_map(rib_file, as_num, cfg_dir):
    ID_MAP_JSON_FILE = '../config/asn_2_id.json'
    ID_MAP_RAW_FILE = '../config/asn_2_id.cfg'
    IP_MAP_RAW_FILE = '../config/as_ips.cfg'
    asn_2_id = {}
    asns = []
    as_id = 0
    asn_2_ip = defaultdict(lambda : set())
    with open(rib_file, 'r') as f:
        for line in f.readlines():
            if "FROM" in line:
                as_ip = line.split("FROM: ")[1].split("\n")[0].split(" ")[0]
                asn = int(line.split("FROM: ")[1].split("\n")[0].split(" ")[1][2:])
                if asn == 0:
                    continue
                asn_2_ip[asn].add(as_ip)
                if asn not in asn_2_id:
                    asn_2_id[asn] = as_id
                    asns.append(asn)
                    as_id += 1

    if len(asn_2_id) < as_num:
        add_as_num = as_num - len(asn_2_id)
        asn_pool = range(1, 65535)
        for i in range(0, add_as_num):
            asn = random.sample(asn_pool, 1)[0]
            while asn in asn_2_id:
                asn_pool.remove(asn)
                asn = random.sample(asn_pool, 1)[0]
            asn_pool.remove(asn)
            asn_2_id[asn] = as_id
            as_id += 1
            asns.append(asn)
            asn_2_ip[asn].add(socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))))

    if cfg_dir:
        ID_MAP_JSON_FILE = cfg_dir + ID_MAP_JSON_FILE.split('/')[-1]
        ID_MAP_RAW_FILE = cfg_dir + ID_MAP_RAW_FILE.split('/')[-1]
        IP_MAP_RAW_FILE = cfg_dir + IP_MAP_RAW_FILE.split('/')[-1]

    with open(ID_MAP_JSON_FILE, 'w+') as json_file:
        json.dump(asn_2_id, json_file)

    with open(ID_MAP_RAW_FILE, 'w+') as raw_file:
        lines = ['%d\n' % len(asn_2_id)]
        lines = lines + map(lambda x: ' ' + str(x), asns)
        lines.append('\n')
        #for asn in asns:
        #    lines.append('%d %d\n' % (asn, asn_2_id[asn]))
        raw_file.writelines(lines)

    with open(IP_MAP_RAW_FILE, 'w+') as raw_file:
        lines = ['%d\n' % len(asn_2_id)]
        for asn in asns:
            lines.append('%d' % len(asn_2_ip[asn]))
            lines.append(''.join(' ' + ip for ip in asn_2_ip[asn]))
            lines.append('\n')
        raw_file.writelines(lines)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rib_file', type=str, help='specify the rib file, e.g. ../ribs/bview')
    parser.add_argument('--as_num', type=int, help='specify as number, if as number is larger than rib, we extend the mapping')
    parser.add_argument('--cfg_dir', type=str, help='specify the config file directory, default is ../config/')
    args = parser.parse_args()

    if not args.as_num:
        args.as_num = 0
    generate_as_map(args.rib_file, args.as_num, args.cfg_dir)
