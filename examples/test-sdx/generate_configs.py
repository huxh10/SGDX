#!/usr/bin/env python
#  Author:
#  Arpit Gupta (arpitg@cs.princeton.edu)

import json
import os
from random import shuffle, randint
import sys
import argparse

as_ips_file = "./config/as_ips.cfg"
asn_2_id_file = "./config/asn_2_id.json"
out_fname = "./config/asn_2_ip.json"

def getMatchHash(part, peer, count):
    if "AS" in part: part = int(part.split("AS")[1])
    if "AS" in peer: peer = int(peer.split("AS")[1])

    return int(1*part+1*peer+count)

def getASMap():
    with open(asn_2_id_file, 'r') as f:
        asn_2_id = json.load(f)
    id_2_asn = [0 for i in range(0, len(asn_2_id))]
    for asn, asid in asn_2_id.iteritems():
        id_2_asn[asid] = asn
    return asn_2_id, id_2_asn

def getParticipants(id_2_asn):
    asn_2_ip = {}
    with open(as_ips_file) as f:
        as_num = int(f.readline()[:-1])
        for i in range(0, as_num):
            asn_2_ip[id_2_asn[i]] = {}
            for ip in f.readline()[:-1].split(' ')[1:]:
                asn_2_ip[id_2_asn[i]][ip] = 0

    port_id = 10
    for part in asn_2_ip:
        for ip in asn_2_ip[part]:
            asn_2_ip[part][ip] = port_id
            port_id += 1

    with open(out_fname,'w+') as f:
        json.dump(asn_2_ip, f)

    return asn_2_ip

def generate_global_config(asn_2_ip, asn_2_id, peer_file, cfg_dir):
    # load the base config
    config_filename = "sdx_global.cfg"
    config_file = cfg_dir + config_filename

    with open(peer_file, 'r') as f:
        as_num = int(f.readline()[:-1])
        asid_2_peers = {}
        for i in range(0, as_num):
            asid_2_peers[i] = map(lambda x: int(x), f.readline()[:-1].split(' ')[1:])

    config = {}
    net = "localhost"

    config["VMAC"] = {}
    config["VMAC"]["Mode"] = "Superset"
    config["VMAC"]["Options"] = {}
    config["VMAC"]["Options"]["Superset Bits"] = 30
    config["VMAC"]["Options"]["Next Hop Bits"] = 16
    config["VMAC"]["Options"]["Port Bits"] = 10
    config["VMAC"]["Options"]["VMAC Size"] = 48

    config["VNHs"] = "172.0.1.1/8"

    config["Mode"] = "Multi-Switch"

    config["Flanc Auth Info"] = {}
    config["Flanc Auth Info"]["participants"] = "sdxcontroller"
    config["Flanc Auth Info"]["key"] = "no key"

    config["RefMon Server"] = {}
    config["RefMon Server"]["IP"] = net
    config["RefMon Server"]["Port"] = 5555
    config["RefMon Server"]["key"] = "sdx"

    config["Route Server"] = {}
    config["Route Server"]["Port"] = 3
    config["Route Server"]["MAC"] = "08:00:27:89:3b:ff"
    config["Route Server"]["IP"] = "172.0.255.254"
    config["Route Server"]["AH_SOCKET"] = [net, 6666]
    config["Route Server"]["XRS_SOCKET"] = [net, 6000]

    config["ARP Proxy"] = {}
    config["ARP Proxy"]["Port"] = 4
    config["ARP Proxy"]["MAC"] = "08:00:27:89:33:ff"
    config["ARP Proxy"]["IP"] = "172.0.255.253"
    config["ARP Proxy"]["GARP_SOCKET"] = [net, 4444]
    config["ARP Proxy"]["Interface"] = "x2-eth0"

    config["Participants"] = {}
    for part in asn_2_ip:
        part_id = asn_2_id[part]

        config["Participants"][part_id] = {}
        config["Participants"][part_id]["Ports"] = []
        for nhip in asn_2_ip[part]:
            tmp = {}
            tmp["Id"] = asn_2_ip[part][nhip]
            tmp["MAC"] = ""
            tmp["IP"] = str(nhip)
            config["Participants"][part_id]["Ports"].append(tmp)
        config["Participants"][part_id]["ASN"] = int(part)
        config["Participants"][part_id]["Peers"] = asid_2_peers[part_id]
        config["Participants"][part_id]["Inbound Rules"] = "true"
        config["Participants"][part_id]["Outbound Rules"] = "true"
        host = ""
        config["Participants"][part_id]["Flanc Key"] = "Part"+str(part_id)+"Key"

    config["RefMon Settings"] = {}
    config["RefMon Settings"]["fabric options"] = {}
    config["RefMon Settings"]["fabric options"]["dp alias"] = {}
    config["RefMon Settings"]["fabric options"]["dp alias"]["main-in"] = "main"
    config["RefMon Settings"]["fabric options"]["dp alias"]["main-out"] = "main"
    config["RefMon Settings"]["fabric options"]["OF version"] = "1.3"
    config["RefMon Settings"]["fabric options"]["dpids"] = {}
    config["RefMon Settings"]["fabric options"]["dpids"]["main"] = 1
    config["RefMon Settings"]["fabric options"]["dpids"]["inbound"] = 2
    config["RefMon Settings"]["fabric options"]["dpids"]["outbound"] = 2
    config["RefMon Settings"]["fabric connections"] = {}
    config["RefMon Settings"]["fabric connections"]["inbound"] = {}
    config["RefMon Settings"]["fabric connections"]["inbound"]["main"] = 1
    config["RefMon Settings"]["fabric connections"]["inbound"]["outbound"] = 2
    config["RefMon Settings"]["fabric connections"]["inbound"]["refmon"] = 9
    config["RefMon Settings"]["fabric connections"]["outbound"] = {}
    config["RefMon Settings"]["fabric connections"]["outbound"]["main"] = 1
    config["RefMon Settings"]["fabric connections"]["outbound"]["inbound"] = 2
    config["RefMon Settings"]["fabric connections"]["outbound"]["refmon"] = 9
    config["RefMon Settings"]["fabric connections"]["main"] = {}
    config["RefMon Settings"]["fabric connections"]["main"]["inbound"] = 1
    config["RefMon Settings"]["fabric connections"]["main"]["outbound"] = 2
    config["RefMon Settings"]["fabric connections"]["main"]["route server"] = 3
    config["RefMon Settings"]["fabric connections"]["main"]["arp proxy"] = 4
    config["RefMon Settings"]["fabric connections"]["main"]["refmon"] = 5

    for part in asn_2_ip:
        part_id = asn_2_id[part]
        config["RefMon Settings"]["fabric connections"]["main"][part_id] = asn_2_ip[part].values()

    with open(config_file, "w") as f:
        json.dump(config, f)

''' main '''
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('filter_file', type=str, help='e.g. ./bgp_policies/peers_uni_500_020.cfg')
    parser.add_argument('cfg_dir', type=str, help='specify the config file directory, e.g. ./config/')
    args = parser.parse_args()

    as_ips_file = args.cfg_dir + as_ips_file.split('/')[-1]
    asn_2_id_file = args.cfg_dir + asn_2_id_file.split('/')[-1]
    out_fname = args.cfg_dir + out_fname.split('/')[-1]

    asn_2_id, id_2_asn = getASMap()
    asn_2_ip = getParticipants(id_2_asn)

    generate_global_config(asn_2_ip, asn_2_id, args.filter_file, args.cfg_dir)
