#!/usr/bin/env python
#  Author:
#  Arpit Gupta (arpitg@cs.princeton.edu)

import json
import os
from random import shuffle, randint
import sys
import argparse


def getMatchHash(part, peer_id, count):
    return int(1 * part + 1 * peer_id + count)

def generatePoliciesParticipant(part, asn_2_ip, peers, frac, limit_out, cfg_dir):
    # randomly select fwding participants
    shuffle(peers)
    count = int(frac * len(peers))
    fwding_peers = set(peers[:count])

    # Generate Outbound policies
    cookie_id = 1
    policy = {}
    policy["outbound"] = []
    for peer_id in fwding_peers:
        peer_count = randint(1, limit_out)
        for ind in range(1, peer_count+1):
            tmp_policy = {}

            # Assign Cookie ID
            tmp_policy["cookie"] = cookie_id
            cookie_id += 1

            # Match
            match_hash = getMatchHash(int(part), peer_id, ind)
            tmp_policy["match"] = {}
            tmp_policy["match"]["tcp_dst"] = match_hash
            tmp_policy["match"]["in_port"] = asn_2_ip[part].values()[0]

            # Action: fwd to peer's first port (visible to part)
            tmp_policy["action"] = {"fwd": peer_id}

            # Add this to participants' outbound policies
            policy["outbound"].append(tmp_policy)

    policy["inbound"] = []
    inbound_count = randint(1, limit_out)
    for ind in range(1, peer_count+1):
        tmp_policy = {}
        # Assign Cookie ID
        tmp_policy["cookie"] = cookie_id
        cookie_id += 1

        # Match
        match_hash = getMatchHash(int(part), 0, ind)
        tmp_policy["match"] = {}
        tmp_policy["match"]["tcp_dst"] = match_hash

        # Action: fwd to peer's first port (visible to part)
        tmp_policy["action"] = {"fwd": asn_2_ip[part].values()[0]}

        # Add this to participants' outbound policies
        policy["inbound"].append(tmp_policy)

    # Dump the policies to appropriate directory
    policy_filename = "participant_" + "AS" + part + ".py"
    policy_file = cfg_dir + "policies/" + policy_filename
    with open(policy_file,'w') as f:
        json.dump(policy, f)


''' main '''
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('cfg_dir', type=str, help='specify the config file directory, e.g. ./config/')
    parser.add_argument('-f', '--frac', type=str, default='1.0', help='fraction of SDN fowarding peers')
    args = parser.parse_args()
    frac = float(args.frac)

    asn_2_ip = json.load(open(args.cfg_dir + "asn_2_ip.json", 'r'))
    asn_2_id = json.load(open(args.cfg_dir + "asn_2_id.json", 'r'))
    config = json.load(open(args.cfg_dir + "sdx_global.cfg", "r"))

    # Params
    limit_out = 4

    for part in asn_2_ip:
        generatePoliciesParticipant(part, asn_2_ip, config["Participants"][str(asn_2_id[part])]["Peers"], frac, limit_out, args.cfg_dir)
