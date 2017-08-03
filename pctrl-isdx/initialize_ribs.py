
import os
import json
import sqlite3
import time
import multiprocessing as mp
from multiprocessing import Process
import argparse
from ribm import rib, RibTuple
from decision_process import best_path_selection


class Peer:
    def __init__(self, asn, asn_2_ip, asn_2_id, prefrns, input_path):
        self.asn = asn
        self.asn_2_ip = asn_2_ip
        self.asn_2_id = asn_2_id
        self.prefrns = prefrns
        self.input_path = input_path
        self.prefixes = {}
        self.get_time_log = []
        self.compute_time_log = []
        self.add_local_time_log = []
        self.add_output_time_log = []

        self.rib = {"input": rib(asn,"input"),
                    "local": rib(asn,"local"),
                    "output": rib(asn,"output")}

        self.local_rib = {"input":{}, "local":{}, "output":{}}

    def get_route(self, rib_name, prefix):
        return self.rib[rib_name].get(prefix=prefix)

    def get_routes(self, rib_name, prefix):
        return self.rib[rib_name].get_all(prefix=prefix)

    def add_route(self, rib_name, attributes):
        self.rib[rib_name].add(attributes)
        #self.rib[rib_name].commit()

    def update_route(self, rib_name, attributes):
        self.rib[rib_name].update(('prefix'), attributes)

    def updateInputRib(self, asid):
	rib_file = self.input_path + "/rib_" + str(asid)
        tmp = {}
        with open(rib_file, 'r') as f:
            ind = 0
            for line in f:
                #print line
                if line.startswith("TIME"):
                    tmp = {}
                    x = line.split("\n")[0].split(": ")
                    tmp[x[0]] = x[1]

                elif line.startswith("\n"):
                    # Parsed one entry from the RIB text file
                    #if ind%100000 == 0:
                    #    print "## ",self.asn, " entry: ", ind
                    self.updateRibEntry(tmp)
                    # NOTE: cheat with reduced size
                    if ind > 100:
                        break
                    ind += 1
                else:
                    x = line.split("\n")[0].split(": ")
                    if len(x) >= 2:
                        tmp[x[0]] = x[1]

    def updateRibEntry(self, elem):
        if "IPV4_UNICAST" in elem["TYPE"]:
            #print "Updating the rib entry ", elem
            # Get the prefix
            prefix = elem["PREFIX"]
            neighbor = elem["FROM"].split(" ")[0]
            asn = elem["FROM"].split(" ")[1][2:]
            #print [str(x) for x in self.asn_2_ip[self.asn].keys()], neighbor
            self.prefixes[prefix] = 0

            # Get the attributes
            #origin = elem['ORIGIN'] if 'ORIGIN' in elem else ''
            origin = ''
            as_path = elem['ASPATH'] if 'ASPATH' in elem else ''

            #med = elem["MULTI_EXIT_DISC"] if "MULTI_EXIT_DISC" in elem else ''
            med = ''

            #communities = elem["COMMUNITY"] if "COMMUNITY" in elem else ''
            communities = ''

            atomic_aggregate = ''

            # TODO: Current logic currently misses the case where there are two next hops
            next_hop = elem["NEXT_HOP"]

            atrributes = RibTuple(prefix, neighbor, next_hop, origin, as_path, communities, med, atomic_aggregate, self.asn_2_id[asn])
            #print prefix, atrributes

            # Add this entry to the input rib for this participant
            self.add_route("input", atrributes)
            #self.rib["input"].commit()
            """
            if prefix not in self.local_rib["input"]:
                self.local_rib["input"][prefix] = []
            self.local_rib["input"][prefix].append(atrributes)
            """

    def updateLocalOutboundRib(self):
        for prefix in self.prefixes:
            t1 = time.time()
            routes = self.get_routes('input', prefix)
            #routes = self.local_rib["input"][prefix]
            #print routes
            #print "For prefix ", prefix, " # of routes ", len(routes)
            t2 = time.time()
            best_route = best_path_selection(routes, self.prefrns)
            #print "Best route: ", best_route

            # Update the local rib
            t3 = time.time()
            self.update_route('local', best_route)
            #self.local_rib["local"][prefix] = best_route

            # Update the output rib
            t4 = time.time()
            self.update_route('output', best_route)
            t5 = time.time()
            #self.local_rib["output"][prefix] = best_route
            self.get_time_log.append(t2-t1)
            self.compute_time_log.append(t3-t2)
            self.add_local_time_log.append(t4-t3)
            self.add_output_time_log.append(t5-t4)
            '''
            if len(self.get_time_log) % 1000 == 0:
                print self.asn, "get_time_log", sum(self.get_time_log)
                print self.asn, "comput_time_log", sum(self.compute_time_log)
                print self.asn, "add_local_time_log", sum(self.add_local_time_log)
                print self.asn, "add_output_time_log", sum(self.add_output_time_log)
                self.get_time_log = []
                self.compute_time_log = []
                self.add_local_time_log = []
                self.add_output_time_log = []
            '''

    def test_ribs(self):
        for prefix in self.prefixes:
            routes = self.get_routes("input", prefix)
            best_route = self.get_route("local", prefix)
            #print self.asn, "For prefix: ", prefix, " ribs has ", len(routes), " routes"
            #print routes
            #print self.asn, "For prefix: ", prefix, " best route is:", best_route

def processRibIter(asn, asn_2_ip, asn_2_id, prefrn, path):
    peer = Peer(asn, asn_2_ip, asn_2_id, prefrns, path)
    #print "Peer::", asn
    start = time.time()
    peer.updateInputRib(asn_2_id[asn])
    #print "##", id, "Prefix number %d" % len(peer.prefixes), "Time to update the input Rib ", time.time()-start
    start = time.time()
    peer.updateLocalOutboundRib()
    #print "##", id, "Time to update the local/output Rib ", time.time()-start
    #peer.save_ribs()
    peer.test_ribs()


''' main '''
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('example_name', help='Example Name Directory')
    parser.add_argument('rib_name', help='RIB Name Directory')
    parser.add_argument('rank_name', help='Ranking File')
    args = parser.parse_args()

    path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "examples", args.example_name))
    cfg_path = os.path.join(path, args.rib_name)
    asn_2_ip = json.load(open(cfg_path + "/asn_2_ip.json", 'r'))
    asn_2_id = json.load(open(cfg_path + "/asn_2_id.json", 'r'))

    # get local preference
    with open(path + "/" + args.rank_name, "r") as f:
        assert len(asn_2_ip) == int(f.readline()[:-1])
        prefrns = map(lambda x: map(lambda y: int(y), x[:-1].split(' ')[1:]), f.readlines())

    """
    for asn in asn_2_ip:
        print asn, "start"
        processRibIter(asn, asn_2_ip, asn_2_id, prefrns[asn_2_id[asn]], cfg_path)
        print asn, "done"
    """
    asns = asn_2_ip.keys()
    as_num = len(asns)
    para_group = 10
    for i in range(0, para_group):
        process = []
        iter = 0
        for asn in asns[i * (as_num / para_group): (i + 1) * (as_num / para_group)]:
            process.append(Process(target = processRibIter, args = (asn, asn_2_ip, asn_2_id, prefrns[asn_2_id[asn]], cfg_path)))
            process[iter].start()
            iter += 1

        for p in process:
            p.join()
    #"""
    print "RIB Initialization Done"

    """
    base_fname = 'ribs/AS12306.db'
    # Copy .db files for all participants
    for part in asn_2_ip:
        if part not in base_fname:
            new_fname = "ribs/"+part+".db"
            os.system('cp '+base_fname+" "+new_fname)
    """
