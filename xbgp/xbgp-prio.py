#!/usr/bin/env python
#  Author:
#  Rudiger Birkner(ETH Zurich)

import argparse
import json
import os
import sys
np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
print np
if np not in sys.path:
    sys.path.append(np)
from time import sleep, time, strptime, mktime
from threading import Thread
from netaddr import IPAddress
from multiprocessing import Queue
import multiprocessing as mp
from Queue import Empty
from multiprocessing.connection import Client
import threading
import util.log
from util.crypto_util import AESCipher
from ppsdx.route import Route
from ppsdx.participant_db import ParticipantDB
import pickle
import ppsdx.port_config as port_config
from util.statistics_collector_2 import StatisticsCollector
import xbgp_process
from multiprocessing import Process, Manager

# Run each iteration for half an hour duration
update_minutes = 18000
LOG=False

KEY_LENGTH = 16

class ExaBGPEmulator(object):
    def __init__(self, address, port, authkey, input_file, speed_up, rate, mode, debug = False, number_of_processes=1):
        self.logger = util.log.getLogger('xbgp-prio')
        #if debug:
        #    self.logger.setLevel(logging.CRITICAL)
        self.logger.debug('init')

        self.input_file = input_file

        self.route_id_counter=0

        self.statistics = StatisticsCollector()

        self.real_start_time = time()
        self.simulation_start_time = 0
        self.speed_up = speed_up
        self.mode = int(mode)
        self.fp_thread = None
        self.us_thread = None
        self.send_rate = int(rate)
        self.run = True
        '''server_filename = "server_settings.cfg"
        server_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "examples", example_name))
        server_file = os.path.join(server_path, server_filename)
        self.server_settings = json.load(open(server_file, 'r'))'''
        self.update_queue = mp.Manager().Queue()
        self.logger.debug('connecting to RS1')
        self.conn_rs1 = Client((port_config.process_assignement["rs1"], port_config.ports_assignment["rs1_receive_bgp_messages"]), authkey=None)
        self.logger.debug('connected to RS1')
        self.logger.debug('connecting to RS2')
        self.conn_rs2 = Client((port_config.process_assignement["rs2"], port_config.ports_assignment["rs2_receive_bgp_messages"]), authkey=None)
        self.logger.debug('connected to RS2')
        self.participant_db = ParticipantDB()
        self.number_of_participants = len(self.participant_db.bgp_speaker_2_id.keys())
        self.neighbor2prefix2exported_to = {}
        for participant in self.participant_db.bgp_speaker_2_id:
            self.neighbor2prefix2exported_to[participant]={}

        self.number_of_processes=number_of_processes
        self.manager = Manager()
        self.worker_to_handler_queue = self.manager.Queue()
        self.handler_to_worker_queue = self.manager.Queue()
        self.worker_ids_queue = self.manager.Queue()
        map(self.worker_ids_queue.put,range(0,self.number_of_processes))
        self.workers_pool = mp.Pool(self.number_of_processes, xbgp_process.send_main,(self.handler_to_worker_queue,self.worker_to_handler_queue,self.worker_ids_queue,self.conn_rs1,self.conn_rs2,))

    def receive_from_workers(self):
        waiting =0
        stop_counter=self.number_of_processes
        while True:
            try:
                #self.logger.info("waiting for message from worker")
                msg = self.worker_to_handler_queue.get(True, 1)

                self.logger.info("received message from worker")
                #logger.debug("received message from worker: " + str(msg))

                if "stop" in msg:
                    self.logger.info("received STOP message from xbgp worker")

                    stop_counter-=1
                    print "received STOP: " + str(stop_counter)
                    if stop_counter == 0:
                        print "sending final STOP"
                        self.send_update_rs1(pickle.dumps(msg))
                        self.send_update_rs2(pickle.dumps(msg))
                        sleep(5)
                        break
                    continue

            except Empty:
                if waiting == 0:
                    #self.logger.debug("Waiting for BGP update...")
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        #self.logger.debug("Waiting for BGP update...")
                        pass


    def file_processor(self):
        with open(self.input_file) as infile:
            tmp = {}
            next_hop = ""
            flag = 0

            for line in infile:
                if line.startswith("TIME"):

                    flag = 1

                    tmp = {"exabgp": "3.4.8", "type": "update"}
                    next_hop = ""

                    x = line.split("\n")[0].split(": ")[1]
                    time = mktime(strptime(x, "%m/%d/%y %H:%M:%S"))
                    tmp["time"] = int(time/self.speed_up)

                elif flag == 1:
                    if 'Keepalive' in line or line.startswith("\n"):
                        # Only process Update Messages
                        flag = 0

                    else:
                        x = line.split("\n")[0].split(": ")

                        if "neighbor" not in tmp:
                             tmp["neighbor"] = {"address": {}, "asn": {}, "message": {"update": {}}}

                        elif line.startswith("FROM"):
                            x = x[1].split(" ")
                            if IPAddress(x[0]).version == 4:
                                tmp["neighbor"]["ip"] = x[0]
                                tmp["neighbor"]["address"]["peer"] = x[0]
                                tmp["neighbor"]["asn"]["peer"] = x[1][2:]
                            else:
                                flag = 0
                        elif line.startswith("TO"):
                            x = x[1].split(" ")
                            if IPAddress(x[0]).version == 4:
                                tmp["neighbor"]["address"]["local"] = x[0]
                                tmp["neighbor"]["asn"]["local"] = x[1][2:]
                            else:
                                flag = 0
                        elif line.startswith("ORIGIN"):
                            if "attribute" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["attribute"] = {}
                            tmp["neighbor"]["message"]["update"]["attribute"]["origin"] = x[1].lower()

                        elif line.startswith("ASPATH"):
                            if "attribute" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["attribute"] = {}
                            tmp["neighbor"]["message"]["update"]["attribute"]["as-path"] = "[ " + x[1] + " ]"

                        elif line.startswith("MULTI_EXIT_DISC"):
                            if "attribute" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["attribute"] = {}
                            tmp["neighbor"]["message"]["update"]["attribute"]["med"] = x[1]

                        elif line.startswith("NEXT_HOP"):
                            if "announce" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["announce"] = {"ipv4 unicast": []}
                            #tmp["neighbor"]["message"]["update"]["announce"] = {"ipv4 unicast": {x[1]: {}}}
                            #next_hop = x[1]
                            tmp["neighbor"]["message"]["update"]["announce"]["nexthop"] = x[1]
                        elif line.startswith("COMMUNITY"):
                            if "announce" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["announce"] = {}
                            tmp["neighbor"]["message"]["update"]["announce"]["community"] =  x[1]

                        elif line.startswith("ANNOUNCE"):
                            if "announce" not in tmp["neighbor"]["message"]["update"]:
                                #tmp["neighbor"]["message"]["update"]["announce"] = {"ipv4 unicast": {}}
                                tmp["neighbor"]["message"]["update"]["announce"] = {"ipv4 unicast": []}
                            flag = 2
                        elif line.startswith("WITHDRAW"):
                            #tmp["neighbor"]["message"]["update"]["withdraw"] = {"ipv4 unicast": {}}
                            tmp["neighbor"]["message"]["update"]["withdraw"] = {"ipv4 unicast": []}
                            flag = 3

                elif flag >= 2:
                    if line.startswith("\n"):
                        if not self.run:
                            break
                        if LOG: print "Adding Update to queue..."
                        self.logger.debug('Adding Update to queue...')
                        routes = self.create_routes_to_be_sent(tmp)
                        for route in routes:
                            self.update_queue.put({"route" : route, "time" : tmp["time"]})
                        while self.update_queue.qsize() > 32000:

                            self.logger.debug('queue is full - taking a break')

                            sleep(self.sleep_time(tmp["time"])/2)

                            if not self.run:
                                break

                        flag = 0
                    else:
                        if line.startswith("ANNOUNCE"):
                            if "announce" not in tmp["neighbor"]["message"]["update"]:
                                #tmp["neighbor"]["message"]["update"]["announce"] = {"ipv4 unicast": {}}
                                tmp["neighbor"]["message"]["update"]["announce"] = {"ipv4 unicast": []}
                            flag=2
                        elif line.startswith("WITHDRAW"):
                            tmp["neighbor"]["message"]["update"]["withdraw"] = {"ipv4 unicast": []}
                            flag=3
                        else:
                            x = line.split("\n")[0].split()[0]
                            if flag==2:
                                #tmp["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"][next_hop][x] = {}
                                tmp["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"].append(x)
                                #self.logger.debug(tmp["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"])
                                self.logger.debug(tmp["time"])
                            else:
                                #tmp["neighbor"]["message"]["update"]["withdraw"]["ipv4 unicast"][x] = {}
                                tmp["neighbor"]["message"]["update"]["withdraw"]["ipv4 unicast"].append(x)

        time_value = tmp["time"]
        tmp = {}
        tmp["time"]=time_value+1
        tmp["stop"]=1
        self.update_queue.put(tmp)
        self.run=False


    def create_routes_to_be_sent(self,bgp_update):


        # 1. generate key for the incoming route
        key = os.urandom(KEY_LENGTH)
        keystr = key.encode("hex")
        self.logger.debug("key:" + keystr)

        self.cipher = AESCipher(key)

        routes = []
        # for each IP prefix destination add a route in the queue
        if "announce" in bgp_update["neighbor"]["message"]["update"]:

            # GENERATE ANNOUNCEMENTS
            communities = self.get_export_policies(bgp_update)
            export_policies_communities = communities["export_policies_communities"]

            # 0. generate export data structure. Each export policy is modeled
            # by a list of boolean values: True if export is allowed, False otherwise
            export_policy = self.get_export_policy_array(export_policies_communities)

            # 1. generate nonce
            random_nonce = self.get_nonce()

            # 3. XOR nonce with export policy
            encrypted_export_policy = self.get_xored_export_policy(export_policy,random_nonce)


            for prefix in bgp_update["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"]:

                route = Route()
                route.neighbor = bgp_update["neighbor"]["ip"]
                route.prefix = prefix
                self.logger.debug("prefix: " + str(prefix))
                route.time=bgp_update["time"]
                route.id = self.route_id_counter
                self.route_id_counter+=1

                self.statistics.xbgp_update_processing(route.id)

                route.as_path =self.parse_as_path(bgp_update["neighbor"]["message"]["update"]["attribute"]["as-path"])
                route.next_hop = bgp_update["neighbor"]["message"]["update"]["announce"]["nexthop"]
                encrypted_exp_policies_rs1 = random_nonce
                encrypted_exp_policies_rs2 = encrypted_export_policy
                route.communities = communities["non_export_policies_communities"]
                route.type="announce"

                # 3. encrypting the route
                self.logger.debug("Encrypting route, id: " + str(route.id))
                encrypted_route = self.cipher.encrypt(pickle.dumps(route)) #encrypt serialized route object
                #encrypted_route = route#self.cipher.encrypt(pickle.dumps(route)) #encrypt serialized route object

                self.logger.debug("encrypted-route: " + str(encrypted_route))

                routes.append({"prefix" : prefix, "bgp_next_hop" : bgp_update["neighbor"]["ip"],"route-in-clear" : None, "route_id" : route.id, "encrypted_route" : encrypted_route , "encrypted_exp_policies_rs1" : encrypted_exp_policies_rs1, "encrypted_exp_policies_rs2" : encrypted_exp_policies_rs2, "key" : keystr, "type" : route.type , "announcement_id" : route.id,})

                self.statistics.xbgp_update_end_processing(route.id)

            '''
            # COMPUTE THE PER-DIFFERENCE FOR EACH PREFIX
            for prefix in bgp_update["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"]:
                print "prefix: " + str(prefix)

                if prefix not in self.neighbor2prefix2exported_to[route.neighbor]:
                    self.neighbor2prefix2exported_to[route.neighbor][route.prefix]={}
                withdraw_export_policy_str = self.get_difference_array(export_policy,self.neighbor2prefix2exported_to[route.neighbor][route.prefix])
                self.neighbor2prefix2exported_to[route.neighbor][prefix]=export_policy

                self.logger.debug(withdraw_export_policy_str)
                # if the announcement range is reduced, a withdraw message must be sent to those
                # members that should no longer see the prefix
                if withdraw_export_policy_str["changed"]:
                     # 1. generate nonce
                    random_nonce_withdraw = self.get_nonce()

                    # 3. XOR nonce with export policy
                    encrypted_export_policy_withdraw = self.get_xored_export_policy(withdraw_export_policy_str["array"],random_nonce_withdraw)

                    route_withdraw = Route()
                    route.id = self.route_id_counter
                    route_withdraw.neighbor = bgp_update["neighbor"]["ip"]
                    route_withdraw.prefix = prefix
                    route_withdraw.type="withdraw"
                    route_withdraw.id = self.route_id_counter
                    self.route_id_counter+=1

                    self.logger.debug("Encrypting route " + str(route.id))
                    #self.cipher = AESCipher(key)
                    encrypted_route_withdraw = self.cipher.encrypt(pickle.dumps(route_withdraw)) #encrypt serialized route object
                    routes.append({"route-in-clear" : None, "route_id" : route.id, "encrypted_route" : encrypted_route_withdraw , "encrypted_exp_policies_rs1" : random_nonce_withdraw, "encrypted_exp_policies_rs2" : encrypted_export_policy_withdraw, "key" : keystr , "type" : route_withdraw.type})

        '''

        '''# GENERATE WITHDRAWALS
        if "withdraw" in bgp_update["neighbor"]["message"]["update"]:
            for prefix in bgp_update["neighbor"]["message"]["update"]["withdraw"]["ipv4 unicast"]:
                route = Route()
                route.neighbor = bgp_update["neighbor"]["ip"]
                route.prefix = prefix
                route.type="withdraw"
                route.id = self.route_id_counter
                self.route_id_counter+=1

                if route.prefix not in self.neighbor2prefix2exported_to[route.neighbor]:
                    break
                withdraw_export_policy = self.neighbor2prefix2exported_to[route.neighbor][route.prefix]
                self.neighbor2prefix2exported_to[route.neighbor][route.prefix]=[False] * self.number_of_participants
                self.logger.debug("withdraw export policy: " + str(withdraw_export_policy))
                # if the announcement range is reduced, a withdraw message must be sent to those
                # members that shuold no longer see the prefix

                # 1. generate nonce
                random_nonce_withdraw = self.get_nonce()

                # 3. XOR nonce with export policy
                encrypted_export_policy_withdraw = self.get_xored_export_policy(withdraw_export_policy,random_nonce_withdraw)


                self.logger.debug("Encrypting route " + str(route.id))
                #self.cipher = AESCipher(key)
                encrypted_route_withdraw = self.cipher.encrypt(pickle.dumps(route)) #encrypt serialized route object



                routes.append({"route-in-clear" : None, "route_id" : route.id, "encrypted_route" : encrypted_route_withdraw , "encrypted_exp_policies_rs1" : random_nonce_withdraw, "encrypted_exp_policies_rs2" : encrypted_export_policy_withdraw, "key" : keystr , "type" : route.type})
        '''
        return routes


    def get_difference_array(self,array1,array2):
        from2=[]
        struct = {"changed" : False , "array" : from2}
        if len(array2) > 0:
            for i in range(0,len(array1)):
                if  (not array1[i]) and array2[i]:
                    from2.append(True)
                    struct["changed"]=True
                else:
                    from2.append(False)
        return struct


    def get_xored_export_policy(self, export_policy, random_nonce):
        self.logger.debug("encrypting the export policy")
        return map(lambda x,y : x ^ y, export_policy, random_nonce)

    def get_nonce(self):
        self.logger.debug("generating nonce")
        #return map(lambda x : random.random() > 0.5,[0] * self.number_of_participants)
        return  [True] * self.number_of_participants

    def get_export_policy_array(self,export_policies_communities):
        self.logger.debug("generating export_policy structure")
        is_export_all=True
        # check whether it is a blacklist (ie, is_export_all=True) or a white-list (ie, is_export_all=False)
        for community in export_policies_communities:
            if(community[0]=="0" and community[1]=="6695"):
                is_export_all=False
        if is_export_all:
            export_policy = [True] * self.number_of_participants
        else:
            export_policy = [False] * self.number_of_participants
        self.logger.debug("export policy is export all? " + str(is_export_all))
        self.logger.debug("export policy communities:  " + str(export_policies_communities))
        sum =0
        # extract the ASes that are black- or white-listed
        for community in export_policies_communities:
            if(community[0]=="0" and community[1]=="6695") or (community[0]=="6695" and community[1]=="6695"):
                continue
            else:
                self.logger.debug("community: " + str(community))
                if community[1] not in self.participant_db.asnumber_2_bgp_speakers.keys():
                    continue
                for bgp_speaker in self.participant_db.asnumber_2_bgp_speakers[community[1]]:
                    if bgp_speaker not in self.participant_db.bgp_speaker_2_id:
                        continue
                    index = self.participant_db.bgp_speaker_2_id[bgp_speaker]
                    self.logger.debug("community for speaker " + str(bgp_speaker) + " with id: " + str(index) + " as-number:" + str(community[1]))
                    self.logger.debug("community[0]: " + str(community[0]) + " community[1]==0 : " + str(community[1]=="6695") )
                    if community[0]=="0" and community[1]!="6695":
                        export_policy[index] = False
                        self.logger.debug("export-policy[index]: " + str(export_policy[index]))
                    if community[0]=="6695" and community[1]!="6695":
                        export_policy[index] = True

        #self.logger.debug("export policy is: " + str(export_policy))
        return export_policy


    def get_export_policies(self,bgp_update):
        bgp_update = bgp_update["neighbor"]
        # parse communities from the bgp update
        export_policies_communities = []
        non_export_policies_communities = []
        if("community" in bgp_update["message"]["update"]["announce"]):
            split_communities = bgp_update["message"]["update"]["announce"]["community"].split(" ")
            for community in split_communities:
                if community.split(":")[0] == "0" or community.split(":")[0] == "6695":
                    export_policies_communities.append((community.split(":")[0],community.split(":")[1]))
                else:
                    non_export_policies_communities.append((community.split(":")[0],community.split(":")[1]))
        return {"export_policies_communities" : export_policies_communities , "non_export_policies_communities" : non_export_policies_communities}


    def bgp_update_sender(self):
        counter=0
        while self.run or not self.update_queue.empty():
            try:
                # get msg. type: {"route", "time"}
                msg = self.update_queue.get(True, 1)
            except Empty:
                continue

            if self.simulation_start_time == 0:
                self.real_start_time = time()
                self.simulation_start_time = msg["time"]

            current_bgp_update = msg["time"]
            elapsed = current_bgp_update - self.simulation_start_time
            if elapsed > update_minutes:
                print "start: current", self.simulation_start_time, current_bgp_update
                tmp = {}
                tmp["stop"]=1
                self.logger.debug(("send stop from elapsed time"))
                self.send_update_rs1(tmp)
                break

            sleep_time = self.sleep_time(msg["time"])

            sleep(sleep_time)

            if "stop" in msg:
                #self.send_update_rs1({"stop"  : None})
                for x in range(0,self.number_of_processes):
                    self.handler_to_worker_queue.put(msg)
                break
            else:
                #get route: type {"prefix", "bgp_next_hop", "route-in-clear", "route_id", "encrypted_route",
                # "encrypted_exp_policies_rs1", "encrypted_exp_policies_rs2", "key", "type", "announcement_id"}
                route = msg["route"]
                self.handler_to_worker_queue.put(route)
                '''x=1000
                for x in range(0,x):
                    route["announcement_id"]=counter
                    counter+=1
                    self.statistics.xbgp_update_send_update(route["announcement_id"])
                    self.logger.info("sending route " + str(route["announcement_id"]) )
                    self.send_update_rs1(route)

                    self.send_update_rs2(route)'''


        '''f=open('statistics-xbgp-prio.txt','w')
        f.write("announcement_id start_xbgp_processing_time end_xbgp_processing_time xbgp_update_send_update\n")
        for bgp_update_id in self.statistics.observations.keys():
            start_xbgp_processing_time = self.statistics.observations[bgp_update_id]["start-xbgp-processing-time"]
            end_xbgp_processing_time = self.statistics.observations[bgp_update_id]["end-xbgp-processing-time"]
            xbgp_update_send_update = self.statistics.observations[bgp_update_id]["xbgp_update_send_update"]

            f.write(str(bgp_update_id) + " " + str("{0:.15f}".format(start_xbgp_processing_time)) +" " + str("{0:.15f}".format(end_xbgp_processing_time))+" " + str("{0:.15f}".format(xbgp_update_send_update)) + "\n")'''
        sleep(10)


    def bgp_update_rate_sender(self):
        current_count = 0
        count = 0
        #print "Queue Empty: ", self.update_queue.empty()
        # #sleep(2)
        while not self.update_queue.empty() or self.run:
            try:
                bgp_update = self.update_queue.get(True, 1)
            except Empty:
                continue
            if self.simulation_start_time == 0:
                self.simulation_start_time = bgp_update["time"]

            current_bgp_update = bgp_update["time"]
            elapsed = current_bgp_update - self.simulation_start_time
            if elapsed > update_minutes:
                print "start: current", self.simulation_start_time, current_bgp_update
                break

            if current_count == self.send_rate:
                current_count = 0
                #print "Current Count: ", current_count
                sleep(1)
            current_count += 1
            count += 1

            self.send_update(bgp_update)

        #self.stop()

    def parse_as_path(self,as_path_xbgp_format):
        as_path_split = as_path_xbgp_format.split(" ")
        return as_path_split[1:len(as_path_split)-1]


    def sleep_time(self, update_time):
        time_diff = update_time - self.simulation_start_time
        wake_up_time = self.real_start_time + time_diff
        sleep_time = wake_up_time - time()

        if sleep_time < 0:
            sleep_time = 0

        return sleep_time

    def send_update_rs1(self, update):
        self.conn_rs1.send(pickle.dumps(update))

    def send_update_rs2(self, update):
        self.conn_rs2.send(pickle.dumps(update))

    def start(self):
        self.logger.debug('start file processor')
        self.fp_thread = Thread(target=self.file_processor)
        self.fp_thread.start()

        self.logger.debug('start worker_listener')
        self.fp_thread = Thread(target=self.receive_from_workers)
        self.fp_thread.start()

        print "mode: ", self.mode
        self.logger.debug('start update sender')
        if self.mode == 0:
            self.us_thread = Thread(target=self.bgp_update_sender)
            self.us_thread.start()
        if self.mode == 1:
            self.us_thread = Thread(target=self.bgp_update_rate_sender)
            self.us_thread.start()

    def stop(self):
        '''
        server1 = tuple([self.server_settings["server1"]["IP"], int(self.server_settings["server1"]["PORT"])])
        server2 = tuple([self.server_settings["server2"]["IP"], int(self.server_settings["server2"]["PORT"])])

        conn = Client(server1, authkey = None)
        data = 'terminate'
        conn.send(json.dumps(data))
        conn.close()

        conn = Client(server2, authkey = None)
        data = 'terminate'
        conn.send(json.dumps(data))
        conn.close()
        '''
        self.logger.debug('terminate')


        while self.run:
            try:
                self.fp_thread.join(1)
                #self.logger.debug('MAIN: self.run = ' + str(self.run))
            except KeyboardInterrupt:
                self.logger.debug('KeyboardInterrupt received')
                self.run=False
        self.fp_thread.join()

        self.run=False

        self.logger.debug('bgp update sender terminated')

        self.us_thread.join()
        self.logger.debug('file processor terminated')

        #self.update_queue.close()

        self.conn_rs1.close()


def main(args):
    # logging - log level
    #logging.basicConfig(level=logging.INFO)

    # base_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","examples",args.dir,"config"))
    # config_file = os.path.join(base_path, "sdx_global.cfg")
    # config = json.load(open(config_file, 'r'))
    #ah_socket = tuple(config["Route Server"]["AH_SOCKET"])

    if args.speedup:
        speedup = args.speedup
    else:
        speedup = 1

    print args.processes
    exabgp_instance = ExaBGPEmulator(args.ip, args.port, args.key, args.input, speedup, args.rate, args.mode, args.debug,args.processes)

    exabgp_instance.start()

    exabgp_instance.logger.debug('mch: waiting for join()')

    exabgp_instance.stop()

def send_main():
    pass

''' main '''
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('ip', help='ip address of the xrs')
    parser.add_argument('port', help='port of the xrs', type=int)
    parser.add_argument('key', help='authkey of the xrs')
    parser.add_argument('input', help='bgp input file')
    parser.add_argument('rate', help='bgp updates rate/second')
    parser.add_argument('mode', help='xbgp mode 0: bgp update time based 1: bgp update rate based')
    parser.add_argument('--processes', help='number of parallel senders', type=int)
    # parser.add_argument('dir', help='Example directory name')
    parser.add_argument('-d', '--debug', help='enable debug output', action="store_true")
    parser.add_argument('--speedup', help='speed up of replay', type=float)
    args = parser.parse_args()
    main(args)
