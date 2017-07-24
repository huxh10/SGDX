#!/usr/bin/env python
#  Author:
#  Rudiger Birkner(ETH Zurich)

import argparse
import json
import struct
import socket
import os
import sys
np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
print np
if np not in sys.path:
    sys.path.append(np)
from time import sleep, time, strptime, mktime
from threading import Thread
from Queue import Queue, Empty
from multiprocessing.connection import Client
import util.log
from util.crypto_util import AESCipher
from pprs.route import Route
import pickle
import pprs.port_config as port_config
from copy import deepcopy

# Run each iteration for half an hour duration
update_minutes = 1800

KEY_LENGTH = 16
SIX_PACK_RS = 0
SGX_RS = 1


class ExaBGPEmulator(object):
    def __init__(self, rs, address, port, input_file, speed_up, rate, mode):
        self.logger = util.log.getLogger('xbgp')
        self.logger.debug('init')
        self.route_id_counter = 0
        self.real_start_time = time()
        self.simulation_start_time = 0

        self.input_file = input_file
        self.speed_up = speed_up
        self.rs = rs
        self.send_rate = int(rate)
        self.mode = int(mode)

        self.run = True
        self.fp_thread = None
        self.us_thread = None
        self.update_queue = Queue()
        if self.rs == SIX_PACK_RS:
            self.logger.debug('connecting to RS1')
            self.conn_rs1 = Client((port_config.process_assignement["rs1"], port_config.ports_assignment["rs1_receive_bgp_messages"]), authkey=None)
            self.logger.debug('connected to RS1')
            self.logger.debug('connecting to RS2')
            self.conn_rs2 = Client((port_config.process_assignement["rs2"], port_config.ports_assignment["rs2_receive_bgp_messages"]), authkey=None)
            self.logger.debug('connected to RS2')
        elif self.rs == SGX_RS:
            self.logger.debug('connecting to RS')
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((address, port))
            self.logger.debug('connected to RS')

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
                            tmp["neighbor"]["ip"] = x[0]
                            tmp["neighbor"]["address"]["peer"] = x[0]
                            tmp["neighbor"]["asn"]["peer"] = x[1][2:]

                        elif line.startswith("TO"):
                            x = x[1].split(" ")
                            tmp["neighbor"]["address"]["local"] = x[0]
                            tmp["neighbor"]["asn"]["local"] = x[1][2:]

                        elif line.startswith("ORIGIN"):
                            if "attribute" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["attribute"] = {}
                            tmp["neighbor"]["message"]["update"]["attribute"]["origin"] = x[1].lower()

                        elif line.startswith("ASPATH"):
                            if "attribute" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["attribute"] = {}
                            tmp["neighbor"]["message"]["update"]["attribute"]["as-path"] = []
                            for asn in x[1].split(' '):
                                if asn[0] == '{':
                                    for i in asn[1:-1].split(','):
                                        tmp["neighbor"]["message"]["update"]["attribute"]["as-path"].append(int(i))
                                else:
                                    tmp["neighbor"]["message"]["update"]["attribute"]["as-path"].append(int(asn))

                        elif line.startswith("MULTI_EXIT_DISC"):
                            if "attribute" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["attribute"] = {}
                            tmp["neighbor"]["message"]["update"]["attribute"]["med"] = x[1]

                        elif line.startswith("NEXT_HOP"):
                            if "announce" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["announce"] = {}
                            tmp["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"] = {x[1]: {}}
                            next_hop = x[1]

                        elif line.startswith("COMMUNITY"):
                            if "attribute" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["attribute"] = {}
                            tmp["neighbor"]["message"]["update"]["attribute"]["community"] =  x[1]

                        elif line.startswith("ANNOUNCE"):
                            if "announce" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["announce"] = {"ipv4 unicast": {}}
                            flag = 2

                        elif line.startswith("WITHDRAW"):
                            tmp["neighbor"]["message"]["update"]["withdraw"] = {"ipv4 unicast": {}}
                            flag = 3

                elif flag >= 2:
                    if line.startswith("\n"):
                        if not self.run:
                            break

                        if self.rs == SIX_PACK_RS:
                            routes = self.create_routes_to_be_sent(tmp)
                        elif self.rs == SGX_RS:
                            routes = self.create_routes_per_prefix(tmp)
                        for route in routes:
                            self.update_queue.put({'route': route, "time": tmp["time"]})

                        while self.update_queue.qsize() > 32000:
                            self.logger.debug('queue is full - taking a break')
                            sleep(self.sleep_time(tmp["time"])/2)
                            if not self.run:
                                break
                        flag = 0

                    else:
                        if line.startswith("ANNOUNCE"):
                            if "announce" not in tmp["neighbor"]["message"]["update"]:
                                tmp["neighbor"]["message"]["update"]["announce"] = {"ipv4 unicast": {}}
                            flag = 2

                        elif line.startswith("WITHDRAW"):
                            tmp["neighbor"]["message"]["update"]["withdraw"] = {"ipv4 unicast": {}}
                            flag = 3

                        else:
                            x = line.split("\n")[0].split()[0]
                            if flag == 2:
                                tmp["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"][next_hop][x] = {}
                            else:
                                tmp["neighbor"]["message"]["update"]["withdraw"]["ipv4 unicast"][x] = {}

        self.run = False
        print "file processor done"

    def create_routes_per_prefix(self, bgp_update):
        routes = []
        if "announce" not in bgp_update["neighbor"]["message"]["update"]:
            return routes
        nh_dict = bgp_update["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"]
        for next_hop in nh_dict:
            for prefix in nh_dict[next_hop]:
                bgp_update["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"] = {next_hop: {prefix: {}}}
                routes.append(deepcopy(bgp_update))
        return routes

    def create_routes_to_be_sent(self, bgp_update):
        # 1. generate key for the incoming route
        key = os.urandom(KEY_LENGTH)
        keystr = key.encode("hex")
        self.cipher = AESCipher(key)

        routes = []
        # for each IP prefix destination add a route in the queue
        if "announce" in bgp_update["neighbor"]["message"]["update"]:
            # GENERATE ANNOUNCEMENTS
            for next_hop in bgp_update["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"]:
                for prefix in bgp_update["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"][next_hop]:
                    route = Route()
                    route.neighbor = bgp_update["neighbor"]["ip"]
                    route.prefix = prefix
                    route.time = bgp_update["time"]
                    route.id = self.route_id_counter
                    self.route_id_counter += 1
                    route.as_path = bgp_update["neighbor"]["message"]["update"]["attribute"]["as-path"]
                    route.next_hop = next_hop
                    if "community" in bgp_update["neighbor"]["message"]["update"]["attribute"]:
                        route.communities = bgp_update["neighbor"]["message"]["update"]["attribute"]["community"]
                    route.type = "announce"

                    encrypted_route = self.cipher.encrypt(pickle.dumps(route)) #encrypt serialized route object
                    routes.append({"prefix" : prefix, "asn" : bgp_update["neighbor"]["asn"]["peer"], "route-in-clear" : None, "route_id" : route.id, "encrypted_route" : encrypted_route, "key" : keystr, "type" : route.type , "announcement_id" : route.id})

        return routes

    def bgp_update_sender(self):
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
                break

            sleep_time = self.sleep_time(msg["time"])
            sleep(sleep_time)

            if self.rs == SIX_PACK_RS:
                self.send_update_rs1(msg["route"])
                self.send_update_rs2(msg["route"])
            elif self.rs == SGX_RS:
                self.send_update(msg["route"])

        self.stop()

    def bgp_update_rate_sender(self):
        current_count = 0
        count = 0
        while not self.update_queue.empty() or self.run:
            try:
                msg = self.update_queue.get(True, 1)
            except Empty:
                continue
            if self.simulation_start_time == 0:
                self.simulation_start_time = msg["time"]

            current_bgp_update = msg["time"]
            elapsed = current_bgp_update - self.simulation_start_time
            if elapsed > update_minutes:
                print "start: current", self.simulation_start_time, current_bgp_update
                break

            if current_count == self.send_rate:
                current_count = 0
                sleep(1)
            current_count += 1
            count += 1

            if self.rs == SIX_PACK_RS:
                self.send_update_rs1(msg["route"])
                self.send_update_rs2(msg["route"])
            elif self.rs == SGX_RS:
                self.send_update(msg["route"])

        self.stop()

    def bgp_update_fast_sender(self):
        count = 0
        while not self.update_queue.empty() or self.run:
            try:
                msg = self.update_queue.get(True, 1)
            except Empty:
                continue
            count += 1
            if self.rs == SIX_PACK_RS:
                self.send_update_rs1(msg["route"])
                self.send_update_rs2(msg["route"])
            elif self.rs == SGX_RS:
                self.send_update(msg["route"])

        print "total sent announcements: " + str(count)
        self.stop()

    def sleep_time(self, update_time):
        time_diff = update_time - self.simulation_start_time
        wake_up_time = self.real_start_time + time_diff
        sleep_time = wake_up_time - time()
        if sleep_time < 0:
            sleep_time = 0
        return sleep_time

    def send_update(self, update):
        s = json.dumps(update)
        self.conn.send(struct.pack("H", len(s) + 2) + s)

    def send_update_rs1(self, update):
        self.conn_rs1.send(pickle.dumps(update))

    def send_update_rs2(self, update):
        self.conn_rs2.send(pickle.dumps(update))

    def start(self):
        self.logger.debug('start file processor')
        self.fp_thread = Thread(target=self.file_processor)
        self.fp_thread.start()

        self.logger.debug('start update sender')
        if self.mode == 0:
            self.us_thread = Thread(target=self.bgp_update_sender)
            self.us_thread.start()
        if self.mode == 1:
            self.us_thread = Thread(target=self.bgp_update_rate_sender)
            self.us_thread.start()
        if self.mode == 2:
            self.us_thread = Thread(target=self.bgp_update_fast_sender)
            self.us_thread.start()

    def stop(self):
        self.logger.debug('terminate')
        if self.rs == SIX_PACK_RS:
            self.send_update_rs1({"stop": 1})
            self.send_update_rs2({"stop": 1})
        elif self.rs == SGX_RS:
            self.send_update({"stop": 1})

        if self.run == True:
            self.run = False
            self.us_thread.join()
        self.logger.debug('bgp update sender terminated')

        self.fp_thread.join()
        self.logger.debug('file processor terminated')

        if self.rs == SIX_PACK_RS:
            self.conn_rs1.close()
            self.conn_rs2.close()
        elif self.rs == SGX_RS:
            self.conn.close()


def main(args):
    speedup = args.speedup if args.speedup else 1

    exabgp_instance = ExaBGPEmulator(args.rs, args.ip, args.port, args.input, speedup, args.rate, args.mode)
    exabgp_instance.start()

    while exabgp_instance.run:
        try:
            sleep(0.5)
        except KeyboardInterrupt:
            exabgp_instance.stop()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('rs', help='0: six-pack rs, 1: sgx rs', type=int)
    parser.add_argument('ip', help='ip address of the xrs')
    parser.add_argument('port', help='port of the xrs', type=int)
    parser.add_argument('input', help='bgp input file')
    parser.add_argument('rate', help='bgp updates rate/second')
    parser.add_argument('mode', help='xbgp mode 0: bgp update time based 1: bgp update rate based 2: as fast as possible')
    parser.add_argument('--speedup', help='speed up of replay', type=float)
    args = parser.parse_args()
    main(args)
