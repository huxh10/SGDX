'''
receives BGP messages and assign them to the set of SMPC workers
'''


import argparse
import json
from multiprocessing.connection import Listener, Client
import os
import Queue
from threading import Thread
import sys
np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if np not in sys.path:
    sys.path.append(np)
import util.log
from xrs.server import server as Server
import random
import os
import pickle
import subprocess
from time import sleep
import time
import multiprocessing as mp
from multiprocessing import Process, Manager
import prio_worker_rs1
from load_ribs import load_ribs
from Queue import Empty
import threading
import port_config
from Queue import Queue, PriorityQueue
import sys

logger = util.log.getLogger('prio-handler-rs1')
RS1_MODE = 1

class PrioHandlerRs1:
    def __init__(self, asn_2_id_file, rib_file, number_of_processes):
        logger.info("Initializing the Priority Handler for RS1.")

        self.number_of_processes = number_of_processes
        with open(asn_2_id_file, 'r') as f:
            self.asn_2_id = json.load(f)
        self.prefix_2_nh_id_2_route = load_ribs(rib_file, self.asn_2_id, RS1_MODE) if rib_file else {}

        # Initialize a XRS Server
        self.server_receive_bgp_messages = Server(logger, endpoint=(port_config.process_assignement["rs1"], port_config.ports_assignment["rs1_receive_bgp_messages"]),authkey=None)
        # NOTE: fake sending, only for performance test
        #self.server_send_mpc_output = Server(logger, endpoint=(port_config.process_assignement["rs1"], port_config.ports_assignment["rs1_send_mpc_output"]),authkey=None)
        self.rs1_to_rs2_client = Client((port_config.process_assignement["rs2"], port_config.ports_assignment["rs1_rs2"]), authkey=None)
        logger.debug("connected to rs2")
        self.run = True

        self.lock = mp.Manager().Lock()
        #self.lock_stop = mp.Manager().Lock()
        #self.lock_stop.acquire()
        #self.stop_received=False

        # create workers
        self.manager = Manager()
        self.handler_to_worker_queue = self.manager.Queue() # it should be a priority queue
        self.worker_to_handler_queue = self.manager.Queue()
        self.worker_ids_queue = self.manager.Queue()
        map(self.worker_ids_queue.put,range(port_config.ports_assignment["worker_port"],port_config.ports_assignment["worker_port"]+self.number_of_processes))

        self.prefix_2_messages_queued = {}
        self.prefixes_under_processing = set()

        self.workers_pool = mp.Pool(self.number_of_processes, prio_worker_rs1.prio_worker_main,(self.handler_to_worker_queue,self.worker_to_handler_queue,self.worker_ids_queue,))

    def start(self):
        self.receive_bgp_routes_th = Thread(target=self.receive_bgp_routes)
        self.receive_bgp_routes_th.setName("self.receive_bgp_routes_th")
        self.receive_bgp_routes_th.start()

        self.receive_from_workers()

    def receive_from_workers(self):
        waiting = 0
        stop_counter=self.number_of_processes
        while True:
            try:
                msg = self.worker_to_handler_queue.get(True, 1)

                if "stop" in msg:
                    logger.info("received STOP message from worker")
                    stop_counter -= 1
                    print "stop received " + str(stop_counter)
                    self.rs1_to_rs2_client.send(pickle.dumps(msg))
                    if stop_counter == 0:
                        # NOTE: fake sending, only for performance test
                        #self.server_send_mpc_output.sender_queue.put(pickle.dumps(msg))
                        time.sleep(5)
                        break
                    continue

                if msg["type"] == "to-rs2" or msg["type"] == "to-rs2-init":
                    self.rs1_to_rs2_client.send(pickle.dumps(msg))

                if msg["type"] == "to-hosts":
                    # NOTE: fake sending, only for performance test
                    #self.server_send_mpc_output.sender_queue.put(pickle.dumps(msg))
                    self.lock.acquire()
                    if msg["prefix"] in self.prefix_2_messages_queued.keys():
                        old_msg = self.prefix_2_messages_queued[msg["prefix"]].pop(0)
                        as_id = self.asn_2_id[old_msg["asn"]]
                        self.prefix_2_nh_id_2_route[msg["prefix"]][as_id] = {}
                        self.prefix_2_nh_id_2_route[msg["prefix"]][as_id]["announcement_id"] = old_msg["announcement_id"]
                        self.prefix_2_nh_id_2_route[msg["prefix"]][as_id]["key"] = old_msg["key"]
                        self.handler_to_worker_queue.put((old_msg["announcement_id"], {"prefix" : old_msg["prefix"], "announcement_id" : old_msg["announcement_id"], "encrypted_route" : old_msg["encrypted_route"], "as_id" : as_id, "messages" : self.prefix_2_nh_id_2_route[old_msg["prefix"]]}))
                        if len(self.prefix_2_messages_queued[old_msg["prefix"]]) == 0:
                            del self.prefix_2_messages_queued[old_msg["prefix"]]
                    else:
                        self.prefixes_under_processing.remove(msg["prefix"])
                    #if len(self.prefix_2_messages_queued.keys())==0 and self.stop_received:
                    #    self.lock_stop.release() # allow to send the STOP message to the workers
                    self.lock.release()


            except Empty:
                if waiting == 0:
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass
        self.rs1_to_rs2_client.close()
        logger.debug("shutting down receive from workers")


    def receive_bgp_routes(self):
        logger.info("Starting the Server to handle incoming BGP Updates from ExaBGP. Listening on port 6000")
        self.server_receive_bgp_messages.start()
        logger.info("Connected to ExaBGP via port 6000")
        # NOTE: fake sending, only for performance test
        #self.server_send_mpc_output.start()
        #logger.info("RS1 connected to Host Receiver Mock ")

        waiting = 0
        while self.run:
            # get BGP messages from ExaBGP
            try:
                msg = self.server_receive_bgp_messages.receiver_queue.get(True, 1)
                msg = pickle.loads(msg)
                waiting = 0

                # Received BGP bgp_update advertisement from ExaBGP
                if "stop" in msg:
                    close_msg = {"stop" : 1}
                    logger.info("Waiting 20 seconds before sending closing message " + str(close_msg))
                    print "getting stop lock..."
                    self.lock.acquire()
                    self.stop_received=True
                    self.lock.release()
                    print "Waiting 20 seconds before sending closing message "
                    time.sleep(20)
                    #self.lock_stop.acquire()
                    logger.info("Sending closing message " + str(close_msg))
                    print "Sending closing message"
                    for _ in range(0,self.number_of_processes):
                        self.handler_to_worker_queue.put((sys.maxint,msg))
                    #self.lock_stop.release()
                    break
                else:
                    self.lock.acquire()
                    if msg["prefix"] in self.prefixes_under_processing:
                        if msg["prefix"] not in self.prefix_2_messages_queued.keys():
                            self.prefix_2_messages_queued[msg["prefix"]]=[]
                        self.prefix_2_messages_queued[msg["prefix"]].append(msg)
                        self.lock.release()
                    else:
                        self.lock.release()
                        if msg["prefix"] not in self.prefix_2_nh_id_2_route.keys():
                            self.prefix_2_nh_id_2_route[msg["prefix"]]={}
                        as_id = self.asn_2_id[msg["asn"]]
                        self.prefix_2_nh_id_2_route[msg["prefix"]][as_id] = {}
                        self.prefix_2_nh_id_2_route[msg["prefix"]][as_id]["announcement_id"] = msg["announcement_id"]
                        self.prefix_2_nh_id_2_route[msg["prefix"]][as_id]["key"] = msg["key"]
                        self.handler_to_worker_queue.put((msg["announcement_id"], {"prefix" : msg["prefix"], "announcement_id" : msg["announcement_id"], "encrypted_route" : msg["encrypted_route"], "as_id" : as_id, "messages" : self.prefix_2_nh_id_2_route[msg["prefix"]]}))
                        self.prefixes_under_processing.add(msg["prefix"])

            except Empty:
                if waiting == 0:
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass
        logger.debug("receive_routes_shut_down")

    def stop(self):
        while True:
            try:
                self.receive_bgp_routes_th.join(1)
                logger.debug("waiting for join receive_bgp_routes")
            except KeyboardInterrupt:
                self.run=False
        logger.info("Stopping.")
        self.run = False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("asn_2_id_file", type=str, help="specify asn_2_id json file")
    parser.add_argument('-r', '--rib_file', type=str, help='specify the rib file, eg.g. ../examples/test-rs/ribs/bview')
    parser.add_argument("-p","--processes", help="number of parallel SMPC processes", type=int, default=1)
    args = parser.parse_args()

    pprs = PrioHandlerRs1(args.asn_2_id_file, args.rib_file, args.processes)
    rs_thread = Thread(target=pprs.start)
    rs_thread.setName("PrioHandler1Thread")
    rs_thread.daemon = True
    rs_thread.start()

    while rs_thread.is_alive():
        try:
            rs_thread.join(1)
            #logger.info("waiting for join pprs")
            #print "waiting for join pprs"
            #logger.debug("join cycle")
        except KeyboardInterrupt:
            pprs.stop()
    print "waiting before dying"
    logger.info("waiting before dying")

    for thread in threading.enumerate():
        print thread.name


if __name__ == '__main__':
    main()
