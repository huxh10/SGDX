'''
receives BGP messages and assign them to the set of SMPC workers
'''


import argparse
import json
from multiprocessing.connection import Listener, Client
import os
import signal
import Queue
from threading import Thread
import sys
np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if np not in sys.path:
    sys.path.append(np)
import util.log
from xrs.server import server as Server
from route import Route
import route as route_static
import random
import os
import pickle
#from util.crypto_util import AESCipher
from functools import cmp_to_key
import math
from participant_db import ParticipantDB
import subprocess
from time import sleep
import time
from util.statistics_collector_2 import StatisticsCollector
import multiprocessing as mp
from multiprocessing import Process, Manager
import prio_worker_rs1
from Queue import Empty
import threading
from member_preferences import MemberPreferences
import port_config
from Queue import Queue, PriorityQueue
import sys

logger = util.log.getLogger('all-handler-rs1')

ABY_EXEC_PATH="../bin/ixp.exe"
#ABY_EXEC_PATH="/home/vagrant/aby/bin/ixp.exe"

DUMMY_KEY="00000000000000000000000000000000ff"

KEY_LENGTH = 16

AS_ROW_ENCODING_SIZE = 32 # bits

KEY_ID_SIZE = 8 # bits

class AllHandlerRs1:

    def __init__(self, number_of_processes):
        logger.info("Initializing the All Handler for RS1.")

        self.number_of_processes = number_of_processes

        # Initialize a XRS Server
        self.server_receive_bgp_messages = Server(logger, endpoint=(port_config.process_assignement["rs1"], port_config.ports_assignment["rs1_receive_bgp_messages"]),authkey=None)
        self.server_send_mpc_output = Server(logger, endpoint=(port_config.process_assignement["rs1"], port_config.ports_assignment["rs1_send_mpc_output"]),authkey=None)
        self.rs1_to_rs2_client = Client((port_config.process_assignement["rs2"], port_config.ports_assignment["rs1_rs2"]), authkey=None)
        logger.debug("connected to rs2")
        self.run = True
        self.route_id_counter=0
        self.member_preferences = MemberPreferences()

        self.statistics_handler = StatisticsCollector()

        self.update_queue = mp.Manager().Queue()
        self.update_queue = mp.Queue()
        self.lock = mp.Manager().Lock()
        #self.lock_stop = mp.Manager().Lock()
        #self.lock_stop.acquire()
        #self.stop_received=False

        self.participant_db = ParticipantDB()
        self.number_of_participants = len(self.participant_db.bgp_speaker_2_id.keys())

        # create workers
        self.manager = Manager()
        self.handler_to_worker_queue = self.manager.Queue() # it should be a priority queue
        self.worker_to_handler_queue = self.manager.Queue()
        self.worker_ids_queue = self.manager.Queue()
        map(self.worker_ids_queue.put,range(port_config.ports_assignment["worker_port"],port_config.ports_assignment["worker_port"]+self.number_of_processes))

        self.prefix_2_bgp_next_hop_2_route = {}
        self.member_2_member_2_local_pref = {}

        self.prefix_2_messages_queued={}
        self.prefixes_under_processing=set()
        '''self.worker_2_prefix_under_processing = {}
        map(self.worker_2_prefix_under_processing.put,range(port_config.ports_assignment["worker_port"],port_config.ports_assignment["worker_port"]+self.number_of_processes))
        for port_id in range(port_config.ports_assignment["worker_port"],port_config.ports_assignment["worker_port"]+self.number_of_processes):
            self.worker_2_prefix_under_processing[port_id]=Queue()'''


        self.workers_pool = mp.Pool(self.number_of_processes, prio_worker_rs1.prio_worker_main,(self.handler_to_worker_queue,self.worker_to_handler_queue,self.worker_ids_queue,))

    def start(self):
        self.receive_bgp_routes_th = Thread(target=self.receive_bgp_routes)
        self.receive_bgp_routes_th.setName("self.receive_bgp_routes_th")
        self.receive_bgp_routes_th.start()

        self.receive_from_workers()

    def receive_from_workers(self):
        waiting =0
        stop_counter=self.number_of_processes
        while True:
            try:
                #logger.info("waiting for message from worker")
                msg = self.worker_to_handler_queue.get(True, 1)

                logger.info("received message from worker")
                #logger.debug("received message from worker: " + str(msg))

                if "stop" in msg:
                    logger.info("received STOP message from worker")
                    stop_counter-=1
                    print "stop received " + str(stop_counter)
                    self.rs1_to_rs2_client.send(pickle.dumps(msg))
                    if stop_counter == 0:
                        self.server_send_mpc_output.sender_queue.put(pickle.dumps(msg))
                        time.sleep(5)
                        break
                    continue

                if msg["type"] == "to-rs2" or msg["type"] == "to-rs2-init":
                    logger.info("received TO-RS2 message from worker")
                    self.rs1_to_rs2_client.send(pickle.dumps(msg))

                if msg["type"] == "to-hosts":
                    logger.info("received TO-HOSTS message from worker")
                    logger.debug("processed route-id: " + str(msg["announcement_id"]))
                    self.statistics_handler.record_end_of_bgp_update_processing(msg["announcement_id"])
                    self.server_send_mpc_output.sender_queue.put(pickle.dumps(msg))
                    self.lock.acquire()
                    if msg["prefix"] in self.prefix_2_messages_queued.keys():
                        old_msg = self.prefix_2_messages_queued[msg["prefix"]].pop(0)
                        self.prefix_2_bgp_next_hop_2_route[msg["prefix"]][old_msg["bgp_next_hop"]] = old_msg
                        logger.info("adding route " + str(old_msg["announcement_id"]) + " into the worker queue")
                        self.handler_to_worker_queue.put((old_msg["announcement_id"],{"bgp_next_hop" : old_msg["bgp_next_hop"], "prefix" : old_msg["prefix"], "announcement_id" : old_msg["announcement_id"], "messages" : self.prefix_2_bgp_next_hop_2_route[old_msg["prefix"]]}))
                        if len(self.prefix_2_messages_queued[old_msg["prefix"]])==0:
                            del self.prefix_2_messages_queued[old_msg["prefix"]]
                    else:
                        self.prefixes_under_processing.remove(msg["prefix"])
                    #if len(self.prefix_2_messages_queued.keys())==0 and self.stop_received:
                    #    self.lock_stop.release() # allow to send the STOP message to the workers
                    self.lock.release()


            except Empty:
                if waiting == 0:
                    #logger.debug("Waiting for BGP update...")
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass
                        #logger.debug("Waiting for BGP update...")
        self.rs1_to_rs2_client.close()
        logger.debug("shutting down receive from workers")

        f=open('statistics-prio-rs1-handler.txt','w')
        f.write("route_id initial end difference lock route_inserted\n")
        for bgp_update_id in self.statistics_handler.observations.keys():
            start_processing_time= self.statistics_handler.observations[bgp_update_id]["start-processing-time"]
            end_processing_time= self.statistics_handler.observations[bgp_update_id]["end-processing-time"]
            lock_time= self.statistics_handler.observations[bgp_update_id]["lock-waiting-time"]
            route_inserted_time=self.statistics_handler.observations[bgp_update_id]["route-inserted-time"]
            wait_receive_time=self.statistics_handler.observations[bgp_update_id]["wait-receive-time"]
            f.write(str(bgp_update_id) + " " + str("{0:.9f}".format(start_processing_time))+" " + str("{0:.9f}".format(end_processing_time))+" " + str("{0:.9f}".format(end_processing_time-start_processing_time))+ " " + str("{0:.9f}".format(lock_time-start_processing_time))+" " + str("{0:.9f}".format(route_inserted_time-start_processing_time))+ " " + str("{0:.9f}".format(start_processing_time-wait_receive_time))+ "\n")



    def receive_bgp_routes(self):
        logger.info("Starting the Server to handle incoming BGP Updates from ExaBGP. Listening on port 6000")
        self.server_receive_bgp_messages.start()
        logger.info("Connected to ExaBGP via port 6000")
        self.server_send_mpc_output.start()
        logger.info("RS1 connected to Host Receiver Mock ")

        waiting=0
        while self.run:
            # get BGP messages from ExaBGP
            try:
                self.statistics_handler.wait_to_receive()
                msg = self.server_receive_bgp_messages.receiver_queue.get(True, 1)
                msg = pickle.loads(msg)

                waiting = 0

                logger.info("Got bgp_route from ExaBGP. " + str(msg))
                #logger.debug("Got bgp_update from ExaBGP.")
                # Received BGP bgp_update advertisement from ExaBGP

                if "stop" in msg:
                    close_msg = {"stop" : 1}
                    logger.info("Waiting 20 seconds before sending closing message " + str(close_msg))
                    print str("getting lock ")
                    self.lock.acquire()
                    self.stop_received=True
                    self.lock.release()
                    print str("Waiting 20 seconds before sending closing message ")
                    time.sleep(20)
                    #self.lock_stop.acquire()
                    logger.info("Sending closing message " + str(close_msg))
                    print "Sending closing message"
                    for _ in range(0,self.number_of_processes):
                        self.handler_to_worker_queue.put((sys.maxint,msg))
                    #self.lock_stop.release()
                    break
                else:
                    self.statistics_handler.received_bgp_update(msg["announcement_id"])
                    self.lock.acquire()
                    self.statistics_handler.lock_acquired(msg["announcement_id"])
                    #self.statistics_handler.record_end_of_bgp_update_processing(msg["announcement_id"])
                    if msg["announcement_id"] % 100 ==0:
                        print str(msg["announcement_id"])
                    logger.debug("received route-id: " + str(msg["announcement_id"]))
                    if msg["prefix"] in self.prefixes_under_processing:
                        logger.info("adding route " + str(msg["announcement_id"]) + " into the QUEUE queue")
                        if msg["prefix"] not in self.prefix_2_messages_queued.keys():
                            self.prefix_2_messages_queued[msg["prefix"]]=[]
                        self.prefix_2_messages_queued[msg["prefix"]].append(msg)
                        self.lock.release()
                    else:
                        self.lock.release()
                        if msg["prefix"] not in self.prefix_2_bgp_next_hop_2_route.keys():
                            self.prefix_2_bgp_next_hop_2_route[msg["prefix"]]={}
                        self.prefix_2_bgp_next_hop_2_route[msg["prefix"]][msg["bgp_next_hop"]] = msg
                        logger.info("adding route " + str(msg["announcement_id"]) + " into the worker queue")
                        self.handler_to_worker_queue.put((msg["announcement_id"],{"bgp_next_hop" : msg["bgp_next_hop"], "prefix" : msg["prefix"], "announcement_id" : msg["announcement_id"], "messages" : self.prefix_2_bgp_next_hop_2_route[msg["prefix"]]}))
                        self.prefixes_under_processing.add(msg["prefix"])
                    self.statistics_handler.route_inserted(msg["announcement_id"])

            except Empty:
                if waiting == 0:
                    #logger.debug("Waiting for BGP update...")
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass
                        #logger.debug("Waiting for BGP update...")
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
        # locate config file
    # base_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","examples",args.dir,"config"))
    # config_file = os.path.join(base_path, "sdx_global.cfg")

    parser.add_argument("-p","--processes", help="number of parallel SMPC processes", type=int, default=1)
    args = parser.parse_args()

    # start route server
    # sdx_rs = route_server(config_file)
    pprs = AllHandlerRs1(args.processes)
    rs_thread = Thread(target=pprs.start)
    rs_thread.setName("AllHandler1Thread")
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
