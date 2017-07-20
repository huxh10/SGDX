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
from xrs.client_2 import client as Client2
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
import prio_worker_rs2
from Queue import Empty
import threading
from member_preferences import MemberPreferences
import port_config

logger = util.log.getLogger('all-handler-rs2')

ABY_EXEC_PATH="../aby/bin/ixp.exe"
#ABY_EXEC_PATH="/home/vagrant/aby/bin/ixp.exe"

KEY_LENGTH = 16

AS_ROW_ENCODING_SIZE = 32 # bits

KEY_ID_SIZE = 8 # bits

class AllHandlerRs2:

    def __init__(self, number_of_processes):
        logger.info("Initializing the All Handler for RS2.")

        # Init the
        self.server_receive_bgp_messages = None
        self.number_of_processes = number_of_processes
        
        # Initialize a XRS Server
        self.server_receive_bgp_messages = Server(logger, endpoint=(port_config.process_assignement["rs2"], port_config.ports_assignment["rs2_receive_bgp_messages"]))
        self.server_send_mpc_output = Server(logger, endpoint=(port_config.process_assignement["rs2"], port_config.ports_assignment["rs2_send_mpc_output"]))
        self.server_rs1 = Server(logger, endpoint=(port_config.process_assignement["rs2"],  port_config.ports_assignment["rs1_rs2"]))
        self.run = True
        self.route_id_counter=0
        self.member_preferences = MemberPreferences()

        self.statistics_handler = StatisticsCollector()

        self.update_queue = mp.Manager().Queue()

        # start the MPC process in background

        self.participant_db = ParticipantDB()
        self.number_of_participants = len(self.participant_db.bgp_speaker_2_id.keys())

        self.receive_mappings_from_rs1_th = Thread(target=self.receive_mappings_from_rs1)
        self.receive_mappings_from_rs1_th.setName("receive_mappings_from_rs1_th")
        self.receive_mappings_from_rs1_th.daemon = True
        self.receive_mappings_from_rs1_th.start()

        self.id_2_msg = mp.Manager().dict()
        self.id_2_port = mp.Manager().dict()
        self.port2stop = mp.Manager().dict()

        self.lock = mp.Manager().Lock()
        self.port2stop_lock = mp.Manager().Lock()
        self.stop_port = False

        self.prefix_2_bgp_next_hop_2_route = {}

        self.member_2_member_2_local_pref = {}

        self.handler_2_worker_queues={}
        self.worker_2_handler_queue = mp.Queue()
        for i in range(port_config.ports_assignment["worker_port"],port_config.ports_assignment["worker_port"]+self.number_of_processes):
            self.handler_2_worker_queues[i]=mp.Queue()

        # create workers
        self.receive_from_workers_th = Thread(target=self.receive_from_workers)
        self.receive_from_workers_th.setName( "receive_from_workers_th")
        #self.receive_from_workers_th.daemon = True
        self.receive_from_workers_th.start()

        #self.workers_pool = mp.Pool(self.number_of_processes, all_worker_rs2.all_worker_main,(self.handler_to_worker_queue,self.worker_ids_queue,))

        # Setup a list of processes that we want to run
        self.processes = [mp.Process(target=prio_worker_rs2.prio_worker_main, args=(x, self.handler_2_worker_queues[x], self.worker_2_handler_queue ))
                          for x in range(port_config.ports_assignment["worker_port"],port_config.ports_assignment["worker_port"]+self.number_of_processes)]

        # Run processes
        for p in self.processes:
            p.start()




    def receive_mappings_from_rs1(self):
        waiting=0
        logger.info("connecting to RS1")
        self.server_rs1.start()
        logger.info("connected to RS1 for receiving mapping messages")
        while self.run:
            # get BGP messages from ExaBGP
            try:
                msg = self.server_rs1.receiver_queue.get(True, 1)
                msg = pickle.loads(msg)

                waiting = 0

                logger.info("Got mapping message from RS1. " + str(msg))
                #logger.debug("Got bgp_update from ExaBGP.")
                # Received BGP bgp_update advertisement from ExaBGP

                if "stop" in msg:
                    self.port2stop_lock.acquire()
                    logger.info("received stop message")
                    port = msg["port"]
                    if self.stop_port:
                        self.handler_2_worker_queues[port].put(msg)
                    self.port2stop[port] = None
                    logger.info("port2stop: " + str(self.port2stop))
                    if len(self.port2stop) == self.number_of_processes:
                        self.port2stop_lock.release()
                        break
                    self.port2stop_lock.release()
                    continue

                if msg["type"] == "to-rs2-init":
                    logger.info("received initialization message")
                    pass

                if "announcement_id" in msg:
                    logger.info("received route_id message")
                    announcement_id = msg["announcement_id"]
                    self.lock.acquire()
                    self.id_2_port[announcement_id] = msg["worker_port"]
                    if announcement_id in self.id_2_msg:
                        logger.info("adding route " + str(announcement_id) + " into the worker queue")
                        #send message to the correct worker
                        if self.id_2_msg[announcement_id]["prefix"] not in self.prefix_2_bgp_next_hop_2_route.keys():
                            self.prefix_2_bgp_next_hop_2_route[self.id_2_msg[announcement_id]["prefix"]]={}
                        self.prefix_2_bgp_next_hop_2_route[self.id_2_msg[announcement_id]["prefix"]][self.id_2_msg[announcement_id]["bgp_next_hop"]] = self.id_2_msg[announcement_id]
                        self.handler_2_worker_queues[self.id_2_port[announcement_id]].put({"announcement_id" : msg["announcement_id"], "messages" : self.prefix_2_bgp_next_hop_2_route[self.id_2_msg[announcement_id]["prefix"]]})
                        del self.id_2_port[announcement_id]
                        del self.id_2_msg[announcement_id]

                    self.lock.release()


            except Empty:
                if waiting == 0:
                    #logger.debug("Waiting for RS1 mapping...")
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass
                        #logger.debug("Waiting for RS1 mapping...")

        logger.debug("closing reception from RS1")



    def start(self):
        logger.info("Starting the Server to handle incoming BGP Updates from ExaBGP. Listening on port 6002")
        self.server_receive_bgp_messages.start()
        logger.info("Connected to ExaBGP via port 6002")
        self.server_send_mpc_output.start()
        logger.info("RS2 connected to Host Receiver Mock ")


        while self.run:
            # get BGP messages from ExaBGP
            waiting =0
            try:
                msg = self.server_receive_bgp_messages.receiver_queue.get(True, 1)
                msg = pickle.loads(msg)

                waiting = 0

                logger.debug("Got bgp_route from ExaBGP. ")
                #logger.debug("Got bgp_update from ExaBGP.")
                # Received BGP bgp_update advertisement from ExaBGP

                if "stop" in msg:
                    close_msg = {"stop" : 1}
                    logger.info("Shutting down  exa receiver.")
                    self.port2stop_lock.acquire()
                    logger.info("received stop message")

                    for port in self.port2stop.keys():
                        self.handler_2_worker_queues[port].put(msg)
                    else:
                        self.stop_port = True
                    self.port2stop_lock.release()
                    #self.send_update(close_msg)
                    self.server_receive_bgp_messages.conn.close()
                    time.sleep(5)
                    break
                else:
                    logger.info("msg received: " + str(msg))
                    announcement_id = msg["announcement_id"]
                    self.lock.acquire()
                    self.statistics_handler.received_bgp_update(msg["announcement_id"])
                    self.id_2_msg[announcement_id] = msg
                    if announcement_id in self.id_2_port:
                        #send message to the correct worker
                        if self.id_2_msg[announcement_id]["prefix"] not in self.prefix_2_bgp_next_hop_2_route.keys():
                            self.prefix_2_bgp_next_hop_2_route[self.id_2_msg[announcement_id]["prefix"]]={}
                        logger.info("adding route " + str(announcement_id) + " into the worker queue")
                        self.prefix_2_bgp_next_hop_2_route[self.id_2_msg[announcement_id]["prefix"]][self.id_2_msg[announcement_id]["bgp_next_hop"]] = msg
                        self.handler_2_worker_queues[self.id_2_port[announcement_id]].put({"announcement_id" : msg["announcement_id"], "messages" : self.prefix_2_bgp_next_hop_2_route[msg["prefix"]]})

                        del self.id_2_port[announcement_id]
                        del self.id_2_msg[announcement_id]
                    self.lock.release()


            except Queue.Empty:
                if waiting == 0:
                    #logger.debug("Waiting for BGP update...")
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass
                        #logger.debug("Waiting for BGP update...")
        logger.debug("Closing reception from hosts")
        '''if self.single:
            f=open('statistics-single.txt','w')
        else:
            f=open('statistics-all.txt','w')
        f.write("route_id pre_mpc mpc total\n")
        for bgp_update in self.statistics.observations.keys():
            for route_id in self.statistics.observations[bgp_update]["routes"].keys():
                total_pre_mpc_time = self.statistics.observations[bgp_update]["routes"][route_id]["total-time-python-no-mpc"]
                total_mpt_time = self.statistics.observations[bgp_update]["routes"][route_id]["total-mpc-time"]
                total_time = self.statistics.observations[bgp_update]["routes"][route_id]["total-time-after-mpc"]
                f.write(str(route_id) + " " + str(total_pre_mpc_time) + " " + str(total_mpt_time) + " " + str(total_time) + "\n")

        # saving statistics
        print str(self.statistics)'''

        logger.debug("joining RS1 and worker receiver threads ")
        self.receive_mappings_from_rs1_th.join()
        logger.debug("joined RS1 ")
        self.receive_from_workers_th.join()
        logger.debug("joined workers ")
        for p in self.processes:
            p.join()



    def receive_from_workers(self):
        waiting =0
        stop_counter=0
        while True:
            try:
                msg = self.worker_2_handler_queue.get(True, 1)

                logger.debug("received message from worker")
                #logger.debug("received message from worker: " + str(msg))

                if "stop" in msg:
                    logger.debug("received STOP message from worker")
                    stop_counter+=1
                    if stop_counter == self.number_of_processes:
                        logger.debug("sending STOP message to member")
                        self.server_send_mpc_output.sender_queue.put(pickle.dumps(msg))
                        break
                    continue


                if msg["type"] == "to-hosts":
                    logger.debug("sending TO-HOSTS message from worker")
                    self.statistics_handler.record_end_of_bgp_update_processing(msg["announcement_id"])
                    self.server_send_mpc_output.sender_queue.put(pickle.dumps(msg))


            except Empty:
                if waiting == 0:
                    #logger.debug("Waiting for BGP update...")
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass
                        #logger.debug("Waiting for BGP update...")

        f=open('statistics-prio-rs2-handler.txt','w')
        f.write("route_id initial end difference\n")
        for bgp_update_id in self.statistics_handler.observations.keys():
            start_processing_time= self.statistics_handler.observations[bgp_update_id]["start-processing-time"]
            end_processing_time= self.statistics_handler.observations[bgp_update_id]["end-processing-time"]
            f.write(str(bgp_update_id) + " " + str("{0:.9f}".format(start_processing_time))+" " + str("{0:.9f}".format(end_processing_time))+" " + str("{0:.9f}".format(end_processing_time-start_processing_time))+ "\n")




    def stop(self):
        logger.info("Stopping.")
        self.run = False


def main():
    parser = argparse.ArgumentParser()
    # locate config file

    parser.add_argument("-p","--processes", help="number of parallel SMPC processes", type=int, default=1)
    args = parser.parse_args()


    # start route server
    # sdx_rs = route_server(config_file)
    pprs = AllHandlerRs2(args.processes)
    rs_thread = Thread(target=pprs.start)
    rs_thread.setName("AllHandler2")
    rs_thread.daemon = True
    rs_thread.start()

    while rs_thread.is_alive():
        try:
            rs_thread.join(1)
            #logger.debug("join cycle")
        except KeyboardInterrupt:
            pprs.stop()

    logger.info("waiting before dying")
    logger.info("thread count: " + str(threading.active_count()))

    for thread in threading.enumerate():
        print thread.name + " " + str(thread.is_alive())
    for p in pprs.processes:
        print p.is_alive()

    sleep(5)

if __name__ == '__main__':
    main()
