'''
receives BGP messages and assign them to the set of SMPC workers
'''


import argparse
from multiprocessing.connection import Listener
import os
import Queue
from threading import Thread
import sys
np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if np not in sys.path:
    sys.path.append(np)
import json
import util.log
from server_pprs import server as Server
import random
import os
import pickle
import subprocess
from time import sleep
import time
import multiprocessing as mp
from multiprocessing import Process, Manager
import prio_worker_rs2
from load_ribs import load_ribs
from Queue import Empty
import threading
import port_config

logger = util.log.getLogger('prio-handler-rs2')
RS2_MODE = 2

class PrioHandlerRs2(object):
    def __init__(self, asn_2_id_file, rib_file, number_of_processes):
        logger.info("Initializing the All Handler for RS2.")

        self.number_of_processes = number_of_processes
        with open(asn_2_id_file, 'r') as f:
            self.asn_2_id = json.load(f)

        self.prefix_2_nh_id_2_route_id = load_ribs(rib_file, self.asn_2_id, RS2_MODE) if rib_file else {}

        # Initialize a XRS Server
        self.server_receive_bgp_messages = Server(logger, endpoint=(port_config.process_assignement["rs2"], port_config.ports_assignment["rs2_receive_bgp_messages"]))
        # NOTE: fake sending, only for performance test
        #self.server_send_mpc_output = Server(logger, endpoint=(port_config.process_assignement["rs2"], port_config.ports_assignment["rs2_send_mpc_output"]))
        self.server_rs1 = Server(logger, endpoint=(port_config.process_assignement["rs2"],  port_config.ports_assignment["rs1_rs2"]))
        self.run = True

        # start the MPC process in background
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
        waiting = 0
        logger.info("connecting to RS1")
        self.server_rs1.start()
        logger.info("connected to RS1 for receiving mapping messages")
        while self.run:
            # get BGP messages from ExaBGP
            try:
                msg = self.server_rs1.receiver_queue.get(True, 1)
                msg = pickle.loads(msg)
                waiting = 0

                # Received BGP bgp_update advertisement from ExaBGP
                if "stop" in msg:
                    self.port2stop_lock.acquire()
                    logger.info("received stop message")
                    port = msg["port"]
                    while not self.handler_2_worker_queues[port].empty():
                        sleep(1)
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
                    logger.info("received initialization message from rs1")
                    pass

                if "announcement_id" in msg:
                    announcement_id = msg["announcement_id"]
                    self.lock.acquire()
                    self.id_2_port[announcement_id] = msg["worker_port"]
                    if announcement_id in self.id_2_msg:
                        #send message to the correct worker
                        if self.id_2_msg[announcement_id]["prefix"] not in self.prefix_2_nh_id_2_route_id.keys():
                            self.prefix_2_nh_id_2_route_id[self.id_2_msg[announcement_id]["prefix"]]={}
                        as_id = self.asn_2_id[self.id_2_msg[announcement_id]["asn"]]
                        self.prefix_2_nh_id_2_route_id[self.id_2_msg[announcement_id]["prefix"]][as_id] = announcement_id
                        self.handler_2_worker_queues[self.id_2_port[announcement_id]].put({"announcement_id" : msg["announcement_id"], "as_id" : as_id, "messages" : self.prefix_2_nh_id_2_route_id[self.id_2_msg[announcement_id]["prefix"]]})
                        del self.id_2_port[announcement_id]
                        del self.id_2_msg[announcement_id]

                    self.lock.release()

            except Empty:
                if waiting == 0:
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass

        logger.debug("closing reception from RS1")


    def start(self):
        logger.info("Starting the Server to handle incoming BGP Updates from ExaBGP. Listening on port 6002")
        self.server_receive_bgp_messages.start()
        logger.info("Connected to ExaBGP via port 6002")
        # NOTE: fake sending, only for performance test
        #self.server_send_mpc_output.start()
        #logger.info("RS2 connected to Host Receiver Mock ")

        while self.run:
            # get BGP messages from ExaBGP
            waiting = 0
            try:
                msg = self.server_receive_bgp_messages.receiver_queue.get(True, 1)
                msg = pickle.loads(msg)
                waiting = 0

                # Received BGP bgp_update advertisement from ExaBGP
                if "stop" in msg:
                    close_msg = {"stop" : 1}
                    logger.info("Shutting down exa receiver.")
                    self.port2stop_lock.acquire()
                    logger.info("received stop message")

                    exit_flag = 0
                    while not exit_flag:
                        exit_flag = 1
                        for port in self.port2stop.keys():
                            if not self.handler_2_worker_queues[port].empty():
                                exit_flag = 0
                        sleep(1)
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
                    announcement_id = msg["announcement_id"]
                    self.lock.acquire()
                    self.id_2_msg[announcement_id] = msg
                    if announcement_id in self.id_2_port:
                        #send message to the correct worker
                        if msg["prefix"] not in self.prefix_2_nh_id_2_route_id.keys():
                            self.prefix_2_nh_id_2_route_id[msg["prefix"]]={}
                        as_id = self.asn_2_id[msg["asn"]]
                        self.prefix_2_nh_id_2_route_id[msg["prefix"]][as_id] = announcement_id
                        self.handler_2_worker_queues[self.id_2_port[announcement_id]].put({"announcement_id" : announcement_id, "as_id": as_id, "messages" : self.prefix_2_nh_id_2_route_id[msg["prefix"]]})
                        del self.id_2_port[announcement_id]
                        del self.id_2_msg[announcement_id]
                    self.lock.release()

            except Queue.Empty:
                if waiting == 0:
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass

        logger.debug("Closing reception from hosts")
        logger.debug("joining RS1 and worker receiver threads ")
        self.receive_mappings_from_rs1_th.join()
        logger.debug("joined RS1 ")
        self.receive_from_workers_th.join()
        logger.debug("joined workers ")
        for p in self.processes:
            p.join()

    def receive_from_workers(self):
        waiting = 0
        stop_counter = 0
        while True:
            try:
                msg = self.worker_2_handler_queue.get(True, 1)

                if "stop" in msg:
                    logger.debug("received STOP message from worker")
                    stop_counter += 1
                    if stop_counter == self.number_of_processes:
                        logger.debug("sending STOP message to member")
                        # NOTE: fake sending, only for performance test
                        #self.server_send_mpc_output.sender_queue.put(pickle.dumps(msg))
                        break
                    continue

                if msg["type"] == "to-hosts":
                    pass
                    # NOTE: fake sending, only for performance test
                    #self.server_send_mpc_output.sender_queue.put(pickle.dumps(msg))

            except Empty:
                if waiting == 0:
                    waiting = 1
                else:
                    waiting = (waiting % 30) + 1
                    if waiting == 30:
                        pass

    def stop(self):
        logger.info("Stopping.")
        self.run = False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("asn_2_id_file", type=str, help="specify asn_2_id json file")
    parser.add_argument('-r', '--rib_file', type=str, help='specify the rib file, eg.g. ../examples/test-rs/ribs/bview')
    parser.add_argument("-p","--processes", help="number of parallel SMPC processes", type=int, default=1)
    args = parser.parse_args()

    pprs = PrioHandlerRs2(args.asn_2_id_file, args.rib_file, args.processes)
    rs_thread = Thread(target=pprs.start)
    rs_thread.setName("PrioHandler2")
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
