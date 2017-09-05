#!/usr/bin/env python
#  Author:
#  Muhammad Shahbaz (muhammad.shahbaz@gatech.edu)
#  Rudiger Birkner (Networked Systems Group ETH Zurich)
#  Arpit Gupta (Princeton)


import argparse
from collections import namedtuple
import json
from multiprocessing.connection import Listener, Client
import os
import Queue
import sys
from threading import Thread, Lock
import time
import socket
import struct

np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if np not in sys.path:
    sys.path.append(np)
import util.log

from server import server as Server


logger = util.log.getLogger('XRS')

Config = namedtuple('Config', 'ah_socket')

bgpListener = None
config = None

participantsLock = Lock()
participants = dict()
portip2participant = dict()

clientPoolLock = Lock()
clientActivePool = dict()
clientDeadPool = set()

count_lock = Lock()

def create_sig():
    with open('sig', 'w+') as f:
        pass

class PctrlClient(object):
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr

        self.run = True
        self.id = None
        self.peers_in = []
        self.peers_out = []

    def start(self):
        logger.info('BGP PctrlClient started for client ip %s.', self.addr)
        msg_buff = ''
        while self.run:
            try:
                rv = self.conn.recv(4096)
            except EOFError as ee:
                break

            if not rv:
                break

            logger.debug('PctrlClient: Trace: Got rv, original route: %s', rv)
            msg_buff += rv
            offset = 0
            buff_len = len(msg_buff)
            while buff_len - offset >= 2:
                msg_len = ord(msg_buff[offset]) | ord(msg_buff[offset + 1]) << 8
                if buff_len - offset < msg_len:
                    break
                data = msg_buff[offset + 2: offset + msg_len]
                if data == 'stop':
                    with count_lock:
                        bgpListener.stop_counts += 1
                        logger.info("stop_counts:%d" % bgpListener.stop_counts)
                    if bgpListener.stop_counts == bgpListener.as_num:
                        logger.info("last stop signal received, exiting...")
                        with open('result', 'w+') as f:
                            f.write('route_count:%d start_time:%0.6f end_time:%0.6f' % (bgpListener.route_id + 1, bgpListener.start_time, bgpListener.end_time))
                        bgpListener.run = False
                    self.run = False
                    break
                else:
                    data = json.loads(data)
                    self.process_message(**data)
                offset += msg_len
            msg_buff = msg_buff[offset:]

        self.conn.close()

        # remove self
        with clientPoolLock:
            logger.debug('Trace: PctrlClient.start: clientActivePool before: %s', clientActivePool)
            logger.debug('Trace: PctrlClient.start: clientDeadPool before: %s', clientDeadPool)
            t = clientActivePool[self]
            del clientActivePool[self]
            clientDeadPool.add(t)
            logger.debug('Trace: PctrlClient.start: clientActivePool after: %s', clientActivePool)
            logger.debug('Trace: PctrlClient.start: clientDeadPool after: %s', clientDeadPool)

        with participantsLock:
            logger.debug('Trace: PctrlClient.start: portip2participant before: %s', portip2participant)
            logger.debug('Trace: PctrlClient.start: participants before: %s', participants)
            found = [k for k,v in portip2participant.items() if v == self.id]
            for k in found:
                del portip2participant[k]

            found = [k for k,v in participants.items() if v == self]
            for k in found:
                del participants[k]
            logger.debug('Trace: PctrlClient.start: portip2participant after: %s', portip2participant)
            logger.debug('Trace: PctrlClient.start: participants after: %s', participants)


    def process_message(self, msgType=None, **data):
        if msgType == 'hello':
            rv = self.process_hello_message(**data)
        elif msgType == 'bgp':
            rv = self.process_bgp_message(**data)
        else:
            logger.warn("Unrecognized or absent msgType: %s. Message ignored.", msgType)
            rv = True

        return rv


    def process_hello_message(self, id=None, peers_in=None, peers_out=None, ports=None, **data):
        if not (id is not None and isinstance(ports, list) and
                isinstance(peers_in, list) and isinstance(peers_out, list)):
            logger.warn("hello message from %s is missing something: id: %s, ports: %s, peers_in: %s, peers_out: %s. Closing connection.", self.addr, id, ports, peers_in, peers_out)
            return False

        self.id = id = int(id)
        self.peers_in = set(peers_in)
        self.peers_out = set(peers_out)

        with participantsLock:
            logger.debug('Trace: PctrlClient.hello: portip2participant before: %s', portip2participant)
            logger.debug('Trace: PctrlClient.hello: participants before: %s', participants)
            for port in ports:
                portip2participant[port] = id
            participants[id] = self
            logger.debug('Trace: PctrlClient.hello: portip2participant after: %s', portip2participant)
            logger.debug('Trace: PctrlClient.hello: participants after: %s', participants)

        create_sig()

        return True


    def process_bgp_message(self, announcement = None, **data):
        if announcement:
            bgpListener.send(announcement)
        return True


    def send(self, route):
        logger.debug('Sending a route update to participant %d', self.id)
        if route:
            msg = json.dumps({'bgp': route, 'route_id': route['route_id']})
        else:
            msg = 'stop'
        self.conn.send(struct.pack('H', len(msg) + 2) + msg)


class PctrlListener(object):
    def __init__(self):
        logger.info("Initializing the BGP PctrlListener")
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(config.ah_socket)
        self.listener.listen(128)
        self.run = True


    def start(self):
        logger.info("Starting the BGP PctrlListener")

        while self.run:
            try:
                self.listener.settimeout(1)
                (conn, addr) = self.listener.accept()

                pc = PctrlClient(conn, addr)
                t = Thread(target=pc.start)

                with clientPoolLock:
                    logger.debug('Trace: PctrlListener.start: clientActivePool before: %s', clientActivePool)
                    logger.debug('Trace: PctrlListener.start: clientDeadPool before: %s', clientDeadPool)
                    clientActivePool[pc] = t

                    # while here, join dead threads.
                    while clientDeadPool:
                        clientDeadPool.pop().join()
                    logger.debug('Trace: PctrlListener.start: clientActivePool after: %s', clientActivePool)
                    logger.debug('Trace: PctrlListener.start: clientDeadPool after: %s', clientDeadPool)

                t.start()
            except socket.timeout:
                pass
        logger.info("listener socket close")
        self.listener.close()


    def stop(self):
        logger.info("Stopping PctrlListener.")
        self.run = False


class BGPListener(object):
    def __init__(self, as_num):
        logger.info('Initializing the BGPListener')

        # Initialize XRS Server
        self.server = Server(logger)
        self.run = True
        self.route_id = 0
        self.start_time = 0
        self.end_time = 0
        self.as_num = int(as_num)
        self.stop_counts = 0

    def start(self):
        logger.info("Starting the Server to handle incoming BGP Updates.")
        self.server.start()

        waiting = 0
        while self.run:
            # get BGP messages from ExaBGP via stdin in client.py,
            # which is routed to server.py via port 6000,
            # which is routed to here via receiver_queue.
            try:
                route = self.server.receiver_queue.get(True, 1)
            except Queue.Empty:
                if waiting == 0:
                    logger.debug("Waiting for BGP update...")
                waiting = (waiting+1) % 30
                continue

            if self.start_time == 0:
                self.start_time = time.time()

            waiting = 0
            logger.debug("\n BGPListener: Got original route from ExaBGP: %s\n", route)
            route = json.loads(route)

            if 'stop' in route:
                logger.info("BGPListener: stop signal received from ExaBGP")
                peers = participants.values()
                for peer in peers:
                    peer.send([])
                continue
            self.route_id = route["route_id"]

            # Received BGP route advertisement from ExaBGP
            try:
                advertise_ip = route['neighbor']['ip']
            except KeyError:
                continue

            found = []
            with participantsLock:
                try:
                    advertise_id = portip2participant[advertise_ip]
                    peers_out = participants[advertise_id].peers_out
                except KeyError:
                    continue

                for id, peer in participants.iteritems():
                    # Apply the filtering logic
                    if id in peers_out and advertise_id in peer.peers_in:
                        found.append(peer)

            for peer in found:
                # Now send this route to participant `id`'s controller'
                peer.send(route)

            self.end_time = time.time()
        self.server.stop()


    def send(self, announcement):
        self.end_time = time.time()
        #self.server.sender_queue.put(announcement)


    def stop(self):
        logger.info("Stopping BGPListener.")
        self.run = False


def parse_config(config_file):
    "Parse the config file"

    # loading config file
    logger.debug("Begin parsing config...")

    with open(config_file, 'r') as f:
        config = json.load(f)

    ah_socket = tuple(config["Route Server"]["AH_SOCKET"])

    logger.debug("Done parsing config")
    return Config(ah_socket)


def main():
    global bgpListener, pctrlListener, config

    parser = argparse.ArgumentParser()
    parser.add_argument('as_num', help='the as number')
    parser.add_argument('dir', help='the directory of the example')
    args = parser.parse_args()

    # locate config file
    config_file = "../examples/" + args.dir + "sdx_global.cfg"

    logger.info("Reading config file %s", config_file)
    config = parse_config(config_file)

    bgpListener = BGPListener(args.as_num)
    bp_thread = Thread(target=bgpListener.start)
    bp_thread.start()

    pctrlListener = PctrlListener()
    pp_thread = Thread(target=pctrlListener.start)
    pp_thread.start()

    create_sig()

    while bp_thread.is_alive():
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            bgpListener.stop()

    bp_thread.join()
    pctrlListener.stop()
    pp_thread.join()
    logger.info("route server exits.")


if __name__ == '__main__':
    main()
