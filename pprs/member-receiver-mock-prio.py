__author__ = 'marco'

import argparse
import pickle
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
#from Crypto.Cipher import AES
import subprocess
from util.crypto_util import AESCipher
import multiprocessing as mp
import port_config


logger = util.log.getLogger('Mock-Host')

KEY_LENGTH = 16             # bytes
KEY_ID_SIZE = 16            # bits
KEY_HEX_LENGTH = 32         # number of hex of key, KEY_LENGTH * 2
KEY_AND_ID_HEX_LENGTH = 36  # number of hex of key and id, KEY_LENGTH * 2 + KEY_ID_SIZE / 4

DUMMY_KEY="00000000000000000000000000000000"

RS1_MODE =1
RS2_MODE =2


class Host:
    def __init__(self):
        logger.info("Initializing the Host.")

        with open(asn_2_id_file, 'r') as f:
            self.asn_2_id = json.load(f)
        self.id_2_asn = [ '' for i in xrange(0, len(self.asn_2_id))]
        for asn, as_id in self.asn_2_id.items():
            self.id_2_asn[as_id] = asn

        # connect to XRS Server
        self.conn_to_rs1 = Client((port_config.process_assignement["rs1"], port_config.ports_assignment["rs1_send_mpc_output"]), authkey=None)
        self.conn_to_rs2 = Client((port_config.process_assignement["rs2"], port_config.ports_assignment["rs2_send_mpc_output"]), authkey=None)
        self.run = True

        self.stop_received_from_one_rs=False
        self.route_id_to_msges = {}

    def start(self):
        self.lock = mp.Manager().Lock()
        self.receive_messages_th = Thread(target=self.receive_messages,args=[RS2_MODE])
        self.receive_messages_th.setName( "receiver from rs2")
        self.receive_messages_th.daemon = True
        self.receive_messages_th.start()

        self.receive_messages(RS1_MODE)

        logger.debug("waiting for RS1_MODE thread")
        self.receive_messages_th.join()
        logger.debug("ending")

    def receive_messages(self,mode):
        conn=None
        if mode == RS1_MODE:
            conn = self.conn_to_rs1
        else:
            conn = self.conn_to_rs2
        waiting = 0

        # start the MPC process in background
        i=0
        while self.run:
            # get messages
            #try:
            #if mode == RS1_MODE:
            #    print "waiting for message from RS1"
            #else:
            #    print "waiting for message from RS2"
            msg = conn.recv()
            msg = pickle.loads(msg)
            #if mode == RS1_MODE:
            #    print "Got message from RS1. " + str("stop" in msg)
            #else:
            #    print "Got message from RS2. " + str("stop" in msg)
            #except:
            #    pass

            waiting = 0

            if "stop" in msg:
                logger.info("received stop message "  + str(mode))
                break
            else:
                self.lock.acquire()
                logger.debug("received message for announcement_id " + str(msg["announcement_id"]))
                if mode == RS1_MODE:
                    if msg["announcement_id"] not in self.route_id_to_msges:
                        self.route_id_to_msges[msg["announcement_id"]] = {}
                    self.route_id_to_msges[msg["announcement_id"]]["rs1"] = msg["key"]
                    self.route_id_to_msges[msg["announcement_id"]]["encrypted_route"] = msg["encrypted_route"]
                    self.route_id_to_msges[msg["announcement_id"]]["list_of_route_ids"] = msg["list_of_route_ids"]
                else:
                    if msg["announcement_id"] not in self.route_id_to_msges:
                        self.route_id_to_msges[msg["announcement_id"]]={}
                    self.route_id_to_msges[msg["announcement_id"]]["rs2"] = msg["key"]
                if "rs1" in self.route_id_to_msges[msg["announcement_id"]] and \
                   "rs2" in self.route_id_to_msges[msg["announcement_id"]]:
                    self.reconstruct_message(msg["announcement_id"])
                    pass
                self.lock.release()

        print "exiting receive message " + str(mode)

    def reconstruct_message(self, announcement_id):
        encrypted_route = self.route_id_to_msges[announcement_id]["encrypted_route"]
        keys_from_rs1 = self.route_id_to_msges[announcement_id]["rs1"].decode("hex")
        keys_from_rs2 = self.route_id_to_msges[announcement_id]["rs2"].decode("hex")
        key = xor_strings(keys_from_rs1, keys_from_rs2).encode("hex")
        list_of_route_ids = self.route_id_to_msges[announcement_id]["list_of_route_ids"]
        #print "key1: " + self.route_id_to_msges[route_id]["rs1"]
        #print "key2: " + self.route_id_to_msges[route_id]["rs2"]
        logger.debug("key: " + key)
        keys = []
        ids = []
        for i in range(0, len(key) / KEY_AND_ID_HEX_LENGTH):
            keys.append(key[i * KEY_AND_ID_HEX_LENGTH: i * KEY_AND_ID_HEX_LENGTH + KEY_HEX_LENGTH])
            ids.append(key[i * KEY_AND_ID_HEX_LENGTH + KEY_HEX_LENGTH: i * KEY_AND_ID_HEX_LENGTH + KEY_AND_ID_HEX_LENGTH])
            logger.info("key received for route_id: " + ids[i])
                 #print "getting encrypted key:" + key
            if keys[i] == DUMMY_KEY:
                logger.info("BGP-speaker " + self.id_2_asn[i] + " received dummy key for announcement " + str(announcement_id))
                pass
            else:
                logger.debug("ready to decrypt with key " + str(keys[i]))
                cipher = AESCipher(keys[i].decode("hex"))
                route_id = list_of_route_ids[int(ids[i], 16)-1];
                encrypted_route =self.route_id_to_msges[route_id]["encrypted_route"]
                decrypted_object = cipher.decrypt(encrypted_route)
                decrypted_route = pickle.loads(decrypted_object) # decrypt serialized route object
                logger.info("decrypted route: " + str(decrypted_route)))
                logger.info("BGP-speaker " + self.id_2_asn[i] + " decrypted route: " + str(decrypted_route.id) + " for announcement " + str(announcement_id))

    def stop(self):
        logger.info("Stopping.")
        self.run = False

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("asn_2_id_file", type=str, help="specify asn_2_id json file")
    args = parser.parse_args()

    pprs = Host(args.asn_2_id_file)
    rs_thread = Thread(target=pprs.start)
    rs_thread.daemon = True
    rs_thread.start()

    while rs_thread.is_alive():
        try:
            rs_thread.join(1)
        except KeyboardInterrupt:
            pprs.stop()

if __name__ == '__main__':
    main()
