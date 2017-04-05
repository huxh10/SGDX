#!/usr/bin/env python
#  Author:
#  Muhammad Shahbaz (muhammad.shahbaz@gatech.edu)
#  Arpit Gupta

#from multiprocessing.connection import Client
import os
import sys
import socket
import struct
import json
from threading import Thread

np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if np not in sys.path:
    sys.path.append(np)
import util.log


sendLogger = util.log.getLogger('XRS-send')
recvLogger = util.log.getLogger('XRS-recv')

'''Write output to stdout'''
def _write(stdout,data):
    stdout.write(data + '\n')
    stdout.flush()

''' Sender function '''
def _sender(conn,stdin):
    # Warning: when the parent dies we are seeing continual
    # newlines, so we only access so many before stopping
    counter = 0

    while True:
        try:
            line = stdin.readline().strip()

            if line == "":
                counter += 1
                if counter > 100:
                    break
                continue
            counter = 0

            #if 'message' in msg['neighbor'] and 'update' in msg['neighbor']['message'] and 'announce' in msg['neighbor']['message']['update'] and 'ipv4 unicast' in msg['neighbor']['message']['update']['announce']:
            #    sendLogger.debug('find ipv4 unicast' + str(msg['neighbor']['message']['update']['announce']['ipv4 unicast']))

            conn.send(struct.pack("H", len(line) + 2) + line)

            sendLogger.debug(line)

        except:
            pass

''' Receiver function '''
def _receiver(conn,stdout):
    msg_buff = ''
    while True:
        try:
            line = conn.recv(4096)

            if not line:
                conn.close()
                recvLogger.info("connection to BGP Relay closed\n")
                exit(0)

            if line == "":
                continue
            recvLogger.debug("Client receive " + str(len(line)) + " bytes: " + line)
            msg_buff += line
            offset = 0
            buff_len = len(msg_buff)
            while buff_len - offset >= 2:
                msg_len = ord(msg_buff[offset]) | ord(msg_buff[offset + 1]) << 8
                recvLogger.debug("Client process msg_len: " + str(msg_len))
                if buff_len - offset < msg_len:
                    break

                _write(stdout, msg_buff[offset + 2: offset + msg_len])
                ''' example: announce route 1.2.3.4 next-hop 5.6.7.8 as-path [ 100 200 ] '''
                recvLogger.debug(msg_buff[offset + 2: offset + msg_len])
                offset += msg_len
            msg_buff = msg_buff[offset:]

        except:
            pass

''' main '''
if __name__ == '__main__':

    #conn = Client(('localhost', 6000), authkey='xrs')
    #conn = Client(('localhost', 6000))
    # TODO refine connection management
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(('localhost', 6000))

    sender = Thread(target=_sender, args=(conn,sys.stdin))
    sender.start()

    receiver = Thread(target=_receiver, args=(conn,sys.stdout))
    receiver.start()

    sender.join()
    receiver.join()
