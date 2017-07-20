#!/usr/bin/env python
#  Author:
#  Muhammad Shahbaz (muhammad.shahbaz@gatech.edu)

from multiprocessing import Queue
from multiprocessing.connection import Client
from threading import Thread

''' bgp server '''
class client(object):

    def __init__(self, logger, endpoint=('localhost', 6000), authkey=None):
        self.logger = logger

        self.conn = Client(endpoint, authkey=authkey)

        self.sender_queue = Queue()
        self.receiver_queue = Queue()

    def start(self):
        self.sender = Thread(target=_sender, args=(self.conn,self.sender_queue))
        self.sender.start()

        self.receiver = Thread(target=_receiver, args=(self.conn,self.receiver_queue))
        self.receiver.start()

''' sender '''
def _sender(conn,queue):
    while True:
        try:
            line = queue.get()
            conn.send(line)
        except:
            break

''' receiver '''
def _receiver(conn,queue):
    while True:
        try:
            line = conn.recv()
            queue.put(line)
        except EOFError:
            break
        except:
            pass

''' main '''
if __name__ == '__main__':
    while True:
        server = server()
        while True:
            try:
                print server.receiver_queue.get()
                server.sender_queue.put('announce route %s next-hop %s as-path [ %s ]' % ('200.0.0.0/16','172.0.0.1','100'))
            except:
                print 'thread ended'
                break
