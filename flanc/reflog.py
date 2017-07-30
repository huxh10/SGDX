#!/usr/bin/env python
#  Author:
#  Muhammad Shahbaz (muhammad.shahbaz@gatech.edu)
#  Rudiger Birkner (Networked Systems Group ETH Zurich)

import json
import argparse
from reflog_server import server as Server
from time import time
from threading import Thread
from multiprocessing import Queue
from multiprocessing.connection import Listener, Client
import Queue

''' Reference Monitor that just store all received Flow Mods in a file'''
class RefLog():

    def __init__(self, address, port, key, logfile):
        #self.listener = Listener((address, int(port)))
        self.log = open(logfile, "w")

        self.address = address
        self.port = int(port)
        self.key = key
	self.server = Server(tuple([self.address, self.port]), None)

    def start(self):
        self.receive = True
	self.server.start()
        self.receiver()

    ''' receiver '''
    def receiver(self):
        while self.receive:
            #conn = self.listener.accept()
		try:
			msg = self.server.receiver_queue.get(True, 1)
			if msg != "terminate":
				msg = json.loads(msg)
				#print "Message received:: ", msg
				self.log.write('BURST: ' + str(time()) + '\n')
				self.log.write('PARTICIPANT: ' + str(msg['auth_info']['participant']) + '\n')
				for flow_mod in msg["flow_mods"]:
				    self.log.write(json.dumps(flow_mod) + '\n')
				self.log.write('\n')
		except Queue.Empty:
		    #print "Could not process"
		    pass
		    #conn.close()

    def stop(self):
        self.receive = False

        tmp_conn = Client((self.address, self.port))
        tmp_conn.send("terminate")
        tmp_conn.close()

        self.log.close()


def main(argv):
    reflog_instance = RefLog(args.ip, args.port, args.key, args.logfile)

    rl_thread = Thread(target=reflog_instance.start)
    rl_thread.daemon = True
    rl_thread.start()

    while rl_thread.is_alive():
        try:
            rl_thread.join(1)
        except KeyboardInterrupt:
            reflog_instance.stop()


''' main '''
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('ip', help='ip address of the refmon')
    parser.add_argument('port', help='port of the refmon')
    parser.add_argument('key', help='authkey of the refmon')
    parser.add_argument('logfile', help='log file')
    args = parser.parse_args()

    main(args)
