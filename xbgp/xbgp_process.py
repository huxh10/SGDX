import util.log
from Queue import Empty
import pickle
import time

logger = util.log.getLogger('xbgp-process')


class XBGPProcess():

    def __init__(self,handler_to_worker_queue,worker_to_handler_queue,workers_pool,conn1,conn2):
        # get port
        self.conn1=conn1
        self.conn2=conn2
        self.handler_to_worker_queue = handler_to_worker_queue
        self.worker_to_handler_queue = worker_to_handler_queue
        self.id = workers_pool.get()


   # process a BGP route
    def process_update(self):

        print str(self.id) + " is ready"
        while True:

            try:
                #logger.info("waiting for handler message")
                route = self.handler_to_worker_queue.get(True, 1)
            except Empty:
                continue

            if "stop" in route:
                time.sleep(1)
                print "sending STOP " + str(self.id)
                self.worker_to_handler_queue.put(route)
                break

            x=1000
            counter=0
            '''
            for x in range(0,x):
                route["announcement_id"]=counter+(self.id*10000)
                counter+=1
                route["prefix"]=route["announcement_id"]
                logger.info("sending route " + str(route["announcement_id"])  + "worker id:"  + str(self.id)  )
                self.send_update_rs1(route)

                self.send_update_rs2(route)
            '''
            logger.debug("sending route id: " + str(route["announcement_id"])  + "worker id:"  + str(self.id)  )
            self.send_update_rs1(route)

            self.send_update_rs2(route)

    def send_update_rs1(self, update):
        self.conn1.send(pickle.dumps(update))

    def send_update_rs2(self, update):
        self.conn2.send(pickle.dumps(update))

def send_main(handler_to_worker_queue,worker_to_handler_queue,workers_pool,conn1,conn2):
    process = XBGPProcess(handler_to_worker_queue,worker_to_handler_queue,workers_pool,conn1,conn2)
    process.process_update()
