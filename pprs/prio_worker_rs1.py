
import pickle
import json
import time
import util.log
from Queue import Empty
import subprocess


logger = util.log.getLogger('worker-prio-rs1')

ABY_EXEC_PATH="../aby/bin/ixp.exe"

DUMMY_KEY="00000000000000000000000000000000ffff"

KEY_LENGTH = 16             # bytes

AS_ROW_ENCODING_SIZE = 32   # bits

KEY_ID_SIZE = 16            # bits

PARALLELIZATION_FACTOR = 1

RS1=0

FIRST_PORT=7760

FILTER_SHARE = 'filter_share1.json'

RESULT_FILE = 'result_1_'

GEN_SIG_FILE = 'sig_1'


class PrioWorker1():
    def __init__(self, handler_to_worker_queue, worker_to_handler_queue, workers_pool):
        # get port
        self.port = workers_pool.get()
        worker_to_handler_queue.put({"type" : "to-rs2-init", "worker_port" : self.port})
        self.worker_to_handler_queue = worker_to_handler_queue
        self.workers_pool = workers_pool
        self.handler_to_worker_queue = handler_to_worker_queue

        logger.debug("launching ixp.exe on port " + str(self.port))
        logger.info("taskset -c " + str(self.port-FIRST_PORT) + " " +ABY_EXEC_PATH +' -r 0 -a 0.0.0.0 -o 1 -f 3 -p ' + str(self.port))
        args = ("taskset -c " + str(self.port-FIRST_PORT) + " " + ABY_EXEC_PATH +' -r 0 -a 0.0.0.0 -o 1 -f 3 -p ' + str(self.port))
        self.p = subprocess.Popen(args.split(" "),stdout=subprocess.PIPE,stdin=subprocess.PIPE, bufsize=8096)
        self.p.stdout.readline()
        self.load_policy()
        self.send_export_policy_to_mpc()
        self.result_file = open(RESULT_FILE + str(self.port), 'w+')
        self.send_start_sig_2_gen()
        logger.debug("process launched")

    def send_start_sig_2_gen(self):
        with open(GEN_SIG_FILE, 'w+') as f:
            pass

    def load_policy(self):
        # filter
        with open(FILTER_SHARE, 'r') as f:
            self.export_policies = json.load(f)
        self.number_of_participants = len(self.export_policies)

    def send_export_policy_to_mpc(self):
        export_rows_strings = [ "" for i in xrange(0, self.number_of_participants)]
        for i in xrange(0, self.number_of_participants):
            for j in xrange(0, self.number_of_participants):
                v = 2 if self.export_policies[i][j] else 0
                export_rows_strings[i] += '{num:0{width}x}'.format(num=v, width=AS_ROW_ENCODING_SIZE/4)

        myinput = "5" + "\n" + str(self.number_of_participants)
        # invoking the MPC
        print >> self.p.stdin, myinput # write input
        self.p.stdin.flush() # not necessary in this case
        for i in xrange(0, self.number_of_participants):
            print >> self.p.stdin, export_rows_strings[i]
            self.p.stdin.flush() # not necessary in this case
        logger.debug("export policies sent to smpc")

    def process_update(self):
        print str(self.port) + " is ready"
        while True:
            try:
                msg = self.handler_to_worker_queue.get(True, 1)
            except Empty:
                continue

            if "stop" in msg[1]:
                logger.info("stop received")
                print "stop received" + str(self.port)
                break

            start_time = time.time()
            msg = msg[1]
            list_of_msg_for_prefix = msg["messages"] # remove the route_id used to prioritize the announcements in the queue

            self.worker_to_handler_queue.put({"type" : "to-rs2", "announcement_id" : msg["announcement_id"], "worker_port" : self.port})

            # RUNNING THE MPC
            number_of_routes = len(list_of_msg_for_prefix) + 1

            # (key + id) for each route in this prefix list
            keys_str = DUMMY_KEY    # add DUMMY_KEY for default zero choice
            i = 1
            list_of_route_ids = []  # helpful for the member-receiving-mock
            for nh_id in list_of_msg_for_prefix.keys():
                list_of_route_ids.append(list_of_msg_for_prefix[nh_id]["announcement_id"])
                keys_str += list_of_msg_for_prefix[nh_id]["key"]
                keys_str += '{num:0{width}x}'.format(num = i, width = KEY_ID_SIZE / 4)
                i += 1

            assert len(list_of_route_ids) is 1
            myinput = "3" + "\n" + str(number_of_routes) + "\n" + str(msg["as_id"]) + "\n" + keys_str + "\n" + "0"

            # invoking the MPC
            print >> self.p.stdin, myinput # write input
            self.p.stdin.flush() # not necessary in this case
            self.p.stdout.readline()
            str_host = ""
            for i in xrange(0, self.number_of_participants):
                line = self.p.stdout.readline().rstrip()
                str_host += line

            end_time = time.time()
            self.result_file.write("Performance test: announcement_id:%d start_time:%.6f end_time:%.6f\n" % (msg["announcement_id"], start_time, end_time))
            self.result_file.flush()
            self.worker_to_handler_queue.put({"type" : "to-hosts",  "announcement_id" : msg["announcement_id"], "encrypted_route" : msg["encrypted_route"], "key" : str_host, "prefix" : msg["prefix"], "list_of_route_ids" : list_of_route_ids})

        #close the process
        myinput = "6\n"
        print >> self.p.stdin, myinput # write input
        self.p.stdin.flush() # not necessary in this case

        self.result_file.close()
        self.worker_to_handler_queue.put({"stop" : None , "port" : self.port})
        print "stop sent to handler" + str(self.port)


def prio_worker_main(handler_to_worker_queue, workers_to_rs2_queue, workers_pool):
    worker = PrioWorker1(handler_to_worker_queue, workers_to_rs2_queue, workers_pool)
    worker.process_update()
