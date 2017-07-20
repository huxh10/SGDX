
import pickle
import json
import util.log
from Queue import Empty
import subprocess


logger = util.log.getLogger('worker-prio-rs2')

ABY_EXEC_PATH="../aby/bin/ixp.exe"

DUMMY_KEY="000000000000000000000000000000000000"

KEY_LENGTH = 16             # bytes

AS_ROW_ENCODING_SIZE = 32   # bits

KEY_ID_SIZE = 16            # bits

PARALLELIZATION_FACTOR = 1

RS2 = 1

FIRST_PORT=7760

FILTER_SHARE = 'filter_share2.json'

RANK_SHARE = 'rank_share2.json'


class AllWorker2():

    def __init__(self,port,handler_to_worker_queue,worker_2_handler_queue):
        # get port
        self.port = port

        self.handler_to_worker_queue = handler_to_worker_queue
        self.worker_2_handler_queue = worker_2_handler_queue

        logger.debug("launching ixp.exe on port " + str(self.port))
        logger.info("taskset -c " + str(self.port-FIRST_PORT) + " " +ABY_EXEC_PATH +' -r 1 -o 1 -f 3 -a 0.0.0.0 -p ' + str(self.port))
        args = ("taskset -c " + str(self.port-FIRST_PORT) + " " +ABY_EXEC_PATH +' -r 1 -o 1 -f 3 -a 0.0.0.0 -p ' + str(self.port))
        self.p = subprocess.Popen(args.split(" "),stdout=subprocess.PIPE,stdin=subprocess.PIPE, bufsize=8096)
        self.p.stdout.readline()
        logger.debug("process launched")
        self.load_policy()

    def load_policy(self):
        # filter
        with open(FILTER_SHARE, 'r') as f:
            self.export_policies = json.laod(f)
        self.number_of_participants = len(self.export_policies)
        # rank
        with open(RANK_SHARE, 'r') as f:
            self.selection_policies = json.load(f)
        assert self.number_of_participants == len(self.selection_policies)

    def send_export_policy_to_mpc(self):
        export_rows_strings = [ "" for i in xrange(0, self.number_of_participants)]
        for i in xrange(0, self.number_of_participants):
            for j in xrange(0, self.number_of_participants):
                v = 2 if self.export_policies[i][j] else 0
                export_rows_strings[i] += '{num:0{width}x}'.format(num=v, width=AS_ROW_ENCODING_SIZE/4)
        logger.debug("export_rows_string: " + export_rows_strings)

        myinput = "5" + "\n" + str(self.number_of_participants) + "\n"
        # invoking the MPC
        logger.info("input-to-mpc: " + myinput)
        print >> self.p.stdin, myinput # write input
        self.p.stdin.flush() # not necessary in this case
        for i in xrange(0, self.number_of_participants):
            print >> self.p.stdin, export_rows_strings[i] + "\n"
        print >> self.p.stdin, 0
        self.p.stdin.flush() # not necessary in this case

    # process a BGP update message
    def process_update(self):
        print str(self.port) + " is ready"
        while True:
            try:
                msg = self.handler_to_worker_queue.get(True, 1)
            except Empty:
                continue

            logger.info("received message: " + str(msg))
            if "stop" in msg:
                logger.info("stop received")
                break

            list_of_msg_for_prefix = msg["messages"] #remove the route_id used to prioritize the announcements in the queue

            # RUNNING THE MPC
            number_of_routes = len(list_of_msg_for_prefix) + 1

            # (key + id) for each route in this prefix list
            keys_str = DUMMY_KEY    # add DUMMY_KEY for default zero choice
            i = 1
            list_of_route_ids = []
            for nh_id in list_of_msg_for_prefix.keys():
                list_of_route_ids.append(list_of_msg_for_prefix[nh_id]["announcement_id"])
                keys_str += '{num:0{width}x}'.format(num = 0, width = KEY_LENGTH * 2)
                keys_str += '{num:0{width}x}'.format(num = 0, width= KEY_ID_SIZE / 4)
                i += 1

            if len(list_of_route_ids) > 1:
                local_prefs = ""
                for as_id in xrange(0, self.number_of_participants):
                    local_prefs += "0000"   # indicator
                    for nh_id in list_of_msg_for_prefix.keys():
                        local_prefs += "0000" if nh_id == as_id else self.selection_policies[as_id][nh_id]
                myinput = "4" + "\n" + str(number_of_routes) + "\n" + str(msg["as_id"]) + "\n" + keys_str + "\n" + local_prefs + "\n" + "0"
            else:
                myinput = "3" + "\n" + str(number_of_routes) + "\n" + str(msg["as_id"]) + "\n" + keys_str + "\n" + "0"


            # invoking the MPC
            logger.info("input-to-mpc: " + myinput)
            print >> self.p.stdin, myinput # write input
            self.p.stdin.flush() # not necessary in this case
            logger.debug("reading line")
            logger.debug(self.p.stdout.readline())
            str_host = ""
            for i in xrange(0, self.number_of_participants):
                line = self.p.stdout.readline().rstrip()
                logger.info(line)
                str_host += line

            self.worker_2_handler_queue.put({"type" : "to-hosts",  "announcement_id" : msg["announcement_id"],  "key" : str_host, "list_of_route_ids" : list_of_route_ids})

        #close the process
        myinput = "6\n"
        print >> self.p.stdin, myinput # write input
        self.p.stdin.flush() # not necessary in this case

        self.worker_2_handler_queue.put({"stop" : None})


def prio_worker_main(port,handler_to_worker_queue,worker_2_handler_queue):
    worker = AllWorker2(port,handler_to_worker_queue,worker_2_handler_queue)
    worker.process_update()
