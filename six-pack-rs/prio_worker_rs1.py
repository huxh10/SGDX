
import pickle
import util.log
from Queue import Empty
import subprocess
from participant_db import ParticipantDB
from util.statistics_collector_2 import StatisticsCollector
from member_preferences import  MemberPreferences
import time

logger = util.log.getLogger('worker-all-rs1')


ABY_EXEC_PATH="../aby/bin/ixp.exe"
#ABY_EXEC_PATH="/home/vagrant/aby/bin/ixp.exe"

DUMMY_KEY="00000000000000000000000000000000ff"

KEY_LENGTH = 16

AS_ROW_ENCODING_SIZE = 32 # bits

KEY_ID_SIZE = 8 # bits

PARALLELIZATION_FACTOR = 1

MOCK = False

RS1=0

FIRST_PORT=7760


class AllWorker1():

    def __init__(self,handler_to_worker_queue,worker_to_handler_queue, workers_pool):
        # get port
        self.port = workers_pool.get()
        worker_to_handler_queue.put({"type" : "to-rs2-init", "worker_port" : self.port})
        self.worker_to_handler_queue = worker_to_handler_queue
        self.workers_pool = workers_pool
        self.handler_to_worker_queue = handler_to_worker_queue

        logger.debug("launching ixp.exe on port " + str(self.port))
        if not MOCK:
            #args = (ABY_EXEC_PATH +' -r 0 -a localhost -o 1 -f 2 -p ' + str(self.port))
            logger.info("taskset -c " + str(self.port-FIRST_PORT) + " " +ABY_EXEC_PATH +' -r 0 -a 0.0.0.0 -o 1 -f 3 -p ' + str(self.port))
            args = ("taskset -c " + str(self.port-FIRST_PORT) + " " + ABY_EXEC_PATH +' -r 0 -a 0.0.0.0 -o 1 -f 3 -p ' + str(self.port))
            self.p = subprocess.Popen(args.split(" "),stdout=subprocess.PIPE,stdin=subprocess.PIPE, bufsize=8096)
            self.p.stdout.readline()
        logger.debug("process launched")
        self.participant_db = ParticipantDB()
        self.number_of_participants = len(self.participant_db.bgp_speaker_2_id)
        self.mock_counter=0
        self.statistics = StatisticsCollector()
        self.member_preference = MemberPreferences()
        #self.nbstreamreader = NonBlockingStreamReader()


    # process a BGP route
    def process_update(self):

        print str(self.port) + " is ready"
        while True:

            try:
                #logger.info("waiting for handler message")
                msg = self.handler_to_worker_queue.get(True, 1)
            except Empty:
                continue

            if "stop" in msg[1]:
                logger.info("stop received")
                print "stop received" + str(self.port)
                break

            logger.info("msg: " + str(msg))
            msg=msg[1]
            list_of_msg_for_prefix=msg["messages"] #remove the route_id used to prioritize the announcements in the queue

            announcement_id = msg["announcement_id"]
            if msg["announcement_id"] % 100 ==0:
                print "worker" + str(msg["announcement_id"])

            prefix = msg["prefix"]
            self.statistics.received_bgp_update(announcement_id)
            self.worker_to_handler_queue.put({"type" : "to-rs2", "announcement_id" : announcement_id, "worker_port" : self.port})

            encrypted_route = msg["messages"][msg["bgp_next_hop"]]["encrypted_route"]

            # RUNNING THE MPC
            number_of_routes = len(list_of_msg_for_prefix)+1

            #self.statistics.pre_export(announcement_id)
            export_rows_string=""
            i=0
            for bgp_speaker in self.participant_db.bgp_speaker_2_id.keys():
                sum=0
                for next_hop in list_of_msg_for_prefix.keys():
                    sum = sum << 1
                    if list_of_msg_for_prefix[next_hop]["encrypted_exp_policies_rs1"][i]==True:
                        sum+=1
                sum = sum << 1
                i+=1
                #export_row_string="{0:#0{1}x}".format(sum,AS_ROW_ENCODING_SIZE/4+2)[2:]
                export_row_string='{num:0{width}x}'.format(num=sum, width=AS_ROW_ENCODING_SIZE/4)
                export_rows_string+=export_row_string
            logger.debug("export_rows_string: " + export_rows_string)

            #self.statistics.pre_keys(announcement_id)
            #add dummy key
            keys_str = DUMMY_KEY

            i=1
            list_of_route_ids = [] # helpful for the member-receiving-mock
            for next_hop in list_of_msg_for_prefix.keys():
                #logger.info("list_of_msg: " + str(list_of_msg_for_prefix))
                #logger.info("msg: " + str(next_hop))
                #logger.info("msg[\"announcement_id\"]: " + str(list_of_msg_for_prefix[next_hop]["announcement_id"]))
                #logger.info(" list_of_route_ids: " + str(list_of_route_ids))
                list_of_route_ids.append(list_of_msg_for_prefix[next_hop]["announcement_id"])
                #logger.info("new_key: " + str(list_of_msg_for_prefix[next_hop]["key"]))
                keys_str+=list_of_msg_for_prefix[next_hop]["key"]
                #logger.info("key_str: " + str(keys_str))
                keys_str+='{num:0{width}x}'.format(num=i, width=KEY_ID_SIZE/4)
                #logger.info("key_str + id: " + str(keys_str))
                i+=1

            if len(list_of_route_ids)>1:
                local_prefs=""
                #create local prefs file
                #logger.info("member_preference: " + str(self.member_preference.member_2_member_2_local_pref))
                #self.statistics.pre_prefs(announcement_id)
                for bgp_speaker in self.participant_db.bgp_speaker_2_id.keys():
                    local_prefs+="00"
                    pre_look_up = self.member_preference.member_2_member_2_local_pref[self.participant_db.bgp_speakers_2_asnumber[bgp_speaker]]
                    for next_hop in list_of_msg_for_prefix.keys():
                        if next_hop == bgp_speaker:
                            local_pref="00"
                        else:
                            bgp_next_hop  = list_of_msg_for_prefix[next_hop]["bgp_next_hop"]
                            #print "8359" in self.member_preference.member_2_member_2_local_pref.keys()
                            local_pref = pre_look_up[self.participant_db.bgp_speakers_2_asnumber[bgp_next_hop]][RS1]
                        local_prefs+=local_pref
                myinput = "2"+"\n"+str(self.number_of_participants) +"\n" +str(number_of_routes) + "\n" + export_rows_string + "\n" + keys_str +  "\n" + local_prefs + "\n"+ "0"
            else:
                myinput = "1"+"\n"+str(self.number_of_participants) +"\n" +str(number_of_routes) + "\n" + export_rows_string + "\n" + keys_str +  "\n"+ "0"

            # invoking the MPC
            if MOCK:
                if self.mock_counter == 0:
                    self.worker_to_handler_queue.put({"type" : "to-hosts", "route_id" : self.mock_counter, "encrypted_route" : "aaaa", "key" : "0" * 34 * 743})
                elif self.mock_counter == 1:
                    self.worker_to_handler_queue.put({"type" : "to-hosts", "route_id" : self.mock_counter, "encrypted_route" : "bbbb", "key" : "0" * 34 * 743})
                elif self.mock_counter == 2:
                    self.worker_to_handler_queue.put({"type" : "to-hosts", "route_id" : self.mock_counter, "encrypted_route" : "cccc", "key" : "0" * 34 * 743})
                else :
                    self.worker_to_handler_queue.put({"type" : "to-hosts", "route_id" : self.mock_counter, "encrypted_route" : "dddd", "key" : "0" * 34 * 743})
                self.mock_counter+=1
            else:
                self.statistics.record_start_smpc(announcement_id)
                #print "id: " + str(announcement_id)
                logger.info("input-to-mpc: " + myinput)
                #self.statistics.record_start_smpc(announcement_id)
                print >> self.p.stdin, myinput # write input
                self.p.stdin.flush() # not necessary in this case
                self.statistics.record_start_smpc_input_sent(announcement_id)
                logger.debug("reading line")
                logger.debug(self.p.stdout.readline())
                self.statistics.record_end_of_smpc_processing(announcement_id)
                str_host=""
                for i in range(0,self.number_of_participants):
                    line=self.p.stdout.readline().rstrip()
                    logger.info(line)
                    str_host+=line
                #for i in range(0,self.number_of_participants):
                #    self.p.stdout.readline()

                #logger.info("Sending route to Host. Key: " +str_host)
                self.statistics.record_end_of_bgp_update_processing(announcement_id)
                self.worker_to_handler_queue.put({"type" : "to-hosts",  "announcement_id" : announcement_id, "encrypted_route" : encrypted_route, "key" : str_host, "prefix" : prefix, "list_of_route_ids" : list_of_route_ids})

            #self.server_send_mpc_output.sender_queue.put(pickle.dumps({"encrypted_route" : encrypted_route, "key" : str_host}))

        #close the process
        if not MOCK:
            myinput = "4\n"
            print >> self.p.stdin, myinput # write input
            self.p.stdin.flush() # not necessary in this case

        self.worker_to_handler_queue.put({"stop" : None , "port" : self.port})
        print "stop sent to handler" + str(self.port)

        f=open('statistics-prio-rs1-worker-'+str(self.port)+'.txt','w')
        f.write("route_id start-processing-time start-smpc-time smpc-time-no-output smpc-time-no-output-input-sent total-time smpc-time\n")
        for bgp_update_id in self.statistics.observations.keys():
            start_processing_time= self.statistics.observations[bgp_update_id]["start-processing-time"]
            start_smpc_time= self.statistics.observations[bgp_update_id]["start-smpc-time"]
            start_smpc_time_input_sent= self.statistics.observations[bgp_update_id]["start-smpc-time-input-sent"]
            smpc_time_no_output_reading= self.statistics.observations[bgp_update_id]["end-smpc-time"] - start_smpc_time
            smpc_time_no_output_reading_input_sent = self.statistics.observations[bgp_update_id]["end-smpc-time"] - start_smpc_time_input_sent
            total_time = self.statistics.observations[bgp_update_id]["end-processing-time"] - self.statistics.observations[bgp_update_id]["start-processing-time"]
            smpc_time = self.statistics.observations[bgp_update_id]["end-processing-time"] - self.statistics.observations[bgp_update_id]["start-smpc-time"]
            f.write(str(bgp_update_id) + " " + str("{0:.9f}".format(start_processing_time)) + " " + str("{0:.9f}".format(start_smpc_time)) + " " + str("{0:.9f}".format(smpc_time_no_output_reading))  + " " + str("{0:.9f}".format(smpc_time_no_output_reading_input_sent)) + " " + str("{0:.9f}".format(total_time)) +" " + str("{0:.9f}".format(smpc_time)) + "\n")
        f.close()

def prio_worker_main(handler_to_worker_queue,workers_to_rs2_queue, workers_pool):
    worker = AllWorker1(handler_to_worker_queue,workers_to_rs2_queue, workers_pool)
    worker.process_update()
