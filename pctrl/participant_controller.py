#  Author:
#  Arpit Gupta (Princeton)
#  Robert MacDavid (Princeton)


import argparse
import atexit
import json
from multiprocessing.connection import Listener, Client
import os
from signal import signal, SIGTERM
from sys import exit
from threading import RLock, Thread
import time

import sys
np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if np not in sys.path:
    sys.path.append(np)
import util.log
from xctrl.flowmodmsg import FlowModMsgBuilder

from lib import PConfig
from ss_lib import vmac_part_port_match
from ss_rule_scheme import update_outbound_rules, init_inbound_rules, init_outbound_rules, msg_clear_all_outbound, ss_process_policy_change
from supersets import SuperSets

import pprint


TIMING = True


class ParticipantController(object):
    def __init__(self, id, config_file, policy_file, logger):
        # participant id
        self.id = id
        # print ID for logging
        self.logger = logger

        # used to signal termination
        self.run = True
        self.prefix_lock = {}

        # Initialize participant params
        self.cfg = PConfig(config_file, self.id)
        # Vmac encoding mode
        # self.cfg.vmac_mode = config_file["vmac_mode"]
        # Dataplane mode---multi table or multi switch
        # self.cfg.dp_mode = config_file["dp_mode"]


        self.policies = self.load_policies(policy_file)

        # The port 0 MAC is used for tagging outbound rules as belonging to us
        self.port0_mac = self.cfg.port0_mac

        # BGP and VNHs related params
        self.VNH_2_prefix = {}
        self.prefix_2_VNH = {}
        self.VNH_2_part = {}

        # Superset related params
        if self.cfg.isSupersetsMode():
            self.supersets = SuperSets(self, self.cfg.vmac_options)
        else:
            # TODO: create similar class and variables for MDS
            self.mds = None

        # Keep track of flow rules pushed
        self.dp_pushed = []
        # Keep track of flow rules which are scheduled to be pushed
        self.dp_queued = []


    def xstart(self):
        # Start all clients/listeners/whatevs
        self.logger.info("Starting controller for participant")

        # Route server client, supersets RS client, Reference monitor client, Arp Proxy client
        self.xrs_client = self.cfg.get_xrs_client(self.logger)
        self.xrs_client.send({'msgType': 'hello', 'id': int(self.cfg.id)}, add_header=True)

        # send the initial sdn policy reachability to route server
        self.supersets.run_rulecounts(self)
        self.xrs_client.send({'msgType': 'sdn-reach', 'add': self.supersets.rulecounts.keys()}, add_header=True)

        self.arp_client = self.cfg.get_arp_client(self.logger)
        self.arp_client.send({'msgType': 'hello', 'macs': self.cfg.get_macs()})

        # Participant Server for dynamic route updates
        self.participant_server = self.cfg.get_participant_server(self.id, self.logger)
        if self.participant_server is not None:
            self.participant_server.start(self)

        self.refmon_client = self.cfg.get_refmon_client(self.logger)

        # Send flow rules for initial policies to the SDX's Reference Monitor
        self.initialize_dataplane()
        self.push_dp()

        # Start the event handlers
        ps_thread_arp = Thread(target=self.start_eh_arp)
        ps_thread_arp.daemon = True
        ps_thread_arp.start()

        ps_thread_xrs = Thread(target=self.start_eh_xrs)
        ps_thread_xrs.daemon = True
        ps_thread_xrs.start()

        ps_thread_arp.join()
        ps_thread_xrs.join()
        self.logger.debug("Return from ps_thread.join()")

    def sanitize_policies(self, policies):

        port_count = len(self.cfg.ports)

        # sanitize the inbound policies
        if 'inbound' in policies:
            for policy in policies['inbound']:
                if 'action' not in policy:
                    continue
                if 'fwd' in policy['action'] and int(policy['action']['fwd']) >= port_count:
                    policy['action']['fwd'] = 0
                    self.logger.warn('Port count in inbound policy is too big.  Setting it to 0.')

        # sanitize the outbound policies
        if 'outbound' in policies:
            for policy in policies['outbound']:
                # If no cookie field, give it cookie 0. (Should be OK for multiple flows with same cookie,
                # though they can't be individually removed.  TODO: THIS SHOULD BE VERIFIED)
                if 'cookie' not in policy:
                    policy['cookie'] = 0
                    self.logger.warn('Cookie not specified in new policy.  Defaulting to 0.')

        return policies


    def load_policies(self, policy_file):
        # Load policies from file

        with open(policy_file, 'r') as f:
            policies = json.load(f)

        return self.sanitize_policies(policies)


    def initialize_dataplane(self):
        "Read the config file and update the queued policy variable"

        self.logger.info("Initializing inbound rules")

        final_switch = "main-in"
        if self.cfg.isMultiTableMode():
            final_switch = "main-out"

        rule_msgs = init_inbound_rules(self.id, self.policies,
                                        self.supersets, final_switch)
        self.logger.debug("Rule Messages INBOUND:: "+json.dumps(rule_msgs))

        rule_msgs2 = init_outbound_rules(self, self.id, self.policies,
                                        self.supersets, final_switch)
        self.logger.debug("Rule Messages OUTBOUND:: "+json.dumps(rule_msgs2))

        if 'changes' in rule_msgs2:
            if 'changes' not in rule_msgs:
                rule_msgs['changes'] = []
            rule_msgs['changes'] += rule_msgs2['changes']

        #TODO: Initialize Outbound Policies from RIB
        self.logger.debug("Rule Messages:: "+json.dumps(rule_msgs))
        if 'changes' in rule_msgs:
            self.dp_queued.extend(rule_msgs["changes"])


    def push_dp(self):
        '''
        (1) Check if there are any policies queued to be pushed
        (2) Send the queued policies to reference monitor
        '''

        self.logger.debug("Pushing current flow mod queue:")

        # it is crucial that dp_queued is traversed chronologically
        fm_builder = FlowModMsgBuilder(self.id, self.refmon_client.key)
        for flowmod in self.dp_queued:
            self.logger.debug("MOD: "+str(flowmod))
            if (flowmod['mod_type'] == 'remove'):
                fm_builder.delete_flow_mod(flowmod['mod_type'], flowmod['rule_type'], flowmod['cookie'][0], flowmod['cookie'][1])
            elif (flowmod['mod_type'] == 'insert'):
                fm_builder.add_flow_mod(**flowmod)
            else:
                self.logger.error("Unhandled flow type: " + flowmod['mod_type'])
                continue
            self.dp_pushed.append(flowmod)

        self.dp_queued = []
        self.refmon_client.send(json.dumps(fm_builder.get_msg()))


    def stop(self):
        "Stop the Participants' SDN Controller"

        self.logger.info("Stopping Controller.")

        # Signal Termination and close blocking listener
        self.run = False

        # TODO: confirm that this isn't silly
        #self.refmon_client = None


    def start_eh_arp(self):
        self.logger.info("ARP Event Handler started.")

        while self.run:
            # need to poll since recv() will not detect close from this end
            # and need some way to shutdown gracefully.
            if not self.arp_client.poll(1):
                continue
            try:
                tmp = self.arp_client.recv()
            except EOFError:
                break

            data = json.loads(tmp)
            self.logger.debug("ARP Event received: %s", data)

            # Starting a thread for independently processing each incoming network event
            event_processor_thread = Thread(target=self.process_event, args=(data,))
            event_processor_thread.daemon = True
            event_processor_thread.start()

        self.arp_client.close()
        self.logger.debug("Exiting start_eh_arp")


    def start_eh_xrs(self):
        self.logger.info("XRS Event Handler started.")
        msg_buff = ''

        while self.run:
            try:
                tmp = self.xrs_client.recv()
            except EOFError:
                break

            if not tmp:
                break
            self.logger.debug("XRS Event received " + str(len(tmp)) + " bytes: " + tmp)
            msg_buff += tmp
            offset = 0
            buff_len = len(msg_buff)
            while buff_len - offset >= 2:
                msg_len = ord(msg_buff[offset]) | ord(msg_buff[offset + 1]) << 8
                self.logger.debug("XRS Event msg_len: " + str(msg_len))
                if buff_len - offset < msg_len:
                    break
                data = json.loads(msg_buff[offset + 2: offset + msg_len])
                self.process_event(data)
                offset += msg_len
            msg_buff = msg_buff[offset:]

        self.xrs_client.close()
        self.logger.debug("Exiting start_eh_xrs")


    def process_event(self, data):
        "Locally process each incoming network event"

        if 'bgp-nh' in data:
            self.logger.debug("Event Received: bgp-nh Update.")
            route = data['bgp-nh']
            # Process the incoming BGP updates from XRS
            #self.logger.debug("BGP Route received: "+str(route)+" "+str(type(route)))
            self.process_bgp_nh(route)

        elif 'sdn-reach' in data:
            self.logger.debug("Event Received: sdn-reach Update.")
            parts_set = data['sdn-reach']
            self.process_sdn_reach(parts_set)

        elif 'policy' in data:
            # Process the event requesting change of participants' policies
            self.logger.debug("Event Received: Policy change.")
            change_info = data['policy']
            self.process_policy_changes(change_info)

        elif 'arp' in data:
            (requester_srcmac, requested_vnh) = tuple(data['arp'])
            self.logger.debug("Event Received: ARP request for IP "+str(requested_vnh))
            self.process_arp_request(requester_srcmac, requested_vnh)

        else:
            self.logger.warn("UNKNOWN EVENT TYPE RECEIVED: "+str(data))


    def update_policies(self, new_policies, in_out):
        if in_out != 'inbound' and in_out != 'outbound':
            self.logger.exception("Illegal argument to update_policies: " + in_out)
            raise
        if in_out not in new_policies:
            return
        if in_out not in self.policies:
            self.policies[in_out] = []
        new_cookies = {x['cookie'] for x in new_policies[in_out] if 'cookie' in x}
        self.logger.debug('new_cookies: ' + str(new_cookies))

        # remove any items with same cookie (TODO: verify that this is the behavior we want)
        self.policies[in_out] = [x for x in self.policies[in_out] if x['cookie'] not in new_cookies]
        self.logger.debug('new_policies[io]: ' + str(new_policies[in_out]))
        self.policies[in_out].extend(new_policies[in_out])

    # Remove polices that match the cookies and return the list of cookies for removed policies
    def remove_policies_by_cookies(self, cookies, in_out):
        if in_out != 'inbound' and in_out != 'outbound':
            self.logger.exception("Illegal argument to update_policies: " + in_out)
            raise
        if in_out in self.policies:
            to_remove = [x['cookie'] for x in self.policies[in_out] if x['cookie'] in cookies]
            self.policies[in_out] = [x for x in self.policies[in_out] if x['cookie'] not in cookies]
            self.logger.debug('removed cookies: ' + str(to_remove) + ' from: ' + in_out)
            return to_remove
        return []

    def queue_flow_removals(self, cookies, in_out):
        removal_msgs = []
        for cookie in cookies:
            mod =  {"rule_type":in_out,
                    "cookie":(cookie,2**16-1), "mod_type":"remove"}
            removal_msgs.append(mod)
        self.logger.debug('queue_flow_removals: ' + str(removal_msgs))
        self.dp_queued.extend(removal_msgs)
            

    def process_policy_changes(self, change_info):
        if not self.cfg.isSupersetsMode():
            self.logger.warn('Dynamic policy updates only supported in SuperSet mode')
            return

        # First step towards a less brute force approach: Handle removals without having to remove everything
        if 'removal_cookies' in change_info:
            cookies = change_info['removal_cookies']
            removed_in_cookies = self.remove_policies_by_cookies(cookies, 'inbound')
            self.queue_flow_removals(removed_in_cookies, 'inbound')
            removed_out_cookies = self.remove_policies_by_cookies(cookies, 'outbound')
            self.queue_flow_removals(removed_out_cookies, 'outbound')
            if not 'new_policies' in change_info:
                self.push_dp()
                return

        # Remainder of this method is brute force approach: wipe everything and re-do it
        # This should be replaced by a more fine grained approach
        self.logger.debug("Wiping outbound rules.")
        wipe_msgs = msg_clear_all_outbound(self.policies, self.port0_mac)
        self.dp_queued.extend(wipe_msgs)

        self.logger.debug("pre-updated policies: " + json.dumps(self.policies))
        if 'removal_cookies' in change_info:
            cookies = change_info['removal_cookies']
            self.remove_policies_by_cookies(cookies, 'inbound')
            self.remove_policies_by_cookies(cookies, 'outbound')

        if 'new_policies' in change_info:
            new_policies = change_info['new_policies']
            self.sanitize_policies(new_policies)
            self.update_policies(new_policies, 'inbound')
            self.update_policies(new_policies, 'outbound')

        self.logger.debug("updated policies: " + json.dumps(self.policies))
        self.logger.debug("pre-recomputed supersets: " + json.dumps(self.supersets.supersets))
        # -----------------------------------------
        # TODO: Update policy participants to sxrs
        # -----------------------------------------
        self.initialize_dataplane()
        self.push_dp()

        # Send gratuitous ARP responses for all
        garp_required_vnhs = self.VNH_2_prefix.keys()
        for vnh in garp_required_vnhs:
            self.process_arp_request(None, vnh)
            
        return

        # Original code below...
        
        "Process the changes in participants' policies"
        # TODO: Implement the logic of dynamically changing participants' outbound and inbound policy
        '''
            change_info =
            {
                'removal_cookies' : [cookie1, ...], # Cookies of deleted policies
                'new_policies' :
                {
                    <policy file format>
                }

            }
        '''
        # remove flow rules for the old policies
        removal_msgs = []

        '''
        for cookie in change_info['removal_cookies']:
            mod =  {"rule_type":"outbound", "priority":0,
                    "match":match_args , "action":{},
                    "cookie":cookie, "mod_type":"remove"}
            removal_msgs.append(mod)
        '''

        self.dp_queued.extend(removal_msgs)


        # add flow rules for the new policies
        if self.cfg.isSupersetsMode():
            dp_msgs = ss_process_policy_change(self.supersets, add_policies, remove_policies, policies,
                                                self.port_count, self.port0_mac)
        else:
            dp_msgs = []

        self.dp_queued.extend(dp_msgs)

        self.push_dp()

        return 0


    def process_arp_request(self, part_mac, vnh):
        vmac = ""
        if self.cfg.isSupersetsMode():
            vmac = self.supersets.get_vmac(self, vnh)
        else:
            vmac = "whoa" # MDS vmac goes here

        arp_responses = list()

        # if this is gratuitous, send a reply to the part's ID
        if part_mac is None:
            gratuitous = True
            # set fields appropriately for gratuitous arps
            i = 0
            for port in self.cfg.ports:
                eth_dst = vmac_part_port_match(self.id, i, self.supersets, False)
                arp_responses.append({'SPA': vnh, 'TPA': vnh,
                                   'SHA': vmac, 'THA': vmac,
                                   'eth_src': vmac, 'eth_dst': eth_dst})
                i += 1

        else: # if it wasn't gratuitous
            gratuitous = False
            # dig up the IP of the target participant
            for port in self.cfg.ports:
                if part_mac == port["MAC"]:
                    part_ip = port["IP"]
                    break

            # set field appropriately for arp responses
            arp_responses.append({'SPA': vnh, 'TPA': part_ip,
                        'SHA': vmac, 'THA': part_mac,
                        'eth_src': vmac, 'eth_dst': part_mac})

        if gratuitous:
            self.logger.debug("Sending Gratuitious ARP: "+str(arp_responses))
        else:
            self.logger.debug("Sending ARP Response: "+str(arp_responses))

        for arp_response in arp_responses:
            arp_response['msgType'] = 'garp'
            self.arp_client.send(arp_response)


    def getlock(self, prefixes):
        prefixes.sort()
        hsh = "-".join(prefixes)
        if hsh not in self.prefix_lock:
            #self.logger.debug("First Lock:: "+str(hsh))
            self.prefix_lock[hsh] = RLock()
        #else:
            #self.logger.debug("Repeat :: "+str(hsh))
        return self.prefix_lock[hsh]

    def process_bgp_nh(self, route):
        "Process each incoming BGP advertisement"

        self.logger.debug("process_bgp_nh:: "+str(route))
        vnh_changed = 0
        if route['oprt-type'] == 'withdraw':
            if route['prefix'] in self.prefix_2_VNH:
                del self.prefix_2_VNH[route['prefix']]
            if route['vnh'] in self.VNH_2_prefix:
                del self.VNH_2_prefix[route['vnh']]
            if route['vnh'] in self.VNH_2_part:
                del self.VNH_2_part[route['vnh']]
        elif route['oprt-type'] == 'announce':
            vnh_changed = 1
            self.prefix_2_VNH[route['prefix']] = route['vnh']
            self.VNH_2_prefix[route['vnh']] = route['prefix']
            self.VNH_2_part[route['vnh']] = route['nh_asid']

        # XXX temperal trick
        # to trigger first superset computation
        # what if my next_hop changed, while reachability/superset not changed
        self.process_sdn_reach({})

        if vnh_changed:
            self.process_arp_request(None, vnh)


    def process_sdn_reach(self, parts_set):
        tstart = time.time()
        self.logger.debug("process_sdn_reach:: "+str(parts_set))
        if self.cfg.isSupersetsMode():
            ################## SUPERSET RESPONSE TO BGP ##################
            # update supersets
            "Map the set of BGP updates to a list of superset expansions."
            ss_changes, ss_changed_prefs = self.supersets.update_supersets(self, parts_set)

            if TIMING:
                elapsed = time.time() - tstart
                self.logger.debug("Time taken to update supersets: "+str(elapsed))
                tstart = time.time()

            # ss_changed_prefs are prefixes for which the VMAC bits have changed
            # these prefixes must have gratuitous arps sent
            garp_required_vnhs = [self.prefix_2_VNH[prefix] for prefix in ss_changed_prefs]

            "If a recomputation event was needed, wipe out the flow rules."
            if ss_changes["type"] == "new":
                self.logger.debug("Wiping outbound rules.")
                wipe_msgs = msg_clear_all_outbound(self.policies, self.port0_mac)
                self.dp_queued.extend(wipe_msgs)

                #if a recomputation was needed, all VMACs must be reARPed
                # TODO: confirm reARPed is a word
                garp_required_vnhs = self.VNH_2_prefix.keys()

            if len(ss_changes['changes']) > 0:

                self.logger.debug("Supersets have changed: "+str(ss_changes))

                "Map the superset changes to a list of new flow rules."
                flow_msgs = update_outbound_rules(ss_changes, self.policies,
                        self.supersets, self.port0_mac)

                self.logger.debug("Flow msgs: "+str(flow_msgs))
                "Dump the new rules into the dataplane queue."
                self.dp_queued.extend(flow_msgs)

            if TIMING:
                elapsed = time.time() - tstart
                self.logger.debug("Time taken to deal with ss_changes: "+str(elapsed))
                tstart = time.time()

        ################## END SUPERSET RESPONSE ##################

        else:
            # TODO: similar logic for MDS
            self.logger.debug("Creating ctrlr messages for MDS scheme")

        self.push_dp()

        if TIMING:
            elapsed = time.time() - tstart
            self.logger.debug("Time taken to push dp msgs: "+str(elapsed))
            tstart = time.time()


        # XXX we don't need this combination?
        """ Combine the VNHs which have changed BGP default routes with the
            VNHs which have changed supersets.
        """

        # Send gratuitous ARP responses for all them
        for vnh in garp_required_vnhs:
            self.process_arp_request(None, vnh)

        if TIMING:
            elapsed = time.time() - tstart
            self.logger.debug("Time taken to send garps/announcements: "+str(elapsed))
            tstart = time.time()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dir', help='the directory of the example')
    parser.add_argument('id', type=int,
                   help='participant id (integer)')
    args = parser.parse_args()

    # locate config file
    # TODO: Separate the config files for each participant
    base_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..","examples",args.dir,"config"))
    config_file = os.path.join(base_path, "sdx_global.cfg")

    # locate the participant's policy file as well
    policy_filenames_file = os.path.join(base_path, "sdx_policies.cfg")
    with open(policy_filenames_file, 'r') as f:
        policy_filenames = json.load(f)
    policy_filename = policy_filenames[str(args.id)]

    policy_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            "..","examples",args.dir,"policies"))

    policy_file = os.path.join(policy_path, policy_filename)

    logger = util.log.getLogger("P_" + str(args.id))

    logger.info("Starting controller with config file: "+str(config_file))
    logger.info("and policy file: "+str(policy_file))

    # start controller
    ctrlr = ParticipantController(args.id, config_file, policy_file, logger)
    ctrlr_thread = Thread(target=ctrlr.xstart)
    ctrlr_thread.daemon = True
    ctrlr_thread.start()
    
    atexit.register(ctrlr.stop)
    signal(SIGTERM, lambda signum, stack_frame: exit(1))

    while ctrlr_thread.is_alive():
        try:
            ctrlr_thread.join(1)
        except KeyboardInterrupt:
            ctrlr.stop()

    logger.info("Pctrl exiting")


if __name__ == '__main__':
    main()
