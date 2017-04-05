#!/usr/bin/env python
#  Author:
#  Muhammad Shahbaz (muhammad.shahbaz@gatech.edu)
#  Rudiger Birkner (Networked Systems Group ETH Zurich)
#  Arpit Gupta (Princeton)


from threading import RLock
import time

import os
import sys
np = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if np not in sys.path:
    sys.path.append(np)
import util.log

from decision_process import decision_process, best_path_selection
from ribm import rib, RibTuple


class BGPPeer(object):

    def __init__(self, id, asn, ports):
        self.id = id
        self.asn = asn
        self.ports = ports
        self.prefix_lock = {}
        self.logger = util.log.getLogger('P'+str(self.id)+'-peer')

        self.rib = { "local": rib(str(self.asn),"local") }

    def decision_process_local(self, route):
        'Update the local rib'
        if 'oprt-type' not in route:
            return []
        update_list = []
        prefix = route['prefix'] if 'prefix' in route else ''
        next_hop = route['next-hop'] if 'next-hop' in route else ''
        as_path = route['as-path'] if 'as-path' in route else []
        # we use neighbor field to store the next_hop participant id/asn
        neighbor = str(as_path[0]) if len(as_path) > 0 else '-1'
        if route['oprt-type'] == 'withdraw':
            deleted_route = self.get_route_with_neighbor('local', prefix, neighbor)
            if delete_route != None:
                self.delete_route_with_neighbor('local', prefix, neighbor)
                update_list.append({'withdraw': deleted_route})
        if route['oprt-type'] == 'announce':
            origin = ''
            med = ''
            communities = ''
            atomic_aggregate = ''
            updated_route = RibTuple(prefix, neighbor, next_hop, origin, as_path, communities, med, atomic_aggregate)
            self.update_route('local', updated_route)
            update_list.append({'announce': updated_route})
        return update_list

    def bgp_update_peers(self, updates, prefix_2_VNH, ports):
        changed_vnhs = []
        announcements = []
        for update in updates:
            if 'announce' in update:
                prefix = update['announce'].prefix
                changed_vnhs.append(prefix_2_VNH[prefix])
                for port in ports:
                    announcements.append(announce_route(port["IP"], prefix, prefix_2_VNH[prefix], update['announce'].as_path))
            elif 'withdraw' in update:
                prefix = update['withdraw'].prefix
                for port in self.ports:
                    announcements.append(withdraw_route(port["IP"], prefix, prefix_2_VNH[prefix]))
        return changed_vnhs, announcements


    def getlock(self, prefix):
        if prefix not in self.prefix_lock:
            self.prefix_lock[prefix] = RLock()
        return self.prefix_lock[prefix]


    def process_notification(self,route):
        if ('shutdown' == route['notification']):
            self.rib["input"].delete_all()
            self.rib["local"].delete_all()
            self.rib["output"].delete_all()
            # TODO: send shutdown notification to participants


    def add_route(self,rib_name,attributes):
        with self.getlock(attributes.prefix):
            self.rib[rib_name].add(attributes)


    def get_route(self,rib_name,prefix):
        with self.getlock(prefix):
            return self.rib[rib_name].get(prefix=prefix)


    def get_route_with_neighbor(self,rib_name,prefix, neighbor):
        with self.getlock(prefix):
            return self.rib[rib_name].get(prefix=prefix, neighbor=neighbor)


    def get_routes(self,rib_name,prefix):
        with self.getlock(prefix):
            return self.rib[rib_name].get_all(prefix=prefix)


    def get_all_routes(self, rib_name):
        return self.rib[rib_name].get_all()


    def delete_route(self,rib_name,prefix):
        with self.getlock(prefix):
            self.rib[rib_name].delete(prefix=prefix)


    def delete_route_with_neighbor(self,rib_name,prefix, neighbor):
        with self.getlock(prefix):
            self.rib[rib_name].delete(prefix=prefix, neighbor=neighbor)


    def delete_all_routes(self,rib_name):
        with self.getlock(prefix):
            self.rib[rib_name].delete_all()


    def filter_route(self,rib_name,item,value):
        return self.rib[rib_name].get_all(**{item:value})


    def update_route(self,rib_name,attributes):
        with self.getlock(attributes.prefix):
            self.rib[rib_name].update(('prefix'), attributes)


def bgp_routes_are_equal(route1, route2):
    if route1 is None:
        return False
    if route2 is None:
        return False
    if (route1.next_hop != route2.next_hop):
        return False
    if (route1.as_path != route2.as_path):
        return False
    return True


def announce_route(neighbor, prefix, next_hop, as_path):

    msg = "neighbor " + neighbor + " announce route " + prefix + " next-hop " + str(next_hop)
    msg += " as-path [ ( " + ' '.join(str(ap) for ap in as_path) + " ) ]"

    return msg


def withdraw_route(neighbor, prefix, next_hop):

    msg = "neighbor " + neighbor + " withdraw route " + prefix + " next-hop " + str(next_hop)

    return msg


''' main '''
if __name__ == '__main__':

    mypeer = peer('172.0.0.22')

    route = '''{ "exabgp": "2.0", "time": 1387421714, "neighbor": { "ip": "172.0.0.21", "update": { "attribute": { "origin": "igp", "as-path": [ [ 300 ], [ ] ], "med": 0, "atomic-aggregate": false }, "announce": { "ipv4 unicast": { "140.0.0.0/16": { "next-hop": "172.0.0.22" }, "150.0.0.0/16": { "next-hop": "172.0.0.22" } } } } } }'''

    mypeer.update(route)

    print mypeer.filter_route('input', 'as_path', '300')
