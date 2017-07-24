import os

KEY_LENGTH = 16
RS1_MODE = 1
RS2_MODE = 2

def load_ribs(rib_file, asn_2_id, mode):
    as_size = len(asn_2_id)
    route_id = 2 ** 31
    prefix_2_nh_id_2_route = {}
    with open(rib_file, 'r') as f:
        for line in f:
            if line.startswith('FROM'):
                asn = line[:-1].split(' ')[-1][2:]
            if line.startswith('PREFIX'):
                prefix = line[:-1].split(' ')[-1]
            if line.startswith('\n'):
                if asn == '0':
                    continue
                if prefix not in prefix_2_nh_id_2_route:
                    prefix_2_nh_id_2_route[prefix] = {}
                if mode == RS1_MODE:
                    prefix_2_nh_id_2_route[prefix][asn_2_id[asn]] = {}
                    prefix_2_nh_id_2_route[prefix][asn_2_id[asn]]['announcement_id'] = route_id
                    route_id += 1
                    prefix_2_nh_id_2_route[prefix][asn_2_id[asn]]['key'] = os.urandom(KEY_LENGTH).encode('hex')
                elif mode == RS2_MODE:
                    # dummy action for simple time sync
                    key = os.urandom(KEY_LENGTH).encode('hex')
                    prefix_2_nh_id_2_route[prefix][asn_2_id[asn]] = route_id
                    route_id += 1

    return prefix_2_nh_id_2_route
