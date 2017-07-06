#! /usr/bin/python

import json

RIB_FILE = '../ribs/bview'
MAP_JSON_FILE = '../config/asn_2_id.json'
MAP_TXT_FILE = '../config/asn_2_id.cfg'


def generate_asn_2_id():
    asn_2_id = {}
    asns = []
    as_id = 0
    with open(RIB_FILE, 'r') as rib_file:
        for line in rib_file.readlines():
            if "FROM" in line:
                asn = int(line.split("FROM: ")[1].split("\n")[0].split(" ")[1][2:])
                if asn not in asn_2_id:
                    asn_2_id[asn] = as_id
                    asns.append(asn)
                    as_id += 1

    with open(MAP_JSON_FILE, 'w+') as json_file:
        json.dump(asn_2_id, json_file)

    with open(MAP_TXT_FILE, 'w+') as txt_file:
        lines = ['%d\n' % len(asn_2_id)]
        lines = lines + map(lambda x: ' ' + str(x), asns)
        lines.append('\n')
        #for asn in asns:
        #    lines.append('%d %d\n' % (asn, asn_2_id[asn]))
        txt_file.writelines(lines)


if __name__ == '__main__':
    generate_asn_2_id()
