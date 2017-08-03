#! /usr/bin/python

import argparse

def calclt_time(as_num, rs_result, pctrl_result):
    with open(rs_result, 'r') as f:
        t = f.readline()[:-1].split(' ')
        route_counts = int(t[0].split(':')[1])
        start_time = float(t[1].split(':')[1])
        end_time = float(t[2].split(':')[1])

    for i in range(0, as_num):
        with open(pctrl_result + 'result_' + str(i), 'r') as f:
            t = f.readline()[:-1].split(' ')
            p_route_counts = int(t[0].split(':')[1])
            p_end_time = float(t[1].split(':')[1])
            if p_route_counts > route_counts:
                print "err: p_route_counts:%d larger than route_counts:%d" % (p_route_counts, route_counts)
            else:
                if p_end_time > end_time:
                    end_time = p_end_time

    total_time = end_time - start_time
    per_route_time = total_time / route_counts
    print "routes:%d total_time(s):%0.6f per_route_time(s):%0.6f" % (route_counts, total_time, per_route_time)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('as_num', type=int, help='AS member number')
    parser.add_argument('rs_result', type=str, help='rs result, e.g. ./sxrs/result')
    parser.add_argument('pctrl_result', type=str, help='pctrl result directory, e.g. ./pctrl/result/')
    args = parser.parse_args()

    calclt_time(args.as_num, args.rs_result, args.pctrl_result)
