#! /usr/bin/python

import argparse


def merge_time(file1, file2):
    announcement_id_2_time = {}
    with open(file1, 'r') as f:
        for line in f:
            tmp = line[:-1].split(' ')
            announcement_id_2_time[int(tmp[2].split(':')[1])] = [float(tmp[3].split(':')[1]), float(tmp[4].split(':')[1])]

    with open(file2, 'r') as f:
        for line in f:
            tmp = line[:-1].split(' ')
            announcement_id = int(tmp[2].split(':')[1])
            announcement_id_2_time[announcement_id][0] = announcement_id_2_time[announcement_id][0] if float(tmp[3].split(':')[1]) > announcement_id_2_time[announcement_id][0] else float(tmp[3].split(':')[1])
            announcement_id_2_time[announcement_id][1] = announcement_id_2_time[announcement_id][1] if float(tmp[4].split(':')[1]) < announcement_id_2_time[announcement_id][1] else float(tmp[4].split(':')[1])

    with open(file1 + '_' + file2, 'w+') as f:
        lines = []
        for announcement_id in announcement_id_2_time.keys():
            lines.append("latency: %d\n" % (int((announcement_id_2_time[announcement_id][1] - announcement_id_2_time[announcement_id][0]) * 1000000)))
        f.writelines(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('file1', type=str, help='specify the result file 1')
    parser.add_argument('file2', type=str, help='specify the result file 2')
    args = parser.parse_args()

    merge_time(args.file1, args.file2)
