from pcap import PcapLine
import sys
import os
from pprint import pprint as pp
from convert_pcap import *

def print_map(map, key):
    print("*" * len(str(map[key][0])))
    for v in map[key]:
        print(v)

def search_flag(key, flag):
    for row in map[key]:
        if row.flags == flag:
            return row

    return None


filename = sys.argv[1]
filter = "tcp and port 554 and host not 172.27.70.99"

converted_file = convert_pcap_to_text(filename, filter)

map = {}
flags = {}
avg = {}

with open(converted_file, 'rt') as f:
    print("building connections map ...")
    while True:
        line = f.readline()
        if not line:
            break

        row = PcapLine(line)
        key = row.get_key(True)
        if key not in map.keys():
            map[key] = []

        map[key].append(row)

print('calculating average ...')
for key, val in map.items():
    if val[0].flags != '[S]':
        # print(key)
        # print('first packet is not SYN')
        pass
    else:
        syn_ack = search_flag(key, '[S.]')
        if syn_ack:
            diff = (syn_ack.timestamp - val[0].timestamp).microseconds

            if syn_ack.get_time() not in avg.keys():
                avg[syn_ack.get_time()] = {'hits': 0, 'value': 0, 'max': 0}

            avg[syn_ack.get_time()]['hits'] += 1
            avg[syn_ack.get_time()]['value'] += diff

            if avg[syn_ack.get_time()]['max'] < diff:
                avg[syn_ack.get_time()]['max'] = diff
        else:
            print("SYNACK not found")

print('creating csv file ...')
with open(converted_file + ".srv.perf.csv", 'wt') as f:
    f.write(";".join(['time', 'avg', 'max']) + "\n")
    for k, v in avg.items():
        f.write(";".join([k, str(v['value'] / v['hits']), str(v['max'])]) + "\n")
