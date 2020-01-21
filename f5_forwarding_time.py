import sys
from pprint import pprint as pp
from copy import deepcopy
import os
from pcap import PcapLine

def create_stats(list, row):
    time = row.timestamp.strftime("%H:%M:%S")

    box_to_vip = 1 if row.box_to_vip() else 0
    vip_to_trx = 1 if row.vip_to_trx() else 0
    trx_to_vip = 1 if row.trx_to_vip() else 0
    vip_to_box = 1 if row.vip_to_box() else 0

    if time not in list.keys():
        list[time] = {'box_to_vip_req': 0, 'vip_to_trx_req': 0, 'trx_to_vip_req': 0, 'vip_to_box_req': 0,
                      'vip_to_trx_delay': 0, 'vip_to_box_delay': 0, 'vip_to_trx_fw': 0, 'vip_to_box_fw': 0, 'vip_to_trx_max': 0, 'vip_to_box_max': 0,}
    list[time]['box_to_vip_req'] += box_to_vip
    list[time]['vip_to_trx_req'] += vip_to_trx
    list[time]['trx_to_vip_req'] += trx_to_vip
    list[time]['vip_to_box_req'] += vip_to_box

    if row.vip_to_trx() and row.forwarding_delay:
        list[time]['vip_to_trx_delay'] += row.forwarding_delay
        list[time]['vip_to_trx_fw'] += 1

        if row.forwarding_delay > list[time]['vip_to_trx_max']:
            list[time]['vip_to_trx_max'] = row.forwarding_delay

    if row.vip_to_box() and row.forwarding_delay:
        list[time]['vip_to_box_delay'] += row.forwarding_delay
        list[time]['vip_to_box_fw'] += 1

        if row.forwarding_delay > list[time]['vip_to_box_max']:
            list[time]['vip_to_box_max'] = row.forwarding_delay

def find_in_list(lst, obj):
    found = 0
    key = obj.src_addr if obj.from_box() else obj.dst_addr

    if key in lst:
        for item in lst[key]:
            if item == obj:
                if obj.isRetransmission(item):
                    obj.retransmission = True
                elif item.forwarding_time == 0:
                    item.forwarding_time = (obj.timestamp - item.timestamp).microseconds

                    if (item.forwarding_time > 1000 * 200):
                        line = "-" * len(str(item))
                        print(line)
                        print(item)
                        print(obj)
                    break

        lst[key].append(obj)
    else:
        lst[key] = []
        lst[key].append(obj)

to_box = {}
from_box = {}
container = {}
cnt = 0
with open('dumps/Drops_CF_All_V3.verbose.txt.out', 'rt') as file:
    print("Reading file .... ")
    with open('dumps/delayed.txt', 'wt') as delayed:
        while True:
            cnt += 1

            if cnt % 132026 == 0:
                print(cnt * 10 / 132026)
            line = file.readline()

            if not line:
                break

            if "UDP" not in line and "ARP" not in line and "ICMP" not in line and "172.27.70.99" not in line:
                row = PcapLine(line)

                if row.to_box():
                    key = row.dst_addr
                elif row.from_box():
                    key = row.src_addr
                else:
                    raise ValueError("Cannot identify direction in {}".format(str(row)))

                if key not in container:
                    container[key] = []
                else:
                    for record in container[key]:
                        if row == record:
                            if row.is_retransmission(record):
                                row.retransmission = True
                            else:
                                row.forwarding_delay = (row.timestamp - record.timestamp).microseconds
                                if row.forwarding_delay > 1000 * 500:
                                    delayed.write("*" * len(str(record)) + "\n")
                                    delayed.write(str(record) + "\n")
                                    delayed.write(str(row) + "\n")
                            break

                container[key].append(row)
rows, columns = os.popen('stty size', 'r').read().split()

box_to_vip = {}
vip_to_trx = {}
trx_to_vip = {}
vip_to_box = {}
stats = {}
print("computing stats ...")
for ip in container.keys():
    for row in container[ip]:
        create_stats(stats, row)


def create_csv():
    print("creating stat file ...")
    with open('dumps/stats.csv', 'wt') as output:
        header = ";".join(['time', 'box_to_vip_req', 'vip_to_trx_req',
                           'trx_to_vip_req', 'vip_to_box_req', 'vip_to_box_delay',
                           'vip_to_box_fw', 'vip_to_trx_delay', 'vip_to_trx_fw', 'vip_to_box_max', 'vip_to_trx_max'])
        output.write(header + "\n")
        for item in stats.keys():
            out_line = ";".join([str(item),
                                 str(stats[item]['box_to_vip_req']),
                                 str(stats[item]['vip_to_trx_req']),
                                 str(stats[item]['trx_to_vip_req']),
                                 str(stats[item]['vip_to_box_req']),
                                 str(stats[item]['vip_to_box_delay']),
                                 str(stats[item]['vip_to_box_fw']),
                                 str(stats[item]['vip_to_trx_delay']),
                                 str(stats[item]['vip_to_trx_fw']),
                                 str(stats[item]['vip_to_box_max']),
                                 str(stats[item]['vip_to_trx_max']),
                                 ])
            output.write(out_line + "\n")


create_csv()
