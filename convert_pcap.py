import subprocess
import sys
import os

def convert_pcap_to_text(pcap_file, filter):
    print("converting pcap file to verbose text ...")
    out_file = pcap_file + ".out"
    formatted_file = pcap_file + ".txt"
    os.system("tcpdump -nv -r " + pcap_file + " " + filter + " > " + out_file)
    print("removing unnecessary information ...")
    with open(out_file, 'rt') as file:
        with open(formatted_file, 'wt') as out_file:
            out = ""
            start = True
            while True:
                line = file.readline()

                if "IP" in line and "21:" in line:
                    if not start:
                        out_file.write(out + "\n")
                    start = False
                    out = line.replace("\n", "")
                else:
                    out += line.replace("\n", "")

                if not line:
                    out_file.write(out + '\n')
                    break

    print('done converting pcap to text ...')
    return formatted_file