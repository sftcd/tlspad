#!/usr/bin/env python3

import pyshark,sys

fname='/home/stephen/data/tlspad/dumper-20190114-133113.pcap'

f = pyshark.FileCapture(fname,display_filter='ssl')

try:
    for pkt in f:
        print("")
        src=""
        if 'ip' in pkt:
            src=pkt.ip.src
            dst=pkt.ip.dst
        elif 'ipv6' in pkt:
            src=pkt.ipv6.src
            dst=pkt.ipv6.dst
        else:
            print("No sender!\n");
            print(dir(pkt))
            sys.exit(1)
        if 'tcp' in pkt:
            dport=pkt.tcp.dstport
            sport=pkt.tcp.srcport
        else:
            print(dir(pkt.tcp))
            sys.exit(1)
        if 'ssl' not in pkt:
            print("Skipping\n");
            continue
        #if 'app_data' in pkt.ssl:
            #ss="App data"+pkt.ssl['record_length']

        print(src+":"+sport+"->"+dst+":"+dport+"\n")
        print(dir(pkt.ssl))
        print(pkt.ssl)

except Exception as e:
    sys.stderr.write("Exception: " + str(e) + "\n")

