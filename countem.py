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
            continue
        if not hasattr(pkt.ssl,'record_content_type'):
            continue

        if pkt.ssl.record_content_type=="22":
            # handshake
            print("Handsshake")
            print(src+":"+sport+"->"+dst+":"+dport)
            print(dir(pkt.ssl))
            print(pkt.ssl)
        elif pkt.ssl.record_content_type=="23":
            # application data
            print(src+":"+sport+"->"+dst+":"+dport)
            print("RCT: " + pkt.ssl.record_content_type + "APDU length:" + pkt.ssl.record_length)
            

        #print(dir(pkt.ssl))
        #print(pkt.ssl)


except Exception as e:
    sys.stderr.write("Exception: " + str(e) + "\n")

