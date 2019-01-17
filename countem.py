#!/usr/bin/env python3

# Copyright (c) 2019 Stephen Farrell, stephen.farrell@cs.tcd.ie
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# TLS parameters (numbers used below variously) are found at:
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

import os,sys,argparse,re
import pyshark

# take file or directory name on command line, default to current dir
fodname="."

# command line arg handling 
argparser=argparse.ArgumentParser(description='Basic parse/print some pcaps')
argparser.add_argument('-f','--file',     
                    dest='fodname',
                    help='PCAP file or direcftory name')
args=argparser.parse_args()

if args.fodname is not None:
    fodname=args.fodname

# make list of file names to process
flist=set()
# input string could be space sep list of file or directory names
for onename in fodname.split():
    # if onename is a directory get all '*.pcap[number]' file names therin
    if os.path.isdir(onename):
        pass
        tfiles = [f for f in os.listdir(onename) if re.match(r'.*\.pcap[0-9]*', f)]
        if len(tfiles)!=0:
            for t in tfiles:
                flist.add(onename+"/"+t)
    else:
        # if onename is not a directory add to list if file exists
        if os.path.exists(onename):
            flist.add(onename)

if len(flist)==0:
    print("No input files found - exiting")
    sys.exit(1)

for fname in flist:
    print("Processing " + fname)
    try:
        f = pyshark.FileCapture(fname,display_filter='ssl')
        for pkt in f:
            src=""
            if 'ip' in pkt:
                src=pkt.ip.src
                dst=pkt.ip.dst
            elif 'ipv6' in pkt:
                src=pkt.ipv6.src
                dst=pkt.ipv6.dst
            else:
                print("No sender!");
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
                if hasattr(pkt.ssl,'handshake_type'):
                    if pkt.ssl.handshake_type=="1":
                        print("Client Hello")
                    elif pkt.ssl.handshake_type=="2":
                        print("Server Hello")
                    elif pkt.ssl.handshake_type=="11":
                        print("Certificate")
                    elif pkt.ssl.handshake_type=="15":
                        print("CertificateVerify")
                    else:
                        print("Handsshake: " + pkt.ssl.handshake_type)
                else:
                    print("Weird Handsshake: ")
                    print(dir(pkt.ssl))
                    print(pkt.ssl)
                print(src+":"+sport+"->"+dst+":"+dport)
            elif pkt.ssl.record_content_type=="23":
                # application data
                print(src+":"+sport+"->"+dst+":"+dport)
                print("RCT: " + pkt.ssl.record_content_type + "APDU length:" + pkt.ssl.record_length)
            #print(dir(pkt.ssl))
            #print(pkt.ssl)
        f.close()
    except Exception as e:
        sys.stderr.write("Exception: " + str(e))
    
