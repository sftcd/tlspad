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

import os,sys,argparse,re,random
import pyshark

# take file or directory name on command line, default to current dir
fodname="."

# command line arg handling 
argparser=argparse.ArgumentParser(description='Basic parse/print some pcaps')
argparser.add_argument('-f','--file',     
                    dest='fodname',
                    help='PCAP file or direcftory name')
argparser.add_argument('-s','--handshake-seen',     
                    dest='fodname',
                    help='Only start gathering stats after we see the h/s for this session')
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

# structures/function to handle (the bits wer care about from) a TLS session
# given we may have large inputs, we wanna be less wasterful of memory
# so we'll use classes for this

class TLSSession():
    __slots__ = [ 
            'sess_id',
            'src',
            'sport',
            'dst',
            'dport',
            'certsize',
            'cvsize',
            's_psizes',
            'd_psizes'
            ]

    def __init__(self,src='',sport='',dst='',dport=''):
        self.sess_id=random.getrandbits(32)
        self.src=src # client IP (v4 or v6)
        self.sport=sport # client port
        self.dst=dst  # server IP
        self.dport=dport # server port
        self.certsize=0 # cert size if seen in h/
        self.cvsize=0 # cert verify size if seen in h/s
        self.s_psizes=[] # list of APDU sizes from src, 0 is 1st, 1 2nd seen etc.
        self.d_psizes=[] # list of APDU sizes from dst, 0 is 1st, 1 2nd seen etc.

    def __str__(self):
        return "ID: " + str(self.sess_id) + "\n" + \
                "\t" + self.src + ":" + self.sport + "->" + self.dst + ":" + self.dport + \
                    " cert: " +  str(self.certsize) + " cv size: " + str(self.cvsize) + "\n" +  \
                "\t" + "source  packet sizes: " + str(self.s_psizes) + "\n" + \
                "\t" + "dest packet sizes: " + str(self.d_psizes) 

    def add_apdu(self,size,src):
        if src==True:
            self.s_psizes.append(size)
        elif src==False:
            self.d_psizes.append(size)
        else:
            raise ValueError('Bad boolean given to add_apdu')

def sess_find(sessions,src,sport,dst,dport):
    for s in sessions:
        if s.src==src and s.sport==sport and s.dst==dst and s.dport==dport:
            return s
        elif s.src==dst and s.sport==dport and s.dst==src and s.dport==sport:
            return s
    # otherwise make a new one
    s=TLSSession()
    # extend this set of know server ports sometime
    if dport==443 or dport==993:
        s.src=src
        s.sport=sport
        s.dst=dst
        s.dport=dport
    else:
        s.src=src
        s.sport=sport
        s.dst=dst
        s.dport=dport
    sessions.append(s)
    #print(s)
    return s

# our array of TLS sessions
sessions=[]

# iterate through each file, gathering our stats
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
                print("Not a TCP packet!")
                print(dir(pkt))
                print(pkt)
                sys.exit(1)
            if 'ssl' not in pkt:
                continue
            if not hasattr(pkt.ssl,'record_content_type'):
                continue

            # see if this is a known session or not
            this_sess=sess_find(sessions,src,sport,dst,dport)
    
            if pkt.ssl.record_content_type=="22":
                # handshake
                if hasattr(pkt.ssl,'handshake_type'):
                    if pkt.ssl.handshake_type=="1":
                        #print("ClientHello")
                        pass
                    elif pkt.ssl.handshake_type=="2":
                        #print("ServerHello")
                        pass
                    elif pkt.ssl.handshake_type=="4":
                        #print("NewSessionTicket")
                        pass
                    elif pkt.ssl.handshake_type=="11":
                        #print("Certificate")
                        pass
                    elif pkt.ssl.handshake_type=="12":
                        #print("ServerKeyExchange")
                        pass
                    elif pkt.ssl.handshake_type=="16":
                        #print("ClientKeyExchange")
                        pass
                    elif pkt.ssl.handshake_type=="15":
                        #print("CertificateVerify")
                        pass
                    else:
                        print("Handsshake: " + pkt.ssl.handshake_type)
                        print(src+":"+sport+"->"+dst+":"+dport)
                        print(dir(pkt.ssl))
                        print(pkt.ssl)
                else:
                    print("Weird Handsshake: ")
                    print(src+":"+sport+"->"+dst+":"+dport)
                    print(dir(pkt.ssl))
                    print(pkt.ssl)
            elif pkt.ssl.record_content_type=="23":
                # application data
                #print(src+":"+sport+"->"+dst+":"+dport)
                #print("RCT: " + pkt.ssl.record_content_type + "APDU length:" + pkt.ssl.record_length)
                this_sess.add_apdu(pkt.ssl.record_length,(this_sess.src==src))
            #print(dir(pkt.ssl))
            #print(pkt.ssl)
        f.close()
    except Exception as e:
        sys.stderr.write("Exception: " + str(e) + "\n")
 
for s in sessions:
    print(s)
