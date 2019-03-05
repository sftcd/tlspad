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

import traceback
import os,sys,argparse,re,random,time
import pyshark
from TlsPadFncs import *

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
    print(sys.argv[0] + ": No input files found - exiting")
    sys.exit(1)

# our array of TLS sessions
sessions=[]

analyse_pcaps(flist,sessions,False)
print("Found " + str(len(sessions)) + " sessions.\n")
for s in sessions:
    print(s)
    time.sleep(0.01) 

