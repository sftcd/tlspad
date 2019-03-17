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

# Generate some stats for the TLS sessions seen in a set of pcap
# files

import traceback,math
import os,sys,argparse,re,random,time,ipaddress
import pyshark
from TlsPadFncs import *

# stuff for graphics
import numpy as np
import matplotlib
# uncomment below if you want interactive plots
matplotlib.use('agg')
import matplotlib.pyplot as plt
import matplotlib.cm as cm
from scipy.ndimage.filters import gaussian_filter

def selector_match(s,sels,sl=""):
    '''
    check if TLS session matches selector
    selector is a (list of) IP prefixes (v4/v6)
    '''
    matches=False
    thesel=""
    mbranch="0"
    #smverbose=args.verbose:
    smverbose=False
    if smverbose:
        print("Checking " + str(s.sess_id) +  " vs. Sels="+str(sels)+" type(sels): " + str(type(sels)) + " sl: " + str(sl))
        print("src: " + s.src + " dst: " + s.dst)
    if type(sels)==str and sels=='all': 
        mbranch="1"
        matches=True
        thesel="all"
    elif type(sels)==str and sels=='src' and sl is not None and sl==s.src: 
        mbranch="2"
        matches=True
        matches=True
        thesel="src"
    elif type(sels)==str and sels=='dst' and sl is not None and sl==s.dst: 
        mbranch="3"
        matches=True
        thesel="dst"
    elif type(sels)==list:
        if sl is not None:
            if s.src==sl:
                mbranch="6"
                matches=True
                thesel=sl
            elif s.dst==sl:
                mbranch="7"
                matches=True
                thesel=sl
        if not matches:
            for sel in sels:
                ipsel=ipaddress.ip_network(sel)
                if smverbose:
                    print("Inner checking " + s.src + " vs: " + str(ipsel))
                if ipaddress.ip_address(s.src) in ipsel:
                    mbranch="4"
                    matches=True
                    thesel=s.src
                if not matches and smverbose:
                    print("Inner checking " + s.dst + " vs: " + str(ipsel))
                if not matches and ipaddress.ip_address(s.dst) in ipsel:
                    mbranch="5"
                    matches=True
                    thesel=s.dst
                if matches:
                    break
    if smverbose:
        print("Checked " + str(s.sess_id) +  " vs. " + str(sels) + " result: " + str(matches) + " " + thesel + " branch:" + mbranch)
    return matches,thesel


# heatmap stuff - not currently used, go check out URL below if thinking of putting it back in
# taken from https://stackoverflow.com/questions/2369492/generate-a-heatmap-in-matplotlib-using-a-scatter-data-set
def myplot(x, y, s, bins=1000):
    heatmap, xedges, yedges = np.histogram2d(x, y, bins=bins)
    heatmap = gaussian_filter(heatmap, sigma=s)
    extent = [xedges[0], xedges[-1], yedges[0], yedges[-1]]
    return heatmap.T, extent


# check if file or directory
def check_fod(onename,flist,recurse):
    #print("check_fod - entering to check " + onename)
    #print(flist)
    # if onename is a directory get all '*.pcap[number]' file names therin
    if os.path.isdir(onename):
        pass
        tfiles = [f for f in os.listdir(onename) if re.match(r'.*\.pca(p|p[0-9])$', f)]
        if len(tfiles)!=0:
            for t in tfiles:
                flist.add(onename+"/"+t)
        if recurse:
            tdirs=[d for d in os.listdir(onename) if os.path.isdir(onename+"/"+d)]
            for thedir in tdirs:
                # recurse!
                #print("check_fod - recursing into " + thedir)
                #print(flist)
                check_fod(onename+"/"+thedir,flist,recurse)
    else:
        # if onename is not a directory add to list if file exists
        if os.path.exists(onename):
            flist.add(onename)

# main line code...

# file or direcory name
fodname="."

# max delay for which we bother with a graph (in ms)
# could make this a command line arg I guess
maxdelay=18000

# command line arg handling 
argparser=argparse.ArgumentParser(description='Generate some stats for one or more pcaps')
argparser.add_argument('-f','--file',     
                    dest='fodname',
                    help='PCAP file or directory name')
argparser.add_argument('-i','--ipfile',
                    dest='selectors',
                    help='select output sets based on IPs in file')
argparser.add_argument('-r','--recurse',
                    help='recurse down directories finding pcaps',
                    action='store_true')
argparser.add_argument('-v','--verbose',
                    help='produce more output',
                    action='store_true')
args=argparser.parse_args()

if args.fodname is not None:
    fodname=args.fodname

# default is to group by SRC IP
selectors='all'
if args.selectors is not None:
    # check if file-name, that exists and has a set of prefixes
    # we'll ignore any non-matching sessions
    try:
        with open(args.selectors) as vf:
            selectors=vf.readlines()
        # chew whitespace and CRLFs
        selectors = [x.strip() for x in selectors if not x.startswith('#')]
    except:
        print(sys.argv[0] + ": Error reading IP prefixes from " + args.vantage + " - exiting")
        sys.exit(2)
    # check if those are really IP addresses/prefixes, if not - chuck 'em
    for sel in selectors:
        try:
            ipsel=ipaddress.ip_network(sel)
        except:
            selectors.remove(sel)
            print("Chucking " + sel + " as it doesn't seem to be an IP address")
    if args.verbose:
        print("Selectors set: " + str(selectors))

# make list of file names to process
flist=set()
# input string could be space sep list of file or directory names
for onename in fodname.split():
    check_fod(onename,flist,args.recurse)

if len(flist)==0:
    print(sys.argv[0]+ ": No input files found - exiting")
    sys.exit(1)

# we'd like to go through things in the same order, if the files
# on disk haven't changed
flist=sorted(flist)

# our array of TLS sessions
if args.verbose:
    print("Running  " + sys.argv[0] +  " verbosely...")
    print("Reading pcaps...")
    print(flist)

sessions=[]
analyse_pcaps(flist,sessions,args.verbose)
if args.verbose:
    print("Found " + str(len(sessions)) + " sessions.\n")

# Check if file exists with IPs to ignore...
# Mostly this is for ignoring DNS queries/answers that tend to  
# muck up our noise/music and that'd only be seen from some
# vantage points, OTOH, if we can't see the DNS queries/answers
# then we'd likely also not see the JS code being loaded from
# 3rd party sites, so probably won't use much, but keep code
# just in case
block_arr=[]
bafile='ignore.addrs'
try:
    with open(bafile) as ba:
        block_arr=ba.readlines()
    block_arr = [x.strip() for x in block_arr]
except:
    pass
if args.verbose:
    if len(block_arr)==0:
        print("No addresses to ignore from " + bafile + " (maybe file isn't there?)")
    else:
        print("Addresses to ignore: " + str(block_arr))

#points=[]
xpoints=[]
ypoints=[]
cxpoints=[]
cypoints=[]
sxpoints=[]
sypoints=[]
# group our sessions according to selector
# and keep tabs on overall duration of sessions in groups
for s in sessions:
    if s.dst in block_arr or s.src in block_arr:
        if args.verbose:
            print("Ignoring blocked session: " + s.src + "->" + s.dst)
        continue
    if type(selectors)!= str:
        matches,sel=selector_match(s,selectors)
        if not matches:
            if args.verbose:
                print("Skipping session: " + s.src + "->" + s.dst)
        continue
    # numbers for each session:
    # sess_id
    # for both c2s and s2c direction
    # number of packets in that dir
    # mix pdu
    # max pdu
    # duration
    # num_sizes
    c2sc=len(s.s_delays)
    s2cc=len(s.d_delays)
    duration=0
    if c2sc != 0 or s2cc !=0: 
        duration=max(s.s_delays+s.d_delays)
    min_pdu=0
    if s.min_pdu!=sys.maxsize:
        min_pdu=s.min_pdu
    if args.verbose:
        print([s.sess_id,duration,s.num_sizes,c2sc,s2cc,min_pdu,s.max_pdu])
    if c2sc != 0:
        cxpoints+=s.s_delays
        cypoints+=s.s_psizes
    if s2cc != 0:
        sxpoints+=s.d_delays
        sypoints+=s.d_psizes

print("Processsed " + str(len(sessions)) + " TLS session")

plt.plot(cxpoints, cypoints, 'g.', label="c2s")
plt.plot(sxpoints, sypoints, 'b.', label="s2c")
plt.xlabel("Time (ms)")
plt.ylabel("Packet size (octets)")
plt.title("Tls2Numbers.py -f " + fodname)
plt.xlim([0,maxdelay])
plt.ylim([0,maxdelay])

imgname=fodname+".tls2n.png"
if fodname=='.':
    imgname="cwd.tls2n.png"
plt.savefig(imgname,dpi=600)

# interactive plot - you need to have uncommented the 'agg' line at the start
# plt.show()
