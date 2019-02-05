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

# Work-in-progress, may be abandonded but let's try and see...

# Produce a set of .wav files from the TLS sessions seen in a pcap
# Very much a first cut. And possibly useless, but let's see...

# Goals:
# analyse the TLS sessions to get APDU packets sizes and times
# for each TLS session from a given source IP generate a .wav file
# each packet is turned into a sound via parameters
# parameters:
# - sample freq, default: 44100Hz (audio CD)
# - min note length: default: 100ms shortest note (to translate size -> duration)
#     - this is a proxy for bandwidth
# - overall freq range: default: (bottom=30Hz, top=4000Hz)
#     - based on: https://en.wikipedia.org/wiki/Piano_key_frequencies

# Derived values, for each source IP/wav file:
# - each destination IP gets a range of frequencies, 
#   - divide overall freq range into equal chunks, per dest IP
#   - bottom half or per-dest range for src->dst, top half for dst->src
#   - packet size used to select frequency within range
#   - packet size used to select sound duration based on bandwidth

# Audio sample at time t is the average of notes at that time
# (maybe, have to see...)

# Might try use https://github.com/ttm/mass (via pip install music) and
# see if it works or not...

import traceback
import os,sys,argparse,re,random,time
import pyshark
from TlsPadFncs import *

# take file or directory name on command line, default to current dir
fodname="."

# sample frequency (Hz)
sample_freq=44100

# min note length (ms)
min_note_length=100

# lowest note (Hz)
lowest_note=30

# highest note (Hz)
highest_note=4000

# command line arg handling 
argparser=argparse.ArgumentParser(description='Turn some pcaps into music')
argparser.add_argument('-f','--file',     
                    dest='fodname',
                    help='PCAP file or direcftory name')
argparser.add_argument('-F','--freq',
                    dest='freq',
                    help='Sample frequency (default: 44100Hz)')
argparser.add_argument('-m','--min-note',
                    dest='min_note',
                    help='minumum note length (100ms)')
argparser.add_argument('-L','--low-note',
                    dest='low_note',
                    help='lowest note (default: 30Hz)')
argparser.add_argument('-H','--high-note',
                    dest='high_note',
                    help='highest note (default: 4000Hz)')
args=argparser.parse_args()

if args.fodname is not None:
    fodname=args.fodname

if args.freq is not None:
    # TODO: sanity check later
    sameple_freq=args.freq

if args.min_note is not None:
    # TODO: sanity check later
    min_note_length=args.min_note

if args.low_note is not None:
    # TODO: sanity check later
    lowest_note=args.low_note

if args.high_note is not None:
    # TODO: sanity check later
    highest_note=args.high_note

def size2freq(size,minsize,maxsize,c2s_direction,lowfreq,highfreq,bucketno,nbuckets):
    # map a (packet) size into a frequency based on the low and high
    # frequecies, the number of buckets (TLS sessions involving same
    # src IP) and the packet direction 
    bucketrange=(highfreq-lowfreq)/2
    bucketsize=bucketrange/nbuckets
    bottomstep=lowfreq+stepsize*bucketno
    topstep=bottomstep+stepsize
    if c2s_direction:
        # top half of range is for svr->client
        bottomstep+=(stepsize/2)
        topstep+=(stepsize/2)
    sizerange=(maxsize-minsize)/2
    sizestep=sizerange/nbuckets
    return size/stepsize 

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

# our array of TLS sessions
sessions=[]

analyse_pcaps(flist,sessions)
print("Found " + str(len(sessions)) + " sessions.\n")

class wav_details():
    __slots__ = [
            'fname',
            'src',
            'nsessions',
            'earliest',
            'latest',
            'overall_duration',
            'min_pdu',
            'max_pdu'
            ]

    def __init__(self,fname,src,nsessions=0,earliest=0,latest=-1,overall_duration=0,min_pdu=0,max_pdu=0):
        self.fname=fname
        self.src=src
        self.nsessions=nsessions
        self.earliest=earliest
        if latest is -1:
            self.latest=earliest
        else:
            self.latest=latest
        self.overall_duration=overall_duration
        self.min_pdu=min_pdu
        self.max_pdu=max_pdu

    def __str__(self):
        return("Wav file: " + self.fname + "sessions: " + str(self.nsessions) + "\n" + \
                "\t" + "Start: " + str(self.earliest) + " End: " + str(self.latest) + " Dur: " + str(self.latest-self.earliest))


def find_wav(wavs,ip):
    '''
    search for wav_details mwith matching src IP
    '''
    for w in wavs:
        if w.src==ip:
            return w
    return None

def init_key():
    '''
    return a random 128 bit value, we'll use as a HMAC key below
    '''
    return random.getrandbits(128)

def hash_name(key,fname,src):
    '''
    based on (first) pcap file name and src-ip and a per-run secret
    generate a file name - we do this as a privacy enhancement
    (but it absolutely needs other pcap anonymisation tools I've
    yet to find)
    TODO: write/import HMAC-SHA256
    '''
    return hmac_sha256(key,fname+src)

    

# we'll keep a wav_detail for each
wav_arr=[]
# just for quick checking
src_ips=[]

for s in sessions:
    w=find_wav(wav_arr,s.src)
    if w is None:
        src_ips.append(s.src)
        try:
            #print("Option1: " + str(s.end_time.timestamp()))
            w=wav_details(s.fname,s.src,nsessions=1,earliest=s.timestamp,latest=s.end_time.timestamp())
        except:
            #print("Option2: " + " val: " + str(s.end_time))
            w=wav_details(s.fname,s.src,nsessions=1,earliest=s.timestamp)
        wav_arr.append(w)
    else:
        w.nsessions += 1
    if s.timestamp < w.earliest:
        #print("Re-assign early from:" + str(w.earliest) + " to: " + str(s.timestamp) + " diff: " + str(w.earliest-s.timestamp))
        w.earliest=s.timestamp
    try:
        # end_time might be 0 in which case nothing to do
        if s.end_time.timestamp() > w.latest:
            #print("Re-assign late from:" + str(w.latest) + " to: " + str(s.end_time.timestamp()) + " diff: " + str(s.end_time.timestamp()-w.latest))
            w.latest=s.end_time.timestamp()
    except:
        pass

for w in wav_arr:
    print(str(w))


