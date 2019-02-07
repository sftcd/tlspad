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

# Produce a set of .wav and .midi files from the TLS sessions seen in a pcap
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

import traceback,math
import os,sys,argparse,re,random,time
import pyshark
from TlsPadFncs import *

# for file name hashing
import hmac,hashlib,base64

# for sorting
from operator import itemgetter

# take file or directory name on command line, default to current dir
fodname="."

# sample frequency (Hz)
sample_freq=44100

# min note length (ms)
min_note_length=100

# longest note 
max_note_length=1000

# lowest note (Hz)
lowest_note=30

# highest note (Hz)
highest_note=4000

# midi output wanted
domidi=True

# wav output wanted
dowav=False

# hacky beeps
from beeps import *

# midi instrument number
# there's a list at https://www.midi.org/specifications/item/gm-level-1-sound-set
# that list may be offset by 1, i.e. we start at 0
instrumentnum=1 # piano
#instrumentnum=19 # choral organ

# command line arg handling 
argparser=argparse.ArgumentParser(description='Turn some pcaps into music')
argparser.add_argument('-f','--file',     
                    dest='fodname',
                    help='PCAP file or directory name')
argparser.add_argument('-F','--freq',
                    dest='freq',
                    help='Sample frequency (default: 44100Hz)')
argparser.add_argument('-m','--min-note',
                    dest='min_note',
                    help='minumum note length (100ms)')
argparser.add_argument('-M','--max-note',
                    dest='max_note',
                    help='maximum note length (1s)')
argparser.add_argument('-L','--low-note',
                    dest='low_note',
                    help='lowest note (default: 30Hz)')
argparser.add_argument('-H','--high-note',
                    dest='high_note',
                    help='highest note (default: 4000Hz)')
argparser.add_argument('-i','--instrument',
                    type=int, dest='instrument',
                    help='midi instrument (0:127; default: 0)')
argparser.add_argument('-w','--wav',
                    help='beepy wav file output as well as midi',
                    action='store_true')
argparser.add_argument('-v','--verbose',
                    help='produce more output',
                    action='store_true')
args=argparser.parse_args()

if args.fodname is not None:
    fodname=args.fodname

if args.freq is not None:
    # TODO: sanity check later
    sample_freq=args.freq

if args.min_note is not None:
    # TODO: sanity check later
    min_note_length=args.min_note

if args.max_note is not None:
    # TODO: sanity check later
    max_note_length=args.max_note

if args.low_note is not None:
    # TODO: sanity check later
    lowest_note=args.low_note

if args.high_note is not None:
    # TODO: sanity check later
    highest_note=args.high_note

if args.instrument is not None:
    if args.instrument < 0 or args.instrument >127:
        print("Error: instruments must be integers from 0 to 127")
        sys.exit(1)
    instrumentnum=args.instrument

def size2freqdur(size,minsize,maxsize,c2s_direction,lowfreq,highfreq,bucketno,nbuckets):
    # map a (packet) size into a frequency and duration based on the low 
    # and high frequecies, the number of buckets (TLS sessions involving 
    # same src IP) and the packet direction 

    # frequency range for this bucket
    frange=(highfreq-lowfreq)/nbuckets
    bottomstep=lowfreq+frange*bucketno
    topstep=bottomstep+frange/2
    if not c2s_direction:
        # top half of range is for svr->client
        bottomstep+=(frange/2)
        topstep+=(frange/2)
    freq=topstep-size/minsize
    # duration is min 100ms and max 1s and is distributed evenly according 
    # to min and max pdu sizes
    if maxsize-minsize == 0:
        # likely not what's wanted but let's see...
        normalised=size
    else:
        normalised=(size-minsize)/(maxsize-minsize)
    duration=int(min_note_length+normalised*(max_note_length-min_note_length))
    return freq, duration

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

class the_details():
    '''
    Each .wav,.midi file etc will have these parameters
    '''
    __slots__ = [
            'fname',
            'src',
            'nsessions',
            'earliest',
            'latest',
            'overall_duration',
            'min_pdu',
            'max_pdu',
            'this_session',
            'notes'
            ]

    def __init__(self,fname,src,nsessions=0,earliest=0,latest=-1,overall_duration=0,min_pdu=sys.maxsize,max_pdu=0,this_session=0):
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
        self.this_session=this_session
        self.notes=[]

    def __str__(self):
        return("Details for " + self.fname + ": sessions: " + str(self.nsessions) + "\n" + \
                "\t" + "Start: " + str("%.02F"%self.earliest) + " End: " + str("%.02F"%self.latest) + " Dur: " + str("%.02f"%(self.overall_duration/1000)) + "\n" + \
                "\t" + "Min PDU: " + str(self.min_pdu) + " Max PDU: " + str(self.max_pdu) + "\n" + \
                "\t" + "Notes:\n" + '\n'.join(' '.join(map(str,note)) for note in self.notes))

def find_details(wavs,ip):
    '''
    search for the_details mwith matching src IP
    '''
    for w in wavs:
        if w.src==ip:
            return w
    return None

def init_key():
    '''
    return a random 32 character string, we'll use as a HMAC key below
    '''
    return open("/dev/urandom","rb").read(32)

def hash_name(key,fname,src):
    '''
    based on (first) pcap file name and src-ip and a per-run secret
    generate a wav file name - we do this as a privacy enhancement
    (but it absolutely needs other pcap anonymisation tools I've
    yet to find)
    '''
    # init secret once per run
    if key==None:
        key=init_key()
    m=fname+src
    hmacval = hmac.new(key, msg=m.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
    # we'll truncate as collisions aren't a deal for this
    return hmacval[0:15]

def freq2num(freq):
    '''
    map a frequency in Hz to a midi note number
    according to https://newt.phys.unsw.edu.au/jw/notes.html
    we map this via:
    midinum  =  12*log2(freq/440 Hz) + 69
    I checked the accuracy of this and it seems good based on
    the map at the above URL
    '''
    mnum=12*int(math.log2(freq/440))+69
    #print("Mapped " + str(freq) + " to " + str(mnum))
    return mnum

def size2num(size,righthand,table):
    '''
    Map sizes to midikeys based on a table we build up from
    sizes/keys used, with the right hand for c2s and the left
    hand for s2c packets
    '''
    notemin=21
    notemax=108
    if size in table:
        return table[size]
    if len(table) == 0:
        # initialise
        if righthand:
            table[size]=60 # middle-C
        else:
            table[size]=60 # B below middle-C
    lowest=min(table.items(), key=lambda x: x[1])[1]
    biggest=max(table.items(), key=lambda x: x[1])[1]

    low_num=freq2num(lowest_note)
    high_num=freq2num(highest_note)
    # work our way higher on right hand (c2s) and down
    # the keyboard on left hand (s2c) but don't go
    # past the last keys
    if righthand:
        if biggest < high_num: 
            table[size]=biggest+1
        else:
            table[size]=high_num
    else:
        if lowest > low_num:
            table[size]=lowest-1
        else:
            table[size]=low_num
    return table[size]

# main line code...

# our array of TLS sessions
if args.verbose:
    print("Reading pcaps...")
    print(flist)
sessions=[]
analyse_pcaps(flist,sessions)
if args.verbose:
    print("Found " + str(len(sessions)) + " sessions.\n")

# a per-run hmac secret, just used for file name hashing so not really sensitive
hmac_secret=None

# we'll keep a the_detail for each
the_arr=[]
# just for quick checking
src_ips=[]

for s in sessions:
    w=find_details(the_arr,s.src)
    if w is None:
        wname=hash_name(hmac_secret,s.fname,s.src)
        src_ips.append(s.src)
        try:
            #print("Option1: " + str(s.end_time.timestamp()))
            w=the_details(wname,s.src,nsessions=1,earliest=s.timestamp,latest=s.end_time.timestamp())
        except:
            #print("Option2: " + " val: " + str(s.end_time))
            w=the_details(wname,s.src,nsessions=1,earliest=s.timestamp)
        the_arr.append(w)
    else:
        w.nsessions += 1

    # possibly update overall timing of w
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

    # possibly extend duration based on last packet timing
    if len(s.s_delays) > 0 :
        lst=s.timestamp+s.s_delays[-1]
    else: 
        lst=0
    if len(s.d_delays) > 0 :
        lrt=s.timestamp+s.d_delays[-1]
    else:
        lrt=0
    lt=max(lst,lrt)
    if lt>w.latest:
        w.latest=lt

    # update overall duration
    w.overall_duration=w.latest-w.earliest

    # check if we've new min/max PDU sizes
    if len(s.s_psizes) > 0:
        m1=min(s.s_psizes)
    else:
        m1=sys.maxsize
    if len(s.d_psizes) > 0:
        m2=min(s.d_psizes)
    else:
        m2=sys.maxsize
    minspdu=int(min(m1,m2))
    if minspdu < w.min_pdu:
        w.min_pdu=minspdu

    if len(s.s_psizes) > 0:
        m1=max(s.s_psizes)
    else:
        m1=0
    if len(s.d_psizes) > 0:
        m2=max(s.d_psizes)
    else:
        m2=0
    maxspdu=int(max(m1,m2))
    if maxspdu > w.max_pdu:
        w.max_pdu=maxspdu

# loop again through sessions to pick up PDU details
for s in sessions:
    w=find_details(the_arr,s.src)
    if w is None:
        raise ValueError('No details for session: ' + s.sess_id)
    for i in range(0,len(s.s_psizes)):
        freq,dur=size2freqdur(s.s_psizes[i],w.min_pdu,w.max_pdu,True,lowest_note,highest_note,w.this_session,w.nsessions)
        w.notes.append([freq,dur,s.s_delays[i],s.s_psizes[i],True,w.this_session])
    for i in range(0,len(s.d_psizes)):
        freq,dur=size2freqdur(s.d_psizes[i],w.min_pdu,w.max_pdu,True,lowest_note,highest_note,w.this_session,w.nsessions)
        w.notes.append([freq,dur,s.d_delays[i],s.d_psizes[i],False,w.this_session])
    w.this_session += 1

# sort notes timewise
for w in the_arr:
    w.notes=sorted(w.notes, key=itemgetter(2))

# write out midicsv file, one per src ip
# to play such:
#   $ csvmidi <hash>.midi.csv <hash>.midi
#   $ timidity <hash>.midi
for w in the_arr:
    print("Saving " + w.fname + ".midi.csv")
    # we'll just keep an array of strings with one line per and won't
    # bother making a python CSV structure
    midicsv=[]
    # table version
    table={}
    for note in w.notes:
        # freq2note version
        #notenum=freq2num(note[0])
        # table version
        notenum=size2num(note[3],note[4],table)
        ontime=int(note[1])
        offtime=int(note[1]+note[2])
        if note[2]<100:
            offtime+=100
        # odd structure here is so we can sort on time in a sec...
        midicsv.append([note[5]+2,ontime,",note_on_c,",note[5]+1,notenum,",81"])
        midicsv.append([note[5]+2,offtime,",note_off_c,",note[5]+1,notenum,",0"])
    midicsv.sort(key=itemgetter(1))
    midicsv.sort(key=itemgetter(0))
    # TODO: maybe eliminate any silence > say 2s? shouldn't be hard with this str.
    with open(w.fname+".midi.csv","w") as f:
        # precursor
        f.write('0, 0, Header, 1, '+str(w.nsessions+1)+', 480\n\
1, 0, Start_track\n\
1, 0, Title_t, "Tls2Music ' + w.fname + '"\n\
1, 0, Text_t, "see https://github.com/sftcd/tlspad/"\n\
1, 0, Copyright_t, "This file is in the public domain"\n\
1, 0, Time_signature, 4, 2, 24, 8\n\
1, 0, Tempo, 500000\n\
1, 0, End_track\n\
2, 0, Start_track\n\
2, 0, Program_c, 1, ' + str(instrumentnum) + '\n')
        current_track=midicsv[0][0]
        last_track_end=0
        for line in midicsv:
            if line[0]!=current_track:
                f.write(str(current_track)+', '+str(last_track_end)+', End_track\n')
                current_track=line[0]
                f.write(str(current_track)+', 0, Start_track\n')
                f.write(str(current_track)+', 0, Program_c,'+str(current_track-1)+','+str(instrumentnum) + '\n')
            last_track_end=line[1]
            f.write(str(line[0])+","+str(line[1])+line[2]+str(line[3])+","+str(line[4])+line[5]+"\n")
        f.write(str(current_track)+', '+str(last_track_end)+', End_track\n')
        f.write('0, 0, End_of_file\n')
        f.close()
    del midicsv
    # table version
    # print(table)
    del table

# write out .wav files, one per src ip
if args.wav:
    for w in the_arr:
        print("Saving " + w.fname + ".wav")
        # print(str(w))

        # Audio will contain a long list of samples (i.e. floating point numbers describing the
        # waveform).  If you were working with a very long sound you'd want to stream this to
        # disk instead of buffering it all in memory list this.  But most sounds will fit in 
        # memory.
        waudio = []
        # make space for required duration plus 2s
        append_silence(audio=waudio,sample_rate=sample_freq,duration_milliseconds=w.overall_duration+2000)
        for note in w.notes:
            inject_sinewave(audio=waudio,sample_rate=sample_freq,freq=note[0],start_time=note[2],duration_milliseconds=note[1],volume=0.25)
        save_wav(w.fname+".wav",audio=waudio,sample_rate=sample_freq)


