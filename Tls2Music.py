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

# hacky beeps
from beeps import *

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

# label for output files
label=None

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
            'num_sizes',
            'this_session',
            'pdu_sizes',
            'notes'
            ]
    def __init__(self,fname,src,nsessions=0,earliest=0,latest=-1,overall_duration=0,min_pdu=sys.maxsize,max_pdu=0,num_sizes=0,this_session=0):
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
        self.num_sizes=num_sizes
        self.pdu_sizes=set()
        self.this_session=this_session
        self.notes=[]
    def __str__(self):
        return("Details for " + self.fname + ": session: " + str(self.this_session) + " of " + str(self.nsessions) + "\n" + \
                "\t" + "Start: " + str("%.02F"%self.earliest) + " End: " + str("%.02F"%self.latest) + " Dur: " + str("%.02f"%(self.overall_duration/1000)) + "\n" + \
                "\t" + "Min PDU: " + str(self.min_pdu) + " Max PDU: " + str(self.max_pdu) + " Num sizes: " + str(self.num_sizes) + "\n" + \
                "\t" + "Notes:\n" + '\n'.join(' '.join(map(str,note)) for note in self.notes))

# midi instrument number
# there's a list at https://www.midi.org/specifications/item/gm-level-1-sound-set
# that list may be offset by 1, i.e. we start at 0
instrumentnum=1 # piano
#instrumentnum=19 # choral organ
# TODO: add an array of 16 instruments, one per channel
instarr=[ 
        0, # acoustic grand piano
        9, # glockenspiel 
        21, # accordian
        25, # steel guitar

        33, # electric bass
        40, # violin
        42, # cello
        56, # trumpet

        57, # trombone
        66, # tenor sax
            # channel 10 is drums of various kinds with restrictions on what note numbers can be used
        71, # clarinet
        79, # ocarina

        105, # banjo
        109, # bag pipe
        114, # steel drums
        103, # FX 8 (sci-fi) (huh?)
        ]


# command line arg handling 
argparser=argparse.ArgumentParser(description='Turn some pcaps into music')
argparser.add_argument('-l','--label',     
                    dest='label',
                    help='basename label for midi.csv and .wav output files')
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
                    help='midi instrument (-1:127; default: 0; -1 means built-in combo)')
argparser.add_argument('-N','--notegen',
                    dest='notegen',
                    choices=['table','freq'],
                    help='generate notes from "table" or "freq"')
argparser.add_argument('-w','--wav',
                    help='beepy wav file output as well as midi',
                    action='store_true')
argparser.add_argument('-v','--verbose',
                    help='produce more output',
                    action='store_true')
argparser.add_argument('-T','--logtime',     
                    help='use logarithmic time',
                    action='store_true')
argparser.add_argument('-S','--scaledtime',     
                    help='use scaled time (read code for details:-)',
                    action='store_true')
argparser.add_argument('-A','--allinone',     
                    help='produce only one midi file for all sessions',
                    action='store_true')
argparser.add_argument('-s','--suppress-silence',     
                    type=int, dest='suppress_silence',
                    help='suppress <num> ms of no-change (not really silence but good enough')
args=argparser.parse_args()

if args.fodname is not None:
    fodname=args.fodname

if args.freq is not None:
    sample_freq=args.freq

if args.min_note is not None:
    min_note_length=args.min_note

if args.max_note is not None:
    max_note_length=args.max_note

if args.low_note is not None:
    lowest_note=args.low_note

if args.high_note is not None:
    highest_note=args.high_note

if args.instrument is not None:
    if args.instrument < -1 or args.instrument >127:
        print("Error: instruments must be integers from 0 to 127")
        sys.exit(1)
    instrumentnum=args.instrument

if args.label is not None:
    label=args.label

if args.notegen is not None:
    if args.notegen != "table" and args.notegen != "freq":
        print("Error: -N [table|freq] needed, value given: |" + str(args.notegen) + "| - exiting")
        print(args.notegen)
        sys.exit(2)

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

def size2freqdur(size,minsize,maxsize,c2s_direction,lowfreq,highfreq,channel,nchannels):
    # map a (packet) size into a frequency and duration based on the low 
    # and high frequecies, 

    # duration is min 100ms and max 1s and is distributed evenly according 
    # to min and max pdu sizes
    if maxsize-minsize == 0:
        # likely not what's wanted but let's see...
        normalised=0.5
    else:
        normalised=(size-minsize)/(maxsize-minsize)
    duration=int(min_note_length+normalised*(max_note_length-min_note_length))

    frange=highfreq-lowfreq
    bottomstep=lowfreq
    topstep=bottomstep+frange/2
    if not c2s_direction:
        # top half of range is for svr->client
        bottomstep+=(frange/2)
        topstep+=(frange/2)
    freq=bottomstep+normalised*(topstep-bottomstep)
    return freq, duration

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
    outpuf file are either labelled or anonymised
    - labels are like "<label>-src-ip.midi.csv", anonymised are...
    - based on (first) pcap file name and src-ip and a per-run secret
    generate a wav file name - we do this as a privacy enhancement
    (but it absolutely needs other pcap anonymisation tools I've
    yet to find)
    '''
    # otherwise anonymise
    if key==None:
        key=init_key()
    rv=""
    # init secret once per run
    if label is not None:
        # ":" in file names spells trouble so zap 'em
        # (they'll occur in IPv6 addresses)
        psrc=src.replace(":","")
        hmacval = hmac.new(key, msg=src.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
        if args.allinone:
            rv=str(int(time.time()))+"-"+label+"-all-"+hmacval[0:8]
        else:
            ipver="ipv4"
            if ":" in src:
                ipver="ipv6"
            rv=str(int(time.time()))+"-"+label+"-"+ipver+"-"+hmacval[0:8]
    else:
        m=fname+src
        hmacval = hmac.new(key, msg=m.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
        # we'll truncate as collisions aren't a deal for this
        rv=hmacval[0:15]
    if args.logtime:
        rv+="-log"
    return rv

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

def instrument(inum,channel):
    if inum >=0 and inum <=127:
        return str(inum)
    if inum==-1:
        return str(instarr[channel])
    print("Error: bad instrument number: " + str(inum) + " on channel: " + str(channel))
    return "ERROR"

def killsilence(array, mingap):
    '''
    array has notes:
        [track,on/off-time,on/off-string,channel,notenum,",81"]
    - we want to eliminate any no-change periods >limit ms long by
    reducing the times accordingly
    - that zaps both silences and over-long notes, but good enough
    '''
    time2remove=0
    lasttime=0
    for note in array:
        note[1]-=time2remove
        #print("outer: note: " + str(note) + " lasttime: " + str(lasttime) + " mingap: " + str(mingap) + " ttr:" + str(time2remove))
        wasinner=False
        while (lasttime+mingap)<note[1]:
            note[1]-=mingap
            time2remove+=mingap
            #print("inner: note: " + str(note) + " lasttime: " + str(lasttime) + " mingap: " + str(mingap) + " ttr:" + str(time2remove))
            wasinner=True

        lasttime=note[1]
        if wasinner:
            #print("innerX note: " + str(note) + " lasttime: " + str(lasttime) + " mingap: " + str(mingap) + " ttr:" + str(time2remove))
            pass
    return

# scale time oddly...
def scaletime(x):
    '''
    We'll assume original is ~30s or less (before supression)
    and we'll map down to ~10s, with 1st second expanded to
    2.5s, 2nd linear, 3rd 0.75 and the rest to 0.4
    '''
    mapped=0
    if x < 0:
        raise ValueError('negative X in scaletime - ' + str(x) + ' - exiting')
    elif x <= 1000:
        mapped=int(2.5*x)
        #print("Mapped1: "+str(x)+" to: "+str(mapped)) 
    elif x <= 2000:
        mapped=int((x-1000)+2500)
        #print("Mapped2: "+str(x)+" to: "+str(mapped)) 
    elif x <= 3000:
        mapped=int((x-2000)*0.75+3500)
        #print("Mapped3: "+str(x)+" to: "+str(mapped)) 
    else: 
        mapped=int((x-3000)*0.4+4250)
        #print("Mapped4: "+str(x)+" to: "+str(mapped)) 
    return mapped

# main line code...

# our array of TLS sessions
if args.verbose:
    print("Running verbosely...")
    print("Reading pcaps...")
    print(flist)
sessions=[]
analyse_pcaps(flist,sessions,args.verbose)
if args.verbose:
    print("Found " + str(len(sessions)) + " sessions.\n")
    for s in sessions:
        print(str(s))

# a per-run hmac secret, just used for file name hashing so not really sensitive
hmac_secret=None

# we'll keep a the_detail for each
the_arr=[]
# just for quick checking
src_ips=[]

# Check if file exists with IPs to ignore...
# Mostly this is for ignoring DNS queries/answers that tend to  
# muck up our noise/music (well, might be better when we've a
# bit more work done)
block_arr=[]
bafile='ignore.addrs'
try:
    with open(bafile) as ba:
        block_arr=ba.readlines()
    block_arr = [x.strip() for x in block_arr]
    if args.verbose:
        print("Ignoring addresses from " + bafile)
        print(block_arr)
except:
    pass
if args.verbose:
    if len(block_arr)==0:
        print("No addresses to ignore from " + bafile + " (maybe file isn't there?)")

for s in sessions:
    if s.dst in block_arr or s.src in block_arr:
        if args.verbose:
            print("Ignoring session: " + s.src + "->" + s.dst)
        continue
    if not args.allinone:
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
    else:
        if len(the_arr)==0:
            wname=hash_name(hmac_secret,s.fname,s.src)
            try:
                #print("Option3: " + str(s.end_time.timestamp()))
                w=the_details(wname,s.src,nsessions=1,earliest=s.timestamp,latest=s.end_time.timestamp())
            except:
                #print("Option4: " + " val: " + str(s.end_time))
                w=the_details(wname,s.src,nsessions=1,earliest=s.timestamp)
            the_arr.append(w)
        else:
            w=the_arr[0]
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
    # figure out how many unique sizes we have in all 'w' sessions
    # w.note[3] has sizes
    w.pdu_sizes.add(tuple(s.s_psizes))
    w.pdu_sizes.add(tuple(s.d_psizes))
    w.num_sizes=len(w.pdu_sizes)
    if args.verbose:
        print("Size of Set: " + str(w.num_sizes))

# loop again through sessions to pick up PDU details
for s in sessions:
    if s.dst in block_arr or s.src in block_arr:
        if args.verbose:
            print("Still ignoring session: " + s.src + "->" + s.dst)
        continue
    if not args.allinone:
        w=find_details(the_arr,s.src)
    else:
        w=the_arr[0]
    if w is None:
        raise ValueError('No details for session: ' + s.sess_id)
    for i in range(0,len(s.s_psizes)):
        freq,dur=size2freqdur(s.s_psizes[i],w.min_pdu,w.max_pdu,True,lowest_note,highest_note,w.this_session,w.nsessions)
        w.notes.append([freq,dur,(s.s_delays[i]+s.timestamp)-w.earliest,s.s_psizes[i],True,w.this_session])
    for i in range(0,len(s.d_psizes)):
        freq,dur=size2freqdur(s.d_psizes[i],w.min_pdu,w.max_pdu,False,lowest_note,highest_note,w.this_session,w.nsessions)
        w.notes.append([freq,dur,(s.d_delays[i]+s.timestamp)-w.earliest,s.d_psizes[i],False,w.this_session])
    if len(s.s_psizes)>0 or len(s.d_psizes)>0:
        # midi limit on channels/sessions seems to be max 16 is reliable
        # so we'll re-use and hope for the best if we have >16 TLS sessions 
        # per src IP in a pcap
        if args.verbose:
            print("Warning: >16 TLS sessions in one midi file for " + s.src)
        w.this_session = (w.this_session + 1) % 16
        # this_session will map to midi channel, so we'll skip #10 which is drums
        # because they don't have so many notes as pianos and we lose information
        if w.this_session == 9:
            w.this_session=10

# sort notes timewise
for w in the_arr:
    w.notes=sorted(w.notes, key=itemgetter(2))
    if args.verbose:
        print(w)

# write out midicsv file, one per src ip
# to play such:
#   $ csvmidi <hash>.midi.csv <hash>.midi
#   $ timidity <hash>.midi
for w in the_arr:
    if args.verbose:
        print("Saving " + w.fname + ".midi.csv")
    # we'll just keep an array of strings with one line per and won't
    # bother making a python CSV structure
    midicsv=[]
    # table version
    table={}
    for note in w.notes:
        # freq2note version
        # table version - default
        notenum=size2num(note[3],note[4],table)
        if args.notegen == 'freq':
            notenum=freq2num(note[0])
        # let's move all notes up by N octaves where N is the channel number and
        # do that modulo our bounds
        low_num=freq2num(lowest_note)
        high_num=freq2num(highest_note)
        increment=(note[5]*7)%(high_num-low_num)
        notenum = notenum + increment
        if notenum>=high_num:
            notenum -= (high_num-low_num)
        # linear time
        ontime=int(note[2])
        offtime=int(note[1]+note[2])
        # change if log time...
        if args.logtime:
            try:
                if note[2]==0:
                    # can happen!
                    ontime=0
                else:
                    # add a millisecond to avoid negative logs
                    ontime=int(100*math.log(1+note[2]))
                if note[1]+note[2]==0:
                    # shouldn't happen really 
                    print("ouch2! processing " + w.fname)
                    print(str(w))
                    sys.exit(1)
                else:
                    # add a millisecond to avoid negative logs
                    offtime=int(100*math.log(1+note[1]+note[2]))
            except Exception as e:
                print("ouch! processing " + w.fname)
                print(str(w))
                sys.exit(1)
        # Try another time compression - log compresses too much
        if args.scaledtime:
            ontime=scaletime(note[2])
            offtime=scaletime(note[1]+note[2])

        # odd structure here is so we can sort on time in a sec...
        # let's play with different velocities see what that does...
        # BANG the keys...
        # midicsv.append([note[5]+2,ontime,",note_on_c,",note[5],notenum,",81"])
        # Nice and gentle...
        # midicsv.append([note[5]+2,ontime,",note_on_c,",note[5],notenum,",21"])
        # Earlier channels loudest
        # velocity = 81-5*channel (aka note[5]) 
        vel=int(81-4*note[5])
        midicsv.append([note[5]+2,ontime,",note_on_c,",note[5],notenum,","+str(vel)])
        # might make the above a parameter, but not yet
        midicsv.append([note[5]+2,offtime,",note_off_c,",note[5],notenum,",0"])
    
    # now sort by time
    midicsv.sort(key=itemgetter(1))

    # eliminate any non-changing time gapes > specified limit
    if args.suppress_silence is not None:
        killsilence(midicsv,args.suppress_silence)

    # now sort by track/channel
    midicsv.sort(key=itemgetter(0))

    # TODO: eliminate cases where the same note is hit whilst still on by moving up one
    # go through notes array, note who's turned on/off when, then if an on-note is to
    # be hit, try one up or down until we find a note that's off - then hit that

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
2, 0, Instrument_name_t, "channel 0 misc"\n\
2, 0, Program_c, 0, ' + instrument(instrumentnum,0) + '\n')
        current_track=midicsv[0][0]
        last_track_end=0
        for line in midicsv:
            if line[0]!=current_track:
                f.write(str(current_track)+', '+str(last_track_end)+', End_track\n')
                current_track=line[0]
                f.write(str(current_track)+', 0, Start_track\n')
                f.write(str(current_track)+', 0, Instrument_name_t, "channel '+str(current_track-2)+' misc"\n')
                f.write(str(current_track)+', 0, Program_c,'+str(current_track-2)+','+ instrument(instrumentnum,current_track-2) + '\n')
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
        if args.verbose:
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


