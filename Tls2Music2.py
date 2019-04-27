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

# 2nd cut at this, superceding Tls2Music and chords for a bit

'''
        The latest music scheme:

        Take a cadence and return a set of chords for that 

        We end up with these parameters:
            duration of the cadence (ms)
            for c->s and s->c directions:
                the set of packet sizes seen, with a count of each
            or...
            D, {CS: PC}, {SC: PC} where
            D is overall cadence duraion
            {} represents a set
            CS is a client->server packet size
            PC is the count of the number of those packets sent
            SC is a server->client packet size
            PC is as above

            our non-secret plan:

            high level:
                - ignore too-short notes for now, we can dilate time later
                - map sizes to chords from forte list, for now with a 
                  straight modulus
                - ignore packet times (most aren't useful) other than the
                  first in each direction (and subtract RTT estmiate too)
                - note duration is proportional to the number of bytes in
                  packets of that size (add 'em all up, figure how many
                  (fractional) ms that means per byte and then scale up)
                - volume/velocity similarly reflects number of packets
                  of that size seen
                - c->s is RHS (high notes) of piano keyboard, s->c: LHS
                - within the cadence we'll ascend/descend chords somehow 
                  (yes, that's TBD) - mostly descend for s->c packets as 
                  there're few multipacket c->s cadences

            that'll sound as it does, we'll see when we get there

            to do that, I'll need to merge this with the classes in
            Tls2Music and merge some of those into TlsPadFncs so
            it may take a few mins
'''

import traceback,math
import os,sys,argparse,re,random,time,ipaddress
import pyshark
from TlsPadFncs import *

# for file name hashing
import hmac,hashlib,base64

# for sorting
from operator import itemgetter

# hacky beeps
from beeps import *

# Parameters that can be overridden via command line arguments

# take file or directory name on command line, default to current dir
fodname="."

# label for output files
label=None

# Parameters we don't yet bother allowing be overridden via command line arguments

# time dilation - stretch it all out by this factor
# effects aren't of much interest though - does make
# it all take longer:-)
time_dilation=1

# number of times to repeat output (in the hope that recognition
# is easier if we do that)
overall_repeats=1

# Time-gap between repeats, in ms
repeat_gap=100

# MIDI velicity max, min and number of channels we can use
# and size of channel velocity increment (for overlapping
# key-on conditions) - minvel and nchans could be command
# line arguments, the others don't make sense to vary that
# way
#maxvel=127
#minvel=60
maxvel=90
minvel=40
nchans=15
velinc=(maxvel-minvel)/nchans

# midi instrument number
# there's a list at https://www.midi.org/specifications/item/gm-level-1-sound-set
# that list may be offset by 1, i.e. we start at 0
# channel 10 is drums of various kinds with restrictions on what note numbers can be used
instrumentnum=1 # piano
#instrumentnum=19 # choral organ

# [Forte numbers](https://en.wikipedia.org/wiki/Forte_number) provide a way to number
# chords, I'll ignore the numbers themselves (e.g. "3-3A" would be "014" below and 
# just use the "prime form" of the chords, sorted numerically
# this list extracted from https://www.mta.ca/pc-set/pc-set_new/pages/pc-table/pc-table.html
forte_primes= [
    "012", "013", "014", "015", "016", "024", "025", "026",
    "027", "036", "037", "048", "0123", "0124", "0125", "0126",
    "0127", "0134", "0135", "0136", "0137", "0145", "0146", "0147",
    "0148", "0156", "0157", "0158", "0167", "0235", "0236", "0237",
    "0246", "0247", "0248", "0257", "0258", "0268", "0347", "0358",
    "0369", "01234", "01235", "01236", "01237", "01245", "01246", "01247",
    "01248", "01256", "01257", "01258", "01267", "01268", "01346", "01347",
    "01348", "01356", "01357", "01358", "01367", "01368", "01369", "01457",
    "01458", "01468", "01469", "01478", "01568*", "02346", "02347", "02357",
    "02358", "02368", "02458", "02468", "02469", "02479", "03458", "012345",
    "012346", "012347", "012348", "012356", "012357", "012358", "012367", "012368",
    "012369", "012378", "012456", "012457", "012458", "012467", "012468", "012468T",
    "012469", "012478", "012479", "012567", "012568", "012569", "012578", "012579",
    "012678", "013457", "013458", "013467", "013468", "013468T", "013469", "013478",
    "013479", "013568", "013568T", "013569", "013578", "013579", "013679", "014568",
    "014579*", "014589", "014679", "023457", "023458", "023468", "023469", "023568",
    "023579", "023679*", "024579", "0123456", "0123457", "0123458", "0123467", "0123468",
    "0123468T", "0123469", "0123478", "0123479", "0123567", "0123568", "0123568T", "0123569",
    "0123578", "0123578T", "0123579", "0123678", "0123679", "0124568", "0124568T", "0124569",
    "0124578", "0124578T", "0124579", "0124589", "0124678", "0124678T", "0124679", "0124689",
    "0125679*", "0125689", "0134568", "0134578", "0134578T*", "0134579", "0134679", "0134679T",
    "0134689", "0135679", "0145679*", "0234568", "0234579", "0234679", "01234567", "01234568",
    "01234568T", "01234569", "01234578", "01234578T", "01234579", "01234589", "01234678", "01234678T",
    "01234679", "01234679T", "01234689", "01234789", "01235678", "01235678T", "01235679", "01235679T",
    "01235689", "01235789", "01236789", "01245679", "01245689", "01245689T", "01245789", "01345679",
    "01345689", "02345679", "012345678", "012345679", "012345689", "012345789", "012346789" ]

class NoteInfo():
    '''
    Info about a note/packet
    '''
    __slots__ = [
            # networking fields
            "c2s",
            # midi fields
            "instrument",
            "track",
            "channel",
            "ontime",
            "offtime",
            "notenum",
            "vel",
            ]
    def __init__(self,c2s=False,ch=0,tr=0,inst=0,vel=0):
        self.c2s=c2s
        self.notenum=0
        self.ontime=0
        self.offtime=0
        self.vel=0
        self.channel=ch
        self.track=tr
        self.instrument=inst
        self.vel=vel
    def __str__(self):
        s_str="Note: " 
        if self.c2s:
            s_str += " Dir: C->S" 
        else:
            s_str += " Dir: S->C" 
        s_str+=" num: " + str(self.notenum) + " on: " + str(self.ontime) + " off: " + str(self.offtime) + " ch: " + str(self.channel) \
                + " track: " + str(self.track) + " instrument: " + str(self.instrument) + " vel: " + str(self.vel)
        return(s_str)

def get_start(foo):
    return foo.ontime

class Chords():
    '''
        Info about a chord
    '''
    __slots__ =  [
                'chord_id',
                'reltime',
                'duration',
                'fortes',
                'counts',
                'sizes',
                'c2sdirs',
                'notes',
            ]
    def __init__(self,t=0,dur=0,f=[],c=[],s=[],d=[],n=[]):
        self.chord_id=random.getrandbits(32)
        self.reltime=t
        self.duration=dur
        self.fortes=f
        self.counts=c
        self.sizes=s
        self.c2sdirs=d
        self.notes=n
    def __str__(self):
        return "Chords: " + str(self.chord_id) + " reltime: " + str(self.reltime) + " duration: " + str(self.duration) + "\n" \
                + "Forte primes:"  + str(self.fortes) + "\n" \
                + "Counts:" + str(self.counts) + "\n" \
                + "Sizes:" + str(self.sizes) + "\n" \
                + "Directions:" + str(self.c2sdirs) + "\n" \
                + "Notes:" + '\n'.join('\t'+str(note) for note in self.notes) 
    def pickchordN(self,n):
        try:
            return forte_primes[n]
        except:
            raise ValueError('pickchordN: out of range, ' + str(n) + ' > length(' + str(len(forte_primes)) + ')')
    def hash2N(self,size):
        return size % len(forte_primes)
    def nextchord(self,size):
        return self.pickchordN(self.hash2N(size))

class tls_session_set():
    '''
    Each set of TLS sessions will have these parameters
    '''
    __slots__ = [
            'fname', # a base name for a file when we save a rendering
            'selector', # the selector used to group sessions, e.g. src IP
            'nsessions', # number of sessions
            'earliest', # overall earliest date
            'latest', # overall latest date
            'overall_duration', # obvious:-)
            'notes', # the set of notes in a musical rendering
            'sessions'
            ]
    def __init__(self,fname="",selector=None,nsessions=0,earliest=sys.maxsize,latest=0,overall_duration=0):
        self.fname=fname
        self.selector=selector
        self.nsessions=nsessions
        self.earliest=earliest
        if latest is -1:
            self.latest=earliest
        else:
            self.latest=latest
        self.overall_duration=overall_duration
        self.notes=[]
        self.sessions=[]
    def __str__(self):
        return("Details for " + self.fname + ": sessions: " + str(self.nsessions) + "\n" + \
                "\t" + "Earliest: " + str("%.02F"%self.earliest) + " Latest: " + str("%.02F"%self.latest) + " Dur: " + str("%.02f"%(self.overall_duration/1000)) + "\n" + \
                "\t" + "Notes:\n" + '\n'.join('\t'+str(note) for note in self.notes) + \
                "\n" + "Session IDs: \n" + '\n'.join('\t'+str(s.sess_id) for s in self.sessions) )

# Functions

def cadence2notes(cadence,channel,track,instrument,verbose):
    # initial client and server size/count arrays
    c2stotal=0
    csc={}
    for size in cadence["c2sp"]:
        c2stotal+=size
        if size in csc:
            csc[size]=csc[size]+1
        else:
            csc[size]=1
    ssc={}
    s2ctotal=0
    for size in cadence["s2cp"]:
        s2ctotal+=size
        if size in ssc:
            ssc[size]=ssc[size]+1
        else:
            ssc[size]=1
    coffset=0
    counts=[]
    sizes=[]
    notes=[]
    dur=0
    for size in csc:
        counts.append(csc[size])
        sizes.append(size)
    for ind in range (0,len(csc)):
        coffset+=dur
        dur=0.5*(counts[ind]*sizes[ind]/c2stotal)*cadence["dur"]
        # middle C plus some octaves
        n=NoteInfo(True,channel,track,instrument)
        n.ontime=cadence["c2st"][0]+coffset
        n.offtime=n.ontime+dur
        n.notenum=60+(sizes[ind]*counts[ind])%60
        notes.append(n)
    soffset=0
    counts=[]
    sizes=[]
    dur=0
    for size in ssc:
        counts.append(ssc[size])
        sizes.append(size)
    for ind in range (0,len(ssc)):
        soffset+=dur
        dur=0.5*(counts[ind]*sizes[ind]/s2ctotal)*cadence["dur"]
        # middle C minus some octaves
        n=NoteInfo(False,channel,track,instrument)
        n.ontime=cadence["c2st"][0]+soffset
        n.offtime=n.ontime+dur
        n.notenum=60-(sizes[ind]*counts[ind])%60
        notes.append(n)

    return notes

def cadence2chords(cadence,channel,track,instrument,verbose):
    # initial client and server size/count arrays
    c2stotal=0
    csc={}
    for size in cadence["c2sp"]:
        c2stotal+=size
        if size in csc:
            csc[size]=csc[size]+1
        else:
            csc[size]=1
    ssc={}
    s2ctotal=0
    for size in cadence["s2cp"]:
        s2ctotal+=size
        if size in ssc:
            ssc[size]=ssc[size]+1
        else:
            ssc[size]=1
    thesechords=Chords(cadence["c2st"][0],cadence["dur"],[],[],[],[],[])
    for size in csc:
        thesechords.fortes.append(thesechords.nextchord(size))
        thesechords.counts.append(csc[size])
        thesechords.sizes.append(size)
        thesechords.c2sdirs.append(True)
    for size in ssc:
        thesechords.fortes.append(thesechords.nextchord(size))
        thesechords.counts.append(ssc[size])
        thesechords.sizes.append(size)
        thesechords.c2sdirs.append(False)
    # ok map those fortes to notes, with duration proportional to overall bytecount in that direction
    # and velocity proportional to log(count)
    coffset=0
    soffset=0
    offset=0
    for ind in range(0,len(csc)+len(ssc)):
        # c2s calc then fix if other dir
        dur=0
        if thesechords.c2sdirs[ind] is True:
            coffset+=dur
            offset=coffset
            dur=0.5*(thesechords.counts[ind]*thesechords.sizes[ind]/c2stotal)*thesechords.duration
            # middle C plus some octaves
            base=60+(channel%4)*12
        else:
            soffset+=dur
            offset=soffset
            dur=0.5*(thesechords.counts[ind]*thesechords.sizes[ind]/s2ctotal)*thesechords.duration
            # middle C minus some octaves
            base=60-(channel%4)*12
        for k in range(0,len(thesechords.fortes[ind])):
            n=NoteInfo(thesechords.c2sdirs[ind],channel,track,instrument)
            n.ontime=thesechords.reltime+offset
            n.offtime=n.ontime+dur
            if thesechords.fortes[ind][k]=='T':
                n.notenum=base+10
            elif thesechords.fortes[ind][k]=='E':
                n.notenum=base+11
            elif thesechords.fortes[ind][k]=='*':
                # TODO: check out what that fecking '*' means:-)
                n.notenum=base+12
            else:
                n.notenum=base+ord(thesechords.fortes[ind][k])-ord('0')
            thesechords.notes.append(n)
    return thesechords

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

def find_set(s,session_sets):
    '''
    search for tls_session_set mwith matching IPs
    '''
    if len(session_sets)==0:
        if args.verbose:
            print("find_set: Empty set of session_sets!")
    for w in session_sets:
        for s1 in w.sessions:
            if s.sess_id==s1.sess_id:
                #if args.verbose:
                    #print("find_set picked:"+str(w))
                return w
    if args.verbose:
        print("find_set picked none!")
    return None

def init_key():
    '''
    return a random 32 character string, we'll use as a HMAC key below
    '''
    return open("/dev/urandom","rb").read(32)

def hash_name(key,fname,src,sels):
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
        # this is clumsy - TODO: fix later
        allinone=type(sels)==str and sels=='all'
        rmatch=type(sels)==list 
        if allinone:
            rv=str(int(time.time()))+"-"+label+"-all-"+hmacval[0:8]
        elif rmatch:
            rv=str(int(time.time()))+"-"+label+"-range-"+hmacval[0:8]
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
    return rv

def instrument(inum,hashedinst):
    if inum >=0 and inum <=127:
        # was specified on commandline so use that
        return str(inum)
    if inum==-1:
        # old way...
        #return str(instarr[hashedinst])
        return str(hashedinst)
    print("Error: bad instrument number: " + str(inum) + " on channel: " + str(channel))
    return "ERROR"

def killsilence(array, mingap):
    '''
    array has notes:
        [track,on/off-time,on/off-string,channel,notenum,velocity]
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
    We'll assume original is ~30s or so 
    1st second is expanded to 4s
    2nd second is expanded to 2s
    3rd is linear 
    and the rest to 0.4
    '''
    mapped=0
    if x < 0:
        raise ValueError(sys.argv[0] + ': negative X in scaletime - ' + str(x) + ' - exiting')
    elif x <= 1000:
        mapped=int(4*x)
    elif x <= 2000:
        mapped=int((2*x-1000)+4000)
    elif x <= 3000:
        mapped=int((x-2000)+6000)
    else: 
        mapped=int((x-3000)*0.4+7000)
    return mapped

# the velocity with which we hit keys, this function will
# all us play with that
def velocity(notenum,channel,offset,duration,overall_duration):
    # starting point
    vel=int(81-4*channel)
    # let's try out a few options, see what sounds better and then
    # make those command line args later (maybe)
    option="midloud"
    if option=="midloud":
        # start quieter, then loud in middle, then quieter again
        # but still keep earlier channels louder
        # 81 is max, 40 is min
        sine_adjust=math.sin(math.pi*offset/overall_duration)
        dperchan=0.5*(maxvel-minvel)/nchans
        vel=maxvel-minvel-channel*dperchan
        newvel=minvel+int(vel*sine_adjust)
        if False and args.verbose:
            print("Sine ajdusted from " + str(vel) + " to " + str(newvel) + " sa: " + str(sine_adjust) + " off: " + str(offset) + " overall: " + str(overall_duration))
        vel=newvel
    return vel


# main line code...

# command line arg handling 
argparser=argparse.ArgumentParser(description='Turn some pcaps into music')
argparser.add_argument('-l','--label',     
                    dest='label',
                    help='basename label for midi.csv and .wav output files')
argparser.add_argument('-f','--file',     
                    dest='fodname',
                    help='PCAP file or directory name')
argparser.add_argument('-i','--instrument',
                    type=int, dest='instrument',
                    help='midi instrument (-1:127; default: 0; -1 means built-in combo)')
argparser.add_argument('-v','--verbose',
                    help='produce more output',
                    action='store_true')
argparser.add_argument('-S','--scaledtime',     
                    help='use scaled time (read code for details:-)',
                    action='store_true')
argparser.add_argument('-s','--suppress-silence',     
                    type=int, dest='suppress_silence',
                    help='suppress <num> ms of no-change (not really silence but good enough')
argparser.add_argument('-V','--vantage',
                    dest='vantage',
                    help='select output sets based on vantage point')
argparser.add_argument('-r','--repeats',
                    type=int, dest='repeats',
                    help='repeat output N times')
argparser.add_argument('-d','--drums',
                    help='add drumbeats, once per packet',
                    action='store_true')
argparser.add_argument('-c','--chords',
                    help='map TLS patterns to chords, not notes',
                    action='store_true')
args=argparser.parse_args()

if args.fodname is not None:
    fodname=args.fodname

if args.instrument is not None:
    if args.instrument < -1 or args.instrument >127:
        print("Error: instruments must be integers from 0 to 127")
        sys.exit(1)
    instrumentnum=args.instrument

if args.label is not None:
    label=args.label

if args.repeats is not None:
    overall_repeats=args.repeats

# default is to group by SRC IP
selectors='src'
if args.vantage is not None:
    if args.vantage=='all':
        selectors='all'
    elif args.vantage=='src':
        selectors='src'
    elif args.vantage=='dst':
        selectors='dst'
    else: 
        # check if file-name, that exists and has a set of prefixes
        # we'll ignore any non-matching sessions
        try:
            with open(args.vantage) as vf:
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
        print("Vantage point set, selectors: " + str(selectors))

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
    print(sys.argv[0]+ ": No input files found - exiting")
    sys.exit(1)

# our array of TLS sessions
if args.verbose:
    print("Running  " + sys.argv[0] +  " verbosely...")
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

# we'll keep an array of tls_session_set values
the_arr=[]
if selectors is None or (selectors is not None and type(selectors)==str and selectors=='all'):
    # just one set of tls sessions so, whatever determined by selectors
    s=tls_session_set()
    s.selector=selectors
    the_arr.append(s)

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

# check if file exists with the IPs of the "primary" server
# (i.e. A/AAAA for the DNS name we're talking to)
# if so, then we'll allocate those first instruments with
# higher volume and allocate the other sessions to instruments
# and channels based on the list of those sorted by IP address
primary_arr=[]
primaryfile="primaries.ips"
try:
    with open(primaryfile) as pf:
        primary_arr=pf.readlines()
    primary_arr = [x.strip() for x in primary_arr]
except:
    pass
if args.verbose:
    if len(primary_arr)==0:
        print("No addresses to prefer from " + primaryfile + " (maybe file isn't there?)")
    else:
        print("Addresses to treat as primary: " + str(primary_arr))
if len(primary_arr)>=15:
    print("Can't handle so many primaries (only 15 channels) - exiting")
    sys.exit(1)

# group our sessions according to selector
# and keep tabs on overall duration of sessions in groups
for s in sessions:
    if s.dst in block_arr or s.src in block_arr:
        if args.verbose:
            print("Ignoring blocked session: " + s.src + "->" + s.dst)
        continue
    w=None
    for sl in the_arr:
        matches,sel=selector_match(s,selectors,sl.selector)
        if w is None and matches:
            if args.verbose:
                print("Selecting session: " + s.src + "->" + s.dst)
            w=sl
            break;
    if w is None and type(selectors)==list:
        matches, sel= selector_match(s,selectors)
        if matches:
            w=tls_session_set()
            w.selector=sel
            the_arr.append(w)
            if args.verbose:
                print("Matched session: " + s.src + "->" + s.dst + " Matching on " + sel )
        else:
            if args.verbose:
                print("Skipping over session: " + s.src + "->" + s.dst)
            continue
    if w is None and type(selectors)==str and selectors=='src':
        w=tls_session_set()
        w.selector=s.src
        the_arr.append(w)
    if w is None and type(selectors)==str and selectors=='dst':
        w=tls_session_set()
        w.selector=s.dst
        the_arr.append(w)
    if w is None:
        print("Oops - w is None when it shouldn't be")
        sys.exit(3)
    if w.fname=="":
        # initialise some
        wname=hash_name(hmac_secret,s.fname,s.src,selectors)
        w.fname=wname
    if w.earliest > s.timestamp:
        w.earliest=s.timestamp
    try:
        if w.latest < s.end_time.timestamp:
            w.latest=s.end_time.timestamp
    except:
        # end_time might not be set yet, that's ok
        pass
    w.nsessions += 1
    w.sessions.append(s)

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
    if args.verbose:
        print("overall: " + str(w.overall_duration) + "E: " +  str(w.earliest) + " L:" + str(w.latest))

# Could be selectors given mean we have no sessions to handle
if len(the_arr)==0:
    print(sys.argv[0] + ": No sessions selected - exiting")
    sys.exit(0)

# allocate sessions to channels/instruments
# if there is a non-empty primary list then...
# if src/dst is in primary list, then that gets lowest numbered channels
# else if there is no primary list then we number from 0 on up
# midi channel 9 is drums, so is handled specially (if at all)

wcnt=0
for w in the_arr:
    wcnt+=1
    # next primary and secondary channels to allocate
    pchan=0
    schan=14
    # first sort the sessions in each W
    w.sessions=sorted(w.sessions,key=get_sortstr)
    for s in w.sessions:
        
        if len(primary_arr)==0:
            if args.verbose:
                print("\tAllocated " + str(s.sess_id) + " to channel " + str(pchan))
            s.channel=pchan
            pchan+=1
        elif (len(s.s_psizes)>0 or len(s.d_psizes)>0) and (s.src in primary_arr or s.dst in primary_arr):
            if args.verbose:
                print("\tAllocated " + str(s.sess_id) + " to primary channel " + str(pchan))
            s.channel=pchan
            pchan+=1
        else:
            if args.verbose:
                print("\tAllocated " + str(s.sess_id) + " to channel " + str(schan))
            s.channel=schan
            schan-=1
        if (schan-1) <= pchan:
            # start over
            pchan=0
            schan=14
        if pchan==14:
            pchan=0

# bump up by one for anyone >=9 so we use 0..8 and 10..15
for w in the_arr:
    for s in w.sessions:
        if s.channel >=9:
            s.channel += 1

# loop again through sessions to pick up PDU details
# and generate initial note info
for w in the_arr:
    track=0
    for s in w.sessions:
        # break remaining sessions into cadences
        insts=analyse_cadence([s])
        if args.verbose:
            print("Found " + str(len(insts)) + " exchanges/cadences in session "+ str(s.sess_id) + "\n")
        for e in insts:
            if args.verbose:
                print("Exchange:" + str(e))
            if args.chords:
                echords=cadence2chords(e,s.channel,track+2,s.instrument,args.verbose)
                if args.verbose:
                    print("Chords: " + str(echords))
                if len(echords.notes)!=0:
                    for n in echords.notes:
                        w.notes.append(n)
                # keep 'em in a bit
                del echords
            else:
                cnotes=cadence2notes(e,s.channel,track+2,s.instrument,args.verbose)
                for n in cnotes:
                    w.notes.append(n)

        if args.drums:
            # add a drum hit for each packet, different percussion instrument for c2s and s2c
            # percussion instruments are encoded via note numbers from 35 to 81
            # that (I think, roughly) maps to 65Hz (35), to 880Hz (81)
            # so we'll try note 35 (acoustic bass drum) = 65Hz for c2s
            # and note 38 (acoustic snare) = 77Hz for s2c
            # but we hardcode drums for now
            for i in range(0,len(s.s_psizes)):
                n=NoteInfo(True,9,track+2,9)
                n.ontime=(s.s_delays[i]+s.timestamp)-w.earliest
                n.offtime=n.ontime+100
                n.notenum=35
                w.notes.append(n)
            for i in range(0,len(s.d_psizes)):
                n=NoteInfo(False,9,track+2,9)
                n.ontime=(s.d_delays[i]+s.timestamp)-w.earliest
                n.offtime=n.ontime+200
                n.notenum=38
                w.notes.append(n)
        track+=1

# sort notes timewise
for w in the_arr:
    w.notes=sorted(w.notes, key=get_start)
    if args.verbose:
        print(w)
        print("\n")

# pick notes from frequencies and handle time munging
for w in the_arr:
    for note in w.notes:
        # linear time, with possible dilation
        ontime=time_dilation*int(note.ontime)
        offtime=time_dilation*int(note.offtime)
        notenum=note.notenum
        # Try another time compression - log compresses too much
        if args.scaledtime:
            ontime=time_dilation*scaletime(note.ontime)
            offtime=time_dilation*scaletime(note.offtime)
        # bit of paranoia...
        if ontime < 0.0:
            print("Weird ontime: " + str(ontime))
            sys.exit(4)
        if offtime < 0.0:
            print("Weird offtime: " + str(offtime))
            sys.exit(4)
        # handle velocity (loudness) 
        vel=velocity(notenum,note.channel,ontime,offtime-ontime,time_dilation*w.overall_duration)
        # add what we've calculated to note
        note.notenum=notenum
        note.ontime=ontime
        note.offtime=offtime
        note.vel=vel

# write out midicsv file, one per src ip
# to play such:
#   $ csvmidi <hash>.midi.csv <hash>.midi
#   $ timidity <hash>.midi
for w in the_arr:
    if len(w.notes)==0:
        if args.verbose:
            print("Not writing to " + w.fname + ".midi.csv - no notes!")
        continue
    if args.verbose:
        print("Writing to " + w.fname + ".midi.csv")

    # we'll just keep an array of strings with one line per and won't
    # bother making a python CSV structure
    midicsv=[]
    for repeat in range(0,overall_repeats):
        for note in w.notes:
            # odd structure here is so we can sort on time in a sec...
            repeat_offset=repeat*(w.overall_duration+repeat_gap)
            midicsv.append([note.track,note.ontime+repeat_offset,",note_on_c,",note.channel,note.notenum,note.vel,note.instrument])
            midicsv.append([note.track,note.offtime+repeat_offset,",note_off_c,",note.channel,note.notenum,0,note.instrument])
    
    # now sort again by time
    midicsv.sort(key=itemgetter(1))

    # eliminate any non-changing time gaps > specified limit
    if args.suppress_silence is not None:
        killsilence(midicsv,args.suppress_silence)
    
    # now sort by track/channel
    midicsv.sort(key=itemgetter(0))

    with open(w.fname+".midi.csv","w") as f:
        # precursor
        current_track=midicsv[0][0]
        f.write('0, 0, Header, 1, '+str(w.nsessions+1)+', 480\n\
1, 0, Start_track\n\
1, 0, Title_t, "Tls2Music ' + w.fname + '"\n\
1, 0, Text_t, "see https://github.com/sftcd/tlspad/"\n\
1, 0, Copyright_t, "This file is in the public domain"\n\
1, 0, Time_signature, 4, 2, 24, 8\n\
1, 0, Tempo, 500000\n\
1, 0, End_track\n' +
str(current_track) + ', 0, Start_track\n' +
str(current_track) + ', 0, Instrument_name_t, "channel ' + str(midicsv[0][3]) + ' "\n' +
str(current_track) + ', 0, Program_c, '+ str(midicsv[0][3]) + ', ' + instrument(instrumentnum,midicsv[0][6]) + '\n')
        last_track_end=0
        for line in midicsv:
            if line[0]!=current_track:
                f.write(str(current_track)+', '+str(last_track_end)+', End_track\n')
                current_track=line[0]
                f.write(str(current_track)+', 0, Start_track\n')
                f.write(str(current_track)+', 0, Instrument_name_t, "channel '+str(line[3])+'"\n')
                f.write(str(current_track)+', 0, Program_c,'+str(line[3])+','+ instrument(instrumentnum,line[6]) + '\n')
            last_track_end=line[1]
            f.write(str(line[0])+","+str(line[1])+line[2]+str(line[3])+","+str(line[4])+","+str(line[5])+"\n")
        f.write(str(current_track)+', '+str(last_track_end)+', End_track\n')
        f.write('0, 0, End_of_file\n')
        f.close()
    del midicsv



