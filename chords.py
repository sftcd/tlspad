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

# This file will likely disappear. Used it to play about with chords
# to understand 'em before using 'em.

import traceback
import os,sys,argparse,re,random,time
from TlsPadFncs import *

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

class Chords():
    __slots__ =  [
                'chord_id',
                'reltime',
                'notes',
            ]

    def __init__(self,t=0,n=[]):
        self.chord_id=random.getrandbits(32)
        self.reltime=t
        self.notes=n

    def __str__(self):
        return "Chords: " + str(self.chord_id) + " reltime: " + str(self.reltime) + "\n" + str(self.notes) 

    def pickchordN(self,n):
        try:
            return forte_primes[n]
        except:
            raise ValueError('pickchordN: out of range, ' + str(n) + ' > length(' + str(len(forte_primes)) + ')')

    def hash2N(self,size):
        return size % len(forte_primes)

    def nextchord(self,size):
        return self.pickchordN(self.hash2N(size))

def session2chords(sess: TLSSession):
    '''
        OBE: I'll no longer use this, it's just here for the record...

        Take a TLSsession and return a set of chords for that session
        TODO: add some chord progression stuff but without adding
        synthetic structure (if possible)
    '''
    chords=Chords(0,[])
    for size in sess.s_psizes:
        chords.notes.append(chords.nextchord(size))
    for size in sess.d_psizes:
        chords.notes.append(chords.nextchord(size))
    return chords

def cadence2chords(cadence):
    '''
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
    # initial client and server size/count arrays
    csc={}
    for size in cadence["c2sp"]:
        if size in csc:
            csc[size]=csc[size]+1
        else:
            csc[size]=1
    ssc={}
    for size in cadence["s2cp"]:
        if size in ssc:
            ssc[size]=ssc[size]+1
        else:
            ssc[size]=1
    print("Dur: " + str(cadence["dur"]) + " C->S: " + str(csc))
    print("Dur: " + str(cadence["dur"]) + " S->C: " + str(ssc))

    chords=Chords(cadence["c2st"][0],[])
    for size in csc:
        chords.notes.append(chords.nextchord(size))
    for size in ssc:
        chords.notes.append(chords.nextchord(size))
    return chords

if __name__ == '__main__':
    '''
    #first cut, newer test code below
    try:
        tc=Chords(0,[])
        foo=tc.pickchordN(1)
        print("tc[1]:" + str(foo))
        tc.pickchordN(100)
    except Exception as e:
        print("Good exception: " + str(e))
    print("Base thing: " + str(tc))
    '''
    try:
        sessions=[]
        flist=[]
        flist.append(sys.argv[1])
        analyse_pcaps(flist,sessions,True)
        insts=analyse_cadence(sessions)
        #print(insts)
        i=0
        for exchange in insts:
            print("Doing exchange "+str(i))
            print("Exchange: " + str(exchange))
            echords=cadence2chords(exchange)
            print("Chords: " + str(echords))
            print("Done with exchange "+str(i))
            i+=1
    except Exception as e:
        print("Bad exception: " + str(e))


