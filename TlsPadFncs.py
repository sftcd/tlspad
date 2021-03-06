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

# structures/function to handle (the bits wer care about from) a TLS session
# given we may have large inputs, we wanna be less wasterful of memory
# so we'll use classes for this

class TLSSession():
    __slots__ = [ 
            'sess_id',
            'fname',
            'version',
            'start_time',
            'end_time',
            'timestamp',
            'src',
            'sport',
            'dst',
            'dport',
            'certsize',
            'cvsize',
            'chsize',
            'shsize',
            'chtime',
            'rttest',
            'min_pdu',
            'max_pdu',
            'num_sizes',
            's_psizes',
            's_delays',
            'd_psizes',
            'd_delays',
            'channel',
            'instrument',
            'sortstr'
            ]

    def __init__(self,fname='',ver='',stime=0,tstamp='0',src='',sport='',dst='',dport=''):
        self.sess_id=random.getrandbits(32)
        self.fname=fname # file name in which packet was seen
        self.version=ver # TLS version from the 1st relevant packet we see
        self.start_time=stime # file-relative start time of session
        self.end_time=0 # file-relative start time of session
        self.timestamp=float(tstamp) # file-relative start time of session
        self.src=src # client IP (v4 or v6)
        self.sport=sport # client port
        self.dst=dst  # server IP
        self.dport=dport # server port
        self.certsize=0 # cert size if seen in h/
        self.cvsize=0 # cert verify size if seen in h/s
        self.chsize=0 # ClientHello size
        self.shsize=0 # ServerHello size
        self.chtime=0 # for Estimated RTT record time of ClientHello 
        self.rttest=0 # Estimated RTT based on gap between ClientHello and ServerHello timing
        self.min_pdu=sys.maxsize 
        self.max_pdu=0
        self.num_sizes=0
        self.s_psizes=[] # list of APDU sizes from src, 0 is 1st, 1 2nd seen etc.
        self.s_delays=[] # list of relative time offsets from session start
        self.d_psizes=[] # list of APDU sizes from dst, 0 is 1st, 1 2nd seen etc.
        self.d_delays=[] # list of relative time offsets from session start
        self.channel=0 # used in Tls2Music only (so far)
        self.instrument=0 # used in Tls2Music only (so far)
        self.sortstr=src+":"+sport+"->"+dst+":"+dport

    def __str__(self):
        return "ID: " + str(self.sess_id) + " V:" + self.version + "\n" + \
                " started: " + str(self.start_time) + " ended: " + str(self.end_time) + " tstamp: " + str(self.timestamp) + "\n" +  \
                " file: " + self.fname + "\n" + \
                "\t" + self.src + ":" + self.sport + "->" + self.dst + ":" + self.dport + "\n" + \
                "\t" + "CH size: " +  str(self.chsize) + " SH size: " + str(self.shsize) + "\n" +  \
                "\t" + "Estimated RTT: " +  str(self.rttest) + "\n" + \
                "\t" + "Cert size: " +  str(self.certsize) + " CV size (proxy): " + str(self.cvsize) + "\n" +  \
                "\t" + "Min PDU: " + str(self.min_pdu) + " Max PDU: " + str(self.max_pdu) + " Num sizes: " + str(self.num_sizes) + "\n" + \
                "\t" + "number tx'd: " + str(len(self.s_psizes)) + " rx'd: " + str(len(self.d_psizes)) + "\n" + \
                "\t" + "source packet sizes: " + str(self.s_psizes) + "\n"+ \
                "\t" + "source packet times: " + str(["%.3f" % v for v in self.s_delays]) + "\n" + \
                "\t" + "dest packet sizes: " + str(self.d_psizes) + "\n" + \
                "\t" + "dest packet times: " + str(["%.3f" % v for v in self.d_delays]) + "\n"  + \
                "\t" + "channel " + str(self.channel) + " instrument: " + str(self.instrument)

    def add_apdu(self,size,pkttime,pstamp,src):

        #print ("type(pstamp): " + str(type(pstamp)) + " type(self.timestamp): " + str(type(self.timestamp)))
        tdiff=float(pstamp)-self.timestamp
        msecs=tdiff*1000
        isize=int(size)
        if src==True:
            self.s_psizes.append(isize)
            slen=len(self.s_delays)
            if slen>0 and self.s_delays[slen-1]>msecs:
                print("Oddity: src going backwards in time to " + str(msecs) + " from " + str(self) + " tstamp: " + str(pstamp))
            self.s_delays.append(float(msecs))
        elif src==False:
            self.d_psizes.append(isize)
            dlen=len(self.d_delays)
            if dlen>0 and self.d_delays[dlen-1]>msecs:
                print("Oddity: dest going backwards in time to " + str(msecs) + " from "+ str(self) + " tstamp: " + str(pstamp))
            self.d_delays.append(float(msecs))
        else:
            raise ValueError('Bad (non-boolean) given to add_apdu')
        if isize < self.min_pdu:
            self.min_pdu=isize
        if isize > self.max_pdu:
            self.max_pdu=isize
        # probably v. slow but we don't get huge numbers of packets/session
        # so likely not a big deal
        self.num_sizes=len(set(self.s_psizes+self.d_psizes))
    
    def note_chsize(self,cs):
        self.chsize=cs

    def note_shsize(self,ss):
        self.shsize=ss

    def note_end(self,pkttime):
        self.end_time=pkttime

# used for sorting sessions
def get_sortstr(s):
    return s.sortstr

def sess_find(fname,sessions,ver,ptime,ptstamp,src,sport,dst,dport):
    #print ("Checking for " + src + ":" + sport + " to/from " + dst + ":" + dport + "|")
    for s in sessions:
        #print("Considering: " + str(s))
        if s.fname==fname and s.src==dst and s.sport==dport and s.dst==src and s.dport==sport:
            #print("Matched reverse")
            return s
        elif s.fname==fname and s.src==src and s.sport==sport and s.dst==dst and s.dport==dport:
            #print("Matched forward")
            return s
    # otherwise make a new one
    # TODO: extend/parameterise this set of known server ports sometime
    if dport=="443" or dport=="853" or dport=="993":
        #sys.stderr.write("New Session option 1: " + sport + "->" + dport + "\n") 
        s=TLSSession(fname,ver,ptime,ptstamp,src,sport,dst,dport)
        sessions.append(s)
        return s
    elif sport=="443" or sport=="853" or sport=="993":
        #sys.stderr.write("New Session option 2: " + sport + "->" + dport + "\n") 
        s=TLSSession(fname,ver,ptime,ptstamp,dst,dport,src,sport)
        sessions.append(s)
        return s
    else:
        # take 'em as they come
        s=TLSSession(fname,ver,ptime,ptstamp,src,sport,dst,dport)
        #print("New Session option 3: " + sport + "->" + dport + "Session ID: " + str(s.sess_id))
        sessions.append(s)
        return s

def analyse_pcaps(flist,sessions,verbose):
    # iterate through each file, gathering our stats
    for fname in flist:
        if verbose:
            print("Processing " + fname)
        try:
            f = pyshark.FileCapture(fname,display_filter='ssl')
            chtime=0
            for pkt in f:
                src=""
                if 'ip' in pkt:
                    src=pkt.ip.src
                    dst=pkt.ip.dst
                elif 'ipv6' in pkt:
                    src=pkt.ipv6.src
                    dst=pkt.ipv6.dst
                else:
                    sys.stderr.write("No sender!\n");
                    sys.stderr.write(str(dir(pkt))+"\n")
                    sys.stderr.write(str(pkt)+"\n")
                    continue
                if 'tcp' in pkt:
                    dport=pkt.tcp.dstport
                    sport=pkt.tcp.srcport
                else:
                    sys.stderr.write("Not a TCP packet!"+"\n")
                    sys.stderr.write(str(dir(pkt))+"\n")
                    sys.stderr.write(str(pkt)+"\n")
                    continue
                if 'ssl' not in pkt:
                    #print ("Skipping non SSL packet from " + src)
                    continue
                if not (hasattr(pkt.ssl,'record_content_type') or hasattr(pkt.ssl,'record_opaque_type')):
                    #print("Skipping SSL packet with nonsense content")
                    continue
    
                ver='unknown'
                if hasattr(pkt.ssl,'record_version'):
                    ver=pkt.ssl.record_version
    
                # see if this is a known session or not
                this_sess=sess_find(fname,sessions,ver,pkt.sniff_time,pkt.sniff_timestamp,src,sport,dst,dport)
    
                if hasattr(pkt.ssl,'record_content_type') and pkt.ssl.record_content_type=="20":
                    # print("ChangeCipherSpec")
                    pass
                elif hasattr(pkt.ssl,'record_content_type') and pkt.ssl.record_content_type=="21":
                    # TODO: if we get two of these, one from each side, that may be good reason to
                    # think that's the end of this TLS session, but maybe more checking is
                    # needed, we'll see...
                    # print("EncryptedAlert at " + str(pkt.sniff_time) + " for: " + str(this_sess))
                    this_sess.note_end(pkt.sniff_time)
                    pass
                elif hasattr(pkt.ssl,'record_content_type') and pkt.ssl.record_content_type=="22":
                    # handshake
                    if hasattr(pkt.ssl,'handshake_type'):
                        if pkt.ssl.handshake_type=="1":
                            #print("ClientHello for " + str(this_sess.sess_id))
                            this_sess.note_chsize(pkt.ssl.record_length)
                            this_sess.chtime=pkt.sniff_time
                            pass
                        elif pkt.ssl.handshake_type=="2":
                            #print("ServerHello")
                            this_sess.note_shsize(pkt.ssl.record_length)
                            if this_sess.chtime==0:
                                this_sess.rttest=-1
                            else:
                                td=pkt.sniff_time-this_sess.chtime
                                this_sess.rttest=int(td.total_seconds()*1000)
                            pass
                        elif pkt.ssl.handshake_type=="4":
                            #print("NewSessionTicket")
                            pass
                        elif pkt.ssl.handshake_type=="11":
                            #print("Certificate")
                            this_sess.certsize=pkt.ssl.record_length
                            # If RSA:
                            # Use the server cert modulus size as a proxy for what
                            # would be the size of a TLS1.3 CertificateVerify
                            # Modulus format here is of the form "00:aa:bb..."
                            # So we want to loose the colons (1/3 of length)
                            # then divide by 2 to get octets
                            # then add 10 which'd be the overhead for a TLS1.3 CertificateVerify
                            # So bottom line is divide by 3, then add 10
                            # and "//" is integer divide for python 3
                            if hasattr(pkt.ssl,'pkcs1_modulus'):
                                mlen=len(pkt.ssl.pkcs1_modulus)
                                mlen=(mlen//3)+10
                                if this_sess.cvsize==0:
                                    this_sess.cvsize=mlen
                                else:
                                    # Don't think this should happen, but who knows...
                                    # If it does, better we know
                                    sys.stderr.write("Re-setting cvsize for " + str(this_sess.sess_id) + \
                                        " from: " + str(this_sess.cvsize) + \
                                        " to: " + str(mlen) + "\n" )
                                    this_sess.cvsize=mlen
                            elif hasattr(pkt.ssl,'pkcs1_ecparameters') and hasattr(pkt.ssl,'x509af_subjectpublickey'):
                                # same encoding as above
                                pklen=len(pkt.ssl.x509af_subjectpublickey)//3+10
                                this_sess.cvsize=pklen
                            else:
                                sys.stderr.write("No modulus or ECParameters for session: " + str(this_sess.sess_id)+ "\n")
                                sys.stderr.write(str(dir(pkt.ssl))+ "\n")
                                sys.stderr.write(str(pkt.ssl)+ "\n")
                        elif pkt.ssl.handshake_type=="12":
                            #print("ServerKeyExchange")
                            pass
                        elif pkt.ssl.handshake_type=="14":
                            #print("ServerHelloDone")
                            pass
                        elif pkt.ssl.handshake_type=="16":
                            #print("ClientKeyExchange")
                            pass
                        elif pkt.ssl.handshake_type=="15":
                            #print("CertificateVerify")
                            this_sess.cvsize=pkt.ssl.record_length
                            pass
                        elif pkt.ssl.handshake_type=="22":
                            #print("CertificateStatus")
                            pass
                        else:
                            sys.stderr.write("Handshake: " + pkt.ssl.handshake_type + "\n")
                            sys.stderr.write(src+":"+sport+"->"+dst+":"+dport + "\n")
                            sys.stderr.write(str(dir(pkt.ssl)) + "\n")
                            sys.stderr.write(str(pkt.ssl) + "\n")
                    else:
                        # This should just be encrypted Finished messages in TLS1.2
                        # but can be others in TLS1.3 - we'll ignore 'em anyway
                        # (for now:-)
                        #sys.stderr.write("Weird Handsshake: " + "\n")
                        #sys.stderr.write(src+":"+sport+"->"+dst+":"+dport + "\n")
                        #sys.stderr.write(str(dir(pkt.ssl)) + "\n")
                        #sys.stderr.write(str(pkt.ssl) + "\n")
                        pass
                elif hasattr(pkt.ssl,'record_content_type') and pkt.ssl.record_content_type=="23":
                    # application data, count it!
                    this_sess.add_apdu(pkt.ssl.record_length,pkt.sniff_time,pkt.sniff_timestamp,(this_sess.src==src and this_sess.sport==sport))
                elif hasattr(pkt.ssl,'record_opaque_type') and pkt.ssl.record_opaque_type=="23":
                    # also application data, count it! why the diference I wonder?
                    if not hasattr(pkt.ssl,'change_cipher_spec'):
                        this_sess.add_apdu(pkt.ssl.record_length,pkt.sniff_time,pkt.sniff_timestamp,(this_sess.src==src and this_sess.sport==sport))
                    else:
                        #print("CCS")
                        pass
                elif hasattr(pkt.ssl,'record_content_type') and pkt.ssl.record_content_type=="24":
                    # print("Heartbeat!")
                    pass
                else:
                    sys.stderr.write("Unexpected Message: "  + str(this_sess.sess_id) + "\n")
                    sys.stderr.write(str(dir(pkt.ssl))+"\n")
                    sys.stderr.write(str(pkt.ssl)+"\n")
            f.close()
            # there's occasional (but possibly predictable, not sure) exceptions
            # from the bowels of tshark, maybe a little sleep with fix...
            # time.sleep(5) 
            # nope, didn't work
        except Exception as e:
            sys.stderr.write(str(traceback.format_exc()))
            sys.stderr.write("Exception: " + str(e) + "\n")

def analyse_cadence(sessions):
    interactions=[]
    for s in sessions: 
        # for each c2s packet delay, figure what packets send and rx'd before
        # next c2s packet, and store that exchange in our list of interactions
        numc2ss=len(s.s_delays)
        # we're likely at least 10ms is needed for a real answer, otherwise
        # the s2c packet likely answers the previous c2s packet
        # estimate of RTT is based on the ClientHello/ServerHello
        # time gap, use that if it's >0 (it might not be if e.g.
        # the ClientHello was sent before we started capturing
        # traffic)
        rttest=10
        if s.rttest>0:
            rttest=s.rttest
        # eat any APDUs from server before the client has sent one
        # my theory is that those are TLSv1.3 EncryptedExtensions or
        # maybe session tickets, with 0RTT early data, that'd not be
        # right but I'm not sure I'm seeing that (based on using 
        # wireshark to also look at traffic)
        # TODO: check theory!
        s2cind=0
        if numc2ss!=0:
            first_c2sd=s.s_delays[0] 
            while s2cind<len(s.d_delays) and s.d_delays[s2cind] < first_c2sd:
                s2cind+=1
        c2sind=0
        next_c2sd=0
        while c2sind < numc2ss:
            c2st=[]
            c2sp=[]
            this_c2sd=s.s_delays[c2sind] 
            c2st.append(int(this_c2sd))
            c2sp.append(s.s_psizes[c2sind])
            if (c2sind<(numc2ss-1)):
                # if there are two c2s messages <10ms apart, we'll assume
                # that's down to fragmentation or similar and merge 'em
                # as even if they're separate HTTP requests, the answers
                # will be interleaved too (from our non-decrypting 
                # perspective)
                diff_c2sd=0
                while diff_c2sd < rttest and c2sind<(numc2ss-1):
                    next_c2sd=s.s_delays[c2sind+1]
                    diff_c2sd=next_c2sd-this_c2sd
                    if diff_c2sd < rttest:
                        c2sind+=1
                        c2st.append(int(next_c2sd))
                        c2sp.append(s.s_psizes[c2sind])
            else:
                next_c2sd=sys.maxsize
            c2sind+=1
            # store the sizes and timings of packets 'till the next
            # c2s time
            s2ct=[]
            s2cp=[]
            exchange={}
            while s2cind<len(s.d_delays) and s.d_delays[s2cind] < (next_c2sd + rttest):
                s2ct.append(int(s.d_delays[s2cind]))
                s2cp.append(s.d_psizes[s2cind])
                s2cind+=1
            exchange["sess_id"]=s.sess_id
            exchange["fname"]=s.fname
            if len(s2ct) > 0 :
                exchange["dur"]=s2ct[-1]-this_c2sd
            else:
                exchange["dur"]=0
            exchange["rttest"]=rttest
            exchange["c2st"]=c2st
            exchange["c2sp"]=c2sp
            exchange["s2ct"]=s2ct
            exchange["s2cp"]=s2cp
            #print(exchange)
            interactions.append(exchange)
    #print(interactions)
    return(interactions)

