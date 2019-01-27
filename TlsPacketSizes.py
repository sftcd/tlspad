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
            'fname',
            'version',
            'start_time',
            'timestamp',
            'src',
            'sport',
            'dst',
            'dport',
            'certsize',
            'cvsize',
            's_psizes',
            's_delays',
            'd_psizes',
            'd_delays'
            ]

    def __init__(self,fname='',ver='',stime=0,tstamp='0',src='',sport='',dst='',dport=''):
        self.sess_id=random.getrandbits(32)
        self.fname=fname # file name in which packet was seen
        self.version=ver # TLS version from the 1st relevant packet we see
        self.start_time=stime # file-relative start time of session
        self.timestamp=float(tstamp) # file-relative start time of session
        self.src=src # client IP (v4 or v6)
        self.sport=sport # client port
        self.dst=dst  # server IP
        self.dport=dport # server port
        self.certsize=0 # cert size if seen in h/
        self.cvsize=0 # cert verify size if seen in h/s
        self.s_psizes=[] # list of APDU sizes from src, 0 is 1st, 1 2nd seen etc.
        self.s_delays=[] # list of relative time offsets from session start
        self.d_psizes=[] # list of APDU sizes from dst, 0 is 1st, 1 2nd seen etc.
        self.d_delays=[] # list of relative time offsets from session start

    def __str__(self):
        return "ID: " + str(self.sess_id) + " V:" + ver + " time: " + str(self.start_time) + " tstamp: " + str(self.timestamp) + "\n" +  \
                " file: " + self.fname + "\n" + \
                "\t" + self.src + ":" + self.sport + "->" + self.dst + ":" + self.dport + \
                    " cert: " +  str(self.certsize) + " cv size: " + str(self.cvsize) + "\n" +  \
                "\t" + "source packet sizes: " + str(self.s_psizes) + "\n"+ \
                "\t" + "source packet times: " + str(["%.3f" % v for v in self.s_delays]) + "\n" + \
                "\t" + "dest packet sizes: " + str(self.d_psizes) + "\n" + \
                "\t" + "dest packet times: " + str(["%.3f" % v for v in self.d_delays]) + "\n" 

    def add_apdu(self,size,pkttime,pstamp,src):

        # this way was broken, not sure why
        #tdiff=pkttime-self.start_time
        #msecs=tdiff.microseconds/1000

        # this way works:-) str->float; subtract; then secs -> millisecs
        #print ("type(pstamp): " + str(type(pstamp)) + " type(self.timestamp): " + str(type(self.timestamp)))
        tdiff=float(pstamp)-self.timestamp
        msecs=tdiff*1000
        if src==True:
            self.s_psizes.append(size)
            slen=len(self.s_delays)
            if slen>0 and self.s_delays[slen-1]>msecs:
                print("Oddity: src going backwards in time to " + str(msecs) + " from " + str(self) + " tstamp: " + str(pstamp))
            self.s_delays.append(msecs)
        elif src==False:
            self.d_psizes.append(size)
            dlen=len(self.d_delays)
            if dlen>0 and self.d_delays[dlen-1]>msecs:
                print("Oddity: dest going backwards in time to " + str(msecs) + " from "+ str(self) + " tstamp: " + str(pstamp))
            self.d_delays.append(msecs)
        else:
            raise ValueError('Bad (non-boolean) given to add_apdu')

def sess_find(fname,sessions,ver,ptime,ptstamp,src,sport,dst,dport):
    for s in sessions:
        if s.fname==fname and s.src==src and s.sport==sport and s.dst==dst and s.dport==dport:
            return s
        elif s.fname==fname and s.src==dst and s.sport==dport and s.dst==src and s.dport==sport:
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
        #sys.stderr.write("New Session option 3: " + sport + "->" + dport + "\n") 
        s=TLSSession(fname,ver,ptime,src,sport,dst,dport)
        sessions.append(s)
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
                # print("EncryptedAlert")
                pass
            elif hasattr(pkt.ssl,'record_content_type') and pkt.ssl.record_content_type=="22":
                # handshake
                if hasattr(pkt.ssl,'handshake_type'):
                    if pkt.ssl.handshake_type=="1":
                        #print("ClientHello for " + str(this_sess.sess_id))
                        pass
                    elif pkt.ssl.handshake_type=="2":
                        #print("ServerHello")
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
                this_sess.add_apdu(pkt.ssl.record_length,pkt.sniff_time,pkt.sniff_timestamp,(this_sess.src==src))
            elif hasattr(pkt.ssl,'record_opaque_type') and pkt.ssl.record_opaque_type=="23":
                # also application data, count it! why the diference I wonder?
                if not hasattr(pkt.ssl,'change_cipher_spec'):
                    this_sess.add_apdu(pkt.ssl.record_length,pkt.sniff_time,pkt.sniff_timestamp,(this_sess.src==src))
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
 
print("Found " + str(len(sessions)) + " sessions.\n")
for s in sessions:
    print(s)
    time.sleep(0.01) 

