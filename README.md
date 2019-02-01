
# Investigating TLS padding

This repo has (or rather, will have) scripts to investigate TLS padding.
The goal is to try figure if there're useful TLS padding schemes that
help mitigate (not necessarily "solve") traffic analysis attacks, particularly, 
for scenarios where Encrypted SNI might be used. 

Note: we won't decrypt or MitM any TLS sessions for this.

This is a side project related to my 
[openssl ESNI fork](https://github.com/sftcd/openssl/blob/master/esnistuff/design.md)

To start with, I need some idea of what packet sizes are used in the wild, so
initial work relates to a [measurement script](dumper.sh) to capture some
packets. Once I have some of those, I'll figure out how I want to analyse
the pcap files.

## Tools here

- [dumper.sh](dumper.sh) is a bash script that's a small wrapper on tshark or tcpdump
    - [functions.sh](functions.sh) has some bash utility stuff I tend to re-use
- [TLSPacketSizes.py](TLSPacketSizes.py) does some simple per-session counts of TLS packet sizes in PCAP files 
    - seems to match at least one ground truth case, more checks needed
    - pyshark still now and then says tshark crashed, will just live with it for now

## Tools used

I spent a little time looking at tooling to extract things from the pcap files.
There are many tools, but nothing so far that's exactly what I want. 

I tried:

- [gopacket](https://github.com/google/gopacket), a golang package, but
  TLS support seems extremely partial, which is a pity.
- [dpkt](https://dpkt.readthedocs.io/), a python module, but that barfs on the
  pcap-ng (I guess) format used by tshark, even though that bug was known in
2014, so that's not too hopeful.
- [python-pcapng](https://github.com/rshk/python-pcapng) seems to handle the
  format but appears to have nothing for TLS, so didn't try that really
- [pyshark](https://kiminewt.github.io/pyshark/) ... and made
  progress with that, so that's where we're at for now. 

Next is to try anonymise the pcap files, in case I wanna publish something
or someone else wants to. There's a [wireshark tools page](https://wiki.wireshark.org/Tools#Capture_file_anonymization),
and a [caida page](https://www.caida.org/tools/taxonomy/anontaxonomy.xml) let's see what we find there. 
At first glance, a lot of these don't appear to be well-maintained.

- pktanon, has an apt install, let's see if that's good enough - nope - doesn't work
with pcapng I guess as it barfs on line 0 of the 1st input tried:-)
- [this page](https://isc.sans.edu/forums/diary/Truncating+Payloads+and+Anonymizing+PCAP+files/23990/) suggests
downloading 2008 vintage code for ``TCPurify`` from the Internet archive and compiling! Well, I'll try anything once...
    - compiles with some warnings and maybe works, but not sure it does what I want (sigh)
    - doesn't seem to handle IPv6
- That last had a comment pointing to [sirano](https://github.com/heia-fr/sirano)
which seems to be a 2015 vintage python thing that might do the biz. Will check
more later (as usual:-)
    - And no IPv6 that I can see (again, sigh, again;-()


