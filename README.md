
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
- [TLSPacketSizes.py](TLSPacketSizes.py) does some simple counts of TLS packet sizes in PCAP files 

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

