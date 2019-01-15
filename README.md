
# Investigating TLS padding

This repo has (or rather, will have) scripts to investigate TLS padding.
The goal is to try figure if there're useful TLS padding schemes that
help mitigate (not necessarily "solve") traffic analysis attacks, particularly, 
for scenarios where Encrypted SNI might be used. 

This is a side project related to my 
[openssl ESNI fork](https://github.com/sftcd/openssl/blob/master/esnistuff/design.md)

To start with, I need some idea of what packet sizes are used in the wild, so
initial work relates to a [measurement script](dumper.sh) to capture some
packets. Once I have some of those, I'll figure out how I want to analyse
the pcap files.

Looking now at tooling to extract things from the pcap files. There are many
tools, but nothing so far that's exactly what I want. State of play of
playing with those:

- Tried golang [gopacket](https://github.com/google/gopacket) but TLS 
support seems extremely partial, which is a pity.
- Tried python [dpkt](https://dpkt.readthedocs.io/) but that barfs on
the pcap-ng (I guess) format used by tshark, even though that bug was
known in 2014, so that's not too hopeful.
- [python-pcapng](https://github.com/rshk/python-pcapng) seems to
handle the format but appears to have nothing for TLS, so didn't
try that really.
- Let's try [pyshark](https://kiminewt.github.io/pyshark/) so...
... and progress with that, so we'll play a bit in [countem.py](countem.py)


Note: we won't decrypt or MitM any TLS sessions for this.
