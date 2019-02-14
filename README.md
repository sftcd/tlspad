
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
the pcap files. First cut is to play about with making noise...

## The musical argument...

The argument is actually fairly simple:
- if we map packet size/timing to music in a regular/predictable manner, and,
- if a user can recognise the difference between site sounds (an unknown!), then
- if either side wants to benefit from ESNI, 
- ... they both need to pad more/better than just ESNI  

Note: we do not yet have evidence that sites do/don't sound different 
enough for human ears to pick that up. Be fun to find out though!

## Tools here

Notes about what you need to install are [here](depends.md). Might turn that into a script
later.

- [dumper.sh](dumper.sh) is a bash script that's a small wrapper on tshark or tcpdump
    - [functions.sh](functions.sh) has some bash utility stuff I tend to re-use
- [TlsPadFncs.py](TlsPadFncs.py) has classes and functions that are used by...
- [TLSPacketSizes.py](TLSPacketSizes.py) does some simple per-session counts of TLS packet sizes in PCAP files 
    - pyshark still now and then says tshark crashed, will just live with it for now
- [Tls2Music.py](Tls2Music.py) takes the packets sizes/times and turns
    those to sound, either a .midi or .wav file or both.
    - that sorta seems to work, state is I need to check accuracy (it's suspect:-)
    - a remaining TODO:
        - re-hit keys, move up/down one if a key/tone is playing now or
        otherwise avoid collisions (but pianos only have 88 keys so we
        can't avoid all, in general) - might not need it so much now, with
        log time and supression it may be less of a deal
- [getpage.py](getpage.py) uses selenium and FF to grab a front page so we can
    capture the pcap and make music
    - A bug just seen that I guess may be related to selenium (no idea of cause or effect;-): 

            *** BUG ***
            In pixman_region32_init_rect: Invalid rectangle passed
            Set a breakpoint on '_pixman_log_error' to debug

- [composer.sh](composer.sh) is a wrapper for the above:

            $ ./composer.sh -h 
            ./composer.sh [-u <url-or-file>] [-f <capture-file/dir>] [-l <label>] [-s limit] [ -i instrument] [-kwvcLSnA]
            
            Wrapper to grab TLS traffic info via tshark or tcpdump. Arguments can be:
            -h - produce this
            -u - URL to access, grab, analyse and turn into midi file
                 This uses: '-l <DNSname> -s 1000 -i -1 -A'
            -f - name of capture file or directory for capture files (default is '.')
            -A - map all pcaps into one music/noise file output
            -i - midi instrument (-1:127; default: 0; -1 means built-in combo)
            -l - label to use for files (will be anonymous hash otherwise)
            -s - suppress silence or noise that doesn't change for the specified limit (in ms)
            -c - clean out audio files in this directory (*.midi.csv, *.wav, *.midi)
            -n - do not clean up temporary files when getting URLs
            -k - skip new data generation and just map csv's to midi's in the current dir
            -L - use logarithmic time
            -S - use scaled time
            -v - be verbose
            -w - produce .wav files as well as .midi (warning: slow, maybe buggy)

    - If you give that a ``-u URL`` or ``-u filename`` (with one URL/line in that file),
    you'll end up with a 
    (set of) midi file(s) you can play with [timidity](https://www.timidity.jp/). 
    - The "-u" option uses selenium to fire up a test browser but that seems to
    fail (blocking) from time to time. Killing the test browser seens to get 
    things to move along ok, albeit we miss that measurement.
    - There're a load of installs needed to get all that to work, I'll document 'em when 
    I set this up on a 2nd box and have to re-do 'em.


## Tools used

Notes made while figuring out what to use. These aren't really organised, but
are just so's I can go back to something later if I wanna.

## General pcap processing

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

## pcap anonymisation

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

## Musical stuff

Things I looked at, in less or lesser detail...

- I hacked the [midicsv](https://www.fourmilab.ch/webtools/midicsv/) output myself for now, but turns out there's 
    a [py-midicsv](https://pypi.org/project/py-midicsv/) thing I should
    check out. Not sure if it adds much.
- [musicalgorithms.org](http://musicalgorithms.org) (no https, sorry;-) has a 
    similar idea and is nearly what I want, but a) it doesn't seem to incorporate
    a packet timing analog, and b) it's too boring when packet sizes repeat a lot
    - there's a python front-end called [purity](https://github.com/aalex/purity) for
    [puredata](https://puredata.info/) that might be worth a look. (After I figure
    out how to get Pd to work at all:-)
- [datadrivendj](https://datadrivendj.com/faq/) seems relevant; uses 
     [Chuck](http://chuck.cs.princeton.edu/) (no https, sorry) - might be
    worth a look, but maybe too complicated;-(
