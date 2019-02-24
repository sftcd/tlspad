
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

Note: we do not yet have evidence that sites do/don't, in general, sound different 
enough for human ears to pick that up in some reliable way. Be fun to find out though!

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
    - sorta seems to work
    - to pick which TLS sessions to in/exclude in a sound file:
        - include all TLS sessions in one sound file: use ``-V all``
        - group sound files by src IP: use ``-V src``
        - group souind files by dst IP: use ``-V dst``
        - only include some IP range(s): use ``-V <fname>``
            - where fname names a file that contains one IPv4/IPv6 prefix per line
            - IPv4 prefixes need to be like: ``192.0.2.0/24`` (i.e. include zeros on right)
            - IPv6 prefixes can be like: ``2001:db8::/32``
        - ``-V`` is for vantage point here even though that's not quite right
        - default is to group by src IPs

- [getpage.py](getpage.py) uses selenium and FF to grab a front page so we can
    capture the pcap and make music
    - Looks like selenium/geckodriver is causing some spurious 
    connections, e.g. to Moz telemetry. Not sure if I should include
    or drop these really. Not part of target URL site, but are part
    of default browsing experience most likely. Plan: Try figure how to
    not make these connecctions then decide later.
        - Added a check internally - if a FF profile directory
        matching ``$HOME/.mozilla/firefox/*.Testing`` exists then 
        the first of those is used as the FF profile when starting.
        Have to see if that honors the "no reporting" privacy
        settings in FF.
        - looks like FF telemetry <blah>.cdn.mozilla.net has nearby
        IPs and some similar DNS names exist in FF about:config
        - Doesn't seem to have done the biz, still seeing connection to
        some unexpected oddball IPs, despite using profile with telemetry
        off
        - Leave it for now, hope to learn more about it as we go


- [composer.sh](composer.sh) is a wrapper for the above:

            $ ./composer.sh -h 
            ./composer.sh [-u <url-or-file>] [-f <capture-file/dir>] [-l <label>] [-s limit] [ -i instrument] [-kwvcLSnA]
            
            Wrapper to grab TLS traffic info via tshark or tcpdump. Arguments can be:
            -h - produce this
            -u - URL to access, grab, analyse and turn into midi file
                This uses: '-l <DNSname> -s 1000 -i -1 -V all'
            -f - name of capture file or directory for capture files (default is '.')
            -V - vantage point/selectors, can be [all|src|dst|file-name]
            -i - midi instrument (-1:127; default: 0; -1 means built-in combo)
            -l - label to use for files (will be anonymous hash otherwise)
            -s - suppress silence or noise that doesn't change for the specified limit (in ms)
            -c - clean out audio files in this directory (*.midi.csv, *.wav, *.midi)
            -n - do not clean up temporary files when getting URLs
            -k - skip new data generation and just map csv's to midi's in the current dir
            -L - use logarithmic time
            -S - use scaled time
            -v - be verbose
            -I - generate ignore list (DNS stubby DoT sessions)
            -w - produce .wav files as well as .midi (warning: slow, maybe buggy)

    - If you give that a ``-u URL`` or ``-u filename`` (with one URL/line in that file),
    you'll end up with a 
    (set of) midi file(s) you can play with [timidity](https://www.timidity.jp/). 
    - The "-u" option uses selenium to fire up a test browser but that seems to
    fail (blocking) from time to time. Killing the test browser seens to get 
    things to move along ok, albeit we miss that measurement.
    - This script may need ``sudo`` depending on how you'v setup packet capture.
    - Added production of output .ogg audio file and spectrogram .png file

- [ignore-stubby.sh](ignore-stubby.sh) generates (or updates) the ``ignore.addrs``
file, with the ``addresss_data`` found in ``/etc/stubby/stubby.cfg. Those are
the addresses stubby uses for DoT.
The ``ignore.addrs`` file causes ``Tls2Music.py`` to skip those addresses when making music.
Including all the DNS IPs sometimes makes for more boring sound:-)

- [playem.sh](playem.sh) is just a quick script to use timidity to play all the 
  ``.midi`` files in the current directory

## Re-factoring

This code is very messy at the moment and badly needs a tidy-up/refactoring.
I've started that. It'll need a couple of iterations. Next up in
terms of things to play about with (other than just tidying code) are:

- note length/freq currently chosen via a simple normalisation
  (basically percent between min and mix) but I seem to see
  lots of sessions with v. few packet sizes which means I get
  the min and max ranges quite often. That maps to v. high or 
  low notes which isn't so great. (Mitigated a chunk by using
  different instruments at different octaves but still...)
    - added the num_sizes input to size2freqdur to take
      that into account but haven't yet used it

- some notes are being lost from some sound files according to 
``timidity`` - need to check and fix
    - changing the min,max note lengths to 500,1500 from 100,1000 (ms)
    seems to have some effect, but doesn't solve the issue

- play some more with the python ``music`` library which seems to
be related to [mass](https://github.com/ttm/mass) (install 
via ``pip install music``) - that'd likely replace the current
``.wav`` file generation code that produces modem noise.

Things along these lines that are a work-in-progress:

- added a ``time_dilation`` feature but it didn't seem to make
    much real diff 

- figure out/guess some b/w number
    - 1MB/s (8Mbps) as a default 
    - @ 44.1KHz sample rate that means 181 rx/tx'd bits/audio-sample
    - base note duration on that

- did the re-hit note up/down thing and now get loads of
  arpeggio-like things, not right still - maybe bump by
  some other interval (there's a TODO in ``avoid2keypresses``)

- added first playing with velocity/loudness changes
     - "midloud" to vary velocity between min and max based on
       sine of where we are in the overall tune (so max about
       the middle)

- added another ensemble (mapping of midi channels to
  instrumennts); not as much difference as expected but more
  playing to be done

## Tools used

Notes made while figuring out `what to use. These aren't really organised, but
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

I still want to try anonymise the pcap files, in case I wanna publish something
or someone else wants to. For now, the .midi files can be anonymous or else
just identify a URL, which is probably ok, but better to do better. 
There's a [wireshark tools page](https://wiki.wireshark.org/Tools#Capture_file_anonymization),
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
- The ubuntu packages "abcmidi" and "absm2ps" provide (respectively) the
  ``midi2abc`` and ``abcm2ps`` tools, that do allow me to map my midi
  files to abc form. Sadly, the latter too barfs on those abc files
  complaining that there are too many notes in a chord, which is 
  not unreasonable really.
- A java thing to check out [aeolian](https://github.com/andeemarks/aeolian)
- A linux journal [article](https://www.linuxjournal.com/content/algorithmic-music-composition-linux-athenacl)
- A way to make a nice [plot](https://stackoverflow.com/questions/5826701/plot-audio-data-in-gnuplot) - might add to composer
- [this](https://github.com/jdesbonnet/audio-to-waterfall-plot-video/blob/master/make-waterfall-video.sh) script can make
 a video from audio, maybe worth a look, probably needs modification.
