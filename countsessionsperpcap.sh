#!/bin/bash

# set -x

# 
# Copyright (C) 2019 Stephen Farrell, stephen.farrell@cs.tcd.ie
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# run a counter over all the pcaps below where we are then count the 
# number of TLS sessions per pcap, with output being a CSV with 
# machine, web-site, number-of-sessions

# This depends on the file naming conventions used elsewhere so won't
# port so easily I guess but good enough

PCL="pcapfile.list"
ANALYSISFILE="pcapanalysis.out"
CSVSESSIONS="sessions-per-site.csv"

# grab new list of PCAP files below here, if needed
if [ ! -f $PCL ]
then
    find . -name '*.*.pcap' >$PCL
fi

# extract packet sizes and times and etc (takes a looooong time!)
if [ ! -f $ANALYSISFILE ]
then
    for file in `cat $PCL`
    do 
        echo $file >> $ANALYSISFILE; 
        ~/code/tlspad/TlsPacketSizes.py -f $file >>$ANALYSISFILE 2>&1 
    done
fi

if [ ! -f $CSVSESSIONS ]
then
    # that file will have a bunch of exceptions, but this seems to
    # grep 'em out of the way (so far!)
    for machine in stephen-think yogg
    do
        cat $ANALYSISFILE | awk '/^\.\/'$machine'/{a=1}/^Found/{print;a=0}a' | \
            grep -v File | \
            grep -v Trace | \
            grep -v self | \
            grep -v ':' | \
            grep -v Exception | \
            grep -v '^[ ]*$' | \
            sed 'N;s/\n/,/' | \
            awk -F'/' '{print $2","$5}' | \
            sed -e 's/Found //' | \
            sed -e 's/ sessions.//' | \
            sed -e 's/.pcap//' | \
            grep $machine  >>$CSVSESSIONS
    done
fi

