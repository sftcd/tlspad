#!/bin/bash

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

# For a given pcap file, try render with all instruments

#set -x

pcap="ny1.pcap"
if [[ "$1" != "" ]]
then
    pcap=$1
fi

srcdir="$HOME/code/tlspad"

for ((inst=0;inst!=128;inst++))
do
    echo "Doing $inst"
    $srcdir/Tls2Music.py -f $pcap -i $inst -V all -l "inst$inst" 
    if [[ "$?" != "0" ]]
    then
        echo "Error - exiting"
        exit 1
    fi
    mv *inst$inst*.csv inst$inst.midi.csv
    csvmidi inst$inst.midi.csv >inst$inst.midi
    #if [[ "$inst" == "1" ]]
    #then
        #exit
    #fi
done
