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

# Produce a csvmidi input file that has notes from nearly everthing

# This is really just used to try see what limits on tooling may be
# so the code is like to be edited each time this is run

OFILE=ai.midi.csv

cat >$OFILE <<EOF
0, 0, Header, 1, 128, 480
1, 0, Start_track
1, 0, Title_t, "Tls2Music 903b131d93d19f5"
1, 0, Text_t, "see https://github.com/sftcd/tlspad/"
1, 0, Copyright_t, "This file is in the public domain"
1, 0, Time_signature, 4, 2, 24, 8
1, 0, Tempo, 500000
1, 0, End_track
EOF


TMPF=`mktemp /tmp/allinstXXXX`

for ((inst=0; inst!=127; inst++ ))
do
    # skip drums
    i16=$((inst%16))
    if [[ "$i16" == "9" ]]
    then
        chan=10
    else
        chan=$i16
    fi
cat >>$OFILE <<EOF
$((inst+2)), 0, Start_track
$((inst+2)), 0, Instrument_name_t, "channel $inst misc"
$((inst+2)), 0, Program_c, $chan, $inst
EOF
    rm -f $TMPF
    for ((note=0; note!=10; note++ ))
    do
        ontime=$((RANDOM%10000))
        duration=$(((RANDOM%1000)+100))
        offtime=$((ontime+duration))
        key=$((RANDOM%127))
        vel=$(((RANDOM%40)+40))
        echo "$((inst+2)),$ontime,note_on_c,$chan,$key,$vel" >>$TMPF
        echo "$((inst+2)),$offtime,note_off_c,$chan,$key,0" >>$TMPF
    done
    sort -n $TMPF >>$OFILE
    lastime=`tail -1 $OFILE | awk -F, '{print $2}'`
    echo "$((inst+2)),$lastime, End_track" >>$OFILE
done

echo "0, 0, End_of_file" >>$OFILE

if [ -f $TMPF ]
then
    rm -f $TMPF
fi
