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

# Start or read a capture file, then generate music

SRCDIR=$HOME/code/tlspad

# load useful functions and variables
. $SRCDIR/functions.sh

function usage()
{
	echo "$0 [-f <capture-file/dir>] [-l <label>] [-S limit] [-wvcL]"
    echo ""
    echo "Wrapper to grab TLS traffic info via tshark or tcpdump. Arguments can be:"
    echo "-h - produce this"
    echo "-f - name of capture file or directory for capture files (default is '.')"
    echo "-l - label to use for files (will be anonymous hash otherwise)"
    echo "-S - suppress silence or noise that doesn't change for the specified limit (in ms)"
    echo "-c - clean out audio files in this directory (*.midi.csv, *.wav, *.midi)"
    echo "-L - use logarithmic time"
    echo "-v - be verbose"
    echo "-w - produce .wav files as well as .mimd (warning: slow, maybe buggy)"
	exit 99
}

# capture file or directory name. if a directory, we store a standard named
# file in there
OFILE="."
VERBOSE=""
WAVOUT=""
LABEL=""
CLEAN="no"
SKIP="no"
JUSTCLEAN="yes"
# default to log time on and 1s suppression as it seems to work nicely
LOGTIME=" -L "
SUPPRESS=" -S 1000 "
# empty strings will turn 'em off
# LOGTIME=""
# SUPPRESS=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o S:Lschwvf:l: -l suppress:,logtime,skip,clean,help,wav,verbose,file:,label: -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
        -f|--file) JUSTCLEAN="no"; OFILE=$2; shift;;
        -S|--suppress) JUSTCLEAN="no"; SUPPRESS="-s $2"; shift;;
        -l|--label) JUSTCLEAN="no"; LABEL=" -l $2"; shift;;
        -s|--skip) SKIP="yes";;
        -c|--clean) CLEAN="yes";;
        -w|--wav) JUSTCLEAN="no"; WAVOUT=" -w ";;
        -L|--logtime) JUSTCLEAN="no"; LOGTIME=" -T ";;
        -v|--verbose) VERBOSE=" -v ";;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

# TODO: we'll do the actual pcap capture stuff later as we'll want the
# option of running a headless browser and doing it all locally, or, 
# provding some UI prompts for the case where the user runs a real 
# browser. So later then. Meanwhile, we'll assume the pcaps are in the
# OFILE variable

if [[ "$CLEAN" == "yes" ]]
then
    rm -f *.midi.csv *.midi *.wav
    if [[ "$JUSTCLEAN" == "yes" ]]
    then
        echo "Just cleaning - exiting"
        exit 0
    fi
fi

# Do the analysis to generate the csvmidi files (and optonal .wavs)
if [[ "$SKIP" == "no" ]]
then
    $SRCDIR/Tls2Music.py -f $OFILE $LABEL $VERBOSE $WAVOUT $LOGTIME $SUPPRESS
fi

# TODO: finer grained control of which csvs to (re-)map to midis
# Now map the csvs to midis (if there are any - that's the first
# if statement 
csvs=(*.midi.csv)
if [ -e  "${csvs[0]}" ];
then
    for file in *.midi.csv
    do
        mf=`basename $file .csv`
        if [ $file -nt $mf ]
        then
            csvmidi $file $mf
        else
            echo "Skipping $file as $mf is newer"
        fi
    done
else
    echo "No csvs to process - exiting"
fi

