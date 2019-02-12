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
	echo "$0 [-u <url>] [-f <capture-file/dir>] [-l <label>] [-s limit] [ -i instrument] [-kwvcLS]"
    echo ""
    echo "Wrapper to grab TLS traffic info via tshark or tcpdump. Arguments can be:"
    echo "-h - produce this"
    echo "-u - URL to access, grab, analyse and turn into midi file"
    echo "     This uses: '-l <DNSname> -s 1000 -i -1'"
    echo "-f - name of capture file or directory for capture files (default is '.')"
    echo "-i - midi instrument (-1:127; default: 0; -1 means built-in combo)"
    echo "-l - label to use for files (will be anonymous hash otherwise)"
    echo "-s - suppress silence or noise that doesn't change for the specified limit (in ms)"
    echo "-c - clean out audio files in this directory (*.midi.csv, *.wav, *.midi)"
    echo "-k - skip new data generation and just map csv's to midi's in the current dir"
    echo "-L - use logarithmic time"
    echo "-S - use scaled time"
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
# default to log time off and 1s suppression as it seems to work nicely
LOGTIME=""
SUPPRESS=" -s 1000 "
INSTRUMENT=" -i -1"
SCALED=""
# empty strings will turn 'em off
# SUPPRESS=""
# INSTRUMENT=""
# if you want log time on
# LOGTIME=" -T "
# if you want scaled time on
# SCALED=" -S "

# no hardcoded URL
URL=""

# temp dir var (if needed)
TDIR=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o Su:i:sLkchwvf:l: -l scaled,url:,instrument:,suppress:,logtime,skip,clean,help,wav,verbose,file:,label: -- "$@")
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
        -u|--url) JUSTCLEAN="no"; URL=$2; shift;;
        -i|--instrument) JUSTCLEAN="no"; INSTRUMENT=" -i $2"; shift;;
        -s|--suppress) JUSTCLEAN="no"; SUPPRESS="-s $2"; shift;;
        -l|--label) JUSTCLEAN="no"; LABEL=" -l $2"; shift;;
        -k|--skip) SKIP="yes";;
        -c|--clean) CLEAN="yes";;
        -w|--wav) JUSTCLEAN="no"; WAVOUT=" -w ";;
        -L|--logtime) JUSTCLEAN="no"; LOGTIME=" -T ";;
        -S|--scaled) JUSTCLEAN="no"; SCALED=" -S ";;
        -v|--verbose) VERBOSE=" -v ";;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [[ "$CLEAN" == "yes" ]]
then
    rm -f *.midi.csv *.midi *.wav
    if [[ "$JUSTCLEAN" == "yes" ]]
    then
        echo "Just cleaning - exiting"
        exit 0
    fi
fi

# we'll do the actual pcap capture stuff later as we'll want the
# option of running a headless browser and doing it all locally, or, 
# provding some UI prompts for the case where the user runs a real 
# browser. So later then. Meanwhile, we'll assume the pcaps are in the
# OFILE variable

if [[ "$SKIP" == "no" && "$URL" != "" ]]
then
    # make sure its https, and barf otherwise
    if [[ ! $URL =~ ^https://.* ]] 
    then
        echo "Bad URL, I only do https for now - exiting"
        exit 4
    fi

    # full URLs might not be good parts of file names so we'll pull out
    # the DNS name and use that
    DNSname=`echo $URL | awk -F/ '{print $3}'`
    if [[ "$VERBOSE" != "" ]]
    then
        echo "DNS: $DNSname"
    fi
    if [[ "$DNSname" == "" ]]
    then
        echo "Can't extract DNS name from $URL - exiting"
        exit 5
    fi

    # probably wanna do a mktemp -d to keep crap and just 
    TDIR=`mktemp -d /tmp/composeXXXX`
    ODIR=$PWD
    if [ ! -d $TDIR ]
    then
        echo "Failed to make temp dir ($TDIR) - exiting"
        exit 1
    fi
    cd $TDIR

    # copy back out the midi file
    # start capture 
    if [[ "$VERBOSE" == ""  ]]
    then
        $SRCDIR/dumper.sh -f $DNSname.pcap -s 10000 >/dev/null 2>&1 &
        dpid=$!
    else
        $SRCDIR/dumper.sh -f $DNSname.pcap -s 10000 &
        dpid=$!
    fi

    # access a URL via a headless browser
    $SRCDIR/getpage.py $URL

    # kill off the tcpdump or tshark process
    sleep 1
    # if dumper still running, kill it
    # this doesn't always work...
    if [[ "$VERBOSE" == ""  ]]
    then
        # ... so we'll also kill all capture instances we may have started
        # should be ok as these aren't usually running but better not add
        # this as a cron job
        kill $dpid >/dev/null 2>&1 
        sudo killall tcpdump >/dev/null 2>&1 
        sudo killall tshark >/dev/null 2>&1 
    else
        kill $dpid >/dev/null 
        sudo killall tcpdump
        sudo killall tshark 
    fi

    # set the label for later
    if [[ "$LABEL" == "" ]]
    then
        LABEL=" -l $DNSname"
    fi

fi

# Do the analysis to generate the csvmidi files (and optonal .wavs)
if [[ "$SKIP" == "no" ]]
then
    $SRCDIR/Tls2Music.py -f $OFILE $LABEL $VERBOSE $WAVOUT $LOGTIME $SUPPRESS $INSTRUMENT $SCALED
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

if [[ "$TDIR" != "" ]]
then
    # clean up
    cd $ODIR
    mv $TDIR/*.midi $ODIR
    rm -rf $TDIR
    #echo "Results in $TDIR - please clean it up"
fi

