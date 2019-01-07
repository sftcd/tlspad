#!/bin/bash

# set -x

# load useful functions and variables
. functions.sh

# 
# Copyright (C) 2018 Stephen Farrell, stephen.farrell@cs.tcd.ie
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

# ports that only run TLS, less privacy concern with logs here
PUREPORTS="port 443 or port 853 or port 993"

# ports that use STARTTLS, possibly more privacy concern with logs here
STPORTS="port 25 or port 110 or port 143 or port 587"

# overall list of ports - we'll omit the STARTTLS ones for now
# and check 'em later see what tcpdump grabs
PORTS="$PUREPORTS" 
#PORTS="$PUREPORTS or $STPORTS" 

function usage()
{
	echo "$0 [-h] [-D] [-f <capture-file/dir>] [-p <\"port list\">] [-i <\"iface-list\">] [-b <tool>] [-s <maxsize>]"
    echo ""
    echo "Wrapper to grab TLS traffic info via tshark or tcpdump. Arguments can be:"
    echo "-h - produce this"
    echo "-D - list possible capture interfaces"
    echo "-f - name of capture file or directory for capture files"
    echo "-p - specifiy port(s) to monitor (quoted list if >1)"
    echo "-i - specifiy interface(s) to monitor (quoted list if >1)"
    echo "-b - specify binary/tool to use, one of \"tcpdump\" or \"tshark\""
    echo "-s - specify the max size of the file to capture (exit when done) units KB, default: 1024"
	exit 99
}

# whether or not to list interfaces to user (who's somehow remembered this
# -D command line arg, but not the -D for tcpdump:-)
LISTIFS="no"

# capture file or directory name. if a directory, we store a standard named
# file in there
OFILE="."

# interfaces to scan, if not specified on command line will take whichever
# of these exists, in this order: "br-lan","wan","eth0","veth-mon","any"
# if none of those exist, we'll exit with an error
IFACES=""

# max size to capture, 0 == unlimited
MAXSIZE=1024

# which tool to use
tshark=`which tshark`
tcpdump=`which tcpdump`
if [[ "$tshark" == "" && "$tcpdump" == "" ]]
then
    echo "No sign of $tskark or $tcpdump - exiting"
    exit 1
fi

mbin=$tcpdump
if [[ "$THISOS" == "Ubuntu" && "$tshark" != "" ]]
then
    # prefer tshark, but as args differ this'll not be that useful:-)
    mbin=$tshark
fi

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o hDf:p:i:b:s: -l help,list,file:,port:,iface:,binary:,size: -- "$@")
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
		-D|--list) LISTIFS="yes" ;;
        -f|--file) OFILE=$2; shift;;
        -i|--iface) IFACES=$2; shift;;
        -p|--ports) PORTS=$2; shift;;
        -b|--binary) mbin=$2; shift;; 
        -s|--size) MAXSIZE=$2; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

# check options

# in case of command line typo
mbend=`basename $mbin`
if [[ "$mbend" != "tcpdump" && "$mbend" != "tshark" ]]
then
    echo "$mbin doesn't seem to be a tcpdump or tshark instance - exiting"
    exit 2
fi

# tcpdump needs a sudo in Ubuntu (if I'm not root)
if [[ "$THISOS" == "Ubuntu" && "$mbend" == "tcpdump" && "$RUNNINGAS" != "root" ]]
then
    # need a sudo, for me any
    mbin="sudo $mbin"
fi

if [[ "$LISTIFS" == "yes" ]]
then
    $mbin -D    
    exit 0
fi

# what inteface(s) to capture from
# take command line if given one
if [[ "$IFACES" == "" ]]
then
    # otherwise figure it out
    available=`ifconfig | grep "^[a-zA-Z]"`
    case "$available" in
        (*br-lan*) IFACES="br-lan";;
        (*wan*) IFACES="wan";;
        (*eth0*) IFACES="eth0";;
        (*veth-mon*) IFACES="veth-mon";;
        (*) echo "Can't tell what interface to use - trying \"any\""
           IFACES="any";;
    esac
fi

theifs=""
for iface in $IFACES
do
    # tried the line below 1st, but hit horrible quoting issues
    # so we'll put the i/f's at the end, which works
    # theifs="-i $iface -f  \" "$PORTS" \" $theifs"
    theifs="-i $iface $theifs"
done

# handle output location and sizing
ofile=""
if [ -d $OFILE ]
then
    ofile="$OFILE/dumper-$NOW.pcap"
elif [ -f $OFILE ]
then
    # backup old file
    mv $OFILE $OFILE-backup-at-$NOW.pcap
    ofile=$OFILE
else
    ofile=$OFILE
fi

msize=""
if [[ "$MAXSIZE" != "0" ]]
then
    msize="-a filesize:$MAXSIZE"
    if [[ "$mbend" == "tcpdump" ]]
    then
        # tcpdump doesn't quite have the right semantics
        # we set to keep one file of the required size
        # and a 2nd that'll grow to that size, IOW we 
        # end up with the MAX capture size we want but
        # need 2x that much disk 
        max_MiB=$(((MAXSIZE*1024)/10000000))
        if [ $((max_MiB <= 0)) ]
        then
            max_MiB="1"
        fi
        msize="-C $max_MiB -W 2" 
    fi
fi

Zarg=""
if [[ "$mbend" == "tcpdump" ]]
then
    Zarg="-Z $RUNNINGAS"
fi


echo "trying: $mbin -f \"$PORTS\" $theifs at $NOW"
$mbin $Zarg $msize -w $ofile -f "$PORTS" $theifs

