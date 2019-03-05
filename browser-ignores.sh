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

# Do dummy selenium transactions to find out what IPs browser insists
# on accessing

SRCDIR=$HOME/code/tlspad

# load useful functions and variables
. $SRCDIR/functions.sh

function usage()
{
	echo "$0 [-b browser] [-vh]"
    echo ""
    echo " Do dummy selenium transactions to find out what IPs browser insists on accessing"
    echo "-h - produce this"
    echo "-b - browser to use: [all|firefox|chrome|opera] (default is firefox)"
    echo "-v - verbose"
	exit 99
}

IGFILE="ignore.addrs"
BROWSER="firefox"
VERBOSE=""

# hardcoded URL - hopefully there's no listener here
LH2USE=127.1.2.123
URL="https://$LH2USE/"

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o b:h -l browser:,help -- "$@")
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
        -b|--browser) BROWSER=$2; shift;;
        -v|--verbose) VERBOSE=" -v ";;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

# check browser setting is ok, there could be some parameter
# needed in future
case "$BROWSER" in
    firefox) ;;
    chrome) ;;
    opera) ;;
    all) ;;
    (*) echo "$0: Bad browser value ($BROWSER) - exiting"; exit 2;;
esac

# check which browser(s) to use
browser_list="firefox"
if [[ "$BROWSER" == "all" ]]
then
    browser_list="firefox opera chrome"
fi

for browser in $browser_list
do
    # start capture 
    if [[ "$VERBOSE" == ""  ]]
    then
        $SRCDIR/dumper.sh -f $browser.pcap -s 10000 >/dev/null 2>&1 &
        dpid=$!
    else
        $SRCDIR/dumper.sh -f $browser.pcap -s 10000 &
        dpid=$!
    fi

    # access a URL via a headless browser
    # that fails sometimes (blocking, apparently) so we want
    # to force a fail after a while, 2mins in our case
    getpage_failed="no"
    timeout 120s $SRCDIR/getpage.py -b $browser -u $URL $VERBOSE
    if (( $? != 0 ))
    then
        getpage_failed="yes"
    fi

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
        if [[ "$CANISUDO" == "yes" ]]
        then
            sudo killall -wq tcpdump >/dev/null 2>&1 
            sudo killall -wq tshark >/dev/null 2>&1 
        else
            # try anyway, probably barf
            echo "Trying to killall tcpdump, tshark without sudo - might fail!"
            killall -wq tcpdump >/dev/null 2>&1 
            killall -wq tshark >/dev/null 2>&1 
        fi
    else
        kill $dpid >/dev/null 
        if [[ "$CANISUDO" == "yes" ]]
        then
            sudo killall -wq tcpdump
            sudo killall -wq tshark 
        else
            # try anyway, probably barf
            echo "Trying to killall tcpdump, tshark without sudo - might fail!"
            killall -wq tcpdump >/dev/null 2>&1 
            killall -wq tshark >/dev/null 2>&1 
        fi
    fi

    if [[ "$getpage_failed" == "no" ]]
    then
        # Do the analysis to generate the list of browser-specific IPs
        if [[ "$VERBOSE" != "" ]]
        then
            echo "Running: someting"
        fi
        # something
    fi

    # list of IPs in pcap
    capips=`tshark -r $browser.pcap -T fields -e ipv6.src -e ip.src -e ip.dst -e ipv6.dst | \
            sed -e 's/[ \t]/\n/g' | sort -u | grep -v "^$"`
    # list of my local IPs and localhost - don't wanna ignore those
    # incl. our fake localhost access
    locals=`hostname -I ` 
    locals="$locals $LH2USE" 
    locals=`echo $locals | sed -e 's/ /\n/g' | sort -u`
    # non locals - these are the ones we want to ignore later
    nonlocals=`comm -23 <(echo "$capips" | sort) <(echo "$locals" | sort)`

    cat >$browser.ips <<EOF
IPs in $browser.pcap:
$capips
Local IPs: 
$locals

Non-Local: 
$nonlocals
EOF

    # mayb use later - map from LF-searated to space-separated
    #| sed -e :a -e '$!N; s/\n/ /; ta'` 

    if [ -f $IGFILE ]
    then
        for addr in $nonlocals 
        do
            #echo $addr
            hitcount=`grep -c $addr $IGFILE` 
            if [[ "$hitcount" == "0" ]]
            then
                echo $addr >>$IGFILE
            fi
        done
    else
        echo "# IPs for Tls2Music.py to ignore" >$IGFILE
        echo "# See https://github.com/sftcd/tlspad for details" >>$IGFILE
        for addr in $nonlocals
        do
            echo $addr >>$IGFILE
        done
    fi 

done # browser_list

# whack in the URLs as well in case they were in a file
echo "Did: $0 -b $BROWSER $VERBOSE" 
