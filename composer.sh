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
	echo "$0 [-u <url-or-file>] [-f <capture-file/dir>] [-b browser][-l <label>] [-s limit] [ -i instrument] [-kwvcLSnA]"
    echo ""
    echo "Wrapper to grab TLS traffic info via tshark or tcpdump. Arguments can be:"
    echo "-h - produce this"
    echo "-u - URL to access, grab, analyse and turn into midi file"
    echo "     This uses: '-l <DNSname> -s 1000 -V all -N freq -M 250'"
    echo "-b - browser to use: [all|firefox|chrome|opera] (default is firefox)"
    echo "-f - name of capture file or directory for capture files (default is '.')"
    echo "-V - vantage point/selectors, can be [all|src|dst|file-name]"
    echo "-i - midi instrument (-1:127; default: 0; -1 means built-in combo)"
    echo "-l - label to use for files (will be anonymous hash otherwise)"
    echo "-s - suppress silence or noise that doesn't change for the specified limit (in ms)"
    echo "-c - clean out audio files in this directory (*.midi.csv, *.wav, *.midi)"
    echo "-n - do not clean up temporary files when getting URLs"
    echo "-k - skip new data generation and just map csv's to midi's in the current dir"
    echo "-L - use logarithmic time"
    echo "-S - use scaled time"
    echo "-v - be verbose"
    echo "-I - generate ignore list (DNS stubby DoT sessions and selenium's defaults)"
    echo "-w - produce .wav files as well as .midi (warning: slow, maybe buggy)"
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
NOCLEAN="no"
VANTAGE=""
BROWSER="firefox"
# default to log time off and 1s suppression as it seems to work nicely
LOGTIME=""
SUPPRESS=" -s 1000 "
INSTRUMENT=""
SCALED=""
# empty strings will turn 'em off
# SUPPRESS=""
# INSTRUMENT=""
# if you want log time on
# LOGTIME=" -T "
# if you want scaled time on
# SCALED=" -S "

# how to generate notes
NOTEGEN=" -N freq"
# NOTEGEN=" -N table"

# whether to generate a new ignore.addrs file, default to yes
GENIGNORE="no"

# no hardcoded URL or URL filename
URL=""

# temp dir var (if needed)
TDIR=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o b:IV:nSu:i:sLkchwvf:l: -l browser:,ignore,vantage:,noclean,scaled,url:,instrument:,suppress:,logtime,skip,clean,help,wav,verbose,file:,label: -- "$@")
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
        -b|--browser) BROWSER=$2; shift;;
        -u|--url) JUSTCLEAN="no"; URL=$2; shift;;
        -i|--instrument) JUSTCLEAN="no"; INSTRUMENT=" -i $2"; shift;;
        -s|--suppress) JUSTCLEAN="no"; SUPPRESS="-s $2"; shift;;
        -l|--label) JUSTCLEAN="no"; LABEL=" -l $2"; shift;;
        -k|--skip) SKIP="yes";;
        -c|--clean) CLEAN="yes";;
        -n|--noclean) NOCLEAN="yes";;
        -w|--wav) JUSTCLEAN="no"; WAVOUT=" -w ";;
        -V|--vantage) JUSTCLEAN="no"; VANTAGE=" -V $2 "; shift;;
        -L|--logtime) JUSTCLEAN="no"; LOGTIME=" -T ";;
        -S|--scaled) JUSTCLEAN="no"; SCALED=" -S ";;
        -I|--ignore) GENIGNORE="yes ";;
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
        echo "$0: Just cleaning - exiting"
        exit 0
    fi
fi

# check browser setting is ok, there could be some parameter
# needed in future
case "$BROWSER" in
    firefox) ;;
    chrome) ;;
    opera) ;;
    all) ;;
    (*) echo "$0: Bad browser value ($BROWSER) - exiting"; exit 2;;
esac
        
# we'll do the actual pcap capture stuff later as we'll want the
# option of running a headless browser and doing it all locally, or, 
# provding some UI prompts for the case where the user runs a real 
# browser. So later then. Meanwhile, we'll assume the pcaps are in the
# OFILE variable

if [[ "$SKIP" == "no" && "$URL" != "" ]]
then
    url_list=""
    if [ -f $URL ] 
    then
        while IFS= read -r oneURL
        do
            if [[ "${oneURL::1}" != "#" ]]
            then
                url_list="$url_list $oneURL"
            fi
        done < "$URL"
        echo "$url_list"
    else
        url_list=$URL
    fi

    # probably wanna do a mktemp -d to keep crap and just 
    TDIR=`mktemp -d /tmp/composeXXXX`
    ODIR=$PWD
    if [ ! -d $TDIR ]
    then
        echo "$0: Failed to make temp dir ($TDIR) - exiting"
        exit 1
    fi
    cd $TDIR

    # drop some meta-data into there
    $SRCDIR/whowhere.sh "$0 $options $*" >>README.md
    # whack in the URLs as well in case they were in a file
    echo "URLS: $url_list" >>README.md

    if [[ "$GENIGNORE" == "yes" ]]
    then
        $SRCDIR/ignore-stubby.sh
        $SRCDIR/browser-ignores.sh -b "$BROWSER"
    fi
    # check which browser(s) to use
    browser_list=$BROWSER
    if [[ "$BROWSER" == "all" ]]
    then
        browser_list="firefox opera chrome"
    fi
    for url in $url_list
    do
        for browser in $browser_list
        do
            # make sure its https, and barf otherwise
            if [[ ! $url =~ ^https://.* ]] 
            then
                echo "$0: Bad URL, I only do https for now - exiting"
                exit 4
            fi

            # full URLs might not be good parts of file names so we'll pull out
            # the DNS name and use that
            DNSname=`echo $url | awk -F/ '{print $3}'`
            if [[ "$VERBOSE" != "" ]]
            then
                echo "DNS: $DNSname"
            fi
            if [[ "$DNSname" == "" ]]
            then
                echo "$0: Can't extract DNS name from $url - exiting"
                exit 5
            fi

            # copy back out the midi file
            # start capture 
            if [[ "$VERBOSE" == ""  ]]
            then
                $SRCDIR/dumper.sh -f $DNSname.$browser.pcap -s 10000 >/dev/null 2>&1 &
                dpid=$!
            else
                $SRCDIR/dumper.sh -f $DNSname.$browser.pcap -s 10000 &
                dpid=$!
            fi

            # access a URL via a headless browser
            # that fails sometimes (blocking, apparently) so we want
            # to force a fail after a while, 2mins in our case
            getpage_failed="no"
            timeout 120s $SRCDIR/getpage.py -b $browser -u $url $VERBOSE
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

            # set the label for later
            if [[ "$LABEL" == "" ]]
            then
                thisLABEL=" -l $DNSname.$browser"
            fi

            # force VANTAGE to all
            VANTAGE=" -V all "

            if [[ "$getpage_failed" == "no" ]]
            then
                # Do the analysis to generate the csvmidi files (and optonal .wavs)
                if [[ "$VERBOSE" != "" ]]
                then
                    echo "Running: $SRCDIR/Tls2Music.py -f $DNSname.$browser.pcap $thisLABEL $VERBOSE $WAVOUT $LOGTIME $SUPPRESS $INSTRUMENT $SCALED $VANTAGE $NOTEGEN"
                fi
                # Whack the used-args to README too...
                echo "Tls2Music Parameters:" >>README.md
                echo "Running: $SRCDIR/Tls2Music.py -f $DNSname.$browser.pcap $thisLABEL $VERBOSE $WAVOUT $LOGTIME $SUPPRESS $INSTRUMENT $SCALED $VANTAGE $NOTEGEN" >>README.md
                $SRCDIR/Tls2Music.py -f $DNSname.$browser.pcap $thisLABEL $VERBOSE $WAVOUT $LOGTIME $SUPPRESS $INSTRUMENT $SCALED $VANTAGE $NOTEGEN
            fi

            # and now force VANTAGE to the DNSname's A and AAAA
            # Note the /32 and /128 below can be omitted if you like
            # and you can use netmasks. For IPv4 netmasks you need to
            # include zeros e.g. "192.0.2.0/24"
            # TODO: The commands below end up with CNAMEs in the
            # file. Either stop that happening or make the python
            # code not barf on it. (Having checked out if the python
            # code does in fact barf on it, but I bet it does:-)
            ipv4=`dig +short a $DNSname` 
            ipv6=`dig +short aaaa $DNSname`
            if [[ "$ipv4" != "" ]]
            then
                for add in $ipv4
                do
                    echo $add >>$DNSname.srvadd
                done
            fi
            if [[ "$ipv6" != "" ]]
            then
                for add in $ipv6
                do
                    echo $add >>$DNSname.srvadd
                done
            fi
            if [ -f $DNSname.srvadd ]
            then
                # so we can avoid yet another Tls2Music parameter:-)
                cp $DNSname.srvadd primaries.ips
                # generate the music you'd see if you just monitored the server side
                VANTAGE=" -V $DNSname.srvadd"
                thisLABEL=" -l $DNSname.$browser-server-vantage"
                if [[ "$VERBOSE" != "" ]]
                then
                    echo "Running: $SRCDIR/Tls2Music.py -f $DNSname.$browser.pcap $thisLABEL $VERBOSE $WAVOUT $LOGTIME $SUPPRESS $INSTRUMENT $SCALED $VANTAGE $NOTEGEN"
                fi
                $SRCDIR/Tls2Music.py -f $DNSname.$browser.pcap $thisLABEL $VERBOSE $WAVOUT $LOGTIME $SUPPRESS $INSTRUMENT $SCALED $VANTAGE $NOTEGEN
            fi
        done # browser_list
    done # url_list
    echo "===================================================" >> README.md
    echo "" >>README.md
fi

# Possibly ignore stubby
if [[ "$SKIP" == "no" && "$URL" == "" ]]
then
    if [[ "$GENIGNORE" == "yes" ]]
    then
        $SRCDIR/ignore-stubby.sh
    fi
fi

# One-shot analysis to generate the csvmidi files (and optonal .wavs)
if [[ "$SKIP" == "no" && "$URL" == "" ]]
then
    if [[ "$GENIGNORE" == "yes" ]]
    then
        $SRCDIR/ignore-stubby.sh
    fi
    $SRCDIR/Tls2Music.py -f $OFILE $LABEL $VERBOSE $WAVOUT $LOGTIME $SUPPRESS $INSTRUMENT $SCALED $VANTAGE $NOTEGEN
fi

# Now map the csvs to midis (if there are any - that's the first
# if statement) and ogg and png 
csvs=(*.midi.csv)
if [ -e  "${csvs[0]}" ];
then
    for file in *.midi.csv
    do
        mf=`basename $file .csv`
        df=`basename $mf .midi`
        if [ $file -nt $mf ]
        then
            csvmidi $file $mf
            if [[ "$VERBOSE" != "" ]]
            then
                timidity $mf -Ov -o $df.ogg
            else
                timidity --quiet $mf -Ov -o $df.ogg >/dev/null 2>&1
            fi
            # we'd like all spectra to be 30s wide so pad with 30s silence
            sox -n -r 44100 -c 2 silence.ogg trim 0.0 30.0
            # then truncate back to 30s for graphic
            sox $df.ogg silence.ogg -n spectrogram -o $df.png -d 30.0 -x 1000 trim 0.0 30.0 
        else
            echo "Skipping $file as $mf is newer"
        fi
    done
else
    echo "$0: No csvs to process - exiting"
    exit 4
fi

cd $ODIR
if [[ "$NOCLEAN" == "no" && "$TDIR" != "" ]]
then
    # clean up
    mv $TDIR/*.midi $ODIR
    mv $TDIR/*.ogg $ODIR
    mv $TDIR/*.png $ODIR
    mv $TDIR/*.srvadd $ODIR
    mv $TDIR/*.ips $ODIR
    # don't kill old versions of this, just add to 'em
    cat $TDIR/README.md >>$ODIR/README.md
    rm -rf $TDIR
else
    echo "Full Results in $TDIR - please clean it up"
    cp $TDIR/*.midi $ODIR
    cp $TDIR/*.ogg $ODIR
    cp $TDIR/*.png $ODIR
    cp $TDIR/*.srvadd $ODIR
    cp $TDIR/*.ips $ODIR
    # don't kill old versions of this, just add to 'em
    cat $TDIR/README.md >>$ODIR/README.md
fi

