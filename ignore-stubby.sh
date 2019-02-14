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

# I have stubby installed on my laptop, that causes DNS queries/answers
# to be sent over TLS (DoT-style) which kind of spoils the musical vibe
# (well, there's no real vibe yet:-). This script pulls the IPs from the
# stubby config and puts 'em in a file in the current directory to be 
# checked by Tls2Music.py. File has one IP per line. Whitespace will be
# chewed, other stuff (e.g. comment line at top) ignored.

STUBBYCFG="/etc/stubby/stubby.yml"
IGFILE="ignore.addrs"

if [ ! -f $STUBBYCFG ]
then
    # nothing to do
    exit 0
fi 

# extract addrs (ipv4 and ipv6) ...
IPs=`grep address_data $STUBBYCFG | grep -v '^#' | awk '{print $3}' | sort | uniq `

if [ -f $IGFILE ]
then
    for addr in $IPs 
    do
        echo $addr
        hitcount=`grep -c $addr $IGFILE` 
        if [[ "$hitcount" == "0" ]]
        then
            echo $addr >>$IGFILE
        fi
    done
else
    echo "# IPs for Tls2Music.py to ignore" >$IGFILE
    echo "# See https://github.com/sftcd/tlspad for details" >>$IGFILE
    for addr in $IPs
    do
        echo $addr >>$IGFILE
    done
fi 
