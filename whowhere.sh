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

# Simple little script to record meta-data about a run

SRCDIR=$HOME/code/tlspad

# load useful functions and variables
. $SRCDIR/functions.sh

CLAs="$*"

lhost=`hostname`

echo 
echo "==================================================="
echo 
echo "Running $0 at $NOW from $STARTDIR"
echo "Host: $lhost "
echo "Command line: $CLAs"

# make a temp file name but don't create the file yet
# this is race-condition unsafe, but should be ok for
# our purposes
TMPF=`mktemp -u /tmp/igstubbyXXXX`
$SRCDIR/ignore-stubby.sh $TMPF
if [ -f $TMPF ]
then
    echo "Stubby addresses:"
    cat $TMPF | sed -e 's/^/    /'
    rm -f $TMPF
else
    echo "No local stubby detected"
fi
echo "ifconfig output: " 
ifconfig  | sed -e 's/^/    /'

echo "==================================================="



