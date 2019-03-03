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

# rsync tlspad data from here to a server machine
# you should have ssh access setup for the relevant box

DEFSERV=basil.dsg.cs.tcd.ie
DEFLDIR=data/tlspad
DEFRDIR=data/tlspad
DEFLOCALHOST="somemachine"

# just simple command line args
# usage: data2server.sh [[remote-user@]server-name [local-directory [ remote-dir]]]
# where directory

if [[ "$1" != "" ]]
then
    server=$1
else
    server=$DEFSERV
fi

# if server has an '@' char then user was specified on
# command line, if not then, not, so nothing to be done:-) 

# TODO: could be good to check if $1 has an '@' char and
# if so see if it's the last char, so basicall handle all
# the options. For now, we don't, since I don't need to
# do that.

# figure out home dir on remote - also verfiies we can ssh
rhome=`ssh $server /bin/pwd`
sshres=$?
if [[ "$sshres" != 0 || "$rhome" == "" ]]
then
    echo "ssh result: $sshres, rhome: $rhome"
    echo "Looks like we can't ssh to $server - exiting"
    exit 1
fi

if [[ "$2" != "" ]]
then
    tdir=$2
    # if tdir starts with a / don't prepend home
    if [[ ${tdir:0:1} == "/" ]]
    then
        ldir=$tdir
    else
        ldir=$HOME/$tdir
    fi
else
    ldir=$HOME/$DEFLDIR
fi

if [[ "$3" != "" ]]
then
    tdir=$3
    # if tdir starts with a / don't prepend home
    if [[ ${tdir:0:1} == "/" ]]
    then
        rdir=$tdir
    else
        rdir=$rhome/$tdir
    fi
else
    rdir=$rhome/$DEFRDIR
fi

lhost=`hostname`
if [[ "$lhost" == "" ]]
then
    lhost=$DEFLOCALHOST
fi

echo "Synching from $ldir to $server:$rdir/$lhost from $lhost"
rsync -e ssh -Pavz $ldir $server:$rdir/$lhost

