#!/bin/bash

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

# Generically useful functions and variables

function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)
STARTDIR=`/bin/pwd`

# Just for the OSes about which I care, add to this as needed.
# Be nicer if there were a generic way to do this but good 
# enough is good enough for now:-)
function whichos()
{
    ua=`uname -a`
    if [[ "$ua" == *"Ubuntu"* ]]
    then
        echo "Ubuntu"
    elif [[ "$ua" == *"turris"* ]]
    then
        echo "OpenWRT"
    fi
}
THISOS=$(whichos)

function amiroot()
{
    theuid=`id -u`
    if [[ "$THEUID" == "0" ]]
    then
        echo "root"
    else
        echo $USER
    fi
}
RUNNINGAS=$(amiroot)
