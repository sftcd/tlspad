#!/usr/bin/env python3

# Copyright (c) 2019 Stephen Farrell, stephen.farrell@cs.tcd.ie
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# Grab a specific web site. When done... exit.

# This is just to trigger traffic that ends up captured by tcpdump
# or wireshark for later analysis. If other things are happening on
# this host at the same time that'll mess up results. Good enough
# as a starter to not bother much with that, but one that'll need 
# to be handled later (probably via post-facto analysis of the 
# pcap files - if one has other stuff, then it can be discarded and
# tests re-run:-)

# Installing this was a bit of a pita. Not quite sure which of 
# these are really needed, but I did...
#   sudo -H pip install selenium
#   sudo apt install firefoxdriver
#   sudo apt install python3-selenium
#   sudo apt install pip3
#   sudo apt install python3-pip
#   wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz
#   tar czvf geckodriver-v0.24.0-linux64.tar.gz
#   sudo mv geckodriver /usr/local/bin/
# Not sure if the order there's correct but roughly

import time,sys,os,re,glob,argparse
from selenium import webdriver
from selenium.webdriver.opera import options as op_options
from selenium.webdriver.common import desired_capabilities

home=os.environ['HOME']
mozpre="/.mozilla/firefox/"
tp_names=glob.glob(os.path.join(home+mozpre,"*.selenium"))

argparser=argparse.ArgumentParser(description='Grab a URL using selenium')
argparser.add_argument('-u','--url',     
                    dest='url',
                    help='URL to fetch')
argparser.add_argument('-v','--verbose',
                    help='produce more output',
                    action='store_true')
argparser.add_argument('-b','--browser',
                    help='specify browser [firefox|opera]',
                    dest="browser")
args=argparser.parse_args()

if args.url is None:
    print(sys.argv[0]+": No URL supplied - exiting")
    sys.exit(1)


def main():
    browser_inited=False
    try:
        if args.browser is None or args.browser=="firefox":
            if len(tp_names)>=1:
                if args.verbose:
                    print("Using profile: " + tp_names[0])
                browser = webdriver.Firefox(tp_names[0])
            else:
                browser = webdriver.Firefox()
        elif args.browser=="opera":
            opopts=op_options.ChromeOptions()
            opcaps=desired_capabilities.DesiredCapabilities.OPERA.copy()
            browser=webdriver.Opera(desired_capabilities=opcaps,options=opopts)
        elif args.browser=="chrome":
            browser=webdriver.Chrome('/usr/local/bin/chromedriver')
        else:
            print(sys.argv[0]+": Unsupported browser - " + args.browser + " - exiting")
            sys.exit(1)
    
        #browser shall call the URL
        browser_inited=True
        browser.get(args.url)
        time.sleep(10)
        browser.quit()
    except Exception as s:
        print("Excepton: " + str(s))
        if browser_inited:
            browser.quit()

if __name__ == "__main__":
    main()
