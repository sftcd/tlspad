# Things needed to use this...

I've put this on a 2nd laptop and note here what I needed to get
stuff to work.  For now all this is for ubuntu 18.04 basically so YMMV if
you're on a different box. And I've not tried it yet on a server/VM with
no audio/display.  I'll also add OpenWRT stuff later (for
[dumper.sh](dumper.sh)), the rest is only for running on Ubuntu.

## Get the repo

I clone the repo into ``$HOME/code/tlspad`` - likely there'll be a dependency
on that path that I should fix, but I've (probably) not yet;-)

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/tlspad

## Ubuntu 18.04 laptop/desktop 

1. For [dumper.sh](dumper.sh):

    - Set up wireshark so you don't need root as per [this page](https://superuser.com/questions/319865/how-to-set-up-wireshark-to-run-without-root-on-debian)
    - install wireshark, tcpdump, tshark and fix permissions to not need root:

            $ sudo apt install wireshark
            $ sudo dpkg-reconfigure wireshark-common
            ...choose the 'yes' option
            $ sudo usermod -a -G wireshark <your-user-name>
            $ sudo chgrp wireshark /usr/bin/dumpcap
            $ sudo chmod 4750 /usr/bin/dumpcap
            ... reboot and log and back in...
            $ sudo apt install tshark
            $ sudo apt install tcpdump

1. for [TlsPacketSizes.py](TlsPacketSizes.py):

    - This and other python things are python3, so you'll need that
    - I needed pip3 for some reason, and it wasn't clear if a previous
    ``sudo -H pip install pyshark`` was needed or not, so ...


            $ sudo apt install python3-pip
            $ sudo -H pip3 install pyshark

    - after that ``$SRCDIR/TlsPacketSizes.py -f <yourpcap>`` should work and
    produce some output about the TLS sessions seen in the pcap file.

1. for [Tls2Music.py](Tls2Music.py):

    - Having done the above, this just worked for me, not sure if some other pip installs will be
    needed on a clean box.
    - The output from ``$SRCDIR/Tls2Music.py -f <yourpcap>`` should be a CSV file.

1. for [getpage.py](getpage.py):

    - We need selenium:

            $ sudo -H  pip3 install selenium

    - We also need geckdriver, I followed [these](https://askubuntu.com/questions/870530/how-to-install-geckodriver-in-ubuntu) instructions:

            $ wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz
            $ tar -xzvf geckodriver-v0.24.0-linux64.tar.gz
            $ chmod u+x getckodriver
            $ sudo cp geckodriver /usr/local/bin

    - The ``getpage.py`` should work if given a URL, the headless browser will
    pop up (depending on your DISPLAY settings), load the page and then exit a few
    seconds later, e.g.:

            $ $SRCDIR/getpage.py https://ietf.org/

1. for [composer.sh](composer.sh):

    - You need ``csvmidi`` to transform the CSV output from ``Tls2Music.py`` to a ``.midi`` file.
    - Yoy can use ``timidity`` to play a ``.midi`` file

            $ sudo apt install midicsv
            $ sudo apt install timidity

	- timidity may need some soundfonts as well, I followed [these instructions](https://unix.stackexchange.com/questions/97883/timidity-no-instrument-mapped-to-tone-bank-0-no-idea-which-one-is-missing) (more or less)...

			$ sudo apt install fluid-soundfont-gm
			$ sudo vi /etc/timidity/timidity.cfg
			... comment out the existing source line using freepats.cfg ...
			... uncomment the source line with fluidr3_gm.cfg ...
			$ sudo service timidity restart

    - So if you take the CSV file from  step 3 you should be able to do:

            $ csvmidi foo.midi.csv foo.midi
            $ timidity foo.midi
            ...noises off stage...

    - There may be more to getting ``timidity`` to work, but it just worked for me on
    my 2nd box with the above. 

    - To generate plots of the sounds, we use ``sox`` (and maybe ``octave`` or ``gnuplot``), so:

            $ sudo apt install sox octave gunplot

	- After all that you should be able to use ``composer.sh`` to get the noise for a URL, e.g.:

			$ $SRCDIR/composer.sh -u https://ietf.org/
			$ timidity 1550078276-ietf.org-all-be28332f.midi
			... moar noises off stage...


## OpenWRT

TBD



