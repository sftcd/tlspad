#!/usr/bin/python3 
# SF version based on: https://stackoverflow.com/questions/33879523/python-how-can-i-generate-a-wav-file-with-beeps
# that version based on : https://www.daniweb.com/code/snippet263775.html
import math
import wave
import struct
import sys

def append_silence(
        audio=[],
        sample_rate=44100,
        duration_milliseconds=500):
    """
    Adding silence is easy - we add zeros to the end of our array
    """
    num_samples = duration_milliseconds * (sample_rate / 1000.0)

    for x in range(int(num_samples)): 
        audio.append(0.0)

    return


def append_sinewave(
        audio=[],
        sample_rate=44100,
        freq=440.0, 
        duration_milliseconds=500, 
        volume=1.0):
    """
    The sine wave generated here is the standard beep.  If you want something
    more aggresive you could try a square or saw tooth waveform.   Though there
    are some rather complicated issues with making high quality square and
    sawtooth waves... which we won't address here :) 
    """ 

    num_samples = duration_milliseconds * (sample_rate / 1000.0)

    for x in range(int(num_samples)):
        audio.append(volume * math.sin(2 * math.pi * freq * ( x / sample_rate )))

    return

def inject_sinewave(
        audio=[],
        sample_rate=44100,
        freq=440.0, 
        start_time=0,
        duration_milliseconds=500, 
        volume=1.0):
    """
    The sine wave generated here is the standard beep.  If you want something
    more aggresive you could try a square or saw tooth waveform.   Though there
    are some rather complicated issues with making high quality square and
    sawtooth waves... which we won't address here :) 
    We just inject this into the audio array at the start_time concerned
    """ 
    num_samples = duration_milliseconds * (sample_rate / 1000.0)
    offset = int(start_time * (sample_rate /1000.0) )
    al=len(audio)
    for x in range(int(num_samples)):
        try:
            ind=x+offset
            if ind<al:
                ov=audio[x+offset]
                nv=volume * math.sin(2 * math.pi * freq * ( x / sample_rate ))
                if abs(ov) <= sys.float_info.epsilon:
                    audio[x+offset]= nv
                else:
                    audio[x+offset]= 0.5 * ov + 0.5 * nv
            else:
                # we've filled to end, may as well return
                return
        except Exception as e:
            print("Overflow: " + str(e) + " x: "  + str(x) + " offset: " + str(offset) + " len(audio): " + str(len(audio)))
            #raise e
    return

def inject_filtered_sinewave(
        audio=[],
        sample_rate=44100,
        freq=440.0, 
        start_time=0,
        duration_milliseconds=500, 
        volume=1.0,
        thefilter=None,
        filarr=None):
    """
    The sine wave generated here is the standard beep.  If you want something
    more aggresive you could try a square or saw tooth waveform.   Though there
    are some rather complicated issues with making high quality square and
    sawtooth waves... which we won't address here :) 
    We just inject this into the audio array at the start_time concerned
    """ 
    if thefilter is None:
        return
    num_samples = duration_milliseconds * (sample_rate / 1000.0)
    offset = int(start_time * (sample_rate /1000.0) )
    al=len(audio)
    for x in range(int(num_samples)):
        try:
            ind=x+offset
            msval=int(1000*ind/sample_rate)
            #print(str(msval))
            if ind<al:
                ov=audio[x+offset]
                nv=volume * math.sin(2 * math.pi * freq * ( x / sample_rate ))
                nv=nv*thefilter(msval,filarr)
                if abs(ov) <= sys.float_info.epsilon:
                    audio[x+offset]= nv
                else:
                    audio[x+offset]= 0.5 * ov + 0.5 * nv
            else:
                # we've filled to end, may as well return
                return
        except Exception as e:
            print("Overflow: " + str(e) + " x: "  + str(x) + " offset: " + str(offset) + " len(audio): " + str(len(audio)))
            #raise e
    return


def save_wav(file_name,audio=[],sample_rate=44100):
    # Open up a wav file
    wav_file=wave.open(file_name,"w")

    # wav params
    nchannels = 1

    sampwidth = 2

    # 44100 is the industry standard sample rate - CD quality.  If you need to
    # save on file size you can adjust it downwards. The stanard for low quality
    # is 8000 or 8kHz.
    nframes = len(audio)
    comptype = "NONE"
    compname = "not compressed"
    wav_file.setparams((nchannels, sampwidth, sample_rate, nframes, comptype, compname))

    # WAV files here are using short, 16 bit, signed integers for the 
    # sample size.  So we multiply the floating point data we have by 32767, the
    # maximum value for a short integer.  NOTE: It is theortically possible to
    # use the floating point -1.0 to 1.0 data directly in a WAV file but not
    # obvious how to do that using the wave module in python.
    for sample in audio:
        wav_file.writeframes(struct.pack('h', int( sample * 32767.0 )))

    wav_file.close()

    return


'''
sps=['502', '502']
spt=['29.589', '1031.098']
dps=['445', '648', '1386', '1386', '1386', '1386', '1386', '1386', '1386', '1386', '1386', '1386']
dpt=['29.532', '979.424', '979.462', '981.778', '981.861', '987.072', '987.179', '990.450', '994.161', '1014.275', '1024.257', '1030.807']

# stretch factor, by how long we multiply time
stretch=5

# find latest time
last_time=int(float(max(spt[-1],dpt[-1])))+1
print("last time: " + str(last_time))

# start marker
#append_sinewave(freq=300,volume=0.25)
append_silence(duration_milliseconds=stretch*last_time+1000)

print("Samples: " + str(len(audio)))

# loop through sent and rx'd packets and beep accordingly
# we assume sps and spt arrays are correctly setup (i.e. same number of elements)

def merge_pkts(sizes,times):
    if len(sizes) != len(times):
        raise ValueError('Lengths of sizes/times not same')
    for x in range(len(sizes)):
        ips=int(sizes[x])
        ipt=int(float(times[x]))
        if x < len(times)-1:
            dur=stretch*(int(float(times[x+1]))-ipt)
        else:
            dur=stretch*100
        if dur==0:
            dur=stretch
        if dur>stretch*100:
            dur=stretch*100
        ipt=stretch*ipt
        print("PS: " + str(ips) + " PT: " + str(ipt) + " DUR: " + str(dur))
        inject_sinewave(freq=ips,start_time=500+ipt,duration_milliseconds=dur,volume=0.25)

merge_pkts(sps,spt)
merge_pkts(dps,dpt)

# end marker
#append_sinewave(freq=300,volume=0.25)

save_wav("output.wav")

'''
