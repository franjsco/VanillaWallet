# helper function
import sounddevice as sd
import hashlib

def getNoiseFromMicrophone(seconds):
    SAMPLE_RATE = 44100     # rate of sampling for audio recording 
    sound = sd.rec(int(SAMPLE_RATE * seconds), samplerate=SAMPLE_RATE, channels=2, blocking=True)
    return hashlib.sha256(bytearray(b''.join(sound))).hexdigest()