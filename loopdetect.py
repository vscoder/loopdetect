#!/usr/bin/env python

import sys
import time
import random
import socket
import pcapy
import dpkt
import dnet

def packetBody(length):
    rez = []
    for x in range(0,length):
        rez.append(random.choice('0123456789abcdef') + random.choice('0123456789abcdef'))
    return rez

class loopDetector:
    packetCount = 0
    loopCount = 0
    timeout = 1

    def __init__(self,iface):
        self.iface = iface
        self.pcaper = pcapy.open_live(iface,100,1,500)
        self.Mac = '00:19:5b:'+':'.join(packetBody(3))
        self.pcaper.setfilter('ether dst cf:00:00:00:00:00 and ether src %s' % self.Mac)
        #wf = wave.open('alarm.wav', 'rb')
        #self.pyA = pyaudio.PyAudio()
        #self.stream = self.pyA.open(format =
        #        self.pyA.get_format_from_width(wf.getsampwidth()),
        #        channels = wf.getnchannels(),
        #        rate = wf.getframerate(),
        #        output = True)
        #self.wfData = wf.readframes(100000)
        #wf.close()

    #def __del__(self):
        #self.stream.stop_stream()
        #self.stream.close()
        #self.pyA.terminate()

    #def PlayAlarm(self):
    #    self.stream.write(self.wfData)

    def Capture(self,hdr,data):
        if data == str(self.sPkt):
            self.packetReceived += 1

    def Process(self):
        while 1:
            try:
                pktData = '00000001' + ''.join(packetBody(42))
                self.sPkt = dpkt.ethernet.Ethernet(dst="cf0000000000".decode('hex'),
                                              src=''.join(self.Mac.split(':')).decode('hex'),
                                              type=36864,data=pktData.decode('hex'))
                endTime = time.time() + self.timeout
                print "Send packet to %s" % self.iface
                self.packetCount += 1
                #print "Packet is: %s" % self.sPkt
                hw = dnet.eth(self.iface)
                hw.send(str(self.sPkt))
                #self.pcaper.sendpacket(str(self.sPkt))
                self.packetReceived = 0
                while time.time() < endTime:
                    try:
                        self.pcaper.dispatch(-1,self.Capture)
                    except socket.timeout:
                        pass
                if self.packetReceived > 1:
                    self.loopCount += 1
                    print "Loop Detected. Duplication found %s" % self.packetReceived
                    #self.PlayAlarm()
            except KeyboardInterrupt:
                break
        print "Packets sent: ", self.packetCount , "Loops discovered : " , self.loopCount

def main():
    dev_list = {}
    n = 0
    iface = ''
    for x in pcapy.findalldevs():
        dev_list[n] = x
        n += 1
    try:
        iface = dev_list[0]
    except KeyError:
        print "No device found"
        exit(1)
    if len(sys.argv) == 2:
        try:
            if sys.argv[1] in  ['list','ls','all']:
                for x in dev_list:
                    print 'Index:', x, 'Device name:' ,dev_list[x]
                return 0
            else:
                iface = dev_list[int(sys.argv[1])]
        except KeyError:
            print "Invalid device id, trying use first"
            iface = dev_list[0]
    ld = loopDetector(iface)
    ld.Process()

if __name__ == "__main__":
    main()
