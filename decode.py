#!/usr/bin/env python

from pyHS100.protocol import TPLinkSmartHomeProtocol
 
import struct
import sys

decrypt = TPLinkSmartHomeProtocol.decrypt

from scapy.all import conf, rdpcap, IP, TCP, UDP, interact, Raw

data = rdpcap(sys.argv[1])

for packet in data:
    payload = None
    t = ''
    if TCP in packet:
        if Raw in packet[TCP]:
            start = packet[TCP][Raw].load[:4]
            start = struct.unpack('!i', start)[0]
            payload = packet[TCP][Raw].load[4:]
            t = 'TCP'
    if UDP in packet:
        if Raw in packet[UDP]:
            start = 0
            payload = packet[UDP][Raw].load
            t = 'UDP'

    if payload:
        print "%s: %s -> %s" % ( t, packet[IP].src, packet[IP].dst)
#        print packet.show()
#        print payload.show()
        print "start: %d ( 0x%08X )" % ( start, start )
        print "len(payload): %d" % ( len(payload) )
        print decrypt(payload)
