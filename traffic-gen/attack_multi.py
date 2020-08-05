"""

s = starting address
e = ending address

-s = 1 -> 10.0.0.1
-e = 4 -> 10.0.0.4

$ sudo python TCP-UDP-ICMP-traffic-gen.py -s 1 -e 4

"""

import sys
import getopt
import time
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP, ICMP
from random import randrange, randint
import random
import signal, os

# Preventing generation of  non routable IPs 
def sourceIPgen():
    not_valid = set([10,127,254,1,2,169,172,192])

    first = randrange(1,256)
    while first in not_valid:
        first = randrange(1,256)

    ip = ".".join([str(first),str(randrange(1,256)),str(randrange(1,256)),str(randrange(1,256))])

    return ip

def gendest(start, end):

    ip = ".".join(["10","0","0",str(randrange(start,end))])
    return ip

def hanlder(signum, frame):
    print 'Crtl+C', signum

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:],'s:e:',['start=','end='])
    except getopt.GetoptError:
        sys.exit(2)
    for opt, arg in opts:
        if opt =='-s':
            start = int(arg)
        elif opt =='-e':
            end = int(arg)
    if start == '':
        sys.exit()
    if end == '':
        sys.exit()

    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

    ip_dst = gendest(start, end)
    ip_src = sourceIPgen()
    t=randrange(15,50)
    udp_packets = Ether()/IP(dst=ip_dst, src=ip_src,ttl=t)/UDP(dport=80,sport=2)
     
    sendp(udp_packets, iface=interface.rstrip(), inter=0.025)
    print(repr(udp_packets))
    
if __name__ == '__main__':
    try:
        while True:
           main(sys.argv)
    
    except KeyboardInterrupt:
        exit


