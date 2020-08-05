import sys
import getopt
import time
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange

def generateSourceIP():
    #Unavailable IP address 
    unavailable = [10, 127, 254, 1, 2, 169, 172, 192]
    #random number in the range [1,256)
    first = randrange(1, 256)
    while first in unavailable:
        first = randrange(1, 256)
    #eg ip "91.85.45.3"
    ip = ".".join([str(first), str(randrange(1,256)), str(randrange(1,256)), str(randrange(1,256))])
    return ip

#start and end which are given as command line arguments. eg, python traffic.py -s 2 -e 64 
def generateDestinationIP(start, end):
    first = 10
    second = 0; 
    third = 0;
    #"10.0.0.10"
    ip = ".".join([str(first), str(second), str(third), str(randrange(start,end))])
    return ip

def main(argv):
    # parsing command line arguments and options. 
    # s --> start address  e--> end address 
    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:e:', ['start=','end='])
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
    #creating virtual interface to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    for i in xrange(1000):
        packets = Ether() / IP(dst = generateDestinationIP (start, end), src = generateSourceIP ()) / UDP(dport = 80, sport = 2)
        print(repr(packets))
        sendp(packets, iface = interface.rstrip(), inter = 0.1)

if __name__ == '__main__':
  main(sys.argv)


