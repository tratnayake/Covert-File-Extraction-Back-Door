from scapy.all import *
from time import *
from datetime import *
import time
import datetime

portsKnocked = []
counter = 0


def checkSequence(portsKnocked,sequence):
    print "Ports Knocked"
    print portsKnocked
    print "sequence"
    print sequence
    last = (len(portsKnocked) - 1)
    if(portsKnocked[last][3] == sequence[2] and portsKnocked[last - 1][3] == sequence[1] and portsKnocked[last-2][3] == sequence[0]):
        return True
    else:
        return False

def checkTimes(portsKnocked,gap):
    #Check the last packet
    last = (len(portsKnocked) - 1)

    lastTimestamp = portsKnocked[last][2]
    #Check the first packet in the range (3)
    startTimestamp = portsKnocked[last-2][2]
    diff = lastTimestamp - startTimestamp
    print diff
    print datetime.timedelta(seconds=5)


#A Successful port knock has occurred if:
def checkKnocks():
    global portsKnocked
    print portsKnocked
    #There have been 3 knocks
    if (len(portsKnocked) >= 3):
        print "3 or more ports knocked"
        # AND If the sequence matches 7000,8000,9000
        if(checkSequence(portsKnocked,[8000,8001,8002])):
            print "Port Knock Sequence CORRECT"
            #AND if the knocks all occured within a span of 5 seconds
            checkTimes(portsKnocked,5)


    #They occured within 5 seconds of each other

def handleIPknocks(packet):
    global portsKnocked
    global counter
    #The TTL key can be taken from the config file
    if (packet.haslayer(IP) and packet["IP"].ttl == 71):
        counter = counter + 1
        print "IP packet caught with TTL key 71"
        timestamp = time.time()
        #packet.show()
        if(packet.haslayer(TCP)):
            print packet["TCP"].dport
            portsKnocked.append(["TCP",counter,timestamp,packet["TCP"].dport])
            print "Packet added to TCP ports knocked"
            checkKnocks()

        if(packet.haslayer(UDP)):
            portsKnocked.append(["udp",counter,timestamp,packet["udp"].dport])
            print "Paacket added to UDP ports knocked"
            checkKnocks()


#Listen for Port knocks
sniff(filter="ip", prn=handleIPknocks)
