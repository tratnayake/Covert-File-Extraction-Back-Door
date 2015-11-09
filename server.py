from scapy.all import *

list portsKnocked = []

def handleIPknocks(packet):
    if (packet["IP"] and packet["IP"].ttl == 71):



#Listen for Port knocks
sniff(filter="ip and host 192.168.0.16", prn=handleIPknocks)
