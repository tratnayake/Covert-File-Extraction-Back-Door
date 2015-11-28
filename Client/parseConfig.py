def parseConfigFile(configFileName):
	f = open(configFileName, 'r')
	for line in f:
		parseKey = line.split("=")[0]
		parseValue = line.split("=")[1]

		if (parseKey == "victimIP"):
			global victimIP
			victimIP = parseValue.rstrip("\n")
		if (parseKey == "ttlKey"):
			global ttlKey
			ttlKey = int(parseValue)
		if (parseKey == "srcPort"):
			global srcPort
			srcPort = int(parseValue)
		if (parseKey == "dstPort"):
			global dstPort
			dstPort = int(parseValue)
		if (parseKey == "encryptionKey"):
			global encryptionKey
			encryptionKey = parseValue.rstrip("\n")
		if (parseKey == "IV"):
			global IV
			IV = parseValue.rstrip("\n")
		if (parseKey == "protocol"):
			global protocol
			protocol = parseValue.rstrip("\n")
		if (parseKey == "password"):
			global password
			password = parseValue.rstrip("\n")
		if (parseKey == "authentication"):
			global authentication
			authentication = parseValue.rstrip("\n")
		if (parseKey == "localIP"):
			global localIP
			localIP = parseValue.rstrip("\n")
		if (parseKey == "saveDir"):
			global saveDir
			saveDir = parseValue.rstrip("\n")

#Main
configFileName = "./configFile.txt"
parseConfigFile(configFileName)
