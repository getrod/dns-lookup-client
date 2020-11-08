import socket

rootDnsIp = '202.12.27.33'
rootDnsPort = 53

def labelsToDomainName(message: bytes, start: int = 0):
    '''Constructs a domain name string with DNS message. Ex: 'cs.fiu.edu'.
    start points to the first byte of the domain name.
    Pointer points after the terminating byte \x00.'''
    labels = []
    pointer = start
    jumped = False
    tempPointer = 0

    while message[pointer] != 0:

        # get flag information for potential compressed message
        flag = bin(message[pointer] >> 6)

        # If the first two bits are 11, point to offset
        if flag[2:4] == '11':
            if jumped == False: 
                jumped = True
                tempPointer = pointer
            binOut = bin(int.from_bytes(message[pointer : pointer + 2], 'big'))
            offset = int(binOut[4:], 2)
            pointer = offset
            continue
        
        # The first byte is label length
        labelLength = message[pointer]
        pointer += 1
        label = message[pointer : pointer + labelLength].decode('utf-8')
        labels.append(label)
        
        # Point to next potential label
        pointer += labelLength
        

    pointer += 1
    if jumped:
        pointer = tempPointer + 2     # point to byte after compressed name
    return ('.'.join(labels), pointer)

def domainNameToLables(domainName: str):
    message = b''
    labels = domainName.split('.')
    for label in labels:
        labelLen = len(label)
        message += labelLen.to_bytes(1, byteorder='big')
        message += label.encode()

    message += b'\x00'
    return message


def dnsQuestionBytesToDict(message: bytes, start: int):
    '''start refers to the first byte of the dns question block.
    pointer points to next by'''
    name, pointer = labelsToDomainName(message, start)
    qType = message[pointer : pointer + 2]
    pointer += 2
    qClass = message[pointer : pointer + 2]
    pointer += 2
    return ({'name': name, 'type': qType, 'class': qClass}, pointer)

def dnsQuestionDictToBytes(dnsDict):
    '''start refers to the first byte of the dns question block'''
    message = b''
    labels = dnsDict.get('name').split('.')
    
    for label in labels:
        labelLen = len(label)
        message += labelLen.to_bytes(1, byteorder='big')
        message += label.encode()

    message += b'\x00'
    message += dnsDict.get('type')
    message += dnsDict.get('class')
    return message

def dnsRecordBytesToDict(message: bytes, start: int, isAuthoritative = False):
    '''start refers to the first byte of the dns resource block'''
    name, pointer = labelsToDomainName(message, start)
    rrType = message[pointer : pointer + 2]
    pointer += 2

    rrClass = message[pointer : pointer + 2]
    pointer += 2

    ttl = message[pointer : pointer + 4]
    pointer += 4

    dataLength = int.from_bytes(message[pointer : pointer + 2], 'big')
    pointer += 2

    if isAuthoritative: 
        data, pointer = labelsToDomainName(message, pointer)
    else: 
        data = message[pointer : pointer + dataLength]
        pointer += dataLength
    
    record = {
        'name': name, 
        'type': rrType, 
        'class': rrClass, 
        'ttl': ttl, 
        'dataLenth': dataLength,
        'data': data
    }
    return (record, pointer)



# class DnsQuestion():
#     def __init__(self, message: bytes):
#         self.message = message

#     @classmethod
#     def fromScratch(cls, domainName: str, qType: bytes = b'\x00\x01', \
#         qClass: bytes = b'\x00\x01'):
#         message = b''

#         labels = domainName.split('.')
#         for label in labels:
#             labelLen = len(label)
#             message += labelLen.to_bytes(1, byteorder='big')
#             message += label.encode()

#         message += b'\x00'
#         message += qType
#         message += qClass
#         print(message)
#         return cls(message)

#     def getName(self):
#         return labelsToDomainName(self.message, 0)


class DnsMessage():
    def __init__(self, message: bytes):
        self.message = message
        self.Id = self.message[0:2]
        self.flags = self.message[2:4]
        self.numQuestions = int.from_bytes(self.message[4:6], 'big')
        self.numAnswers = int.from_bytes(self.message[6:8], 'big')
        self.numAuthority = int.from_bytes(self.message[8:10], 'big')
        self.numAdditional = int.from_bytes(self.message[10:12], 'big')

        pointer = 0
        '''Get DNS questions.'''
        qs = []
        if self.numQuestions != 0:
            # question block starts at byte 12
            pointer = 12
            for i in range(self.numQuestions):
                q, pointer = dnsQuestionBytesToDict(self.message, pointer)
                qs.append(q)

        self.questions = qs

        '''Get DNS answers'''
        ans = []
        if self.numAnswers != 0:
            for i in range(self.numAnswers):
                a, pointer = dnsRecordBytesToDict(self.message, pointer) 
                # a['name'] = labelsToDomainName(a.get('name'), 0)
                ans.append(a)
        self.answers = ans

        '''Get DNS authorities'''
        auths = []
        if self.numAuthority != 0:
            for i in range(self.numAuthority):
                auth, pointer = dnsRecordBytesToDict(self.message, pointer, isAuthoritative=True)
                # auth['data'] = labelsToDomainName(self.message, pointer)
                auths.append(auth)
        self.authorities = auths

        '''Get DNS additional'''
        addInfos = []
        if self.numAdditional != 0:
            print('num additional: ', self.numAdditional)
            for i in range(self.numAdditional):
                info, pointer = dnsRecordBytesToDict(self.message, pointer)
                addInfos.append(info)
        self.additionalInfo = addInfos
        


        




    # def getQuestions(self):
    #     '''Returns the array of DNS questions.'''
    #     qs = []
    #     if self.numQuestions != 0:
    #         # question block starts at byte 12
    #         pointer = 12
    #         for i in range(self.numQuestions):
    #             q, pointer = dnsQuestionBytesToDict(self.message, pointer)
    #             qs.append(q)
    #     return qs
    
    # def getAnswers(self):
    #     ans = []
    #     if self.numAnswers != 0:



##########################
# Testing cs.fiu.edu
iden = b'\x22\x33'
flags = b'\x00\x00'
numQs = b'\x00\x01'
numAns = b'\x00\x00'
numAuth = b'\x00\x00'
numAdd = b'\x00\x00'
host = b'\x02cs\x03fiu\x03edu\x00'
rrType = b'\x00\x01'    # Type A
rrClass = b'\x00\x01'   # Class I

message = iden + flags + numQs + numAns + \
    numAuth + numAdd + host + \
    rrType + rrClass
##########################
print(message)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.sendto(message, (rootDnsIp, rootDnsPort))

data, addr = sock.recvfrom(1024)
print("received message: %s \n NumBytes: %d" % (data, len(data)))
dnsMessage = DnsMessage(data)

print('quesitons')
print(dnsMessage.questions)
print('answers')
print(dnsMessage.answers)
print('authoratative')
print(dnsMessage.authorities)
print('additional info')
print(dnsMessage.additionalInfo)
sock.close()

# test = b'\xc0\x13'
# print(test[0] >> 6 )
# print(int.from_bytes(test, 'big') )

# # convert bytes to binary
# binOut = bin(int.from_bytes(test, 'big'))

# # check if first two bits are 11
# print(binOut[2:4] == '11')

# # get turn the offset binary to int
# print(int(binOut[4:], 2)) 


# qBlock = host + rrType + rrClass
# print('qBlock:')
# print(qBlock)
# q = dnsQuestionBytesToDict(qBlock, 0)
# print('DnsDict:')
# print(q)
# print('converting dnsDict to bytes:')
# q = dnsQuestionDictToBytes(q)
# print(q)


# test = labelsToDomainName(host, 0)
# print(test)