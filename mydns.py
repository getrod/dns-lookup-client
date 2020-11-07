import socket

rootDnsIp = '202.12.27.33'
rootDnsPort = 53

def labelsToDomainName(message: bytes, nameIdx: int):
    '''Constructs a domain name string with DNS message
    in the format label1.label2.lable3. Ex: 'cs.fiu.edu'.
    nameIdx should point to the length of a label'''
    labels = []
    pointer = nameIdx
    
    while message[pointer] != 0:
        # convert potential compressed name to binary
        flag = bin(message[pointer] >> 6)

        # If the first two bits are 11, point to offset
        if flag[2:4] == '11':
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

    return '.'.join(labels)



class DnsQuestion():
    def __init__(self, message: bytes):
        self.message = message

    # def getName(self):
    #     return self.message[]

class DnsMessage():
    def __init__(self, message: bytes):
        self.message = message
    
    def getId(self) -> bytes:
        return self.message[0:2]
    
    def getFlag(self) -> bytes:
        return self.messags[2:4]

    def numQuestions(self) -> bytes:
        return self.message[4:6]
    
    def numAnswers(self) -> bytes:
        return self.message[6:8]
    
    def numAuthority(self) -> bytes:
        return self.message[8:10]

    def numAddition(self) -> bytes:
        return self.message[10:12]


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
# print(message)

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# sock.sendto(message, (rootDnsIp, rootDnsPort))

# data, addr = sock.recvfrom(1024)
# print("received message: %s" % data)
# sock.close()

# test = b'\xc0\x13'
# print(test[0] >> 6 )
# print(int.from_bytes(test, 'big') )

# # convert bytes to binary
# binOut = bin(int.from_bytes(test, 'big'))

# # check if first two bits are 11
# print(binOut[2:4] == '11')

# # get turn the offset binary to int
# print(int(binOut[4:], 2)) 
print(host)
test = labelsToDomainName(host, 0)
print(test)