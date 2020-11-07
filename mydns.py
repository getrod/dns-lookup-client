import socket
rootDnsIp = '202.12.27.33'
rootDnsPort = 53

##########################
# Testing cs.fiu.edu
iden = b'\x22\x33'
flags = b'\x00\x00'
numQs = b'\x00\x01'
numAns = b'\x00\x00'
numAuth = b'\x00\x00'
numAdd = b'\x00\x00'
firstDomainNameSize = b'\x02'   # Size of first domain name
host = b'cs\x03fiu\x03edu'
buf = b'\x00'
rrType = b'\x00\x01'    # Type A
rrClass = b'\x00\x01'   # Class I

message = iden + flags + numQs + numAns + \
    numAuth + numAdd + firstDomainNameSize + host + \
    buf + rrType + rrClass
##########################
print(message)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.sendto(message, (rootDnsIp, rootDnsPort))

data, addr = sock.recvfrom(1024)
print("received message: %s" % data)
sock.close()