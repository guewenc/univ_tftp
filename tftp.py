"""
TFTP Module.
Authors: guewen.cousseau@etu.u-bordeaux.fr | matteo.davoigneau@etu.u-bordeaux.fr
"""

import socket       # Socket lib
import sys          # Sys lib
import threading    # Threading lib

"""
DEFAULT CONSTANTS :
- BLOCK SIZE : 512 bytes
- OPCODE :
    - RRQ : 1
    - WRQ : 2
    - DAT : 3
    - ACK : 4
"""

BLK_SIZE = 512
OP_RRQ, OP_WRQ, OP_DATA, OP_ACK = range(1, 5)

########################################################################
#                          COMMON ROUTINES                             #
########################################################################

# Convert an integer n to a bytes of size size
def intToBytes(n, size):
    try:
        nbr = (n).to_bytes(size, byteorder='big')
    except:
        sys.exit(1)
    return nbr

# Convert an OPCODE to bytes
def encodeOpcode(n, ascii = False):
    if ascii:
        return intToBytes(n, 2).decode("ascii")
    return intToBytes(n, 2)

### RRQ | WRQ FUNCTIONS ###

# Converts msg text to ASCII
def toAscii(msg):
    try:
        msg.encode("ascii").decode("ascii")
    except:
        sys.exit(1)
    return msg

# Build an RRQ / WRQ type package
def makeReqPacket(opcode, filename, blksize, mode='octet'):
    filename = toAscii(filename)
    packet = "{}{}\x00{}\x00".format(encodeOpcode(opcode, True), filename, mode)
    if blksize != BLK_SIZE:
        packet += "blksize\x00{}\x00".format(blksize)
    return packet.encode()

# Decode an RRQ / WRQ type package
def decodeReqPacket(req_packet):
    opcode = int.from_bytes(req_packet[0:2], byteorder='big') # Decode opcode
    args = req_packet[2:].split(b'\x00')
    blksize = BLK_SIZE
    if len(args) == 5: # Block size has been sent
        if args[2].decode() == "blksize":
            blksize = int(args[3].decode()) # Decode block size
    return (opcode, args[0], args[1].decode('ascii'), blksize)

def getOpcodeReqPacket(req_packet):
    return decodeReqPacket(req_packet)[0] # OPCODE

def getFilenameReqPacket(req_packet):
    return decodeReqPacket(req_packet)[1] # Filename

def getBlkSizeReqPacket(req_packet):
    return decodeReqPacket(req_packet)[3] # Block size

### DATA FUNCTIONS ###

# Build an DATA type package
def makeDataPacket(block, data):
    return encodeOpcode(OP_DATA) + intToBytes(block, 2) + data

# Decode an DATA type package
def decodeDataPacket(packet):
    return int.from_bytes(packet[2:4], byteorder='big'), packet[4:]

### ACK FUNCTIONS ###

# Build an ACK type package
def makeAckPacket(block):
    return encodeOpcode(OP_ACK) + intToBytes(block, 2)

# Check if current block is valid
def validAckPacket(block, data):
    if isOpcode(OP_ACK, data):
        return data == makeAckPacket(block)
    return 0

# Send an ACK Packet
def sendAckPacket(s, addr, block, display = True):
    ack = makeAckPacket(block)
    s.sendto(ack, addr)
    if display:
        printLogs(s.getsockname(), addr, OP_ACK, (block, ack))

### ROUTINES FUNCTIONS

# Display logs on client console
def printLogs(addr_s, addr_d, op_code, infos):
    if op_code == OP_RRQ:
        msg = "RRQ={}".format(infos[0])
    elif op_code == OP_WRQ:
        msg = "WRQ={}".format(infos[0])
    elif op_code == OP_ACK:
        msg = "ACK{}={}".format(infos[0], infos[1])
    elif op_code == OP_DATA:
        msg = "DAT{}={}".format(infos[0], infos[1])

    print("[{}:{} -> {}:{}] {}".format(addr_s[0], addr_s[1], addr_d[0], addr_d[1], msg))

# Display logs on server console
def serverLogs(msg):
    print("[INFO] : {}".format(msg))

# Error handler : always shuts down the client, only displays an error and keeps
# the process going on the server.
def errorHandling(err, side):
    if err == 'NO_FILE':
        if side == 'SERVER':
            print("ERROR : Couldn't open file. Does it even exist ?")
        else:
            print("ERROR : Couldn't open file. Does it even exist ?")
            sys.exit(1)

    if err == 'INVALID_BLKSIZE':
        if side == 'SERVER':
            print("ERROR : BLK_SIZE paramaters should be positive")
        else:
            print("ERROR : BLK_SIZE paramaters should be positive")
            sys.exit(1)

    if err == 'SOCKET_CREATION':
        if side == 'SERVER':
            exit("ERROR : Couldn't create socket. Quitting.")
        else:
            print("ERROR : Couldn't create client socket. Abborting.")
            sys.exit(1)

    if err == 'INVALID_ACK':
        if side == 'SERVER':
            print("ERROR : Wrong ACK packet received. Abborting.")
        else:
            print("ERROR : Wrong ACK packet received. Abborting.")
            sys.exit(1)

    if err == 'WRONG_PACKET':
        if side == 'SERVER':
            print("ERROR : Received packet not as intended")
        else:
            print("ERROR : Received packet not as intended")
            sys.exit(1)

    if err == 'CLIENT_DISCONNECT' and side == 'SERVER':
        print("ERROR : Client disconnected while transfering. Abborting.")

    if err == 'SERVER_DISCONNECT' and side == 'CLIENT':
        print("ERROR : Server disconnected while transfering. Is someone already using it ? Abborting.")
        sys.exit(1)

# Request OPCODE is equal to opcode variable
def isOpcode(opcode, request):
    request_opcode = int.from_bytes(request[0:2], byteorder='big')
    if request_opcode == opcode:
        return 1
    return 0

# Open file on mode mode
def openFile(filename, mode):
    try:
        file = open(filename, mode)
    except:
        return 0
    return file

# Receive DATA type block
def receiveData(s, blk_size):
    return s.recvfrom(blk_size + 4)

# Server sends a file to the client (GET command)
def sendFile(temp_s, client_addr, filename, blksize, timeout):
    file = openFile(filename, "rb") # Read bytes mode
    if file == 0:
        errorHandling('NO_FILE', 'SERVER')
        return

    block = 1

    while True: # While not EOF
        data = file.read(blksize)
        temp_s.sendto(makeDataPacket(block, data), client_addr)

        try:
            ack_packet = temp_s.recv(4) # Receive data from client, should be ACKxx
        except:
            errorHandling('CLIENT_DISCONNECT', 'SERVER')
            break

        if not validAckPacket(block, ack_packet):
            errorHandling('INVALID_ACK', 'SERVER')
            break
        block += 1

        if len(data) != blksize:
            break
    file.close()

# Server receives a file from the client (PUT command)
def receiveFile(temp_s, client_addr, filename, blksize, timeout):
    file = openFile(filename, "wb")
    temp_s.sendto(makeAckPacket(0), client_addr) # Send ACK0 : server accepts file

    while True: # While all DATA packets are not received
        try:
            data_packet, client_addr = receiveData(temp_s, blksize) # Should be a DAT
        except:
            errorHandling('CLIENT_DISCONNECT', 'SERVER')
            break

        try:
            isOpcode(OP_DATA, data_packet)
        except:
            errorHandling('WRONG_PACKET', 'SERVER')
            break

        block_number, data = decodeDataPacket(data_packet)
        file.write(data)
        temp_s.sendto(makeAckPacket(block_number), client_addr) # Send ACK0 : server accepts file

        if len(data) != blksize:
            break
    file.close()

########################################################################
#                             SERVER SIDE                              #
########################################################################

def clientTreatement(packet, client_addr, timeout):
    if not (isOpcode(OP_RRQ, packet) or isOpcode(OP_WRQ, packet)):
            errorHandling('WRONG_PACKET', 'SERVER')

    op_code = getOpcodeReqPacket(packet)
    filename = getFilenameReqPacket(packet)
    blksize = getBlkSizeReqPacket(packet)

    try:
        temp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Server temporary socket
        temp_s.settimeout(timeout)
    except:
        errorHandling('SOCKET_CREATION', 'SERVER')

    serverLogs("{}:{} -> Query processing begins".format(client_addr[0], client_addr[1]))

    if op_code == OP_RRQ: # DAT1 from serv then ACK1 from client (GET)
        sendFile(temp_s, client_addr, filename, blksize, timeout)
    elif op_code == OP_WRQ: # ACK0 from serv then DAT1 from client (PUT)
        receiveFile(temp_s, client_addr, filename, blksize, timeout)

    serverLogs("{}:{} -> Query processing ends".format(client_addr[0], client_addr[1]))

def runServer(addr, timeout, thread):
    try:
        server_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Server socket
        server_s.bind(addr)
    except:
        errorHandling('SOCKET_CREATION', 'SERVER')

    serverLogs("Server is listening")

    while True: # Server must not stop
        packet, client_addr = server_s.recvfrom(1024) # Should be RRQ or WRQ

        if thread:
            threading.Thread(None, clientTreatement, None, (packet, client_addr, timeout)).start() # Create thread
        else:
            clientTreatement(packet, client_addr, timeout)

    serverLogs("Server shutdown")
    server_s.close()
    temp_s.close()

########################################################################
#                             CLIENT SIDE                              #
########################################################################

def put(server_addr, filename, targetname, blksize, timeout):
    file = openFile(filename, "rb") # On lit un fichier, donc il doit exister
    if file == 0:
        errorHandling('NO_FILE', 'CLIENT')

    if blksize <= 0:
        errorHandling('INVALID_BLKSIZE', 'CLIENT')

    try:
        client_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Client socket
    except:
        errorHandling('SOCKET_CREATION', 'CLIENT')

    client_s.settimeout(timeout) # Set a timeout

    rqst_packet = makeReqPacket(OP_WRQ, targetname, blksize)
    client_s.sendto(rqst_packet, server_addr)
    printLogs(client_s.getsockname(), server_addr, OP_WRQ, (rqst_packet,))

    block = 0

    while True: # While not EOF
        try:
            ack_packet, server_addr = client_s.recvfrom(4) # Should be an ACK
        except:
            errorHandling('SERVER_DISCONNECT', 'CLIENT')

        try:
            validAckPacket(block, ack_packet)
        except:
            errorHandling('INVALID_ACK', 'CLIENT')

        printLogs(server_addr, client_s.getsockname(), OP_ACK, (block, ack_packet))
        block += 1

        data = file.read(blksize)
        data_packet = makeDataPacket(block, data)
        client_s.sendto(data_packet, server_addr)
        printLogs(client_s.getsockname(), server_addr, OP_DATA, (block, data_packet))

        if len(data) != blksize:
            break

    try:
        ack_packet, server_addr = client_s.recvfrom(4) # Should be an ACK
    except:
        errorHandling('SERVER_DISCONNECT', 'CLIENT')

    try:
        validAckPacket(block, ack_packet)
    except:
        errorHandling('INVALID_ACK', 'CLIENT')

    printLogs(server_addr, client_s.getsockname(), OP_ACK, (block, ack_packet))
    file.close()
    client_s.close()

########################################################################

def get(server_addr, filename, targetname, blksize, timeout):
    try:
        client_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except:
        errorHandling('SOCKET_CREATION', 'CLIENT')

    if blksize <= 0:
        errorHandling('INVALID_BLKSIZE', 'CLIENT')

    client_s.settimeout(timeout) # Set a timeout

    rrq_packet = makeReqPacket(OP_RRQ, filename, blksize)
    client_s.sendto(rrq_packet, server_addr)
    printLogs(client_s.getsockname(), server_addr, OP_RRQ, (rrq_packet,))

    file = openFile(targetname, "wb") # Likely to overwrite file

    while True: # While all DATA packets are not received
        try:
            data_packet, server_addr = receiveData(client_s, blksize) # Should be a DAT
        except:
            errorHandling('SERVER_DISCONNECT', 'CLIENT')

        try:
            isOpcode(OP_DATA, data_packet)
        except:
            errorHandling('WRONG_PACKET', 'CLIENT')

        block, data = decodeDataPacket(data_packet)
        printLogs(server_addr, client_s.getsockname(), OP_DATA, (block, data_packet))

        file.write(data)
        sendAckPacket(client_s, server_addr, block)

        if len(data) != blksize:
            break

    file.close()
    client_s.close()

# EOF
