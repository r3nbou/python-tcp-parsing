import struct
from binascii import hexlify

def quickEthernetProto(data):
    return struct.unpack('!H', data[12:14])[0]

def quickIPProto(data):
    return struct.unpack('!B', data[9])[0]

def quickIPhlen(data):
    return (struct.unpack('!B', data[0])[0] & 0xf)

def quickIPpktlen(data):
    return struct.unpack('!H', data[2:4])[0]

def quickTCPSourcePort(data):
    return struct.unpack('!H', data[:2])[0]

def quickTCPDestPort(data):
    return struct.unpack('!H', data[2:4])[0]

class ethernet():
    destination = ''
    source = ''
    ptype = 0

    def __init__(self):
        self.__del__()
    
    def __del__(self):
        self.destination, self.source, self.ptype = '', '', 0

    def update(self, data):
        self.__del__()
        self.destination, self.source, self.ptype = struct.unpack('!6s6sH', data)
        self.destination = hexlify(self.destination)
        self.source = hexlify(self.source)
    
    def getDestination(self):
        return ':'.join([self.destination[i:i+2] for i in range(0, len(self.destination), 2)])
    
    def getSource(self):
        return ':'.join([self.source[i:i+2] for i in range(0, len(self.source), 2)])
    
    def getType(self):
        return self.ptype

class ip():
    version = 0
    ihl = 0
    typeOfService = 0
    length = 0
    identification = 0
    flags = 0
    ttl = 0
    protocol = 0
    crc = 0
    source = 0
    destination = 0
    options = ''

    def update(self, data):
        self.__del__()
        tmp = struct.unpack('!B', data[:1])[0]
        self.version = (tmp >> 4)
        self.ihl = (tmp & 0xf)
        self.typeOfService = struct.unpack('!B', data[1:2])[0]
        self.length = struct.unpack('!H', data[2:4])[0]
        self.identification = struct.unpack('!H', data[4:6])[0]
        self.flags = struct.unpack('!H', data[6:8])[0]
        self.ttl = struct.unpack('!B', data[8:9])[0]
        self.protocol = struct.unpack('!B', data[9:10])[0]
        self.crc = struct.unpack('!H', data[10:12])[0]
        self.source = struct.unpack('!I', data[12:16])[0]
        self.destination = struct.unpack('!I', data[16:20])[0]

        if self.ihl > 5:
            self.options = struct.unpack('!'+str((self.ihl-5)*4)+'s', data[20:self.ihl*4])[0]

    def pack(self):
        tmp = ((self.version << 4) | self.ihl)
        frmtstr = '!BBHHHBBHII'
        if len(self.options) > 0:
            frmtstr += str(len(self.options)) + 's'
            res = struct.pack(frmtstr, tmp, self.typeOfService, self.length, self.identification,\
                          self.flags, self.ttl, self.protocol, self.crc, self.source, self.destination, self.options)
        else:
            res = struct.pack(frmtstr, tmp, self.typeOfService, self.length, self.identification,\
                          self.flags, self.ttl, self.protocol, self.crc, self.source, self.destination)
        return res

    def __init__(self):
        self.__del__()
    
    def __del__(self):
        self.version = 0
        self.ihl = 0
        self.typeOfService = 0
        self.length = 0
        self.identification = 0
        self.flags = 0
        self.ttl = 0
        self.protocol = 0
        self.crc = 0
        self.source = 0
        self.destination = 0
        self.options = ''

    def getVersion(self):
        return self.version

    def setVersion(self, ver):
        if type(ver) != int:
            raise Exception("Invalid type for IP version")
        self.version = ver

    def getIHL(self):
        return self.ihl

    def setIHL(self, hlen):
        if type(hlen) != int:
            raise Exception("Invalid type for IP IHL")
        self.ihl = hlen

    def getTOS(self):
        return self.typeOfService

    def setTOS(self, tos):
        if type(tos) != int:
            raise Exception("Invalid type for IP type of service")
        self.typeOfService = tos

    def getTotalLength(self):
        return self.length

    def setTotalLength(self, len):
        if type(len) != int:
            raise Exception("Invalid type for IP total length")
        self.length = len

    def getIdentifier(self):
        return self.identification

    def setIdentifier(self, id):
        if type(id) != int:
            raise Exception("Invalid type for IP identifier")
        self.identification = id

    def getFragmentationFlags(self):
        return self.flags

    def setFragmentationFlags(self, flags):
        if type(flags) != int:
            raise Exception("Invalid type for IP fragmentation flags")
        self.flags = flags
    
    def getTimeToLive(self):
        return self.ttl

    def setTimeToLive(self, ttl):
        if type(ttl) != int:
            raise Exception("Invalid type for IP time to live")
        self.ttl = ttl
       
    def getNextProto(self):
        return self.protocol

    def setNextProto(self, proto):
        if type(proto) != int:
            raise Exception("Invalid type for IP identifier")
        self.protocol = proto
    
    def getChecksum(self):
        return self.crc

    def setChecksum(self, crc):
        if type(crc) != int:
            raise Exception("Invalid type for IP checksum")
        self.crc = crc

    def getSource(self):
        return self.source

    def setSource(self, src):
        if type(src) != int:
            raise Exception("Invalid type for IP source")
        self.source = src

    def getDestination(self):
        return self.destination

    def setDestination(self, dest):
        if type(dest) != int:
            raise Exception("Invalid type for IP destination")
        self.destination = dest
    
    def getOptions(self):
        return self.options

    def setOptions(self, opts):
        if type(opts) != str:
            raise Exception("Invalid type for IP options")
        self.options = opts

    def getAllParams(self):
        return {'version': self.version, 'ihl': self.ihl, 'typeOfService': self.typeOfService,
                'totalLength': self.length, 'identification': self.identification, 'fragmentFlags': self.flags,
                'TTL': self.ttl, 'nextProtocol': self.protocol, 'checksum': self.crc,
                'source': self.source, 'destination': self.destination, 'options': self.options}

class tcp():
    sourcePort = 0
    destinationPort = 0
    sequenceNumber = 0
    ackNumber = 0
    hlen = 0
    reserved = 0
    flags = 0
    windowSize = 0
    checksum = 0
    urgentPtr = 0
    options = ''

    def getAllParams(self):
        return {'sourcePort':self.sourcePort, 'destinationPort':self.destinationPort, 'sequenceNumber':self.sequenceNumber,
                'ackNumber': self.ackNumber, 'headerLength': self.hlen, 'flags': self.getFlags(), 'windowSize': self.windowSize,
                'checksum': self.checksum, 'urgentPointer': self.urgentPtr, 'options': self.options}

    def __init__(self):
        self.__del__()

    def __del__(self):
        self.sourcePort = 0
        self.destinationPort = 0
        self.sequenceNumber = 0
        self.ackNumber = 0
        self.hlen = 0
        self.reserved = 0
        self.flags = 0
        self.windowSize = 0
        self.checksum = 0
        self.urgentPtr = 0
        self.options = ''
    
    def update(self, data):
        self.__del__()
        self.sourcePort = struct.unpack('!H', data[:2])[0]
        self.destinationPort = struct.unpack('!H', data[2:4])[0]
        self.sequenceNumber = struct.unpack('!I', data[4:8])[0]
        self.ackNumber = struct.unpack('!I', data[8:12])[0]
        tmp = struct.unpack('!B', data[12:13])[0]
        self.hlen = (tmp >> 4)
        self.reserved = (tmp & 0xf)
        tmp = struct.unpack('!B', data[13:14])[0]
        self.reserved = ((self.reserved << 2) | (tmp >> 6))
        self.flags = (tmp & 0x3f)
        self.windowSize = struct.unpack('!H', data[14:16])[0]
        self.checksum = struct.unpack('!H', data[16:18])[0]
        self.urgentPtr = struct.unpack('!H', data[18:20])[0]
        
        if self.hlen > 5:
            self.options = struct.unpack('!'+str((self.hlen-5)*4)+'s', data[20:self.hlen*4])[0]

    def pack(self):
        tmp1 = ((self.hlen << 4) | (self.reserved >> 2))
        tmp2 = (((self.reserved & 0x3) << 6) | self.flags)
        frmtstr = '!HHIIBBHHH'
        res = ''
        if len(self.options) > 0:
            frmtstr += str(len(self.options)) + 's'
            res = struct.pack(frmtstr, self.sourcePort, self.destinationPort, self.sequenceNumber, self.ackNumber, \
                          tmp1, tmp2, self.windowSize, self.checksum, self.urgentPtr, self.options)
        else:
            res = struct.pack(frmtstr, self.sourcePort, self.destinationPort, self.sequenceNumber, self.ackNumber, \
                          tmp1, tmp2, self.windowSize, self.checksum, self.urgentPtr)
        return res

    def getSourcePort(self):
        return self.sourcePort

    def setSourcePort(self, prt):
        if type(prt) != int:
            raise Exception("Invalid type for TCP source port")
        self.sourcePort = prt

    def getDestinationPort(self):
        return self.destinationPort
    
    def setDestinationPort(self, prt):
        if type(prt) != int:
            raise Exception("Invalid type for TCP destination port")
        self.destinationPort = prt

    def getSequenceNumber(self):
        return self.sequenceNumber

    def setSequenceNumber(self, num):
        if type(num) != int:
            raise Exception("Invalid type for TCP sequence number")
        self.sequenceNumber = num

    def getAckNumber(self):
        return self.ackNumber
    
    def setAckNumber(self, num):
        if type(num) != int:
            raise Exception("Invalid type for TCP ACK number")
        self.ackNumber = num
    
    def getHeaderLen(self):
        return self.hlen

    def setHeaderLen(self, len):
        if type(len) != int:
            raise Exception("Invalid type for TCP header length")
        self.hlen = len
    
    def getFlags(self):
        return self.flags

    def setFlags(self, flags):
        if type(flags) != int:
            raise Exception("Invalid type for TCP flags")
        self.flags = flags

    def getWindowSize(self):
        return self.windowSize
    
    def setWindowSize(self, wsize):
        if type(wsize) != int:
            raise Exception("Invalid type for TCP window size")
        self.windowSize = wsize

    def getChecksum(self):
        return self.checksum

    def setChecksum(self, chck):
        if type(chck) != int:
            raise Exception("Invalid type for TCP checksum")
        self.checksum = chck
    
    def getUrgentPtr(self):
        return self.urgentPtr

    def setUrgentPtr(self, ptr):
        if type(ptr) != int:
            raise Exception("Invalid type for TCP urgent pointer")
        self.urgentPtr = ptr
    
    def getOptions(self):
        return self.options
    
    def setOptions(self, opts):
        if type(opts) != str:
            raise Exception("Invalid type for IP options")
        self.options = opts

    def getFlags(self):
        res = {'urg':0, 'ack':0, 'psh':0, 'rst':0, 'syn':0, 'fin':0}
        if ((self.flags >> 5) & 1):
            res['urg'] = 1
        if ((self.flags >> 4) & 1):
            res['ack'] = 1
        if ((self.flags >> 3) & 1):
            res['psh'] = 1
        if ((self.flags >> 2) & 1):
            res['rst'] = 1
        if ((self.flags >> 1) & 1):
            res['syn'] = 1
        if (self.flags & 1):
            res['fin'] = 1
        return res