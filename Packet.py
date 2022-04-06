from re import S
import cryptography
from cryptography.fernet import Fernet
import struct
import hashlib

class Packet:
    def __init__(self, *args):
        if len(args) > 1 and isinstance(args[0],str) and isinstance(args[1],list):
            print("entrou primeira opção")
            self.ip_from = args[0]
            self.oids = args[1]

        elif len(args) == 0:# and isinstance(args[0],bytes) and isinstance(args[1],Fernet):
            print('decoding ...')
            self.ip_from = None
            self.oids = None
            #self.decode(args[0],args[1])

    def pack(self,fernet):

        ip = [int(i) for i in self.ip_from.split('.')]
        # 4s -> ip {}H -> qt de oids
        header = struct.pack("!4h", *ip)
        data = b''
        # crypt = b''
        for o in self.oids:
            data += bytes(o,'utf-8') + bytes(';','utf-8')
            # crypt += fernet.encrypt(o.encode('utf-8')) + bytes(';','utf-8')
        h = hashlib.md5(header+data).hexdigest()
        msg = header + bytes(str(h),'utf-8') + fernet.encrypt(data)
        # print(h)
        # try:
        #     print('header:')
        #     print(struct.unpack("!4h", msg[0:8]))
        # except Exception as e:
        #     print(e)
        return msg

    def getHash(self):
        ip = [int(i) for i in self.ip_from.split('.')]
        # 4s -> ip {}H -> qt de oids
        header = struct.pack("!4h", *ip)
        data = b''
        for o in self.oids:
            data += bytes(o,'utf-8') + bytes(';','utf-8')
        h = hashlib.md5(header+data).hexdigest()
        # print(h)
        return h


    def decode(self,packetBytes,fernet):
        header = struct.unpack("!4h", packetBytes[0:8])
        # print(header)
        self.ip_from = ".".join([str(x) for x in header])
        hash = packetBytes[8:40].decode('utf-8')
        self.oids = fernet.decrypt(packetBytes[40:]).decode('utf-8').split(';')[0:-1]
        # print(self.oids)
        # print(packetBytes.decode('utf-8'))
        return hash

    def printaPacket(self):
        print('ipfrom: ' + self.ip_from )
        print('oids: ',end="")
        print(self.oids)