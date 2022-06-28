import base64
from cryptography.fernet import Fernet
import hashlib


class Packet:
    def __init__(self, *args):
        if len(args) == 3:
            self.ip_from = args[0]
            
            self.payload = args[1]
            self.type = args[2]

        elif len(args) == 0:
            self.ip_from = None
            self.payload = None
            self.type = None

    def pack(self,fernet):
        header = bytearray(("$".join([self.type,self.ip_from])).encode('latin-1'))
        #divisao = "|".encode('latin-1')
        divisao = ";".encode('latin-1')
        encoded = b""
        if isinstance(self.payload,bytes):
            encoded = fernet.encrypt(self.payload)
            return header+"|".encode('latin-1')+encoded
        elif isinstance(self.payload,list):
            for p in self.payload:
                encoded += (fernet.encrypt(p.encode('latin-1'))+divisao)
            return header+"|".encode('latin-1')+encoded[:-1]

        else:
            # for p in self.payload.split(";"):
            #     encoded += (fernet.encrypt(p.encode('latin-1'))+divisao)
            # return header+"|".encode('latin-1')+encoded[:-1]
            return header+"|".encode("latin-1")+fernet.encrypt(self.payload.encode('latin-1'))
        #encoded = ";".join(self.payload).encode('latin-1')
        
        

        # ip = [int(i) for i in self.ip_from.split('.')]
        # # 4s -> ip {}H -> qt de oids
        # header = struct.pack("!4h", *ip)
        # data = b''
        # # crypt = b''
        # for o in self.oids:
        #     data += bytes(o,'utf-8') + bytes(';','utf-8')
        #     # crypt += fernet.encrypt(o.encode('utf-8')) + bytes(';','utf-8')
        # h = hashlib.md5(header+data).hexdigest()
        # msg = header + bytes(str(h),'utf-8') + fernet.encrypt(data)
        # # print(h)
        # # try:
        # #     print('header:')
        # #     print(struct.unpack("!4h", msg[0:8]))
        # # except Exception as e:
        # #     print(e)
        # return msg

    def getHash(self):
        ip = self.ip_from.split('.')
        header = bytearray(("|".join(ip)).encode('latin-1'))
        divisao = "|".encode('latin-1')

        toHash = b''
        for oid in self.payload:
            toHash += divisao + oid.encode('latin-1')

        return hashlib.md5(header+toHash).hexdigest()


        # ip = [int(i) for i in self.ip_from.split('.')]
        # # 4s -> ip {}H -> qt de oids
        # header = struct.pack("!4h", *ip)
        # data = b''
        # for o in self.oids:
        #     data += bytes(o,'utf-8') + bytes(';','utf-8')
        # h = hashlib.md5(header+data).hexdigest()
        # # print(h)
        # return h
    def getType(self):
        return self.type

    def getOriginPayload(self):
        return(";".join(self.payload))

    def decryptPayload(self,fernet):
        payload = []
        for i in self.payload.split(';'):
            ai = i.encode('latin-1')
            payload.append(fernet.decrypt(ai))
            #payload.append(base64.decode(fernet.decrypt))
        return payload

    def setPayload(self,newpayload,decode=True):
        self.payload=[]
        if decode:
            for i in newpayload:
                self.payload.append(i.decode('latin-1'))
        else:
            self.payload = newpayload

    def decode(self,packetBytes):
        msg = packetBytes.decode('latin-1').split('|')
        header = msg[0].split("$")
        self.ip_from = header[1]
        self.type = header[0]
        self.payload = msg[1]
        # header = struct.unpack("!4h", packetBytes[0:8])
        # # print(header)
        # self.ip_from = ".".join([str(x) for x in header])
        # hash = packetBytes[8:40].decode('utf-8')
        # self.oids = fernet.decrypt(packetBytes[40:]).decode('utf-8').split(';')[0:-1]
        # # print(self.oids)
        # # print(packetBytes.decode('utf-8'))
        # return hash

    def getPayload(self):
        return self.payload

    def printaPacket(self):
        print('ipfrom: ' + self.ip_from )
        print('oids: ',end="")
        print(self.payload)
        print('type: ' + self.type)