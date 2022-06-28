import hashlib

def doHash(b):
    return hashlib.md5(b).digest()


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
        toHash = b""
        if isinstance(self.payload,bytes):
            toHash += header+"|".encode('latin-1')+self.payload
            h = doHash(toHash)
            print("Hash Here 0:")
            print(h)

            encoded = fernet.encrypt(self.payload)
            return header+"|".encode('latin-1')+encoded+divisao+h
        elif isinstance(self.payload,list):
            
            if len(self.payload) > 0:
                # se lista não estiver vazia
                # percorre a lista adicionando todos os elementos separados por ;
                # versão hashed não tem encriptação
                toHash += header+"|".encode('latin-1')
                for p in self.payload:
                    if isinstance(p,bytes):
                        toHash += p+divisao
                        encoded += (fernet.encrypt(p)+divisao)

                    else:

                        toHash += p.encode('latin-1')+divisao
                        encoded += (fernet.encrypt(p.encode('latin-1'))+divisao)
                h = doHash(toHash[:-1])
                print(toHash[:-1])
                print("Hash Here 1:")
                print(h)
                # encoded já vem com o ";"
                return header+"|".encode('latin-1')+encoded + h
            else:
                # Se lista for vazia, então envia apenas a hash como payload
                toHash = header+"|".encode('latin-1')
                h = doHash(toHash)
                print("Hash Here 2:")
                print(h)
                return header + "|".encode('latin-1')+h
        else:
            # for p in self.payload.split(";"):
            #     encoded += (fernet.encrypt(p.encode('latin-1'))+divisao)
            # return header+"|".encode('latin-1')+encoded[:-1]
            toHash = header+"|".encode("latin-1")+self.payload.encode('latin-1')
            h = doHash(toHash)
            print("Hash Here 3:")
            print(h)
            return header+"|".encode("latin-1")+fernet.encrypt(self.payload.encode('latin-1')) + divisao + h
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

    # Calcula Hash do pacote
    # assume que o pacote contém já uma hash
    # usado para verificar se hashes coincidem
    def getHash(self):
        header = bytearray(("$".join([self.type,self.ip_from])).encode('latin-1'))
        #divisao = "|".encode('latin-1')
        divisao = ";".encode('latin-1')
        toHash = b""
        if isinstance(self.payload,bytes):
            toHash += header+"|".encode('latin-1')+self.payload
            h = doHash(toHash)
            return h
        elif isinstance(self.payload,list):
            if len(self.payload) > 0:
                toHash += header+"|".encode('latin-1')
                for p in self.payload:
                    if isinstance(p,bytes):
                        toHash += p+divisao
                    else:
                        toHash += p.encode('latin-1')+divisao
                h = doHash(toHash[:-1])
                return h
            else:
                # Se lista for vazia, então envia apenas a hash como payload
                toHash = header+"|".encode('latin-1')
                h = doHash(toHash)
                return h
        else:
            toHash = header+"|".encode("latin-1")+self.payload.encode('latin-1')
            h = doHash(toHash)
            return h
        
    def getType(self):
        return self.type

    def getOriginPayload(self):
        return(";".join(self.payload))

    def decryptPayload(self,fernet):
        payload = []
        for i in self.payload.split(';')[:-1]:
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

    # devolve pensagem decoded com o checksum incluido
    def decode(self,packetBytes):
        msg = packetBytes.decode('latin-1').split('|')
        header = msg[0].split("$")
        self.ip_from = header[1]
        self.type = header[0]
        self.payload = msg[1]
        h = msg[1].split(";")[-1].encode('latin-1')
        print("HASH RETURNED:")
        print(h)
        return h
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