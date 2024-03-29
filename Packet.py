import hashlib

def doHash(b):
    return hashlib.md5(b).digest()


class Packet:
    def __init__(self, *args):
        if len(args) == 3:
            self.ip_from = args[0]
            
            self.payload = args[1]
            self.type = args[2]
            self.checksum = None

        elif len(args) == 0:
            self.ip_from = None
            self.payload = None
            self.type = None
            self.checksum = None


    def pack(self,fernet):
        header = bytearray(("$".join([self.type,self.ip_from])).encode('latin-1'))
        #divisao = "|".encode('latin-1')
        divisao = ";".encode('latin-1')
        encoded = b""
        toHash = b""
        # Quando é passada uma chave
        if isinstance(self.payload,bytes):
            toHash += header+"|".encode('latin-1')+self.payload
            h = doHash(toHash)
            print("Hash Here 0:")
            print(h)

            encoded = fernet.encrypt(self.payload)
            return header+"$".encode('latin-1') + fernet.encrypt(h) +"|".encode('latin-1')+encoded
        
        
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
                # print(toHash[:-1])
                # print("Hash Here 1:")
                # print(h)
                # encoded já vem com o ";"
                return header+"$".encode('latin-1') + fernet.encrypt(h) +"|".encode('latin-1')+encoded[:-1]
            else:
                # Se lista for vazia, então envia apenas a hash como payload
                toHash = header+"|".encode('latin-1')
                h = doHash(toHash)
                # print("Hash Here 2:")
                # print(h)
                return header+"$".encode('latin-1') + fernet.encrypt(h) + "|".encode('latin-1')
        else:
            toHash = header+"|".encode("latin-1")+self.payload.encode('latin-1')
            h = doHash(toHash)
            # print("Hash Here 3:")
            # print(h)
            return header+"$".encode('latin-1') + fernet.encrypt(h) +"|".encode("latin-1")+fernet.encrypt(self.payload.encode('latin-1'))


    # Calcula Hash do pacote
    # assume que o pacote contém já uma hash
    # usado para verificar se hashes coincidem
    def getHash(self,fernet):
        return fernet.decrypt(self.checksum)

    def calculateHash(self):
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
        for i in self.payload.split(';'):
            ai = i.encode('latin-1')
            payload.append(fernet.decrypt(ai))
            #payload.append(base64.decode(fernet.decrypt))
        return payload

    # É utilizado decode a True quando conteúdo contém oids encoded.
    # decode a False quando payload vem com chaves, que são necessárias vir em bytes
    def setPayload(self,newpayload,decode=True):
        self.payload=[]
        if decode:
            for i in newpayload:
                self.payload.append(i.decode('latin-1'))
        else:
            self.payload = newpayload

    def getUser(self):
        return self.ip_from
    
    def decode(self,packetBytes):
        msg = packetBytes.decode('latin-1').split('|')
        header = msg[0].split("$")
        self.type = header[0]
        self.ip_from = header[1]
        self.checksum = header[2].encode('latin-1')
        self.payload = msg[1]
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