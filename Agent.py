from ast import arg
from base64 import decode
import socket, threading
import json
from cryptography.fernet import Fernet
from Packet import Packet
from pysnmp.hlapi import *
from pysnmp.smi.rfc1902 import *
from MIBsec import MIBsec
from UserMIB import UserMIB
from concurrent.futures import ThreadPoolExecutor
#from Crypter import *
import time
import secrets


class Cleaner:
    def __init__(self,mib,users):
        self.mib = mib
        self.users = users

    def run(self,t,threshold,delThreshold):
        while True:
            time.sleep(t)
        #print("%d sec" % t)
            self.mib.cleanUp(t,threshold,delThreshold)
            self.users.cleanUp(t,threshold,delThreshold)
        #executor.submit(self.run,t,threshold,delThreshold)

#executor = ThreadPoolExecutor(max_workers=1)

#key = bytes(keys["key"],'latin-1')


def getNext(oid):
    try:
        iterator = nextCmd(SnmpEngine(),
                    CommunityData('gsr2022'),
                    UdpTransportTarget(('localhost', 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)))
    except:
        print('error')
        return
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

    else:

        return varBinds[0][1].prettyPrint()
      

def get(oid):
    try:
        iterator = getCmd(SnmpEngine(),
                    CommunityData('gsr2022'),
                    UdpTransportTarget(('localhost', 161)),
                    ContextData(),
                    #ObjectType(ObjectIdentity('sysDescr.0'))
                    #ObjectType(ObjectIdentity('UCD-SNMP-MIB','memMinimumSwap',0))#,
                    #ObjectType(ObjectIdentity('SNMPv2-MIB','sysDescr',0))#,
                    #ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0'))
                    #ObjectType(ObjectIdentity('1.3.6.1.2.1.1'))
                    #ObjectType(ObjectIdentity('.1.3.6.1.2.1.1.1.0'))
                    #.1.3.6.1.2.1.1.1.0
                    ObjectType(ObjectIdentity(oid))
                    )
    except:
        print('error')
        return
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

    else:
        # for varBind in varBinds:
        #     print(' = '.join([x.prettyPrint() for x in varBind]))
        return varBinds[0][1].prettyPrint()

def packetValidation(packet):
    if packet.getType() == 'SET':
        if len(packet.getPayload()) != 3:
            print('pacote inválido : %d' % len(packet.getPayload()))
            return False
        if packet.getPayload()[0] not in ['.1.1.1','.2.2.2','.3.3.3']:
            print('pacote inválido2 : ' + packet.getPayload()[0])
            return False
    else:
        print("type : " + packet.getType())
    return True

class ClientHandler():
    def __init__(self,conn,address,mib,users):
        self.conn = conn
        self.address = address
        self.mib = mib
        self.users = users

    def handleSET(self,packet,fernet):
        # atualizar payload
        # decode = true pois o decrypt apenas desencripta, sendo necessário dar decode
        # Aqui interessa-nos a mensagem como string e não como bytes
        print(packet.getPayload())
        if packet.getPayload()[0] == '.3.3.3':
            # hardcoded
            print('get from mibsec')
            try:
                if (a:=self.mib.getValue(packet.getPayload()[1])) is not None:
                    p = Packet(socket.gethostbyname(socket.gethostname()),a,'response')
                    mts = p.pack(fernet)
                    print("Sending:")
                    print(mts)
                    self.conn.sendall(mts)
                else:
                    a = "Id invalid or no answer yet"
                    p = Packet(socket.gethostbyname(socket.gethostname()),a,'response')
                    mts = p.pack(fernet)
                    print("Sending:")
                    print(mts)
                    self.conn.sendall(mts)
            except Exception as e:
                print(e)
                a = 'Error'
                p = Packet(socket.gethostbyname(socket.gethostname()),a,'response')
                mts=  p.pack(fernet)
                print("Sending:")
                print(mts)
                self.conn.sendall(mts)
        elif packet.getPayload()[0] == '.1.1.1': # get
            key = self.mib.add('GET',self.address,'default',packet.getPayload()[1],None,None,0,20,'received')
            print('received get')
            
            p = Packet(socket.gethostbyname(socket.gethostname()),['received ~ idOper='+str(key),'test'],'response')
            #conn.sendall(('received | idOper='+str(key)).encode('latin-1'))
            mts = p.pack(fernet)
            print("Sending:")
            print(mts)
            self.conn.sendall(mts)
            value = get(packet.getPayload()[1])
            self.mib.updateValue(key,value,'ready')
            print('updated')
        elif packet.getPayload()[0] == '.2.2.2': # getnext
            key = self.mib.add('GET-NEXT',self.address,'default',packet.getPayload()[1],None,None,0,20,'received')
            print('received - get-next')

            p = Packet(socket.gethostbyname(socket.gethostname()),'received ~ idOper='+str(key),'response')
            #conn.sendall(('received | idOper='+str(key)).encode('latin-1'))
            mts = p.pack(fernet)
            print("Sending:")
            print(mts)
            self.conn.sendall(mts)
            value = getNext(packet.getPayload()[1])
            self.mib.updateValue(key,value,'ready')
            print('updated') 

    def handleRequestAuth(self,packet,fernet):
        # desencriptar mensagem
        # -> "secret;checksum"
        # mensagem vem com have, por isso não dar decode
        packet.setPayload(packet.decryptPayload(fernet), decode=False)

        keyUser = (packet.getUser(),self.address)

        # verificação da integridade dos dados
        if packet.calculateHash() != packet.getHash(fernet):
            print("[INFO2] bad checksum")
            p = Packet(socket.gethostbyname(socket.gethostname()),[],'invalidMessage')
            mts = p.pack(fernet)
            self.conn.sendall(mts)
            return
        
        
        managerSecret = packet.getPayload()[0]
        print("managerSecret: RECEBIDO:")
        print(managerSecret)
        #secret = secrets.token_bytes()
        secret = Fernet.generate_key()
        self.users.add(keyUser,'authenticating',None,secret)
        print("Segredo a enviar:")
        print(secret)
        # encriptar key gerada, com a key recebida ; checksum
        managerFernet = Fernet(managerSecret)
        p = Packet(socket.gethostbyname(socket.gethostname()),secret,'requestAuth')
        mts = p.pack(managerFernet)
        print("Sending:")
        print(mts)
        self.conn.sendall(mts)
        

    def clientHandler(self,keys):
        while message:= self.conn.recv(1024):

            packet = Packet()
            packet.decode(message)
            if packet.getUser() not in keys:
                print('Invalid User')
                p = Packet(socket.gethostbyname(socket.gethostname()),[],'invalidAuth')
                mts = p.pack(fernet)
                print("Sending:")
                print(mts)
                self.conn.sendall(mts)
                continue
            
            fernet= Fernet(keys[packet.getUser()])
            # key user usado na userMIB
            keyUser = (packet.getUser(),self.address)
            #if hash != packet.getHash():
            #    print('Pacote comprometido!\nIgnorando packet ...')
            #    continue
            # print("Pacote recebido:")
            # packet.printaPacket()

            if packet.getType() == 'SET':
                packet.setPayload(packet.decryptPayload(fernet), decode=True)

                # Verificação do checksum
                if packet.getHash(fernet) != packet.calculateHash():
                    print("[INFO] bad checksum")
                    p = Packet(socket.gethostbyname(socket.gethostname()),[],'invalidMessage')
                    mts = p.pack(fernet)
                    self.conn.sendall(mts)

                # validação da autenticação
                elif self.users.isAuthenticated(keyUser):
                    self.handleSET(packet,fernet)
                else:
                    print("EXPIRED")
                    p = Packet(socket.gethostbyname(socket.gethostname()),[],'expiredAuth')
                    mts = p.pack(fernet)
                    print("Sending:")
                    print(mts)
                    self.conn.sendall(mts)
            elif packet.getType() == 'requestAuth':
                self.handleRequestAuth(packet,fernet)
            elif packet.getType() == 'finalizeAuth':
                if self.users.getState(keyUser) != 'authenticating':
                    print("AQUIAQUIAQUIAQUIAQUIAQUIAQUIAQUIAQUIAQUIAQUIAQUI\nAQUIAQUIAQUIAQUIAQUIAQUIAQUIAQUI\nAQUIAQUIAQUIAQUIAQUIAQUIAQUIAQUI\nAQUIAQUIAQUIAQUIAQUIAQUIAQUIAQUI")
                    # enviar mensagem de invalido
                    # colocar estado como invalid
                    # adicionar aviso??
                
                packet.setPayload(packet.decryptPayload(fernet),decode=False)
                
                if packet.calculateHash() != packet.getHash(fernet):
                    print("[INFO3] bad checksum")
                    p = Packet(socket.gethostbyname(socket.gethostname()),[],'invalidMessage')
                    mts = p.pack(fernet)
                    self.conn.sendall(mts)
        
                else:
                    a = self.users.getSecret(keyUser)
                    b = packet.getPayload()[0]
                    print(a==b)
                    if a==b:
                        self.users.add(keyUser,'authenticated',20,None)
                        p = Packet(socket.gethostbyname(socket.gethostname()),[],'successAuth')
                        mts = p.pack(fernet)
                        print("Sending:")
                        print(mts)
                        self.conn.sendall(mts)
                    else:
                        self.users.add(keyUser,'invalid',10,None)
                        p = Packet(socket.gethostbyname(socket.gethostname()),[],'invalidAuth')
                        mts = p.pack(fernet)
                        print("Sending:")
                        print(mts)
                        self.conn.sendall(mts)
        
        self.users.deauthenticateAll(self.address)
        print('deauthenticated all with address: ',end="")
        print(self.address)

def main():
    state = MIBsec()
    users = UserMIB()
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ss.bind(('',1234))
    
    cleaner = Cleaner(state,users)
    #executor.submit(cleaner.run,1,0,-10)
    t = threading.Thread(target=cleaner.run, args=(1,0,-10))
    t.start()
    keys = json.load(open('key.json'))
    
    while True:
        ss.listen()
        conn, address = ss.accept()
        clientHandler = ClientHandler(conn,address,state,users)
        t = threading.Thread(target = clientHandler.clientHandler, args=(keys,))
        t.setDaemon(True)
        t.start()
        
    
main()