import socket, threading
import json
from cryptography.fernet import Fernet
from Packet import Packet
from pysnmp.hlapi import *
from pysnmp.smi.rfc1902 import *
from MIBsec import MIBsec
from UserMIB import UserMIB
from concurrent.futures import ThreadPoolExecutor
from Crypter import *
import time
import secrets


class Cleaner:
    def __init__(self,mib,users):
        self.mib = mib
        self.users = users

    def run(self,t,threshold,delThreshold):
        time.sleep(t)
        #print("%d sec" % t)
        self.mib.cleanUp(t,threshold,delThreshold)
        self.users.cleanup(t,threshold,delThreshold)
        executor.submit(self.run,t,threshold,delThreshold)

executor = ThreadPoolExecutor(max_workers=1)

keys = json.load(open('key.json'))
fernet= Fernet(keys["key"])
key = bytes(keys["key"],'latin-1')
state = MIBsec()
users = UserMIB()

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


def handleSET(conn,address,packet):
    if packet.getPayload()[0] == '.3.3.3':
        # hardcoded
        print('get from mibsec')
        try:
            if (a:=state.getValue(packet.getPayload()[1])) is not None:
                p = Packet(socket.gethostbyname(socket.gethostname()),[a,'test'],'response')
                conn.sendall(p.pack(fernet))
            else:
                a = "Id invalid or no answer yet"
                p = Packet(socket.gethostbyname(socket.gethostname()),[a,'test'],'response')
                conn.sendall(p.pack(fernet))
        except Exception as e:
            print(e)
            a = 'Error'
            p = Packet(socket.gethostbyname(socket.gethostname()),[a],'response')
            conn.sendall(p.pack(fernet))
    elif packet.getPayload()[0] == '.1.1.1': # get
        key = state.add('GET',address,'default',packet.getPayload()[1],None,None,0,20,'received')
        print('received get')
        
        p = Packet(socket.gethostbyname(socket.gethostname()),['received ~ idOper='+str(key),'test'],'response')
        #conn.sendall(('received | idOper='+str(key)).encode('latin-1'))
        conn.sendall(p.pack(fernet))
        value = get(packet.getPayload()[1])
        state.updateValue(key,value,'ready')
        print('updated')
    elif packet.getPayload()[0] == '.2.2.2': # getnext
        key = state.add('GET-NEXT',address,'default',packet.getPayload()[1],None,None,0,20,'received')
        print('received - get-next')

        p = Packet(socket.gethostbyname(socket.gethostname()),['received ~ idOper='+str(key),'test'],'response')
        #conn.sendall(('received | idOper='+str(key)).encode('latin-1'))
        conn.sendall(p.pack(fernet))
        value = getNext(packet.getPayload()[1])
        state.updateValue(key,value,'ready')
        print('updated') 

def handleRequestAuth(conn,address,packet):
    # desencriptar mensagem
    # -> "secret;checksum"
    managerSecret = decrypt(key,";".join(packet.getPayload())).split(b";")[0]
    print("Recebido:")
    print(managerSecret)
    secret = secrets.token_bytes()
    users.add(address,'authenticating',None,secret)
    print("Segredo a enviar:")
    print(secret)
    # encriptar key gerada, com a key recebida ; checksum
    a = encrypt(managerSecret,secret+b";test")
    print("A enviar:")
    print(a)

    p = Packet(socket.gethostbyname(socket.gethostname()),[a],'requestAuth')
    conn.sendall(p.pack(fernet))
    

def clientHandler(conn,address):
    while message:= conn.recv(1024):

        packet = Packet()
        hash = packet.decode(message,fernet)
        #if hash != packet.getHash():
        #    print('Pacote comprometido!\nIgnorando packet ...')
        #    continue
        print("Pacote recebido:")
        packet.printaPacket()

        



        if packet.getType() == 'SET':
            # validação do packet/autenticação
            if users.isAuthenticated(address):
                handleSET(conn,address,packet)
            else:
                p = Packet(socket.gethostbyname(socket.gethostname()),[],'expiredAuth')
                conn.sendall(p.pack(fernet))
        elif packet.getType() == 'requestAuth':
            handleRequestAuth(conn,address,packet)
        elif packet.getType() == 'finalizeAuth':
            a = users.getSecret(address)
            b = decrypt(key,";".join(packet.getPayload())).split(b";")[0]
            print(a)
            print(b)
            print(a==b)
            if a==b:
                users.add(address,'authenticated',20,None)
                p = Packet(socket.gethostbyname(socket.gethostname()),[],'successAuth')
                conn.sendall(p.pack(fernet))
            else:
                users.add(address,'invalid',10,None)
                p = Packet(socket.gethostbyname(socket.gethostname()),[],'successAuth')
                conn.sendall(p.pack(fernet))

def main():

    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ss.bind(('',1234))
    
    cleaner = Cleaner(state,users)
    executor.submit(cleaner.run,1,0,-10)

    while True:
        ss.listen()
        conn, address = ss.accept()

        t = threading.Thread(target = clientHandler, args=(conn,address,))
        t.setDaemon(True)
        t.start()
        
    
        
        #ss.sendto(packet.ip_from.encode('latin-1')+b' ' + (','.join(packet.oids)).encode('latin-1'),address)

main()