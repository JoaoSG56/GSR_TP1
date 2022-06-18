from cProfile import run
import socket, threading
import json
from cryptography.fernet import Fernet
from Packet import Packet
from pysnmp.hlapi import *
from pysnmp.smi.rfc1902 import *
from MIBsec import MIBsec
from concurrent.futures import ThreadPoolExecutor
import time


class Cleaner:
    def __init__(self,mib):
        self.mib = mib

    def run(self,t,threshold,delThreshold):
        time.sleep(t)
        print("%d sec" % t)
        self.mib.cleanUp(t,threshold,delThreshold)
        executor.submit(self.run,t,threshold,delThreshold)

executor = ThreadPoolExecutor(max_workers=1)




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

def clientHandler(conn,address,state,fernet):
    while message:= conn.recv(1024):

        packet = Packet()
        hash = packet.decode(message,fernet)
        #if hash != packet.getHash():
        #    print('Pacote comprometido!\nIgnorando packet ...')
        #    continue
        print("Pacote recebido:")
        packet.printaPacket()


        if packet.oids[0] == '.3.3.3':
            # hardcoded
            print('get from mibsec')
            try:
                if (a:=state.getValue(packet.oids[1])) is not None:
                    conn.sendall(a.encode('latin-1'))
                else:
                    conn.sendall("Id invalid or no answer yet".encode('latin-1'))
            except Exception as e:
                print(e)
                conn.sendall(b"Error")
        else:
            type = 'GET' if packet.type == '0' else 'GET-NEXT'
            key = state.add(type,address,'default',packet.oids[0],None,None,0,20,'received')
            print('received')
            
            conn.sendall(('received | idOper='+str(key)).encode('latin-1'))
            
            value = get(packet.oids[0]) if packet.type == '0' else getNext(packet.oids[0])
            state.updateValue(key,value,'ready')
            print('updated')
def main():

    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ss.bind(('',1234))
    keys = json.load(open('key.json'))
    fernet= Fernet(keys["key"])
    state = MIBsec()
    cleaner = Cleaner(state)
    executor.submit(cleaner.run,1,0,-10)

    while True:
        ss.listen()
        conn, address = ss.accept()

        t = threading.Thread(target = clientHandler, args=(conn,address,state,fernet,))
        t.setDaemon(True)
        t.start()
        
    
        
        #ss.sendto(packet.ip_from.encode('latin-1')+b' ' + (','.join(packet.oids)).encode('latin-1'),address)

main()