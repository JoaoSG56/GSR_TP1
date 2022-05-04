import socket
import json
from cryptography.fernet import Fernet
from Packet import Packet
from pysnmp.hlapi import *

class MIBsec:
    def __init__(self):
        self.requests = {}

def get(oid):
    iterator = getCmd(SnmpEngine(),
                CommunityData('public'),
                UdpTransportTarget(('localhost', 161)),
                ContextData(),
                #ObjectType(ObjectIdentity('sysDescr.0'))
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))#,
                # ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0'))
                )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))

def main():
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ss.bind(('',1234))
    keys = json.load(open('key.json'))
    fernet= Fernet(keys["key"])
    while True:
        message, address = ss.recvfrom(1024)
        packet = Packet()
        hash = packet.decode(message,fernet)
        #if hash != packet.getHash():
        #    print('Pacote comprometido!\nIgnorando packet ...')
        #    continue
        for i in packet.oids:
            get(i)
    
        print("Pacote recebido:")
        packet.printaPacket()
        ss.sendto(packet.ip_from.encode('latin-1')+b' ' + (','.join(packet.oids)).encode('latin-1'),address)


main()