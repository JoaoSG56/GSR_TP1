import socket
import json
import cryptography
from cryptography.fernet import Fernet
from pysnmp import hlapi
from Packet import Packet

def main():
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    keys = json.load(open('key.json'))
    fernet= Fernet(keys["key"])
    
    oids = ['.1.2.3.32.2','.4.5.6']

    msg = Packet('127.0.0.1',oids)

    s.sendto(msg.pack(fernet),('127.0.0.1',1234))


main()