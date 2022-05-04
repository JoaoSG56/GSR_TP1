import socket
import json
from cryptography.fernet import Fernet
from Packet import Packet

def main():
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ss.bind(('',1234))
    keys = json.load(open('key.json'))
    fernet= Fernet(keys["key"])
    while True:
        message, address = ss.recvfrom(1024)
        packet = Packet()
        hash = packet.decode(message,fernet)
        if hash != packet.getHash():
            print('Pacote comprometido!\nIgnorando packet ...')
            continue
    
        print("Pacote recebido:")
        packet.printaPacket()
        ss.sendto(packet.ip_from.encode('latin-1')+b' ' + (','.join(packet.oids)).encode('latin-1'),address)

