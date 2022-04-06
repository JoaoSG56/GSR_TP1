import socket
from cryptography.fernet import Fernet
import json
from Packet import Packet

def main():
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ss.bind(('',1234))
    keys = json.load(open('key.json'))
    fernet= Fernet(keys["key"])
    while True:
        message, address = ss.recvfrom(1234)
        packet = Packet()
        hash = packet.decode(message,fernet)
        if hash != packet.getHash():
            print('Pacote comprometido!\nIgnorando packet ...')
            continue
    
        print("Pacote recebido:")
        packet.printaPacket()


main()