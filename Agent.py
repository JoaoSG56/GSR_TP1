import socket
import cryptography
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
        print(hash)
        print(packet.getHash())
        packet.printaPacket()


main()