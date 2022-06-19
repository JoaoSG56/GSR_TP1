import socket
import json
from cryptography.fernet import Fernet
from Packet import Packet
import re

def help():
    sb = "Commands available:\n"

    # help
    sb += "help".ljust(15)
    sb += "print help menu\n"
    
    # get
    sb += "get (oid/id)".ljust(15)
    sb += "send get request to (MIB/MIBsec)\n"

    # get mibsec
    #sb += "get -s id".ljust(15)
    #sb += "send get request to MIBsec\n"

    # get-next
    sb += "getnext oid".ljust(15)
    sb += "send get-next request to MIB\n"

    print(sb)

def request(s,fernet,oids,type):
    #oids = ['.3.3.3','1']
    #oids = ['.1.3.6.1.2.1.1.1.0']

    msg = Packet(socket.gethostbyname(socket.gethostname()),oids,type)
    pack = msg.pack(fernet)
    print(pack)
    s.sendall(pack)
    message = s.recv(1024)
    print(message)

def interpreter(socket,fernet):
    while r := input(':> '):
        #if a:=re.search(r'^(get)( (-s))? (\d+)$',r): # importantes: 1 3 4
        if a:=re.search(r'^(get) (\d+)$',r): # importantes: 2
            print(a.group(2))
            print(f"sending get request with id {a.group(2)} to mibsec")
            request(socket,fernet,['.3.3.3',a.group(2)],'0')
        elif a:=re.search(r'^(get) ((\.\d+)+)$',r): # importantes: 2:
                print(a.group(2))
                print(f"sending get request with oid {a.group(2)} to mib")
                request(socket,fernet,[a.group(2)],'0')

        elif a:=re.search(r'^(getnext) ((\.\d+)+)$',r): # importantes: 1 3 4
            print(f"sending getnext request with id {a.group(2)} to mib")
            request(socket,fernet,[a.group(2)],'1')
        elif r == 'help':
            help()
        else:
            print("invalid input -> see commands: 'help'")

def main():
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('localhost',1234))
    keys = json.load(open('key.json'))
    fernet= Fernet(keys["key"])
    help()
    interpreter(s,fernet)
    s.close()
    


    return
    # oids = ['.3.3.3','1']
    # #oids = ['.1.3.6.1.2.1.1.1.0']
    # msg = Packet('127.0.0.1',oids,'0')
    # pack = msg.pack(fernet)
    # print(pack)
    # s.sendto(pack,('127.0.0.1',1234))
    # message, address = s.recvfrom(1024)
    # s.close()
    # print(message)

main()