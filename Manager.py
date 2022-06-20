import socket
import json
from cryptography.fernet import Fernet
from Packet import Packet
import re
from Crypter import *
import secrets

keys = json.load(open('key.json'))
fernet= Fernet(keys["key"])
k = bytes(keys["key"],'latin-1')
connectionState = {
    "secret":None,
    #"state":"authenticated"
    "state":"deauthenticated"
    # deauthenticated -> requested
    # requested : pode receber um invalid | requestAuth
    # requested -> deauthenticated (caso receba invalid)
    # requested -> 
}
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

def sendRequestAuth(s):
    # send requestAuth
    secret = secrets.token_bytes()
    connectionState['secret'] = secret
    connectionState['state'] = 'requested'
    print("secret:")
    print(secret)
    a = encrypt(k,secret+b";"+'test'.encode('latin-1'))
    print("ecrypted:")
    print(a)
    p = Packet(socket.gethostbyname(socket.gethostname()),[a],'requestAuth')
    s.sendall(p.pack(fernet))

def handleRequestAuth(s,packet):

    agentSecret = decrypt(connectionState['secret'],";".join(packet.getPayload())).split(b';')[0]
    print("recebido:")
    print(agentSecret)
    connectionState['state'] = 'finalizing'

    a = encrypt(k,agentSecret+b";test")
    print("A enviar: ")
    print(a)
    p = Packet(socket.gethostbyname(socket.gethostname()),[a],'finalizeAuth')
    s.sendall(p.pack(fernet))

    
def waitForMessage(s,messageToSend):
    message = s.recv(1024)
    packet = Packet()
    packet.decode(message,fernet)
    if packet.getType() == 'response':
        # Caso a resposta tenha ";", vai dividir por várias partes
        # juntar essas partes
        print(";".join(packet.getPayload()[:-1]))
    elif packet.getType() == 'requestAuth':
        handleRequestAuth(s,packet)
        waitForMessage(s,messageToSend)

    elif packet.getType() == 'successAuth':
        print('success auth')
        connectionState['state'] = 'authenticated'
        s.sendall(messageToSend)
        waitForMessage(s,messageToSend)
    elif packet.getType() == 'expiredAuth':
        connectionState['state'] = 'deauthenticated'
        sendRequestAuth(s)
        waitForMessage(s,messageToSend)
    elif packet.getType() == 'invalidAuth':
        print("Invalid Key. Switch the key")
        exit()


def request(s,fernet,oids):
    #oids = ['.3.3.3','1']
    #oids = ['.1.3.6.1.2.1.1.1.0']

    msg = Packet(socket.gethostbyname(socket.gethostname()),oids,'SET')
    pack = msg.pack(fernet)
    print(pack)
    if connectionState['state'] != 'authenticated':
        sendRequestAuth(s)
        waitForMessage(s,pack)
    else:
        s.sendall(pack)
        waitForMessage(s,pack)

    if connectionState['state'] != 'authenticated':
        print('ALGO ESTA MAL')
        exit()
    
def interpreter(socket,fernet):
    while r := input(':> '):
        #if a:=re.search(r'^(get)( (-s))? (\d+)$',r): # importantes: 1 3 4
        if a:=re.search(r'^(get) (\d+)$',r): # importantes: 2
            print(a.group(2))
            print(f"sending get request with id {a.group(2)} to mibsec")
            request(socket,fernet,['.3.3.3',a.group(2),'test'])
        elif a:=re.search(r'^(get) ((\.\d+)+)$',r): # importantes: 2:
                print(a.group(2))
                print(f"sending get request with oid {a.group(2)} to mib")
                request(socket,fernet,['.1.1.1',a.group(2),'test'])

        elif a:=re.search(r'^(getnext) ((\.\d+)+)$',r): # importantes: 1 3 4
            print(f"sending getnext request with id {a.group(2)} to mib")
            request(socket,fernet,['.2.2.2',a.group(2),'test'])
        elif r == 'help':
            help()
        elif r == 'exit':
            break
        else:
            print("invalid input -> see commands: 'help'")

def main():
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('localhost',1234))

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