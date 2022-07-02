import socket
import json
from cryptography.fernet import Fernet
from Packet import Packet
import re
import sys
#from Crypter import *
#import secrets


#k = bytes(keys["key"],'latin-1')
connectionState = {
    "secret":None,
    #"state":"authenticated"
    "state":"deauthenticated"
    # deauthenticated -> requested
    # requested : pode receber um invalid | requestAuth
    # requested -> deauthenticated (caso receba invalid)
    # requested -> 
}
class Manager:
    def __init__(self,user,fernet,s):
        self.user = user
        self.fernet = fernet
        self.socket = s
    def help(self):
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

    def sendRequestAuth(self):
        # send requestAuth
        #secret = secrets.token_bytes()
        secret = Fernet.generate_key()
        connectionState['secret'] = secret
        connectionState['state'] = 'requested'
        print("secret created by sendRequestAuth:")
        print(secret)
        #a = encrypt(k,secret+b";"+'test'.encode('latin-1'))

        p = Packet(self.user,secret,'requestAuth')
        
        mts = p.pack(self.fernet)
        # print("sending:")
        # print(mts)
        self.socket.sendall(mts)

    def handleRequestAuth(self,packet):
        secretFernet = Fernet(connectionState['secret'])
        agentSecret = packet.decryptPayload(secretFernet)[0]
        connectionState['state'] = 'finalizing'


        p = Packet(self.user,agentSecret,'finalizeAuth')
        self.socket.sendall(p.pack(self.fernet))

        
    def waitForMessage(self,messageToSend):
        message = self.socket.recv(1024)
        packet = Packet()
        packet.decode(message)
        if packet.getType() == 'response':
            # Caso a resposta tenha ";", vai dividir por várias partes
            # juntar essas partes
            originmessage = ""
            for i in packet.decryptPayload(self.fernet):
                originmessage += i.decode('latin-1') + ";"

            print(originmessage[:-1])
        elif packet.getType() == 'requestAuth':
            self.handleRequestAuth(packet)
            self.waitForMessage(messageToSend)

        elif packet.getType() == 'successAuth':
            print('success auth')
            connectionState['state'] = 'authenticated'
            
            self.socket.sendall(messageToSend)
            print("sended")
            print(messageToSend)
            self.waitForMessage(messageToSend)
        elif packet.getType() == 'expiredAuth':
            connectionState['state'] = 'deauthenticated'
            self.sendRequestAuth()
            self.waitForMessage(messageToSend)
        elif packet.getType() == 'invalidAuth':
            print("Invalid Key. Switch the key")
            exit()
        elif packet.getType() == 'invalidMessage':
            print("[WARNING] BAD CHECKSUM")
            print("keep trying?? ...")
            exit()
            #s.sendall(messageToSend)
            #waitForMessage(s,messageToSend)


    def request(self,oids):
        #oids = ['.3.3.3','1']
        #oids = ['.1.3.6.1.2.1.1.1.0']

        msg = Packet('test',oids,'SET')
        pack = msg.pack(self.fernet)
        #print(pack)
        if connectionState['state'] != 'authenticated':
            self.sendRequestAuth()
            self.waitForMessage(pack)
        else:
            self.socket.sendall(pack)
            self.waitForMessage(pack)

        if connectionState['state'] != 'authenticated':
            print('ALGO ESTA MAL')
            exit()
        
    def interpreter(self):
        while r := input(':> '):
            #if a:=re.search(r'^(get)( (-s))? (\d+)$',r): # importantes: 1 3 4
            if a:=re.search(r'^(get) (\d+)$',r): # importantes: 2
                #print(a.group(2))
                print(f"sending get request with id {a.group(2)} to mibsec")
                self.request(['.3.3.3',a.group(2)])
            elif a:=re.search(r'^(get) ((\.\d+)+)$',r): # importantes: 2:
                    #print(a.group(2))
                    print(f"sending get request with oid {a.group(2)} to mib")
                    self.request(['.1.1.1',a.group(2)])

            elif a:=re.search(r'^(getnext) ((\.\d+)+)$',r): # importantes: 1 3 4
                print(f"sending getnext request with id {a.group(2)} to mib")
                self.request(['.2.2.2',a.group(2)])
            elif r == 'help':
                help()
            elif r == 'exit':
                break
            else:
                print("invalid input -> see commands: 'help'")

def main():
    if len(sys.argv) != 4:
        return
    user = sys.argv[1]
    ip = sys.argv[2]
    port = int(sys.argv[3])

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,port))
    
    keys = json.load(open('key.json'))
    if user not in keys:
        print('User invalid')
        return
    fernet= Fernet(keys[user])
    
    manager = Manager(user,fernet,s)
    manager.help()
    manager.interpreter()
    s.close()
    
    # oids = ['.3.3.3','1']
    # #oids = ['.1.3.6.1.2.1.1.1.0']
    # msg = Packet('127.0.0.1',oids,'0')
    # pack = msg.pack(fernet)
    # print(pack)
    # s.sendto(pack,('127.0.0.1',1234))
    # message, address = s.recvfrom(1024)
    # s.close()
    # print(message)

if __name__ == '__main__':
    main()