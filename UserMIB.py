from threading import Lock

class UserMIB:
    def __init__(self):
        self.mib = {}
        self.lock = Lock()

    def add(self,address, state, ttl, secret=None):
        self.lock.acquire()
        try:
            self.mib[address] = {
                    'state':state, # authenticated, expired, authenticating, invalid
                    'ttl': ttl, # ttl em segundos da conexão
                    'secret':secret
                }
        finally:
            self.lock.release()

    def authenticate(self,address,ttl):
        self.lock.acquire()
        try:
            if address in self.mib:
                self.mib[address]['state'] = True
                self.mib[address]['ttl'] = ttl
            else:
                return False
        finally:
            self.lock.release()

    def getSecret(self,address):
        self.lock.acquire()
        try:
            if address in self.mib:
                return self.mib[address]['secret']
            else:
                return None
        finally:
            self.lock.release()


    def isAuthenticated(self,address):
        self.lock.acquire()
        try:
            print("[DEBUG] " + self.mib[address]['state'] + " " + str(self.mib[address]['ttl']))
            return False if address not in self.mib else self.mib[address]['state']=='authenticated'
        finally:
            self.lock.release()
        
    # vai a todas as entradas da mib, e reduz o ttl por <time>
    # se ttl final for estritamente menor que <threshold> então coloca estado como expirado
    # se abaixo de delThreshold, elimina entrada para libertar espaço
    def cleanUp(self,time,threshold,delThreshold):
        self.lock.acquire()
        #print("cleaning upp..")
        try:
            for key in self.mib:
                self.mib[key]["ttl"] -= time
                # Se ttl baixa de threshold mas continua acima de delthreshold
                if self.mib[key]["ttl"] < threshold and self.mib[key]["ttl"] > delThreshold and self.mib[key]['state'] != 'expired':
                    self.mib[key]['state'] = 'expired'
                # Se ttl baixa o delThreshold
                elif self.mib[key]['ttl'] < delThreshold:
                    del self.mib[key]
        finally:
            self.lock.release()