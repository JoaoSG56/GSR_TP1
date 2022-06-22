from threading import Lock
import sys

class MIBsec:
    def __init__(self):
        self.mib = {}
        self.lock = Lock()
        self.lastKey = '-1'

    def add(self,typeOper,idSource,idDest,oidArg,valueArg,typeArg,sizeArg,ttlOper,status):
        self.lock.acquire()
        try:
            self.lastKey = str(int(self.lastKey) + 1)
            self.mib[self.lastKey] = {
                    'typeOper':typeOper,
                    'idSource':idSource,
                    'idDest':idDest,
                    'oidArg':oidArg,
                    'valueArg':valueArg,
                    'typeArg':typeArg,
                    'sizeArg':sizeArg,
                    'ttlOper':ttlOper,
                    'status':status
                }
            return self.lastKey
        finally:
            self.lock.release()

    def get(self,idOper):
        self.lock.acquire()
        try:
            return None if str(idOper) not in self.mib or self.mib[str(idOper)]['status'] != 'ready' else self.mib[str(idOper)]
        finally:
            self.lock.release()
    def getValue(self,idOper):
        self.lock.acquire()
        try:
            if str(idOper) not in self.mib:
                return None

            return self.mib[str(idOper)]['valueArg']
        finally:
            self.lock.release()

    def updateValue(self,idOper,value,status):
        self.lock.acquire()
        try:
            if idOper in self.mib:
                self.mib[idOper]['valueArg'] = value
                self.mib[idOper]['status'] = status
                self.mib[idOper]['typeArg'] = type(value)
                self.mib[idOper]['sizeArg'] = sys.getsizeof(value)
                
                return True
            return False
        finally:
            self.lock.release()
    
    # vai a todas as entradas da mib, e reduz o ttl por <time>
    # se ttl final for estritamente menor que <threshold> então remove entrada
    def cleanUp(self,time,threshold,delThreshold):
        self.lock.acquire()
        #print("here")
        try:
            for key in self.mib:
                self.mib[key]["ttlOper"] -= time
                # Se ttl baixa de threshold mas continua acima de delthreshold
                if self.mib[key]["ttlOper"] < threshold and self.mib[key]["ttlOper"] > delThreshold and self.mib[key]['status'] != 'invalid':
                    self.mib[key]['status'] = 'invalid'
                # Se ttl iguala o delThreshold
                elif self.mib[key]['ttlOper'] == delThreshold:
                    self.mib[key]['status'] = 'deleted'
                # Se ttl baixa o delThreshold
                elif self.mib[key]['ttlOper'] < delThreshold:
                    del self.mib[key]
        finally:
            self.lock.release()