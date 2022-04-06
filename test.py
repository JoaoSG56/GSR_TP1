import json
import hashlib
from cryptography.fernet import Fernet

keys = json.load(open('key.json'))
fernet= Fernet(keys["key"])

data = ["9232","o01ko","sutsmowd"]
ipfrom = "123.111.232.123"

ip = ipfrom.split('.')

header = bytearray(("|".join(ip)).encode('latin-1'))
divisao = "|".encode('latin-1')
for oid in data:
    header += divisao + fernet.encrypt(oid.encode('latin-1'))

s = header.decode('latin-1').split('|')

print("ip: ")
print(s[0:4])
print(s[0])
print(s[1])
print(s[2])
print(s[3])


for o in s[4:-1]:
    print(fernet.decrypt(o.encode('latin-1')).decode('latin-1'))




data = b''
# crypt = b''
for o in data:
    data += bytes(o,'utf-8') + bytes(';','utf-8')
    # crypt += fernet.encrypt(o.encode('utf-8')) + bytes(';','utf-8')
h = hashlib.md5(header+data).hexdigest()
msg = header + bytes(str(h),'utf-8') + data
# print(h)
# try:
#     print('header:')
#     print(struct.unpack("!4h", msg[0:8]))
# except Exception as e:
#     print(e)
