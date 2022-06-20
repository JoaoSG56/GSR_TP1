import secrets
from cryptography.fernet import Fernet
import json
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome import Random

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


keys = json.load(open('key.json'))
#fernet= Fernet(keys["key"])

# Manager: cria segredo, encripta segredo com key, e envia para agent
key = bytes(keys["key"],'latin-1')
s = secrets.token_bytes()
print(s)
print("\n")
print("\n")
a = encrypt(key,s)
print(a)
print("\n")
print("\n")


# agent recebe, decripta mensagem com key
b = decrypt(key,a)
print(b)
print(b == s)
# cria segredo, encripta esse segredo com b
s2 = secrets.token_bytes()
print(s2)
print("\n")
print("\n")
a2 = encrypt(b,s2)
print(a)
print("\n")
print("\n")
# envia para manager


# Manager recebe, desencripta com b
b1 = decrypt(b,a2)
print(b1)
print(b1 == s2)
# envia b1 para o agent encriptado com key
print("\n")
print("\n")
a3 = encrypt(key,b1)
print(a3)




b2 = decrypt(key,a3)
print(b2 == s2)





# a = fernet.encrypt(s)
# print(a)
# print("\n")
# print("\n")
# b = fernet.decrypt(a)
# print(b)
# print(s==b)
# print("\n")
# print("\n")
# print(len(b))
# fernet2 = Fernet(b)
# s2 = secrets.token_bytes(4)
# a2 = fernet2.encrypt(s2)
# print(a2)
# print("\n")
# print("\n")
# b2 = fernet2.decrypt(a2)







