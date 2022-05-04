import cryptography
from cryptography.fernet import Fernet

key = Fernet.generate_key()
print(key)

file = open('key.key', 'wb') #wb = write bytes
file.write(key)
file.close()