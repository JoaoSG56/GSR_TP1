import secrets
from cryptography.fernet import Fernet
import json

keys = json.load(open('key.json'))
fernet= Fernet(keys["key"])

