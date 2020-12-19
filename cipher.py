from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.backends import default_backend

class Cipher(object):
    def __init__(self):
        self.disable()

    def enable(self, key):
        cipher = ciphers.Cipher(
            algorithms.AES(key), modes.CFB8(key), backend=default_backend())
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def disable(self):
        self.encryptor = None
        self.decryptor = None

    def encrypt(self, data):
        if self.encryptor:
            return self.encryptor.update(data)
        else:
            return data

    def decrypt(self, data):
        if self.decryptor:
            return self.decryptor.update(data)
        else:
            return data
