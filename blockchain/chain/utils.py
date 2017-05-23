from cryptography.fernet import Fernet, base64, InvalidSignature, InvalidToken
import hashlib
import os
import uuid
from django.contrib.auth.hashers import make_password, PBKDF2PasswordHasher, BasePasswordHasher, get_random_string


class SymmetricEncryption(object):
    """
    AES256 encryption driven through Fernet library
    """
    @staticmethod
    def generate_key():
        return Fernet.generate_key()

    @staticmethod
    def safe_encode(value):
        if type(value) is str:
            value = value.encode('utf-8')
        return base64.urlsafe_b64encode(value)

    @staticmethod
    def generate_salt(length=12):
        return get_random_string(length=length)

    @classmethod
    def build_encryption_key(cls, password_hash):
        reduced = password_hash[:32].encode('utf-8')
        return base64.urlsafe_b64encode(reduced)

    @staticmethod
    def encrypt(key, secret):
        if type(key) is bytes:
            pass
        if type(secret) is str:
            secret = secret.encode('utf-8')
        if type(secret) is not bytes:
            raise TypeError('%s: Encryption requires string or bytes' % type(secret))

        return Fernet(key).encrypt(secret)

    @staticmethod
    def decrypt(key, token):
        return Fernet(key).decrypt(token)

    @staticmethod
    def hash(key):
        return hashlib.sha512(key).hexdigest()


