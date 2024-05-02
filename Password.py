import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Authutils import Auth


class LoginData:
    def __init__(self, service, username, password, uri):
        self.username = username
        self.password = password
        self.service = service
        self.uri = uri


class DataHandler:
    def __init__(self) -> None:
        self.auth = Auth()
        self.key = None
        self.passlist = []

    def auth(self, passphrase: str) -> bool:
        auth = self.auth.auth(passphrase)
        if not auth:
            return False
        salt = b'A\xbe\xf0\xe1\x12\x1b\x02\xcd\x1b\xd7\x87K\xd7\x10_\x8a'
        key_derivative = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(key_derivative.derive(passphrase))
        print(key)
        self.key = Fernet(key)
        try:
            with open('vault.crypt', 'rb') as file:
                raw = file.read()
                content = self.key.decrypt(raw)
                content = content.decode("utf-8")
                for line in content.split("µ"):
                    data = line.split('§')
                    service = data[0]
                    username = data[1]
                    password = data[2]
                    uri = data[3]
                    login = LoginData(service, username, password, uri)
                    self.passlist.append(login)

        except FileNotFoundError:
            print('No Vault found, a new one will be created when you create a new entry.')
        return True
