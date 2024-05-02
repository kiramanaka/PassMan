from cryptography.fernet import Fernet
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





class DataHandlerOld:
    def __init__(self):
        self.data = []
        self.LoginData = []

    def read(self):
        try:
            with open('passwords.txt', 'r') as file:
                self.data = file.readlines()
                for line in self.data:
                    data = line.split(', ')
                    service = data[0]
                    username = data[1]
                    password = data[2]
                    uri = data[3]
                    login = LoginData(service, username, password, uri)
                    self.LoginData.append(login)
        except FileNotFoundError:
            print('No password file found')
