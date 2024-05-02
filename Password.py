import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Authutils import Auth


class LoginData:
    def __init__(self, service: str, username: str, password: str, uri: str) -> None:
        """
        Constructs all the necessary attributes for the login data object.

        Parameters
        ----------
            service : str
                service for the login
            username : str
                username for the login
            password : str
                password for the login
            uri : str
                uri for the login
        """
        self.username = username
        self.password = password
        self.service = service
        self.uri = uri


class DataHandler:
    """
    A class to handle data.

    Attributes
    ----------
    auth : Auth
        an Auth object to handle authentication
    key : str
        key for encryption and decryption
    passlist : list
        list to store login data
    """
    def __init__(self) -> None:
        """
        Constructs all the necessary attributes for the data handler object.
        """
        self.auth = Auth()
        self.key = None
        self.passlist = []

    def authenticate(self, passphrase) -> bool:
        """
        Authenticates the passphrase and decrypts the vault file if it exists.

        Parameters
        ----------
            passphrase : str
                passphrase for authentication

        Returns
        -------
            bool
                True if authentication is successful, False otherwise
        """
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
        key = base64.urlsafe_b64encode(key_derivative.derive(auth))
        print(key)
        self.key = Fernet(key)
        try:
            with open('vault.crypt', 'rb') as file:
                content = self.key.decrypt(file.read()).decode("utf-8")
                for line in content.split("⁘"):
                    if not line:
                        break
                    data = line.split('⁖')
                    service = data[0]
                    username = data[1]
                    password = data[2]
                    uri = data[3]
                    login = LoginData(service, username, password, uri)
                    self.passlist.append(login)

        except FileNotFoundError:
            print('No Vault found, a new one will be created when you create a new entry.')
        return True

    def search(self, search_term: str, search_by_uri: bool) -> []:
        """
        Searches for the login data by service or uri.

        Parameters
        ----------
            search_term : str
                term to search by
            search_by_uri : bool
                if True, search by uri, else search by service

        Returns
        -------
            list of login data that matches the search term
        """
        results = []
        if search_by_uri:
            for entry in self.passlist:
                if search_term == entry.uri:
                    results.append(entry)
        else:
            for entry in self.passlist:
                if search_term == entry.service:
                    results.append(entry)
        return results

    def save(self) -> None:
        """
        Encrypts and saves the login data to the vault file.
        """
        print("save called")
        content = ""
        for entry in self.passlist:
            line = f"{entry.service}⁖{entry.username}⁖{entry.password}⁖{entry.uri}⁘"
            content = content + line
        raw = bytes(content, "UTF-8")
        encrypted = self.key.encrypt(raw)
        with open('vault.crypt', 'wb') as file:
            file.write(encrypted)

    def get_all(self) -> []:
        """
        Returns all the login data.

        Returns
        -------
            list
                list of all login data
        """
        return self.passlist

    def drop_entry(self, delete: object) -> None:
        """
        Deletes a login data entry.

        Parameters
        ----------
            delete : object
                login data object to delete
        """
        index = 0
        for entry in self.passlist:
            if delete == entry:
                self.passlist.pop(index)
                break
            index += 1

    def create_new(self, service: str, username: str, password: str, uri: str) -> None:
        """
        Creates a new login data and adds it to the list, which is sorted by service.

        Parameters
        ----------
            service : str
                service for the login
            username : str
                username for the login
            password : str
                password for the login
            uri : str
                uri for the login
        """
        login = LoginData(service, username, password, uri)
        self.passlist.append(login)
        self.passlist.sort(key=lambda entry: entry.service)


run = DataHandler()
run.authenticate("test")
"""
run.create_new("testservice", "testuser", "testpassword", "https://www.test.com")
run.create_new("exampleservice", "exampleuser", "examplepassword", "https://www.example.com")
run.save()
"""
print("done")
