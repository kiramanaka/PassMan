from cryptography.hazmat.primitives import hashes


class Auth:
    """
    This class is used for authentication purposes. It uses SHA3_512 and SHA3_384 hash functions from
    the cryptography library.
    """
    def __init__(self):
        """
        The constructor for Auth class. Initializes the control_hash attribute.
        """
        self.control_hash = (b"\x9e\xce\x08n\x9b\xacI\x1f\xac\\\x1d\x10F\xca\x11\xd77\xb9*+.\xbd\x93\xf0\x05\xd7\xb7"
                             b"\x10\x11\x0c\ng\x82\x88\x16n\x7f\xbeyh\x83\xa4\xf2\xe9\xb3\xca\x9fHOR\x1d\x0c\xe4d4\\"
                             b"\xc1\xae\xc9gy\x14\x9c\x14")

    def auth(self, passphrase: str) -> str or bool:
        """
        The function to authenticate the passphrase. It hashes the passphrase using SHA3_512 and compares
        it with the control_hash.

        Parameters:
            passphrase (str): The passphrase to be authenticated.

        Returns:
            str or bool: If the hashed passphrase is not equal to the control_hash, it returns False.
            Otherwise, it returns the result of the build_decrypt_key function.
        """
        digest = hashes.Hash(hashes.SHA3_512())
        digest.update(bytes(passphrase, 'UTF-8'))
        passhash = digest.finalize()
        print(passhash)
        if passhash != self.control_hash:
            return False
        else:
            return self.build_decrypt_key(passphrase)

    def build_decrypt_key(self, passphrase: str) -> bytes:
        """
        The function to build a decryption key. It hashes the passphrase using SHA3_384,
        appends the control_hash to the result, and then hashes the result using SHA3_512.

        Parameters:
            passphrase (str): The passphrase to be used to build the decryption key.

        Returns:
            str: The final decryption key.
        """
        sha384 = hashes.Hash(hashes.SHA3_384())
        sha384.update(bytes(passphrase, 'UTF-8'))
        pre_hash = sha384.finalize()
        pre_hash = pre_hash + self.control_hash
        sha512 = hashes.Hash(hashes.SHA3_512())
        sha512.update(pre_hash)
        return sha512.finalize()


run = Auth()
run.auth("test")
