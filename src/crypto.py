from Crypto.PublicKey   import RSA
from logger     import logger

class RSAError(Exception):
    pass

class KeyManager:
    
    def __init__(self):
        self.myPrivateKey = None
        self.publicKeys = {}

    def getMyKey(self):
        if not self.myPrivateKey:
            raise KeyError("Private key accessed before being set")
        return self.myPrivateKey
    
    def setMyKey(self, key):
        self.myPrivateKey = key

    def addPublicKey(self, who, key):
        self.publicKeys[who] = key

    def findKey(self, who):
        if who not in self.publicKeys:
            raise KeyError("No public key found for '%s'" % name)
        return self.publicKeys[who]

class KeyParser:

    def readPublicKey(self, fileName):
        try:
            f = open(fileName, 'r')
        except IOError:
            logger.error("Public Key file not found at '%s'" % fileName)
            exit(1)

        pem = f.read()
        return self.parsePemPublic(pem)

    def readPrivateKey(self, fileName):
        try:
            f = open(fileName, 'r')
        except IOError:
            logger.error("Private Key file not found at '%s'" % fileName)
            exit(1)

        pem = f.read()
        return self.parsePemPrivate(pem)

    def parsePemPublic(self, pem):
        key = RSA.importKey(pem)
        return RSAPublicKey(key, pem)

    def parsePemPrivate(self, pem):
        key = RSA.importKey(pem)
        return RSAPrivateKey(key, pem)        

class RSAPublicKey:

    def __init__(self, rsaKey, pem):
        self.rsaKey = rsaKey
        self._pem = pem
        self.e = self.rsaKey.e
        self.n = self.rsaKey.n

    def publicEncrypt(self, val):
        return self.rsaKey.encrypt(val, str)[0]

    def privateEncrypt(self, val):
        raise RSAError("Can't private encrypt with a public key")

    def pem(self):
        return self._pem

class RSAPrivateKey:

    def __init__(self, rsaKey, pem):
        self.rsaKey = rsaKey
        self._pem = pem
        self.e = self.rsaKey.e
        self.n = self.rsaKey.n
        self.d = self.rsaKey.d


    def publicEncrypt(self, val):
        return self.rsaKey.encrypt(val, str)[0]

    def privateEncrypt(self, val):
        return self.rsaKey.decrypt(val)

    def pem(self):
        return self._pem

    def publickey(self):
        key = self.rsaKey.publickey()
        return RSAPublicKey(key, key.exportKey())

class SessionKey:

    def text():
        pass