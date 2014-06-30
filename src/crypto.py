from Crypto.PublicKey   import RSA
from logger             import logger
from random             import randrange

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
        if type(val) == str or type(val) == unicode:
            return "%x" % pow(int(val, 16), self.e, self.n)
        else:
            return pow(val, self.e, self.n)

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
        if type(val) == str or type(val) == unicode:
            return "%x" % pow(int(val, 16), self.e, self.n)
        else:
            return pow(val, self.e, self.n)

    def privateEncrypt(self, val):
        if type(val) == str or type(val) == unicode:
            return "%x" % pow(int(val, 16), self.d, self.n)
        else:
            return pow(val, self.d, self.n)

    def pem(self):
        return self._pem

    def publickey(self):
        key = self.rsaKey.publickey()
        return RSAPublicKey(key, key.exportKey())

class SessionKeyFactory:

    def createAESKey(self, key=None):
        if key == None:
            key = randrange(2**128)
        return SessionKey(key)

    def createAESKeyFromHex(slef, val):
        key = int(val, 16)
        return SessionKey(key)

class SessionKey:

    def __init__(self, key):
        self.key = key

    def encrypt(self, val):
        return val

    def decrypt(self, val):
        return val

    def hex(self):
        return "%x" % self.key
        