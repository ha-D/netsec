from twisted.protocols.basic import NetstringReceiver
from twisted.internet.defer  import Deferred

from md5     import md5
from logger  import logger
from base    import application as app

import json

class SecureProtocol(NetstringReceiver):

    def __init__(self):
        self.messageFactory = SecureMessageFactory()

    def messageReceived(self, message):
        """
        Override this
        """
        raise NotImplementedError

    def sendMessage(self, message):
        self.write(message.finalizeForSending().dump())

    def signAndSend(self, message):
        self.sendMessage(message.sign())

    def encryptAndSend(self, message):
        self.sendMessage(message.encrypt())

    def signEncryptAndSend(self, message):
        self.sendMessage(message.sign().encrypt())

    def stringReceived(self, data):
        message = self.messageFactory.buildMessage()

        try:
            message.populate(data)
        except PopulationError:
            logger.warning("Received Message discarded due to error")
            return

        # ! Remove this
        if message.encrypted:
            message.decrypt()

        if message.signed:
            d = message.validateSignature()
        else:
            d = Deferred()

        def signatureValid:
            # Call messageReceived which is to be implemented by user
            self.messageReceived(message)
        def signatureInvalid:
            logger.warning("Invalid Signature on received message, discarding...")

        d.addCallbacks(signatureValid, signatureInvalid)


class SecureMessageFactory:

    def buildMessage(self):
        return SecureMessage(self)

    def inReplyTo(self, message):
        reply = SecureMessage(self)
        reply.encryptionKey = message.senderKey
        return reply


class SecureMessage:

    def __init__(self, factory):
        self.factory = factory

        self.message = {}
        self.signed = False
        self.encrypted = False
        self.encryptionKey = None
        self.senderKey = None
        self.sender = None

    def populate(self, data):
        if type(data) == str:
            try:
                data = json.loads(data)
            except ValueError:
                logger.error("Couldn't parse JSON string:")
                logger.error(data, False)
                logger.error("Aborting SecureMessage population", False)
                raise PopulationError
        elif type(data) != dict:
            logger.error("I can't populate a message with a '%s'", type(data))
            raise PopulationError

        if 'message' not in data:
            logger.warning("No message in data, don't have anything to populate")
            return self
        if 'signed' not in data:
            logger.warning("No 'signed' field in data, assuming false")
        if 'encrypted' not in data:
            logger.warning("No 'encrypted' field in data, assuming false")
        
        self.message = data.get('message', None)
        self.signed = data.get('signed', False)
        self.encrypted = data.get('encrypted', False)

        if 'sender-key' in data:
            self.senderKey = data['sender-key']
        if 'sender' in data:
            self.sender = data['sender']
        if not self.senderKey and not self.sender:
            logger.warning("No sender or sender-ey set for populated message")

        return self

    def encrypt(self, key = None):
        if self.encrypted:
            logger.warning("You tell me to encrypt an already encrypted message, I won't!")
            return self

        # If key is None, get private key from key manager (default)
        if not key:
            if self.encryptionKey:
                key = self.encryptionKey
            else:
                logger.warning("Encrypting message with own private key, smells fishy")
                key = app.keyManager.getMyPrivateKey()

        self.message = RSAEncrypt(json.dumps(self.message), key)

        self.encryptionKey = key
        self.encrypted = True

        return self

    def decrypt(self, key = None):
        if not self.encrypted:
            logger.warning("You tell me to decrypt an already decrypted message, I won't!")
            return self

        # If key is None, get private key from key manager (default)
        if not key:
            key = app.keyManager.getMyPrivateKey()

        try:
            self.message = json.loads(RSADecrypt(self.message, key))
        except ValueError:
            raise SecureMessageError("Decrypting message leads to an invalid JSON")

        self.encryptionKey = None
        self.encrypted = False

        return self

    def sign(self):
        if signed:
            logger.warning("You tell me to sign an already signed message, I won't!")
            return self
        if encrypted:
            raise SecureMessageError("I can't sign an encrypted message, thats not how I work!")

        items = json.dumps(sorted(self.message.items()))
        key = app.keyManager.getMyPrivateKey()

        signature = RSAEncrypt(digest(items), key)
        self.message['signature'] = signature

        self.signed = True
        return self

    def unsign(self):
        if not signed:
            logger.warning("You tell me to unsign a message which is not signed, what do you want me to do?")
            return self
        if encrypted:
            raise SecureMessageError("I can't unsign an encrypted message, thats not how I work!")

        self.message.pop('signature')
        self.signed = False
        return self

    def validateSignature(self):
        if not signed:
            logger.error("How should I validate a signature when there is no signature?!")
            return False
        if encrypted:
            raise SecureMessageError("I can't validate the signature when everything is encrypted")

        if not self.sender and not self.senderKey:
            raise SecureMessageError("Can't validate signature. No sender or sender-key set on message")

        def checkSignature(key):
            signature = self.message['signature']
        
            dig1 = RSADecrypt(signature, key)

            tmpMessage = self.message.copy()
            tmpMessage.pop('signature')
            dig2 = digest(json.dumps(sorted(tmpMessage.items())))    
           
            if dig1 != dig2:
                raise SignatureError

        def keyNotFound(failure):
            logger.error("Couldn't obtain public key for '%s'" % self.sender)
            raise SignatureError
            
        if self.senderKey:
            key = self.senderKey
            d = Deffered()
            d.callback(key)
        elif self.sender:
            d = app.keyManager.findKey(self.sender)

        d.addCallbacks(checkSignature, keyNotFound)

        return d


    def finalizeForSending(self):
        serviceName = config.get("service-name")
        if not serviceName or serviceName == "client":
            self.senderKey = app.keyManager.getMyPublicKey()
        else:
            self.sender = serviceName
        return self

    def dump(self):
        data = {
            'message': self.message,
            'encrypted': self.encrypted,
            'signed': self.signed
        }

        if self.sender:
            data['sender'] = self.sender
        elif self.senderKey:
            data['sender-key'] = self.senderKey

        return json.dumps(data)

    __unicode__ = dump
    __str__ = dump

    def __getitem__(self, key):
        if encrypted:
            raise SecureMessageError("Can't read from an encrypted message")
        return message.__getitem__(key)

    def __setitem__(self, key, item):
        if encrypted:
            raise SecureMessageError("Can't write to an encrypted message")
        return message.__setitem__(key, item)

    def __delitem__(self, key):
        if encrypted:
            raise SecureMessageError("Can't delete from an encrypted message")
        return message.__delitem__(key)

    def __contains__(self, key):
        if encrypted:
            raise SecureMessageError("Can't read from an encrypted message")
        return message.__contains__(key)

    def __iter__(self):
        if encrypted:
            raise SecureMessageError("Can't iterate on an encrypted message")
        return message.__iter__()

class PopulationError(Exception):
    pass
class SecureMessageError(Exception):
    pass
class SignatureError(Exception):
    pass



# Encryption and Hashing Algorithms

def RSAEncrypt(message, key):
    return message.upper()

def RSADecrypt(message, key):
    return message.lower()

def digest(message):
    return md5(message).hexdigest()