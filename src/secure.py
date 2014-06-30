from twisted.protocols.basic import NetstringReceiver
from hashlib import sha1
from logger  import logger
from base    import application as app

from base64  import b64encode, b64decode
import json

class SecureProtocol(NetstringReceiver):
    decryptOnReceive = False
    validateSignatureOnReceive = True

    def messageReceived(self, message):
        """
        Override this
        """
        raise NotImplementedError

    def sendMessage(self, message):
        self.sendString(message.finalizeForSending().dump())

    def stringReceived(self, data):
        message = SecureMessage()

        try:
            message.populate(data)
        except PopulationError:
            logger.warning("Received Message discarded due to error")
            return

        if self.decryptOnReceive and message.encrypted:
            myKey = app.keyManager.getMyKey()
            message.decrypt(myKey)

        if self.validateSignatureOnReceive:
            if message.signed:
                if not message.validateSignature():
                    logger.warning("Invalid Signature on received message, discarding...")
                    return
            else:
                logger.warning("No signature found on message, discarding...")

        if logger.enabled['network']:
            logger.network("\nReceived Message:\n" + message.dump(indent = 4))
            logger.split()

        # Call messageReceived which is to be implemented by user
        self.messageReceived(message)

class SecureMessage:

    def __init__(self):
        self.message = {}
        self.signed = False
        self.sender = None
        self.action = None
        self.signature = None

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

        self.message = data.get('message', None)

        if 'sender' in data:
            self.sender = data['sender']
        else:
            logger.warning("No sender set for populated message")

        if 'action' in data:
            self.action = data['action']

        if 'signature' in data:
            self.signature = data['signature']
            self.signed = True
        else:
            self.signed = False

        return self

    def sign(self):
        if self.signed:
            logger.warning("You tell me to sign an already signed message, I won't!")
            return self

        items = json.dumps(sorted(self.message.items()))
        key = app.keyManager.getMyKey()

        signature = b64encode(RSAPrivateEncrypt(digest(items), key))
        self.signature = signature

        self.signed = True
        return self

    def unsign(self):
        if not self.signed:
            logger.warning("You tell me to unsign a message which is not signed, what do you want me to do?")
            return self

        #self.message.pop('signature')

        self.signature = None
        self.signed = False
        return self

    def validateSignature(self):
        if not self.signed:
            logger.error("How should I validate a signature when there is no signature?!")
            return False

        if not self.sender:
            raise SecureMessageError("Can't validate signature. No sender specified on message")

        try:
            key = app.keyManager.findKey(self.sender)
        except KeyError:
            logger.warning("Can't validate signature from '%s', no public key" % self.sender)
            return False

        signature = self.signature
        
        dig1 = RSAPublicEncrypt(b64decode(signature), key)

        tmpMessage = self.message.copy()
        dig2 = digest(json.dumps(sorted(tmpMessage.items())))

        return dig1 == dig2

    def finalizeForSending(self):
        serviceName = app.config.get("node-name")
        self.sender = serviceName
        return self

    def dump(self, indent=None):
        data = {
            'message': self.message
        }

        if self.sender:
            data['sender'] = self.sender
        
        if self.action:
            data['action'] = self.action

        if self.signed:
            data['signature'] = self.signature

        if indent:
            return json.dumps(data, indent=indent)
        else:
            return json.dumps(data)

    __unicode__ = dump
    __str__ = dump

    def __getitem__(self, key):
        return self.message.__getitem__(key)

    def __setitem__(self, key, item):
        return self.message.__setitem__(key, item)

    def __delitem__(self, key):
        return self.message.__delitem__(key)

    def __contains__(self, key):
        return self.message.__contains__(key)

    def __iter__(self):
        return self.message.__iter__()

class PopulationError(Exception):
    pass

class SecureMessageError(Exception):
    pass



# Encryption and Hashing Algorithms

def RSAPublicEncrypt(message, key):
    return key.publicEncrypt(message)

def RSAPrivateEncrypt(message, key):
    return key.privateEncrypt(message)

def digest(message):
    sha = sha1()
    sha.update(message)
    return sha.hexdigest()