from twisted.internet.defer     import Deferred
from twisted.internet.protocol  import ServerFactory
from twisted.internet.error     import ConnectionDone
from twisted.internet           import reactor
from security   import SecureProtocol, SecureMessage
from base       import NetworkNode
from base       import application as app
from crypto     import SessionKeyFactory, SessionKey, KeyParser
from logger     import logger

import M2Crypto as m2c
import json

class AuthorityProtocol(SecureProtocol):
    decryptOnReceive = False
    validateSignatureOnReceive = False

    def connectionMade(self):
        logger.debug("Connection established with %s" % self.transport.getPeer())

    def messageReceived(self, message):
        logger.verbose("Message with action '%s' received from %s" % (message.action, message.sender))

        if message.action == 'get-session-key':
            self._getSessionKey(message)
        elif message.action == 'set-index':
            self._setIndex(message)
        else:
            return self.factory.fail("Unrecognized action in received message: '%s'" % message.action)

    def connectionLost(self, reason):
        if reason.type == ConnectionDone:
            logger.debug("Connection with Collector closed")
        else:
            self.factory.fail(reason)
            
    def _getSessionKey(self, message):
        try:
            certificate = message['certificate']
            logger.debug(certificate)

            # Create Cert

            # This is not working
            #cert = m2c.X509.load_cert_string(certificate)
            # Stupid hack to get it working
            tmp = open('.tmp.cert', 'w')
            tmp.write(certificate)
            tmp.close()
            cert = m2c.X509.load_cert('.tmp.cert')

            if not self.factory.authNode.validateCert(cert):
                logger.info("Invalid Certificate received from %s" % self.transport.getPeer())
                reply = SecureMessage()
                reply['status'] = 'invalid'
            else:
                logger.verbose("Certificate validated")
                reply = SecureMessage()
                reply['status'] = 'ok'

                sessionKey = self.factory.authNode.generateSessionKey(cert)

                logger.debug("Generated session key '%s'" % sessionKey.hex())
                logger.verbose("Sending session key to client..")
                reply['session-key'] = sessionKey.hex()

            publicKeyPem = cert.get_pubkey().get_rsa().as_pem()
            keyParser = KeyParser()
            publicKey = keyParser.parsePemPublic(publicKeyPem)
            reply.sign().encrypt(publicKey)
            self.sendMessage(reply)

        except KeyError as e:
            return self.factory.fail("Get-Session-Key no: '%s' field found in message" % e)

    def _setIndex(self, message):
        try:
            encPair = message['pair']
            cert = message['certificate']
            try:
                sessionKey = self.factory.authNode.sessionKeys[cert]
            except KeyError:
                return self.factory.fail("Requested to set index for an unregistered certificate")
            
            pairString = sessionKey.decrypt(encPair)

            try:
                pair = json.loads(pairString)
            except:
                logger.warning("Invalid JSON as cert/index pair, discarding message...")
                return

            if pair['certificate'] != cert:
                logger.warning("Encrypted certificate doesn't match client's certificte, discarding message...")
                return

            logger.info("Index set for client")
            logger.verbose("Index: %s" % pair['index'], False)
            logger.verbose("Session Key: %s" % sessionKey.hex(), False)

            self.factory.authNode.indices[cert] = pair['index']
        except KeyError as e:
            return self.factory.fail("Get-Session-Key no: '%s' field found in message" % e)

class AuthorityFactory(ServerFactory):

    protocol = AuthorityProtocol

    def __init__(self, authNode):
        self.authNode = authNode

    def fail(self, reason):
        if type(reason) == str:
            logger.error(reason)
        else:
            logger.error("Error occured in authority protocol")

class AuthorityNode(NetworkNode):

    def __init__(self):
        self.sessionKeys = {}
        self.indices = {}

    def validateCert(self, cert):
        caKey = app.keyManager.findKey('ca')

        # Stupid hack to get it working
        # Shouldn't really be using blocking IO here
        tmp = open('.tmp.pub', 'w')
        tmp.write(caKey.pem())
        tmp.close()
        key = m2c.RSA.load_pub_key('.tmp.pub')

        evpKey = m2c.EVP.PKey()
        evpKey.assign_rsa(key)
        
        return cert.verify(evpKey) == 1

    def generateSessionKey(self, cert):
        if cert in self.sessionKeys:
            raise AuthorityError("Duplicate Certificate, session key for certificate already exists")
        
        # Generate and store session key
        keyFactory = SessionKeyFactory()
        key = keyFactory.createAESKey()
        self.sessionKeys[cert.as_pem()] = key

        return key

    def run(self):
        factory = AuthorityFactory(self)
        port = reactor.listenTCP(app.config.getInt('authority-port'), factory)
        logger.verbose("Authority: Awaiting connections on %s" % port.getHost())

        reactor.run()
    
class AuthorityError(Exception):
    pass