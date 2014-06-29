from twisted.internet.defer     import Deferred
from twisted.internet.protocol  import ClientFactory
from twisted.internet.error     import ConnectionDone
from twisted.internet           import reactor
from security   import SecureProtocol, SecureMessage
from base       import NetworkNode
from base       import application as app
from logger     import logger

#### STAGE 1 ####

class CertProtocol(SecureProtocol):

    decryptOnReceive = False
    validateSignatureOnReceive = True

    def _sendKey(self):
        myKey = app.keyManager.getMyKey()
        myPublicKey = myKey.publickey()

        message = SecureMessage()
        message['public-key'] = myPublicKey.pem()

        logger.verbose("Sending Public Key to CA...")
        logger.debug(message)
        self.sendMessage(message)

    def _checkCertificate(self, cert):
        # TODO checks if any
        self.factory.certficateReceived(cert)

    def connectionMade(self):
        logger.debug("Connection Established with CA")
        self._sendKey()

    def messageReceived(self, message):
        if message['status'] == 'ok':
            if 'certificate' not in message:
                logger.warning("No certificate in received message, discarding...")
            else:
                cert = message['certificate']
                logger.verbose("Received certificate from CA")
                self.factory.certficateReceived(cert)
        else:
            logger.verbose("Public Key was not authorized by CA")
    
        self.transport.loseConnection()

    def connectionLost(self, reason):
        if reason.type == ConnectionDone:
            logger.debug("Connection with CA closed")
        else:
            self.factory.fail(reason)

class CertFactory(ClientFactory):

    protocol = CertProtocol

    def __init__(self, deffered):
        self.deffered = deffered

    def certficateReceived(self, cert):
        if self.deffered is not None:
            d, self.deffered = self.deffered, None
            d.callback(cert)

    def fail(self, reason=None):
        if type(reason) == str:
            reason = ClientError(reason)

        if self.deffered is not None:
            d, self.deffered = self.deffered, None
            d.errback(reason)


#### STAGE 2 ####

class ClientAuthProtocol(SecureProtocol):
    decryptOnReceive = True
    validateSignatureOnReceive = True

    def _sendCert(self):
        message = SecureMessage()
        message.action = 'get-session-key'
        message['certificate'] = self.factory.cert

        authKey = app.keyManager.findKey('authority')

        message.sign().encrypt(authKey)

        sendMessage(message)

    def connectionMade(self):
        logger.verbose("Connection established with Authority")

    def messageReceived(self, message):
        logger.debug("Message received from authority")

        try:
            status = message['status']
            if status != 'ok':
                return self.factory.fail("Certificate not accepted by authority")
    
            sessionKey = message['session-key']

            logger.info("Session Key received from Authority:")
            logger.info(sessionKey, False)

        except KeyError as e:
            return self.factory.fail("Malformed message received from Authority. No '%s' field" % e)            
        

    def connectionLost(self, reason):
        self.factory.fail(reason)


class ClientAuthFactor(ClientFactory):

    protocol = ClientAuthProtocol

    def __init__(self, cert, deffered=None):
        self.cert = cert
        self.deffered = deffered

    def fail(self, reason=None):
        if type(reason) == str:
            reason = ClientError(reason)

        if self.deffered is not None:
            d, self.deffered = self.deffered, None
            d.errback(reason)

class ClientNode(NetworkNode):

    # Stage 1
    def stage1(self):
        # Get Certificate
        host = app.config.get("ca-host")
        port = app.config.get("ca-port")

        d = Deferred()
        factory = CertFactory(d)
        
        logger.verbose("Connecting to CA...")
        reactor.connectTCP(host, port, factory)

        return d

    def stage1Failed(self, reason):
        logger.error("Certification failed, exiting...")
        exit(1)

    # Stage 2
    def stage2(self, cert):
        # Send Certificate
        host = app.config.get("ca-host")
        port = app.config.get("ca-port")

        d = Deferred()
        factory = ClientAuthFactory(cert, d)

        logger.verbose("Connecting to Authority...")
        reactor.connectTCP(host, port, factory)

        return d


    def run(self):
        d = self.stage1()
        d.addCallbacks(lambda x: self.stage1(x), lambda x: self.stage1Failed(x))

        reactor.run()

class ClientError(Exception):
    pass