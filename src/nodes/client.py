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

    def connectionMade(self):
        logger.info("Connection established with Authority")
        self._sendCert()

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

    def _sendCert(self):
        message = SecureMessage()
        message.action = 'get-session-key'
        message['certificate'] = self.factory.cert


        message.sign()
        
        #authKey = app.keyManager.findKey('authority')
        #message.encrypt(authKey)

        logger.debug("Sending certficate to authority")
        self.sendMessage(message)


class ClientAuthFactory(ClientFactory):

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

    def getCertificateFromCA(self):
        host = app.config.get("ca-host")
        port = app.config.get("ca-port")

        d = Deferred()
        factory = CertFactory(d)
        
        logger.verbose("Connecting to CA...")
        reactor.connectTCP(host, port, factory)

        return d

    def getCertificateFailed(self, reason):
        logger.error("Certification failed, exiting...")
        exit(1)

    def sendCertToAuth(self, cert):
        host = app.config.get("authority-host")
        port = app.config.get("authority-port")

        d = Deferred()
        factory = ClientAuthFactory(cert, d)

        logger.split()
        logger.verbose("Connecting to Authority...")
        reactor.connectTCP(host, port, factory)

        return d


    def run(self):

        def stage1():
            d = self.getCertificateFromCA()
            d.addCallbacks(stage2, stage1Failed)

        def stage1Failed(reason):
            self.getCertificateFailed(reason)

        def stage2(result):
            self.sendCertToAuth(result)

        def stage2Failed():
            pass

        stage1()

        reactor.run()

class ClientError(Exception):
    pass