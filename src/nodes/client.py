from twisted.internet.defer     import Deferred
from twisted.internet.protocol  import ClientFactory
from twisted.internet.error     import ConnectionDone
from twisted.internet           import reactor
from security   import SecureProtocol, SecureMessage
from base       import NetworkNode
from base       import application as app
from crypto     import SessionKeyFactory, SessionKey
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

class Stage2Protocol(SecureProtocol):
    
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

            self.factory.receivedSessionKey(sessionKey)

        except KeyError as e:
            return self.factory.fail("Malformed message received from Authority. No '%s' field" % e)            
        

    def connectionLost(self, reason):
        if reason.type == ConnectionDone:
            logger.debug("Connection with Authority closed")
        else:
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


class Stage2Factory(ClientFactory):

    protocol = Stage2Protocol

    def __init__(self, cert, deffered=None):
        self.cert = cert
        self.deffered = deffered

    def receivedSessionKey(self, sessionKey):
        if self.deffered is not None:
            d, self.deffered = self.deffered, None

            keyFactory = SessionKeyFactory()
            key = keyFactory.createAESKeyFromHex(sessionKey)
            d.callback(key)

    def fail(self, reason=None):
        if type(reason) == str:
            reason = ClientError(reason)

        if self.deffered is not None:
            d, self.deffered = self.deffered, None
            d.errback(reason)

#### STAGE 3 ####

class Stage3Protocol(SecureProtocol):
    
    decryptOnReceive = True
    validateSignatureOnReceive = True

    def connectionMade(self):
        logger.debug("Connection established with Collector")
        self._sendVote()

    def messageReceived(self, message):
        logger.debug("Message received from authority")

        try:
            status = message['status']
            if status != 'ok':
                return self.factory.fail("Certificate not accepted by authority")
    
            index = message['index']

            logger.info("Index received from Collector:")
            logger.verbose(index, False)

            self.factory.receivedIndex(index)

        except KeyError as e:
            return self.factory.fail("Malformed message received from Collector. No '%s' field" % e)
        
    def _sendVote(self):
        encVote = self.factory.sessionKey.encrypt(self.factory.vote)

        logger.debug("Encrypting vote with session key:")
        logger.debug(encVote, False)
        logger.verbose("Sending encrypted vote to collector...")

        message = SecureMessage()
        message.action = "vote"
        message['vote'] = encVote
        message.sign()
        self.sendMessage(message)

    def connectionLost(self, reason):
        if reason.type == ConnectionDone:
            logger.debug("Connection with Collector closed")
        else:
            self.factory.fail(reason)


class Stage3Factory(ClientFactory):

    protocol = Stage3Protocol

    def __init__(self, sessionKey, vote, deffered=None):
        self.sessionKey = sessionKey
        self.vote = vote
        self.deffered = deffered

    def receivedIndex(self, index):
        if self.deffered is not None:
            d, self.deffered = self.deffered, None
            d.callback(index)
          
    def fail(self, reason=None):
        if type(reason) == str:
            reason = ClientError(reason)

        if self.deffered is not None:
            d, self.deffered = self.deffered, None
            d.errback(reason)

#################

class ClientNode(NetworkNode):

    def getCertificateFromCA(self):
        host = app.config.get("ca-host")
        port = app.config.get("ca-port")

        d = Deferred()
        factory = CertFactory(d)
        
        logger.verbose("Connecting to CA...")
        reactor.connectTCP(host, port, factory)
        return d

    def sendCertToAuth(self, cert):
        host = app.config.get("authority-host")
        port = app.config.get("authority-port")

        d = Deferred()
        factory = Stage2Factory(cert, d)

        logger.split()
        logger.verbose("Connecting to Authority...")
        reactor.connectTCP(host, port, factory)
        return d

    def sendVoteToCollector(self):
        logger.split()
        self.vote = vote = raw_input("Please Enter Vote Number: ")
        
        host = app.config.get("collector-host")
        port = app.config.get("collector-port")

        d = Deferred()
        factory = Stage3Factory(self.sessionKey, self.vote, d)

        logger.split()
        logger.verbose("Connecting to Collector...")
        reactor.connectTCP(host, port, factory)
        return d

    def run(self):

        def stage1():
            d = self.getCertificateFromCA()
            d.addCallbacks(stage2, stage1Failed)

        def stage1Failed(reason):
            logger.error("Certification failed, exiting...")
            exit(1)

        def stage2(cert):
            self.cert = cert
            d = self.sendCertToAuth(cert)
            d.addCallbacks(stage3, stage2Failed)

        def stage2Failed():
            logger.error("Authoritor protocol failed, exiting...")
            exit(1)

        def stage3(sessionKey):
            self.sessionKey = sessionKey
            d = self.sendVoteToCollector()


        stage1()
        reactor.run()

class ClientError(Exception):
    pass