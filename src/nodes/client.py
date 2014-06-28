from twisted.internet.defer     import Deferred
from twisted.internet.protocol  import ClientFactory
from twisted.internet.error     import ConnectionDone
from twisted.internet           import reactor
from security   import SecureProtocol, SecureMessage
from base      import NetworkNode
from base       import application as app
from logger     import logger

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
        logger.debug("Successfully connected to CA")
        self._sendKey()

    def messageReceived(self, message):
        if message['status'] == 'ok':
            if 'certificate' not in message:
                logger.warning("No certificate in received message, discarding...")
                return
            cert = message['certificate']
        else:
            logger.verbose("Public Key was not authorized by CA")
            return
        logger.verbose("Received certificate from CA")

    def connectionLost(self, reason):
        if reason.type == ConnectionDone:
            logger.debug("Connection with CA closed")
        else:
            logger.warning("Connection with CA unexpectedly closed")
            logger.warning(reason, False)


class CertFactory(ClientFactory):

    protocol = CertProtocol

    def __init__(self, deffered):
        self.deffered = deffered

    def certficateReceived(self, cert):
        self.deffered.callback(cert)


class ClientNode(NetworkNode):

    def getCertificate(self):
        host = app.config.get("ca-host")
        port = app.config.get("ca-port")

        d = Deferred()
        factory = CertFactory(d)
        reactor.connectTCP(host, port, factory)

        return d

    def run(self):
        d = self.getCertificate()

        reactor.run()