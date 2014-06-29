from twisted.internet.defer     import Deferred
from twisted.internet.protocol  import ServerFactory
from twisted.internet.error     import ConnectionDone
from twisted.internet           import reactor
from security   import SecureProtocol, SecureMessage
from base       import NetworkNode
from base       import application as app
from logger     import logger

import M2Crypto as m2c

class AuthorityProtocol(SecureProtocol):
    decryptOnReceive = False
    validateSignatureOnReceive = False

    def makeConnection(self):
        logger.debug("Connection established with %s" % self.transport.getPeer())

    def messageReceived(self, message):
        if message.action == 'get-session-key':
            pass
        elif message.action == 'sth else':
            pass
        else:
            return self.factory.fail("Unrecognized action in received message: '%s'" % message.action)

    def _get_session_key(self, message):
        try:
            certificate = message['certificate']

            # Create Cert
            cert = m2c.X509.load_cert_string(certificate)
            if not self.factory.authNode.validateCert(cert):
                logger.info("Invalid Certificate received from %s" % self.transport.getPeer())
                reply = SecureMessage()
                reply['status'] = 'invalid'
            else:
                reply = SecureMessage()
                reply['status'] = 'ok'

                sessionKey = self.factory.authNode.generateSessionKey()
                reply['session-key'] = sessionKey.text()
        except KeyError as e:
            return self.factory.fail("Get-Session-Key action: no '%s' field found in message" % e)

class AuthorityFactory(ServerFactory):

    protocol = AuthorityProtocol

    def __init__(self, authNode):
        self.authNode = authNode

    def fail(self, reason):
        logger.error(reason)

class AuthorityNode(NetworkNode):
    def validateCert(self, cert):
        pass

    def generateSessionKey(self, cert):
        pass

    pass