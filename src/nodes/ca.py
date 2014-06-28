from twisted.internet           import defer
from twisted.internet.protocol  import Protocol, ServerFactory
from M2Crypto.X509              import X509, FORMAT_PEM, load_cert_string

from security   import SecureProtocol, SecureMessage
from base       import ConfigReader
from base       import application as app
from logger     import logger

import M2Crypto as m2c

import os.path
import time

class CertificateService:
    def createCertificate(self, publicKey):
        cert = m2c.X509.X509()
        
        keyBuffer = m2c.BIO.MemoryBuffer(publicKey)
        key = m2c.RSA.load_pub_key_bio(keyBuffer)

        cert.set_pubkeys(key)

        # Set time
        cur_time = m2.ASN1.ASN1_UTCTIME()
        cur_time.set_time(int(time.time()) - 60*60*24)
        expire_time = m2.ASN1.ASN1_UTCTIME()
        expire_time.set_time(int(time.time()) + 3 * 60 * 60 * 24)
        cert.set_not_before(cur_time)
        cert.set_not_after(expire_time)

        # Sign
        myKey = m2c.RSA.load_key_string(app.keyManager.getMyKey().pem)
        cert.sign(myKey, md="sha1")

        return cert


class CAProtocol(SecureProtocol):
    decryptOnReceive = False
    validateSignatureOnReceive = False

    def connectionMade(self):
        peer = self.transport.getPeer()
        logger.debug("<%s:%s> Connection established" % (peer.host, peer.port))

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        logger.debug("<%s:%s> Connection Lost" % (peer.host, peer.port))

    def messageReceived(self, message):
        peer = self.transport.getPeer()
        logger.debug("<%s:%s> Message Received:" % (peer.host, peer.port))
        logger.debug(message, False)

        myKey = app.keyManager.getMyKey()
        if message.encrypted:
            logger.warning("Received an encrypted message, I wan't expecting messages to be encrypted but I'll proceed...")
            message.decrypt(myKey)

        if 'public-key' not in message:
            logger.warning("Faulty message received: no public-key found. Discarding...")
            return

        publicKey = message['public-key']
        cert = self.factory.cert.createCertificate(publicKey)

        logger.info("Certificate created for client <%s:%s>" % (peer.host, peer.port))
        logger.verbose(cert.as_text())

        reply = SecureMessage()
        reply['certificate'] = cert.as_pem()
        reply.sign()

        sendMessage(reply)


class CAFactory(ServerFactory):
    protocol = CAProtocol

    def __init__(self):
        cert = CertificateService()

