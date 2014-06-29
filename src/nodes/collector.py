from twisted.internet.defer     import Deferred
from twisted.internet.protocol  import ServerFactory
from twisted.internet.error     import ConnectionDone
from twisted.internet           import reactor
from security   import SecureProtocol, SecureMessage
from base       import NetworkNode
from base       import application as app
from crypto     import SessionKeyFactory, SessionKey, KeyParser
from logger     import logger
from random     import randrange


class VoteCollectorProtocol(SecureProtocol):
    
    decryptOnReceive = False
    validateSignatureOnReceive = False

    def connectionMade(self):
        logger.split()
        logger.debug("Connection established with client %s" % self.transport.getPeer())

    def messageReceived(self, message):
        logger.debug("Message received from client")
        try:
            vote = message['vote']
            index = self.factory.receivedVote(vote)

            reply = SecureMessage()
            reply['status'] = 'ok'
            reply['index'] = index
            reply.sign()

            logger.debug("Sending index to client")
            self.sendMessage(reply)
        except KeyError as e:
            return self.factory.fail("Malformed message received from client. No '%s' field" % e)

    def connectionLost(self, reason):
        if reason.type == ConnectionDone:
            logger.debug("Client connection closed")
        else:
            self.factory.fail(reason)

class VoteCollectorFactory(ServerFactory):

    protocol = VoteCollectorProtocol

    def __init__(self, collector):
        self.collector = collector

    def receivedVote(self, vote):
        index = self.collector.createIndex()

        logger.verbose("Vote received from client")
        logger.verbose("Index: %x" % index, False)
        logger.verbose("EncryptedVote: %s" % vote, False)

        self.collector.storeVote(index, vote)

        return index

class CollectorNode(NetworkNode):

    def __init__(self):
        self.votes = {}

    def createIndex(self):
        return randrange(2**32)

    def storeVote(self, index, vote):
        self.votes[index] = vote

    def run(self):
        factory = VoteCollectorFactory(self)
        port = reactor.listenTCP(app.config.getInt('collector-port'), factory)
        logger.verbose("Collector: Awaiting connections on %s" % port.getHost())
        reactor.run()