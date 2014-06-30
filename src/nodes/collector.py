from twisted.internet.defer     import Deferred
from twisted.internet.protocol  import ServerFactory, ClientFactory
from twisted.internet.error     import ConnectionDone
from twisted.internet           import reactor
from twisted.protocols.basic    import LineReceiver
from twisted.internet           import stdio
from secure     import SecureProtocol, SecureMessage
from base       import NetworkNode
from base       import application as app
from crypto     import SessionKeyFactory, SessionKey, KeyParser
from logger     import logger
from random     import randrange

import json

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
            index = self.factory.receivedVote(self, vote)

            reply = SecureMessage()
            reply.action = 'set-index'
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

    def sendResults(self, voteCount, index, vote):
        message = SecureMessage()
        message.action = 'announce-results'
        message['vote-count'] = voteCount
        message['your-vote'] = {
            'index': index,
            'vote': vote
        }
        message.sign()
        self.sendMessage(message)

class VoteCollectorFactory(ServerFactory):

    protocol = VoteCollectorProtocol

    def __init__(self, collector):
        self.collector = collector

    def receivedVote(self, connection, vote):
        index = self.collector.createIndex()

        logger.verbose("Vote received from client")
        logger.verbose("Index: %x" % index, False)
        logger.verbose("EncryptedVote: %s" % vote, False)

        self.collector.storeVote(connection, index, vote)

        return index

    def fail(self, reason):
        if type(reason) == str:
            logger.error(reason)
        else:
            logger.error("Error occured in authority protocol")

class AuthorityProtocol(SecureProtocol):
    
    decryptOnReceive = False
    validateSignatureOnReceive = True

    def connectionMade(self):
        logger.debug("Connection established with Authority")
        self._sendRequest()

    def messageReceived(self, message):
        encTable = message['encrypted-table']
        tableString = self.factory.collectorNode.authKey.decrypt(encTable)
        print(tableString)
        table = json.loads(tableString)

        logger.verbose("Table received from Authority")
        self.factory.collectorNode.countVotes(table)

    def _sendRequest(self):
        message = SecureMessage()

        sessionKeyFactory = SessionKeyFactory()
        sessionKey = sessionKeyFactory.createAESKey()
        self.factory.collectorNode.authKey = sessionKey

        logger.debug("Created session key for Authority connection:")
        logger.debug(sessionKey.hex(), False)

        authKey = app.keyManager.findKey("authority")
        encryptedKey = authKey.publicEncrypt(sessionKey.hex())
    
        message.action = "request-table"
        message['encrypted-session-key'] = encryptedKey
        message.sign()

        self.sendMessage(message)

class AuthorityFactory(ClientFactory):

    protocol = AuthorityProtocol

    def __init__(self, collectorNode):
        self.collectorNode = collectorNode

    def fail(self, reason):
        if type(reason) == str:
            logger.error(reason)
        else:
            logger.error("Error occured in authority protocol")

class Console(LineReceiver):
    from os import linesep as delimiter
    
    def __init__(self, collectorNode):
        self.collectorNode = collectorNode

    def lineReceived(self, line):
        if line == 'end':
            logger.info("Ending elections...")
            self.collectorNode.endElections()


class CollectorNode(NetworkNode):

    def __init__(self):
        self.votes = {}
        self.clients = []

    def createIndex(self):
        return randrange(2**32)

    def storeVote(self, connection, index, vote):
        self.clients.append({
            'connection': connection,
            'index': index,
            'vote': vote
        })
        self.votes[str(index)] = vote

    def countVotes(self, indexTable):
        logger.split()
        logger.verbose("Counting votes")

        logger.split()
        logger.info("Election Results:", False)
        logger.split()

        voteCount = {}
        for index in indexTable:
            # index = int(ind)
            key = SessionKey(int(indexTable[index], 16))
            vote = key.decrypt(self.votes[index])
            logger.special("%7s: %s" % (index, vote), False)
            if vote in voteCount:
                voteCount[vote] += 1
            else:
                voteCount[vote] = 1


        logger.split().split()

        mVote = None
        for vote in voteCount:
            if not mVote or voteCount[vote] > mVote:
                mVote = voteCount[vote]
        for vote in voteCount:
            if voteCount[vote] == mVote:
                logger.extraspecial("%5s: %s (%d)" % (vote, '#'*voteCount[vote], voteCount[vote]), False)
            else:
                logger.special("%5s: %s (%d)" % (vote, '#'*voteCount[vote], voteCount[vote]), False)

        logger.split()
        # Send results to clients
        for client in self.clients:
            client['connection'].sendResults(voteCount=voteCount, index=client['index'], vote=client['vote'])
    
    def endElections(self):
        host = app.config.get("authority-host")
        port = app.config.get("authority-port")

        factory = AuthorityFactory(self)

        logger.split()
        logger.verbose("Connecting to Authority...")
        reactor.connectTCP(host, port, factory)

    def run(self):
        factory = VoteCollectorFactory(self)
        port = reactor.listenTCP(app.config.getInt('collector-port'), factory)
        logger.verbose("Collector: Awaiting connections on %s" % port.getHost())

        stdio.StandardIO(Console(self))
        reactor.run()