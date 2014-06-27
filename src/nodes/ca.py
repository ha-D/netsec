from twisted.internet           import defer
from twisted.internet.protocol  import Protocol, ServerFactory

from security   import SecureProtocol, SecureMessage, SecureMessageFactory
from base       import ConfigReader, NetworkNode, KeyManager
from base       import application as app
from logger     import logger

import argparse
import os.path

def parse_args():
    parser = argparse.ArgumentParser(description="CA Server")
    parser.add_argument('-c', '--config', metavar='config', nargs='*',
                help='path to the configuration file', default=None)
    parser.add_argument('args', nargs = argparse.REMAINDER)

    return parser.parse_args()

class CAProtocol(SecureProtocol):

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



class CAFactory(ServerFactory):
    protocol = CAProtocol

class CAServer(NetworkNode):
    
    def run(self):
        options = parse_args()

        # Read configurations from file
        configFiles = options.config
        if not configFiles and os.path.isfile('config.json'):
            configFiles = ['config.json']
        if not configFiles:
            logger.warning("Couldn't find any configuration files")
        else:
            for configFile in configFiles:
                logger.info("Reading configurations from '%s'" % configFile)
                configReader = ConfigReader(configFile)
                app.config.populate(configReader.config)

        # Read configurations from args
        for key in options.args:
            print(key)

        # Setup and run the reactor
        from twisted.internet import reactor

        factory = CAFactory()
        port = reactor.listenTCP(app.config.getInt('port'), factory)
        logger.verbose("Awaiting connections on %s" % port.getHost())

        reactor.run()