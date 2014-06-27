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
    parser.add_argument('config', metavar='Config', nargs='?',
                help='path to the configuration file', default=None)
    parser.add_argument('args', nargs = argparse.REMAINDER)

    return parser.parse_args()

class CertifyProtocol(SecureProtocol):

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



class CertifyFactory(ServerFactory):
    protocol = CertifyProtocol


class ValidationProtocol(SecureProtocol):

    def messageReceived(self, message):
        pass

class ValidationFactory(ServerFactory):
    protocol = ValidationProtocol
    
class CAServer(NetworkNode):
    
    def run(self):
        options = parse_args()

        # Read configurations from file
        configFile = options.config
        if not configFile and os.path.isfile('config.json'):
                configFile = 'config.json'
        if not configFile:
            logger.warning("Can't find the configuration file, please specify path")
        else:
            logger.info("Reading configurations from '%s'" % configFile)
            configReader = ConfigReader(configFile)
            app.config.populate(configReader.config)

        # Read configurations from args
        for key in options.args:
            print(key)

        # Add service name to configurations
        app.config['service-name'] = 'ca'


        # Setup and run the reactor
        from twisted.internet import reactor

        factory = CertifyFactory()
        port = reactor.listenTCP(app.config.getInt('ca-client-port'), factory)
        logger.verbose("Awaiting client connections on %s" % port.getHost())

        factory = ValidationFactory()
        port = reactor.listenTCP(app.config.getInt('ca-authority-port'), factory)
        logger.verbose("Awaiting authority connections on %s" % port.getHost())

        reactor.run()