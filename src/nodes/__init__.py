from base       import application as app
from logger     import logger
from nodes.ca   import CAFactory

class NetworkNode:

    def run(self):
        """
        Override this
        """
        raise NotImplementedError

    def start(self):
        try:
            self.run()
        except Exception:
            logger.error(traceback.format_exc(()))
            exit(1)


class CANode(NetworkNode):
    def run(self):  
        from twisted.internet import reactor

        factory = CAFactory()
        port = reactor.listenTCP(app.config.getInt('port'), factory)
        logger.verbose("Awaiting connections on %s" % port.getHost())

        reactor.run()