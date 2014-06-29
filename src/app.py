from crypto import KeyManager, KeyParser
from base   import ConfigReader
from base   import application as app
from nodes  import CANode, ClientNode, AuthorityNode, CollectorNode
from logger import logger

import sys, os, inspect, argparse

nodeList = {
    'client': ClientNode,
    'ca': CANode,
    'authority': AuthorityNode,
    'collector': CollectorNode
}

acceptedOptions = [
    "private-key-file",
    "public-key-directory"
]

def parseArgs():
    parser = argparse.ArgumentParser(description="CA Server")
    parser.add_argument('-c', '--config', metavar='config', nargs='*',
                help='path to the configuration file', default=None)
    
    for opt in acceptedOptions:
        parser.add_argument('--'+opt, nargs='?', default=None)

    return parser.parse_args()

def initConfig(options):
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

    # Read extra config options
    otherOptions = dict(options._get_kwargs())
    for opt in acceptedOptions:
        uOpt = opt.replace('-', '_')
        if otherOptions[uOpt]:
            app.config[opt] = otherOptions[uOpt]

    logger.split();

def initKeys():
    # Initialize KeyManager
    keyManager = app.keyManager
    keyParser  = KeyParser()

    # Read public keys
    keyDir = app.config.get("public-key-directory")
    for f in os.listdir(keyDir):
        path = os.path.join(keyDir, f)
        name = f.replace('.pub', '')
        key = keyParser.readPublicKey(path)
        keyManager.addPublicKey(name, key)
        logger.debug("Public key for '%s' read from %s" % (name, path))

    # Read private key
    keyPath = app.config.get("private-key-file")
    key = keyParser.readPrivateKey(keyPath)
    keyManager.setMyKey(key)
    logger.debug("Private Key read from %s" % keyPath)

    logger.split()

if __name__ == "__main__":
    
    # Add project directory to sys path
    cmd_folder = os.path.realpath(os.path.abspath(os.path.split(inspect.getfile( inspect.currentframe() ))[0]))
    if cmd_folder not in sys.path:
        sys.path.insert(0, cmd_folder)

    cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"subfolder")))
    if cmd_subfolder not in sys.path:
        sys.path.insert(0, cmd_subfolder)


    def usage():
        print("Please enter one of the following network nodes to run:")
        for node in nodeList:
            print(" * " + node)
        exit(1)

    if len(sys.argv) < 2:
        usage()

    nodeName = sys.argv[1]
    if nodeName not in nodeList:
        print("No such network node '%s'" % nodeName)
        usage()

    # Remove node name from argv to prevent it being parsed later
    sys.argv.pop(1)


    options = parseArgs()
    initConfig(options)
    initKeys()

    node = nodeList[nodeName]()
    node.start()

