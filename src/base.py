from twisted.internet.defer  import Deferred

from logger import logger

import json, traceback

class Application:
    
    def __init__(self):
        from crypto import KeyManager
        self.config = Configuration()
        self.keyManager = KeyManager()

        
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

class ConfigReader:

    def __init__(self, configFileName):
        # Open Config file
        try:
            configFile = open(configFileName, 'r')
        except IOError:
            logger.error("No such configuration file '%s'" % configFileName)
            exit(1)

        # Parse JSON file
        try:
            config = json.loads(configFile.read())
        except ValueError as e:
            logger.error("There's a problem with your config file!")
            logger.error(e.message, printTag = False)
            exit(1)
        configFile.close()

        self.config = config

class NoValue:
    pass

class Configuration:

    def __init__(self):
        self.config = {}

    def _get(self, name, default = NoValue):
        try:
            val = self.config[name]
        except KeyError:
            if default == NoValue:
                raise KeyError("Can't find '%s' in your config file" % name)
                exit(1)
            val = default
        return val

    def getInt(self, name, default = NoValue):
        val = self._get(name, default)
        try:
            return int(val)
        except ValueError:
            raise ValueError("Expected to find an int for '%s' in config file, but there was none")

    def getString(self, name, default = NoValue):
        return str(self._get(name, default))

    def getBoolean(self, name, default = NoValue):
        return self._get(name, default) == True

    def get(self, name, default = NoValue):
        return self._get(name, default)

    def populate(self, config):
        for key in config:
            self.config[key] = config[key]

    def __getitem__(self, key):
        return self._get(key)

    def __setitem__(self, key, value):
        self.config[key] = value

    def __contains__(self, key):
        return self.config.__contains__(key)

application = Application()