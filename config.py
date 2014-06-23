from logger import logger

import json

class ConfigReader:
    def __init__(self, config_file_name):
        # Open Config file
        try:
            config_file = open(config_file_name, 'r')
        except IOError:
            logger.error("Can't find this file of yours: %s" % config_file_name)
            exit(1)

        # Parse JSON file
        try:
            config = json.loads(config_file.read())
        except ValueError as e:
            logger.error("There's a problem with your config file, fix it!")
            logger.error(e.message, omit_tag = True)
            exit(1)
            
        config_file.close()

        self.config = config

    def _get(self, name, required = False):
        try:
            val = self.config[name]
        except KeyError:
            if required:
                logger.error("Can't find '%s' in your config file" % name)
                exit(1)
            else:
                logger.debug("Can't find '%s' in your config file" % name)
                val = None
        return val

    def get_int(self, name, required = False):
        val = self._get(name, required)
        try:
            return int(val)
        except ValueError:
            logger.error("Expected to find an int for '%s' in config file, but there ain't no int, is there?!")
            exit(1)

    def get_string(self, name, required = False):
        return str(self._get(name, required))

    def get_boolean(self, name, required = False):
        return self._get(name, required) == True

    def get(self, name, required = False):
        return self._get(name, required)