from termcolor import colored as color
import types

class Logger:    
    def __init__(self):
        self.tagColors = {}
        self.messageColors = {}
        self.maxTagSize = 0
        self.splitted = True

    def _log(self, tag, message, printTag):
        tagColor = self.tagColors[tag]
        messageColor = self.messageColors[tag]
        spaceCount = self.maxTagSize - len(tag)
        if printTag:
            print('%s %s %s' % (color('[' + tag + ']', tagColor), ' ' * spaceCount, color(message, messageColor, attrs=['bold'])))
        else:    
            print(' %s  %s %s' % (color(' ' * len(tag), tagColor), ' ' * spaceCount, color(message, messageColor, attrs=['bold'])))
        self.splitted = False

    def addLevel(self, tag, tagColor="white", messageColor=None):
        if (messageColor == None):
            messageColor = tagColor
        self.tagColors[tag] = tagColor
        self.messageColors[tag] = messageColor

        if len(tag) > self.maxTagSize:
            self.maxTagSize = len(tag)

        func = lambda self, message, printTag=True: self._log(tag, message, printTag)
        setattr(self, tag, types.MethodType(func, self, Logger))

    def split(self):
        if not self.splitted:
            print('')
            self.splitted = True


logger = Logger()

logger.addLevel('info', 'green', 'green')
logger.addLevel('verbose', 'green', 'green')
logger.addLevel('debug', 'blue', 'blue')
logger.addLevel('warning', 'yellow', 'yellow')
logger.addLevel('error', 'red', 'red')


