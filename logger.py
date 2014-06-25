from termcolor import colored as color
import types

class Logger:    
    def __init__(self):
        self.tagColors = {}
        self.messageColors = {}
        pass

    def _log(self, tag, message, omit_tag):
        tagColor = self.tagColors[tag]
        messageColor = self.messageColors[tag]
        if omit_tag:
            print(' %s    %s' % (color(' ' * len(tag), tagColor), color(message, messageColor)))
        else:    
            print('%s   %s' % (color('[' + tag + ']', tagColor, attrs=['bold']), color(message, messageColor)))

    def addLevel(self, tag, tagColor="white", messageColor=None):
        if (messageColor == None):
            messageColor = tagColor
        self.tagColors[tag] = tagColor
        self.messageColors[tag] = messageColor

        func = lambda self, message, omit_tag=False: self._log(tag, message, omit_tag)
        setattr(self, tag, types.MethodType(func, self, Logger))


logger = Logger()

logger.addLevel('info', 'grey', 'white')
logger.addLevel('debug', 'yellow', 'yellow')
logger.addLevel('error', 'red', 'red')


