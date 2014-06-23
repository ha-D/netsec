from termcolor import colored as color
import types

class Logger:    
    def __init__(self):
        self.tag_colors = {}
        self.message_colors = {}
        pass

    def _log(self, tag, message, omit_tag):
        tag_color = self.tag_colors[tag]
        message_color = self.message_colors[tag]
        if omit_tag:
            print(' %s    %s' % (color(' ' * len(tag), tag_color), color(message, message_color)))
        else:    
            print('%s   %s' % (color('[' + tag + ']', tag_color, attrs=['bold']), color(message, message_color)))

    def add_level(self, tag, tag_color="white", message_color=None):
        if (message_color == None):
            message_color = tag_color
        self.tag_colors[tag] = tag_color
        self.message_colors[tag] = message_color

        func = lambda self, message, omit_tag=False: self._log(tag, message, omit_tag)
        setattr(self, tag, types.MethodType(func, self, Logger))


logger = Logger()

logger.add_level('info', 'grey', 'white')
logger.add_level('debug', 'yellow', 'yellow')
logger.add_level('error', 'red', 'red')


