import logging, logging.handlers
import pprint
import json
import sys

# Use a global LogLevel to get uniform behavior across all python processes.
#LogLevel = logging.DEBUG
LogLevel = logging.INFO

# where logging info goes / where logServer.py is running.
HOST = 'localhost'
PORT = logging.handlers.DEFAULT_TCP_LOGGING_PORT

socketHandler = logging.handlers.SocketHandler(HOST, PORT)

format='%(asctime)s:%(process)d:%(threadName)s:%(levelname)s:%(name)s:%(pathname)s %(lineno)d:%(message)s'
formatter = logging.Formatter(format)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)

def getLogger(name):
    logger = logging.getLogger(name)
    logger.setLevel(LogLevel)
    #logger.addHandler(socketHandler)
    logger.addHandler(ch)

    return logger
