import logging 
from logging import getLogger, FileHandler, Formatter
import subprocess

class MyLogger():
  logger = getLogger("moryson logger")
  logger.setLevel(logging.DEBUG)
  
  handler = FileHandler(filename="moryson.log")
  handler.setFormatter(Formatter("%(asctime)s %(levelname)8s %(message)s"))
  
  logger.addHandler(handler)

    
  def __init__(self):
    print("init MyLogger")


  def writelog(self, arg, mode):
    if mode == "debug":
      self.logger.debug(arg)
    elif mode == "info":
      self.logger.info(arg)
    elif mode == "warn":
      self.logger.info(arg)
    elif mode == "error":
      self.logger.info(arg)
    
    #logger.info(result.stdout.decode('utf-8'))
