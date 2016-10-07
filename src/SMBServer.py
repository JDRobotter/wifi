from threading import Lock,Thread
from impacket import smbserver
from Utils import *

class SMBServer(Thread):
  daemon = True
  def __init__(self, app, port):
    Thread.__init__(self)
    self.app = app
    self.port = port

  def run(self):
    import logging
    log__ = logging.getLogger('impacket')
    log__.setLevel(logging.CRITICAL)

    self.app.log("[+] Starting SMB server on port %d"%self.port)
    server = smbserver.SimpleSMBServer(listenPort=self.port)
    server.addShare("Rapport2016","/tmp","???")
    server.setSMB2Support(True)
    server.setSMBChallenge('')
    server.setLogFile('')
    def hash_cb(h,v):
      self.app.log("SMB: HASH(%s) %s"%(h,v))
    server.registerHashCallback(hash_cb)
    server.start()
    self.app.log("[%s] SMB server on port %d is shutting down"%(ctxt('x',RED),self.port)) 
