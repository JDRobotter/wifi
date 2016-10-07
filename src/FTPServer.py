from threading import Lock,Thread
import BaseHTTPServer
from SocketServer import ThreadingMixIn, TCPServer, BaseRequestHandler

from Utils import *

class FTPTCPRequestHandler(BaseRequestHandler):

  def respond(self, code, explanation):
    """Send a response to the client."""
    self.request.send('%d %s\r\n' % (code, explanation))
  
  def process_request(self):
    """Parse input into a command and an argument."""
    data = self.request.recv(64)
    if data == "":
      return None
    parts = data.strip().split(' ')
    return parts.pop(0), parts
  
  def handle(self):
    client = self.client_address[0]
    self.server.app.log('FTP: Connexion')
    self.respond(220, "FTP server")
    user = ''
    password = ''
    while True:
      req = self.process_request()
      if req is None:
        break
      cmd, args = req
      if cmd == 'USER':
        user = (args and args[0] or '*missing*')
        self.respond(331, 'Please specify the password.')
      elif cmd == 'PASS':
        password = (args and args[0] or '*missing*')
        self.server.app.log_login(client, {'login': user, 'password': password, 'uri': 'ftp://??'})
        self.respond(230, 'Valid user.')
      elif cmd == 'PWD':
        self.respond(212, '/')
      elif cmd == 'TYPE':
        self.respond(215, 'UNIX')
      elif cmd == 'PASV':
        self.respond(227, 'Passive mode')
      else:
        self.server.app.log("%s %s refused, login required"%(cmd, ' '.join(args)))
        self.respond(530, 'Please login with USER and PASS.')


class FTPTCPServer(ThreadingMixIn, TCPServer):
  allow_reuse_address = True
  daemon_threads = True
  
  def __init__(self, address, handler, app):
    TCPServer.__init__(self, address, handler)
    self.app = app

class FTPServer(Thread):
  daemon=True
  def __init__(self, app, port=21):
    Thread.__init__(self)
    self.app = app
    self.port = port

  def run(self):
    self.app.log("[+] Starting FTP server on port %d"%self.port)
    set_title('ftp server %s'%self.port)
    server = FTPTCPServer(('',self.port), FTPTCPRequestHandler, self.app)
    server.serve_forever()
    self.app.log("[%s] FTP server on port %d is shutting down"%(ctxt('x',RED),self.port)) 
