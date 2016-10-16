from threading import Lock,Thread
import BaseHTTPServer
from SocketServer import ThreadingMixIn, TCPServer, BaseRequestHandler

from Utils import *

class POP3TCPRequestHandler(BaseRequestHandler):

  def handle(self):
    def w(s):
      self.request.sendall('%s\r\n'%s)

    w('+OK POP3 server ready')
    user = {'uri':'pop3://??'}
    client = self.client_address[0]
    while True:
      data = self.request.recv(1024)

      if len(data) == 0:
        break

      if data.startswith('CAPA'):
        w('+OK Capability list follows')
        w('TOP')
        w('USER')
        w('SASL CRAM-MD5')
        w('RESP-CODES')
        w('UIDL')
        w('.')
      elif data.startswith('AUTH'):
        w('-ERR not supported')
      elif data.startswith('USER'):
        w('+OK User accepted')
        user['login'] = data.split(' ')[1].strip()

      elif data.startswith('PASS'):
        w('+OK Password accepted')
        user['password'] = data.split(' ')[1].strip()
        self.server.app.log_login(client, user)

      elif data.startswith('APOP'):
        w('+OK')

      elif data.startswith('LIST'):
        w('+OK 0 messages')
        w('.')

      elif data.startswith('RETR'):
        w('+OK this is a message')
        w('.')

      elif data.startswith('UIDL'):
        w('+OK')
        w('.')

      elif data.startswith('DELE'):
        w('+OK')

      elif data.startswith('NOOP'):
        w('+OK')

      elif data.startswith('QUIT'):
        w('+OK')
        break

class POP3TCPServer(ThreadingMixIn, TCPServer):
  allow_reuse_address = True
  daemon_threads = True
  
  def __init__(self, address, handler, app):
    self.app = app
    TCPServer.__init__(self, address, handler)      

class POP3Server(Thread):
  daemon=True
  def __init__(self, app, port=110):
    Thread.__init__(self)
    self.app = app
    self.port = port

  def run(self):
    self.app.log("[+] Starting POP3 server on port %d"%self.port)
    set_title('pop3server %s'%self.port)
    server = POP3TCPServer(('',self.port), POP3TCPRequestHandler, self.app)
    server.serve_forever()
    self.app.log("[%s] POP3 server on port %d is shutting down"%(ctxt('x',RED),self.port)) 
