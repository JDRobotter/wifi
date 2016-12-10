from threading import Lock,Thread
import BaseHTTPServer
from SocketServer import ThreadingMixIn, TCPServer, BaseRequestHandler
import os
from Webserver import *
from Utils import *

class AdminWebserver(Thread):
  daemon=True
  def __init__(self, app, port = 80, www  = 'www'):
    Thread.__init__(self)
    self.app = app
    self.port = port
    self.www_directory = www

  def run(self):
    set_title('adminserver %s'%self.port)
    self.app.log("[+] Starting ADMIN server on port %d"%self.port)
    server_class=HTTPServer
    handler_class=AdminHTTPRequestHandler
    server_address = ('', self.port)
    httpd = server_class(server_address, self.app, handler_class, True, 'www/')
    httpd.PRE = "HTTP"
    httpd.serve_forever()
    self.app.log("[%s] HTTP server on port %d is shutting down"%(ctxt('x',RED),self.port))

class AdminHTTPRequestHandler(HTTPRequestHandler):    
  
  def _get_status(self):
    self.send_response(200)
    self.end_headers()
    
    status = {}
    
    for essid,ap in self.server.app.aps.iteritems():
      status[ap.ifhostapd.iface] = {}
      status[ap.ifhostapd.iface]['ssid'] = ap.essid
      status[ap.ifhostapd.iface]['count'] = len(ap.clients)
      status[ap.ifhostapd.iface]['inactivity'] = 'unknown'
      try:
        status[ap.ifhostapd.iface]['inactivity'] = (time.time() - ap.activity_ts)
      except:
        pass
      status[ap.ifhostapd.iface]['timeout'] = ap.timeout
      status[ap.ifhostapd.iface]['clients'] = {}
      for mac,client in ap.clients.iteritems():
        client['services'] = self.server.app.guessr.get_services(mac)
        client['dns'] = self.server.app.guessr.get_dns(mac)
        status[ap.ifhostapd.iface]['clients'][mac] = client
        
    
    
    data = json.dumps(status, ensure_ascii=False)
    try:
      self.wfile.write(data.encode('latin-1'))
    except Exception as e:
      print e
      print data
  
  def _get_cookie(self, _bssid, _host):
    path = os.path.join(self.server.app.logpath, '%s_%s.cookie.txt'%(_bssid,host))
    return self._get_file(path)
  
  def _get_file(self, path):
    _path = os.path.join(self.server.www_directory,path)
    if os.path.exists(_path):
        try:
        # open asked file
            data = open(_path,'r').read()

            # send HTTP OK
            self.send_response(200)
            self.end_headers()

            # push data
            self.wfile.write(data)
        except IOError as e:
              self.send_500(str(e))
  
  def do_GET(self):
    path,params,args = self._parse_url()
    if ('..' in args) or ('.' in args):
      self.send_400()
      return
    if len(args) == 1 and args[0] == '':
      path = 'index.html'
    elif len(args) == 1 and args[0] == 'status.json':
      return self._get_status()
    elif len(args) == 1 and args[0] == 'cookie.txt':
      if params is not None:
        m = re.match(
            r"bssid=(.*)\&host=(.*)",params)
        if m is not None:
          bssid,host = m.groups()
          return self._get_cookie(bssid, host)
    return self._get_file(path) 
