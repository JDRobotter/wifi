from threading import Lock,Thread
import BaseHTTPServer
from SocketServer import ThreadingMixIn, TCPServer, BaseRequestHandler
import os
from Webserver import *
from Utils import *
import urlparse

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
    self.send_header('Access-Control-Allow-Origin','*')
    self.end_headers()
    
    status = {}
    
    for essid,ap in self.server.app.aps.iteritems():
      status[ap.ifhostapd.iface] = {}
      status[ap.ifhostapd.iface]['ssid'] = ap.essid
      status[ap.ifhostapd.iface]['wpa2'] = ap.wpa2 != None
      status[ap.ifhostapd.iface]['status'] = ap.status
      status[ap.ifhostapd.iface]['count'] = len(ap.clients)
      status[ap.ifhostapd.iface]['inactivity'] = 'unknown'
      try:
        status[ap.ifhostapd.iface]['inactivity'] = int(time.time() - ap.activity_ts)
      except:
        pass
      status[ap.ifhostapd.iface]['timeout'] = ap.timeout
      status[ap.ifhostapd.iface]['clients'] = {}
      for mac,client in ap.clients.iteritems():
        client['services'] = self.server.app.guessr.get_services(mac)
        client['dns'] = self.server.app.guessr.get_dns(mac)
        client['device'] = self.server.app.guessr.get_device(mac)
        status[ap.ifhostapd.iface]['clients'][mac] = client
        client['inactivity'] = int( time.time() - client['last_activity'])
        
    
    
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
  
  
  def _query(self, query, num):

    self.send_response(200)
    self.end_headers()

    db = self.server.app.db

    obj = db.fetch_last_requests('all',num)

    self.wfile.write(json.dumps(obj))

  def create(self, ap):
    data = json.loads(ap,strict=False)
    wpa = None
    if data.has_key('wpa') and data['wpa'] != "":
      wpa = data['wpa']
    iface = self.server.app.ifhostapds.get_one()
    self.server.app.create_ap(iface, [data['essid']], None, data['timeout'], wpa)
    
  def delete(self, ap):
    data = json.loads(ap,strict=False)
    essid = data['essid']
    self.server.app.aps[essid].timeout = 0
  
  def do_POST(self):
    path,params,args = self._parse_url()
    dparams = {} if params is None else urlparse.parse_qs(params)
    if ('..' in args) or ('.' in args):
      self.send_400()
      return
    length = int(self.headers['Content-Length'])
    post = self.rfile.read(length)
    post = post.decode('string-escape').strip('"')
    if len(args) == 1 and args[0] == 'create.json':
      return self.create(post)
    if len(args) == 1 and args[0] == 'delete.json':
      return self.delete(post)
  
  def do_GET(self):
    path,params,args = self._parse_url()
    dparams = {} if params is None else urlparse.parse_qs(params)
    if ('..' in args) or ('.' in args):
      self.send_response(400)
      self.end_headers()
      return
    if len(args) == 1 and args[0] == '':
      path = 'index.html'

    elif len(args) == 1 and args[0] == 'query.json':
      if 'q' in dparams and 'n' in dparams:
        (q,),(n,) = dparams['q'],dparams['n']
        print q,n
        self._query(q,n)
        return
      else:
        self.send_response(400)
        self.end_headers()
        return

    elif len(args) == 1 and args[0] == 'status.json':
      return self._get_status()
    elif len(args) == 1 and args[0] == 'cookie.txt':
      if 'bssid' in dparams and 'host' in dparams:
        (bssid,),(host,) = dparams['bssid'], dparams['host']
        return self._get_cookie(bssid, host)
    return self._get_file(path) 
