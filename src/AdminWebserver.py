import zlib
from threading import Lock,Thread
import BaseHTTPServer
from SocketServer import ThreadingMixIn, TCPServer, BaseRequestHandler
import socket
import os
from Webserver import *
from Utils import *
import urlparse
import urllib2

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
    httpd = None
    try:
      httpd = server_class(server_address, self.app, handler_class, True, 'www/')
    except socket.error as e:
      self.app.log("%s Could not start ADMIN server on port %d"%(ctxt('[!]',RED),self.port))
      return
    httpd.PRE = "HTTP"
    httpd.serve_forever()
    self.app.log("[%s] ADMIN server on port %d is shutting down"%(ctxt('x',RED),self.port))

class AdminHTTPRequestHandler(HTTPRequestHandler):    
  
  def _send_json(self, obj):
    self.send_response(200)
    self.send_header('Content-Type','application/json')
    self.send_header('Cache-Control','no-cache, no-store, must-revalidate')
    self.send_header('Pragma','no-cache')
    self.send_header('Expires','0')
    self.send_header('Access-Control-Allow-Origin','*')
    self.end_headers()

    data = json.dumps(obj, ensure_ascii=False)
    try:
      self.wfile.write(data)
    except Exception as e:
      raise
    
  def _get_status(self):

    status = {}
    status['total_client_count'] = self.server.app.total_client_count
    status['probes_queue'] = self.server.app.probes_queue
    status['aps'] = {}
    for iface,ap in self.server.app.aps.iteritems():
      for iface, viface in ap.virtuals.iteritems():
        key = viface.iface
        status['aps'][key] = {}
        status['aps'][key]['ssid'] = viface.essid
        status['aps'][key]['wpa2'] = False
        status['aps'][key]['status'] = ap.status
        status['aps'][key]['count'] = len(viface.clients)
        status['aps'][key]['inactivity'] = 'unknown'
        try:
          status['aps'][key]['inactivity'] = int(time.time() - viface.activity_ts)
        except:
          pass
        status['aps'][key]['timeout'] = ap.timeout
        status['aps'][key]['clients'] = {}
        for mac,client in viface.clients.iteritems():
          c = {}
          c['services'] = client.services
          c['name'] = client.name
          c['ip'] = client.ip
          c['device'] = self.server.app.guessr.get_device(mac)
          c['ssl'] = client.ssl
          c['inactivity'] = int( time.time() - client.last_activity)
          status['aps'][key]['clients'][mac] = c
        
    self._send_json(status)

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
        self.send_response(500)
        self.end_headers()
        
  def _get_images(self):
    self.send_response(200)
    self.end_headers()
    imgs = self.server.app.db.get_images()
    data = '<html><ul>'
    for img in imgs:
      print img['service_uri']
      data += '<li><img src="%s" alt=""></li>'%img['service_uri']
    data += '</ul><html>'
    self.wfile.write(data)
    
  def _get_requests(self):
    self.send_response(200)
    self.end_headers()
    requests = self.server.app.db.get_requests('type = "GET"')
    data = '<html><ul>'
    for req in requests:
      headers = req['service_header'].split("\n")
      data += '<li>%s : <a href="/api/request/%10f">%s</a><br/>%s</li>'%(req['service_request'], req['timestamp'], req['service_uri'], '<br/>'.join(headers))
    data += '</ul><html>'
    self.wfile.write(data)
  
  def _get_request(self, id):
    self.send_response(200)
    self.end_headers()
    #TODO better id
    request = self.server.app.db.get_requests('timestamp = "%s"'%id)[0]
    req = urllib2.Request(request['service_uri'])
    for h in request['service_header'].split("\n"):
      items = h.split(":")
      key = items[0]
      value = ':'.join(items[1:])
      req.add_header(key, value)
    
    response = urllib2.urlopen(req)
    data = response.read()
    
    try:
      data = zlib.decompress(data, 16+zlib.MAX_WBITS)
    except:
      pass
    
    self.wfile.write(data)
  
  def _get_version(self):
    self._send_json({'version':self.server.app.version})

  def _query(self, query, num):

    db = self.server.app.db
    obj = db.fetch_last_requests('all',num)

    self._send_json(obj)

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

    elif args[0] == 'api':
      if len(args) == 2 and args[1] == 'query':
        if 'q' in dparams and 'n' in dparams:
          (q,),(n,) = dparams['q'],dparams['n']
          self._query(q,n)
          return
        else:
          self.send_response(400)
          self.end_headers()
          return

      elif len(args) == 2 and args[1] == 'status':
        return self._get_status()

      elif len(args) == 2 and args[1] == 'version':
        return self._get_version()
      elif len(args) == 3 and args[1] == 'request':
        return self._get_request(args[2])
      else:
        self.send_response(400)
        self.end_headers()
        return

    elif len(args) == 1 and args[0] == 'images.html':
      return self._get_images()
    elif len(args) == 1 and args[0] == 'requests.html':
      return self._get_requests()
    elif len(args) == 1 and args[0] == 'cookie.txt':
      if 'bssid' in dparams and 'host' in dparams:
        (bssid,),(host,) = dparams['bssid'], dparams['host']
        return self._get_cookie(bssid, host)
    return self._get_file(path) 
