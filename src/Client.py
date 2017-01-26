import time
from Utils import *

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
    
    self.app.log("[+] %s associated to %s"%(ctxt(bssid,GREEN), ctxt(self.vif.essid, GREEN)))
    
    self.app.db.new_ap_connection(vif.bssid, vif.essid, bssid)
    if ip != '':
      self.connected(ip, name)
  
  def ping(self):
    self.last_activity = time.time()
    
  def get_interface(self):
    return self.vif
  
  def log_login(self, user):
    self.app.log('[+] %s %s login: %s, password: %s, uri: %s'%(ctxt('[*]', RED), ctxt(client_ap, GREEN), ctxt(user['login'], RED),ctxt(user['password'], RED), ctxt(user['uri'], RED)))
    self.db.new_client_credentials(user['login'], user['password'], user['uri'], bssid)
    
  def register_post(self, uri, path):
    self.posts.append({
      'timestamp': time.time(),
      'uri':uri,
      'path':path
      })
    self.app.log("[+] %s post request to %s saved"%(self.bssid, ctxt(uri, GREEN)))
  
  def register_cookie(self, host, path):
    if not self.cookies.has_key(host):
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
    
  def connected(self, ip, name):
    self.ip = ip
    self.name = name
    self.app.log( "[+] %s (%s) %s connected"%(self.bssid, ctxt(self.ip, GREEN), self.name))
    self.db.new_dhcp_lease(self.bssid, ip, name)
  
  def disconnected(self):
    self.app.log( "[-] %s (%s) %s disconnected"%(self.bssid, ctxt(self.ip, GREEN), self.name))
    