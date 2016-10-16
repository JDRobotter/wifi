from user_agents import parse as ua_parse
import re

class ServiceGuessr:
  
  def __init__(self, karma):
    self.karma = karma

  def split_params(self, params):
    kvs = {}
    if params is not None:
      for kv in params.split('&'):
        if kv is None:
          continue
        k,v = kv.split('=')
        kvs[k] = v
    return kvs

  def feed_http_request(self, client_mac, protocol, path, params, headers):
    dparams = self.split_params(params)
    if 'user-agent' in headers:
      ua_string = headers['user-agent']
      # parse UA using lib, store device intel and browser intel
      infos = ua_parse(ua_string)
      self.karma.db.new_device(client_mac,
        infos.device.brand,
        infos.device.model,
        infos.device.family)
      self.karma.db.new_service(client_mac, "browser",
        infos.browser.family,
        '.'.join([str(x) for x in infos.browser.version]),
        infos.browser.version_string)

      m = re.match("Network Info II rv:(\d\.\d\.\d)", ua_string)
      if m is not None:
        version, = m.groups()
        self.karma.db.new_service(client_mac, "app", "network-info-II", version, '')

    if 'host' in headers:
      host = headers['host']
      if host in ('portal.fb.com',):
        self.karma.db.new_service(client_mac, "app", "facebook-messenger", '', '')
      
      elif host in ('voyagessncf.sc.omtrdc.net','t.voyages-sncf.com'):

        version = headers.get('ea-appversion','')
        self.karma.db.new_service(client_mac, "app", "voyages-sncf", version, host)
 
      elif host in ('api.openweathermap.org',):
        self.karma.db.new_service(client_mac, "app", "openweathermap", '', 
          'lat:%s,lon:%s'%(dparams.get('lat','?'),dparams.get('lon','?')))

    # voyage sncf
    if path.startswith('/ext/editorial/inApp'):
      self.karma.db.new_service(client_mac, "app", "voyages-sncf", '', path)

    # WINDOWS 10 live tiles
    elif ((re.match(r'\w\w-\w\w/video/feeds',path) is not None)
      or  (re.match(r'cgtile/v1/\w\w-\w\w',path) is not None)
      or  (re.match(r'HnFService.svc/GetLiveTileMetaData',path) is not None)):
      self.karma.db.new_service(client_mac, "os", "windows10", '', '')
