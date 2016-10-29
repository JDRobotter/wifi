from user_agents import parse as ua_parse
import re

class ServiceGuessr:
  
  def __init__(self, karma):
    self.karma = karma

  def split_params(self, params):
    kvs = {}
    if params is not None:
      try:
        for kv in params.split('&'):
          if kv is None:
            continue
          k,v = kv.split('=')
          kvs[k] = v
      except:
        pass
    return kvs

  def feed_dns_request(self, client_mac, host):
    if host in ('apresolve.spotify.com',):
      self.karma.db.new_service(client_mac, "app", "spotify", '', '')
      return
    
    if host in ('incoming.telemetry.mozilla.org',):
      self.karma.db.new_service(client_mac, "app", "firefox", '', '')
      return

    m = re.match(r'\w.config.skype.com', host)
    if m is not None:
      self.karma.db.new_service(client_mac, "app", "skype", '', '')
      return

    m = re.match(r'\w\+-mtalk.google.com',host)
    if m is not None:
      self.karma.db.new_service(client_mac, "app", "gtalk", '', '')
      return

    m = re.match(r'imap.gmail.com', host)
    if m is not None:
      self.karma.db.new_service(client_mac, "app", "imap-gmail", '', '')
      return

    m = re.match(r'imap.aol.com', host)
    if m is not None:
      self.karma.db.new_service(client_mac, "app", "imap-aol", '', '')
      return

    m = re.match(r'skydrive.wns.windows.com', host)
    if m is not None:
      self.karma.db.new_service(client_mac, "app", "skydrive", '', '')

    m = re.match(r'\w\+.whatsapp.net', host)
    if m is not None:
      self.karma.db.new_service(client_mac, "app", "whatsapp", '', '')
      return

    if host in ('portal.fb.com',):
      self.karma.db.new_service(client_mac, "app", "facebook", '', '')
      return

    if host in ('graph.instagram.com','i.instagram.com'):
      self.karma.db.new_service(client_mac, "app", "instagram", '', '')
      return

    if host in ('dailymotion-mobile-compute.appspot.com',):
      self.karma.db.new_service(client_mac, "app", "dailymotion", '', '')
      return

  def feed_http_request(self, client_mac, protocol, path, params, headers):
    dparams = self.split_params(params)
    if 'user-agent' in headers:
      ua_string = headers['user-agent']
      # parse UA using lib, store device intel and browser intel
      infos = ua_parse(ua_string)

      if infos.device.brand is not None and infos.device.model is not None:
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

      m = re.match("Skype WISPr", ua_string)
      if m is not None:
        self.karma.db.new_service(client_mac, "app", "skype", '', '')

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
    if path.startswith('ext/editorial/inApp'):
      self.karma.db.new_service(client_mac, "app", "voyages-sncf", '', path)

    # WINDOWS 10 live tiles
    elif ((re.match(r'\w\w-\w\w/video/feeds',path) is not None)
      or  (re.match(r'cgtile/v1/\w\w-\w\w',path) is not None)
      or  (re.match(r'HnFService.svc/GetLiveTileMetaData',path) is not None)):
      self.karma.db.new_service(client_mac, "os", "windows10", '', '')
