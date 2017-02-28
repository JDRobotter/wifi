#from user_agents import parse as ua_parse
import re

from src.DeviceGuessr import DeviceGuessr

class ServiceGuessr:
  
  def __init__(self, karma):
    self.karma = karma
    self.services = {}
    self.dns = {}

    self.device_guessr = DeviceGuessr(self.karma)

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
  
  def get_dns(self, mac):
    if mac not in self.dns:
      return []
    return self.dns[mac]
  
  def get_services(self, mac):
    if mac not in self.services:
      return []
    return self.services[mac]
  
  def get_device(self, mac):
    return self.device_guessr.get_device_from_mac(mac)

  def register_service(self, client, service_type, service_name, service_version, service_extra):
    client.register_service(service_type, service_name, service_version, service_extra)

  def feed_dns_request(self, client, host):
    
    if host in ('api.gotinder.com', 'etl.tindersparks.com', 'tinder-et-tinderet-w57qp6gi4lpd-1362323731.us-east-1.elb.amazonaws.com', 'images.gotinder.com'):
      self.register_service(client, "app", "tinder", '', '')
    if host in ('candycrushjelly.king.com', 'candycrushsoda.king.com', 'candycrushsodamobile.king.com'):
      self.register_service(client, "app", "candycrush", '', '')
    
    if host in ('imap-mail.outlook.com','eas.outlook.com', 'smtp-mail.outlook.com'):
      self.register_service(client, "app", "outlook", '', '')
    
    m = re.match(r'.*orange.com$',host)
    if m is not None:
      self.register_service(client, "provider", "orange", '', '')
      return
    
    if host in ('linkedin.com'):
      self.register_service(client, "app", "linkedin", '', '')

    m = re.match(r'.*soundcloud.com$',host)
    if m is not None:
      self.register_service(client, "app", "soundcloud", '', '')
      return

    if host in ('api.leparisien.fr'):
      self.register_service(client, "app", "leparisien", '', '')
    
    if ('snapchat.com') in host:
      self.register_service(client, "app", "snapchat", '', '')  
      
    if host in ('api-cdn.lemonde.fr'):
      self.register_service(client, "app", "lemonde", '', '')
    
    if host in ('mobile-apps.guardianapis.com'):
      self.register_service(client, "app", "theguardian", '', '')
     
    if host in ('app.secure.particuliers.societegenerale.mobi'):
      self.register_service(client, "app", "societegenerale", '', '') 
    
    if host in ('ping3.teamviewer.com'):
      self.register_service(client, "app", "teamviewer", '', '')
      
    if host in ('api.deezer.com', 'live.deezer.com'):
      self.register_service(client, "app", "deezer", '', '')
      return
    
    if host in ('beacon.shazam.com',):
      self.register_service(client, "app", "shazam", '', '')
      return
    
    if host in ('apresolve.spotify.com',):
      self.register_service(client, "app", "spotify", '', '')
      return
    
    if host in ('api.blablacar.com',):
      self.register_service(client, "app", "blablacar", '', '')
    
    m = re.match(r'api.airbnb.com$',host)
    if m is not None:
      self.register_service(client, "app", "airbnb", '', '')
      return
    
    m = re.match(r'.*dropbox.com$',host)
    if m is not None:
      self.register_service(client, "app", "dropbox", '', '')
      return
    
    m = re.match(r'.*bitdefender.com',host)
    if m is not None:
      self.register_service(client, "antivirus", "bitdefender", '', '')
      return
    
    if host in ('incoming.telemetry.mozilla.org',):
      self.register_service(client, "app", "firefox", '', '')
      return

    m = re.match(r'\w.config.skype.com', host)
    if m is not None:
      self.register_service(client, "app", "skype", '', '')
      return

    m = re.match(r'.*mtalk.google.com$',host)
    if m is not None:
      self.register_service(client, "app", "gtalk", '', '')
      return

    m = re.match(r'imap.gmail.com', host)
    if m is not None:
      self.register_service(client, "app", "imap-gmail", '', '')
      return

    m = re.match(r'imap.aol.com', host)
    if m is not None:
      self.register_service(client, "app", "imap-aol", '', '')
      return

    m = re.match(r'skydrive.wns.windows.com', host)
    if m is not None:
      self.register_service(client, "app", "skydrive", '', '')

    m = re.match(r'\w+.whatsapp.net', host)
    if m is not None:
      self.register_service(client, "app", "whatsapp", '', '')
      return

    if host in ('portal.fb.com',):
      self.register_service(client, "app", "facebook", '', '')
      return

    if host in ('graph.instagram.com','i.instagram.com'):
      self.register_service(client, "app", "instagram", '', '')
      return

    if host in ('dailymotion-mobile-compute.appspot.com',):
      self.register_service(client, "app", "dailymotion", '', '')
      return

    if host in ('tts.waze.com',):
      self.register_service(client, "app", "waze", '', '')
      return

  def feed_http_request(self, client, protocol, path, params, headers):
    dparams = self.split_params(params)
    if 'user-agent' in headers:
      ua_string = headers['user-agent']
      # parse UA using lib, store device intel and browser intel
      infos = None
      print("Not implemented")
      #infos = ua_parse(ua_string)
      
      if infos is not None:
        if infos.device.brand is not None and infos.device.model is not None:
          self.device_guessr.new_hint(client.bssid,
            infos.device.brand,
            infos.device.model,
            infos.device.family)

        self.register_service(client, "browser",
          infos.browser.family,
          '.'.join([str(x) for x in infos.browser.version]),
          infos.browser.version_string)

      m = re.match("Network Info II rv:(\d\.\d\.\d)", ua_string)
      if m is not None:
        version, = m.groups()
        self.register_service(client, "app", "network-info-II", version, '')

      m = re.match("Skype WISPr", ua_string)
      if m is not None:
        self.register_service(client, "app", "skype", '', '')

    if 'host' in headers:
      host = headers['host']
      if host in ('portal.fb.com',):
        self.register_service(client, "app", "facebook-messenger", '', '')
      
      elif host in ('voyagessncf.sc.omtrdc.net','t.voyages-sncf.com'):

        version = headers.get('ea-appversion','')
        self.register_service(client, "app", "voyages-sncf", version, host)
 
      elif host in ('api.openweathermap.org',):
        self.register_service(client, "app", "openweathermap", '', 
          'lat:%s,lon:%s'%(dparams.get('lat','?'),dparams.get('lon','?')))

      elif host in ('www.msftconnecttest.com','ipv6.msftconnecttest.com'):
        self.register_service(client, "os", "windows", "", "")

      elif host in ('ctldl.windowsupdate.com',):
        self.register_service(client, "os", "windows-update", '', '')
        return

      elif host in ('tts.waze.com',):
        self.register_service(client, "app", "waze", '', '')
        return
      
      elif host in ('dnsproxy.ff.avast.com',):
        self.register_service(client, "app", "avast", '', '')
        return

    # voyage sncf
    if path.startswith('ext/editorial/inApp'):
      self.register_service(client, "app", "voyages-sncf", '', path)

    # WINDOWS 10 live tiles
    elif ((re.match(r'\w\w-\w\w/video/feeds',path) is not None)
      or  (re.match(r'cgtile/v1/\w\w-\w\w',path) is not None)
      or  (re.match(r'HnFService.svc/GetLiveTileMetaData',path) is not None)):
      self.register_service(client, "os", "windows10", '', '')
