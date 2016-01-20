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
      print "[+] Creating AP %s"%essid
      iface,airbase_process = self.create_access_point(essid)
      subnet = self.karma.get_unique_subnet()
      print "[+] Uping iface %s w/ subnet %s"%(iface,subnet)
      self.setup_iface(iface,subnet)
      print "[+] Starting dhcp server %s %s"%(iface,subnet)
      dhcpd_process = self.start_dhcpd(iface,subnet)

    def start_dhcpd(self, iface, subnet):
      # create a temporary file
      #dnsmasq -d -i eth0 -ieth0 -F 192.168.1.10,192.168.1.200
      cmd = ['dnsmasq',
        '-d',
        '-i', iface,
        '-F', '192.168.%d.100,192.168.%d.200'%(subnet,subnet),
      ]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      return p

    def setup_iface(self, iface, subnet):
      iprange = "192.168.%d.254/24"%subnet
      cmd = ["ifconfig",iface,iprange]
      p = subprocess.Popen(cmd)
      p.wait()

    def create_access_point(self, essid):
      cmd = ["airbase-ng",
        "--essid", "%s"%essid,
        "-c","4",
        self.karma.ifap]
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE)

      while True:
        line = p.stdout.readline()
        m = re.match(r".*Created tap interface (\w+)",line)
        if m is not None:
          iface, = m.groups()
          return iface,p

  def __init__(self, ifmon, ifap):
    self.ifmon = ifmon
    self.ifap = ifap
    self.aps = {}
    self.subnets = set(xrange(50,256)) 

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
  km = Karma2('mon0','mon0')

  #km.do_sniff()
  Karma2.AccessPoint(km,"000XYZ")

  while True:
    time.sleep(1)
