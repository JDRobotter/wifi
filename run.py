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
import sys
sys.path.insert(0,"./impacket/")

from src.AdminWebserver import *
from src.Utils import *
from src.Karma2 import *

#CERTFILE='./certs/fullchain.pem'
#KEYFILE='./certs/privkey.pem'
#FAKE_SSL_DOMAIN="test.domai"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--gateway", help="Choose the router IP address. Example: -g 192.168.0.1")
    parser.add_argument("-m", "--monitor", help="Choose the monitor interface")
    parser.add_argument("-e", "--enable", help="Choose the monitor interface to enable")
    parser.add_argument("-a", "--hostapds", help="List of interfaces which will be used to create aps")
    parser.add_argument("-n", "--name", action="append", help="start this given essid with optional bssid ie myWifi,00:27:22:35:07:70,key")
    parser.add_argument("-w", "--wpa", action='store_true', help="start probed ap with wpa security")
    parser.add_argument("-f", "--metasploit", help="path to the metasploit console")
    parser.add_argument("-t", "--tcpdump", action='store_true', help="run tcpdump on interface")
    parser.add_argument("-o", "--offline", action='store_true', help="offline mode")
    parser.add_argument("-v", "--database", help="database path")
    parser.add_argument("-r", "--redirections", help="List of redirections (default is 80:8080,443:8080")
    parser.add_argument("-s", "--scan", action='store_true', help="run nmap on each new device")
    parser.add_argument("-x", "--management", help="deploy a management AP on this interface")
    parser.add_argument("-d", "--debug", action='store_true', help="debug mode")
    parser.add_argument("-u", "--uri", help="wifiScanMap sync uri")
    parser.add_argument("-b", "--forbidden", help="list of forBidden essid")
    parser.add_argument("-l", "--logpath", help="log path")
    parser.add_argument("-z", "--hostapd", help="hostapd binary path")
    parser.add_argument("-q", "--test", action='store_true', help="run test mode")
    parser.add_argument("-p", "--port", help="admin webserver port")
    parser.add_argument("-y", "--virtual", help="virtual interfaces count (default is one by physical device)")
    parser.add_argument('-i', '--ignore', help='ignore bssid ie. -i mac1 mac2 macN', action='append', nargs='*')
    return parser.parse_args()

if __name__ == '__main__':

  # parse command line
  args = parse_args()


  from distutils.spawn import find_executable

  CHECK_EXECUTABLES = [
    'nmap','iptables','tcpdump','dnsmasq','airmon-ng', 'smbclient',
  ]
  
  if args.hostapd is not None:
    CHECK_EXECUTABLES.append('hostapd')


  # check for executables
  do_not_run = False
  for exe in CHECK_EXECUTABLES:
    if find_executable(exe) is None:
      log( "[x] %s does not seems to be installed (and needed)"%ctxt(exe, RED))
      do_not_run = True
  if do_not_run:
    sys.exit(-1)

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
    if args.hostapds is None:
      args.hostapds = []
    else:
      args.hostapds = args.hostapds.split(',')

    forbidden = ()
    if args.forbidden is not None:
     forbidden = args.forbidden.split(',')
    args.forbidden = forbidden
    
    if args.virtual is not None:
      args.virtual = int(args.virtual)
    
    km = Karma2(args)
    
    signal.signal(signal.SIGUSR1, km.status)
    signal.signal(signal.SIGUSR2, km.status)
    
    if args.port is not None:
      km.start_adminserver(km, int(args.port))
    
    if args.offline:
      km.start_webserver(km, km.redirections[80], km.redirections[443])
      km.start_mailserver(km, km.redirections[110])
      km.start_smbserver(km, km.redirections[445])
      km.start_ftpserver(km, km.redirections[21])

    if args.name is not None:
      aps = []
      for name in args.name:
        # 24h timeout
        props = name.split(',')
        essid = props[0]
        bssid = None
        wpa = None
        
        try:
          bssid = props[1]
        except:
          pass
        
        try:
          wpa = props[2]
        except:
          pass
        
        aps.append({'bssid': bssid, 'essid': essid, 'wpa': wpa})
        
      km.create_aps(aps, 60*60*24*365)
    
    if not args.test:
      km.do_sniff()

    while True:
      if args.test:
        char_set = string.ascii_uppercase + string.digits
        aps = []
        count = 1
        if args.virtual is not None:
          count = random.randint(1,args.virtual)
        for i in range(0,count):
          essid = 'test_%s'%''.join(random.sample(char_set*6, 6))
          bssid = None
          wpa = None
          aps.append({
            'essid':essid,
            'bssid':bssid,
            'wpa':wpa
            })
        
        km.create_aps(aps, 10)
        
      time.sleep(1)

  except KeyboardInterrupt:
    pass
  finally:
    km.stop()
    if args.enable is not None:
      log( "[+] Stopping monitor interface %s properly"%args.monitor)
      cmd = ['airmon-ng','stop',args.monitor]
      p = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
      p.wait()
    if logfile is not None:
      with log_lock:
        l = logfile
        logfile = None
        l.close()

