from threading import Lock,Thread
import os
import subprocess

from Utils import *

class SambaCrawler(Thread):
  daemon = True
  def __init__(self, app, ip, dest):
    Thread.__init__(self)
    self.app = app
    self.ip = ip
    self.dest = dest
  
  def run(self):
    set_title('SambaCrawler %s'%self.ip)
    self.app.log("Samba: crawling %s"%self.ip)
    cmd = ['smbclient','//%s/'%self.ip, '-N', '-L', self.ip]
    try:
      out = subprocess.check_output(cmd)
    except:
      self.app.log("Samba: no samba shares on %s"%self.ip)
      return
    res = re.findall("\s(.*)\sDisk",out)
    dump_path = os.path.join(self.app.logpath,"%s_%d"%(self.dest, 1000*time.time()))
    if res is not None:
      os.mkdir(dump_path)
      for share in res:
        r = share.strip()
        if not '$' in r:
          path = "%s/%s"%(dump_path,r)
          os.mkdir(path)
          self.app.log('Samba: Getting %s'%r)
          cmd = ['smbclient', '//%s/%s'%(self.ip,r),'--socket-options=\'TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072\'', '-N', '-c', '\'prompt OFF;recurse ON;cd \'/\';lcd \'%s\';mget *\''%path]
          out = subprocess.check_output(' '.join(cmd), shell=True) 
