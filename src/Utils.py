import os, random
import re
import subprocess

DEFAULT = '\033[49m\033[39m'
RED = '\033[91m'
BRED = '\033[101m'
DRED = '\033[107m\033[41m'
BLUE = '\033[94m'
DBLUE = '\033[107m\033[44m'
GREEN = '\033[92m'
DGREEN = '\033[107m\033[42m'
YELLOW = '\033[93m'
GREY = '\033[90m'

def ctxt(txt,color):
  return ''.join((color,txt,DEFAULT))


try:
  from prctl import set_name as prctl_set_name
  from prctl import get_name as prctl_get_name
except ImportError:
  prctl_set_name = lambda x:None
  prctl_get_name = lambda :""

def set_title(name):
  """ Set the process name shown in ps, proc, or /proc/self/cmdline """
  prctl_set_name(name)

def get_title():
  """ Get the process name shown in ps, proc or /proc/self/cmdline """
  return prctl_get_name()


class LineReader(object):

  def __init__(self, fd):
    self._fd = fd
    self._buf = ''

  def fileno(self):
    return self._fd

  def readlines(self):
    data = os.read(self._fd, 4096).decode('utf-8')
    if not data:
        # EOF
        return []
    self._buf += data
    if '\n' not in data:
        return []
    tmp = self._buf.split('\n')
    lines, self._buf = tmp[:-1], tmp[-1]
    return lines
  
  
class WLANInterface:
  def __init__(self, iface):
    self.iface = iface
    # iw list | grep "valid interface combinations"
    self.available_ap = self.get_availables_ap()
    self.available = True
    #iw dev wl00e1b0103951 info
    #iw phy phy3 info

  def get_availables_ap(self):
    command = ['iw', 'dev', self.iface, 'info']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()
    (stdoutdata, stderrdata) = process.communicate();
    lines = stdoutdata.splitlines()
    phy = None
    for line in lines:
      line = line.decode("utf8")
      m = re.match('.*wiphy (\d+).*', line)
      if m is not None:
        phy = m.groups()
        break
    if phy is not None:
      command = ['iw', 'phy', 'phy%s'%phy,'info']
      process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      process.wait()
      (stdoutdata, stderrdata) = process.communicate();
      lines = stdoutdata.splitlines()
      parse = False
      for line in lines:
        line = line.decode("utf8")
        if(line.find('valid interface combinations')!=-1):
          parse = True
        if parse:
          m = re.match('.*\*\s.*AP.*=\s(\d+).*', line)
          if m is not None:
            return int(m.groups()[0])
      return 1
          

  def str(self):
    return self.iface

class WLANInterfaces:
  def __init__(self, ifs):
    self.ifs = [WLANInterface(_if) for _if in ifs]

  def get_one(self):
    ifs = [iface for iface in self.ifs if iface.available]

    if len(ifs) == 0:
      return None

    iface = random.choice(ifs)

    iface.available = False
    return iface

  def free_one(self, _iface):
    for iface in self.ifs:
      if iface.iface == _iface.iface:
        iface.available = True
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
  
  def range_null(self):
    return "%s/24"%(self.base%0)
