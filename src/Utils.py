import os, random

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
    data = os.read(self._fd, 4096)
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
    self.available_ap = 2
    self.available = True

  def str(self):
    return self.iface

class WLANInterfaces:
  def __init__(self, ifs):
    self.ifs = [WLANInterface(_if) for _if in ifs]

  def get_one(self):
    ifs = filter(lambda iface:iface.available, self.ifs)

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
