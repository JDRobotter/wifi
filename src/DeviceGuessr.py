

class DeviceGuess:

  @staticmethod
  def add_if_not_none(l,x):
    if x is None:
      pass
    else:
      l.append(x)

  @staticmethod
  def return_probable(l):
    counts = {}
    for v in l:
      if v in counts:
        counts[v] += 1
      else:
        counts[v] = 1
    sort = sorted(iter(list(counts.items())), key=lambda x_y:x_y[1], reverse=True)
    return sort[0][0]

  def __init__(self, brand, model, family):
    self.brand = []
    self.model = []
    self.family = []
    self.add_if_not_none(self.brand,brand)
    self.add_if_not_none(self.model,model)
    self.add_if_not_none(self.family,family)

  def update(self, brand, model, family):
    self.add_if_not_none(self.brand,brand)
    self.add_if_not_none(self.model,model)
    self.add_if_not_none(self.family,family)

  def get_probable_brand(self):
    return self.return_probable(self.brand)

  def get_probable_family(self):
    return self.return_probable(self.family)

  def get_probable_model(self):
    return self.return_probable(self.model)

class DeviceGuessr:
  
  def __init__(self, karma):
    self.karma = karma
    self.devices = {}

  def new_hint(self, mac, brand, model, family):
    print(("NEW DEVICE HINT",mac,brand,model,family))

    # check if device already exist in base
    if not mac in self.devices:
      print("DEVICE ADDED")
      self.devices[mac] = DeviceGuess(brand,model,family)

    else:
      print("DEVICE UPDATED")
      self.devices[mac].update(brand,model,family)

  def get_device_from_mac(self, mac):
    dev = self.devices.get(mac,None)

    if dev is None:
      return {'brand':'?','model':'?','family':'?'}

    return {
      'brand': dev.get_probable_brand(),
      'model': dev.get_probable_model(),
      'family': dev.get_probable_family(),
    }

