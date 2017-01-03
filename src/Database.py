import sqlite3, os, time
from threading import Thread
from Queue import Queue

class ClientsDatabase(Thread):
  daemon = True

  def __init__(self, app):
    Thread.__init__(self)
    self.events_queue = Queue()
    self.app = app

  def run(self):
    p = 'clients.db'

    # --
    # create database
    self.conn = None
    if not os.path.exists(p):
      self.conn = sqlite3.connect(p)
      self.conn.text_factory = str

      c = self.conn.cursor()
      # create tables
      c.execute("""CREATE TABLE ap_connections
                (date TEXT,
                  timestamp INTEGER,
                  ap_bssid TEXT,
                  ap_essid TEXT,
                  client_mac TEXT
                  )""")
      # 
      c.execute("""CREATE TABLE dhcp_leases
                (date TEXT,
                  timestamp INTEGER,
                  client_mac TEXT,
                  client_ip TEXT,
                  client_name TEXT
                  )""")
      #
      c.execute("""CREATE TABLE client_credentials
                  (date TEXT,
                    timestamp INTEGER,
                    service_login TEXT,
                    service_password TEXT,
                    service_uri TEXT,
                    client_mac TEXT
                    )""")
      #
      c.execute("""CREATE TABLE service_request
        (date TEXT,
          timestamp INTEGER,
          client_mac TEXT,
          protocol TEXT,
          type TEXT,
          uri TEXT,
          params TEXT,
          header TEXT,
          was_faked INTEGER
          )""")
      
      #
      c.execute("""CREATE TABLE client_services
        (date TEXT,
          timestamp INTEGER,
          client_mac TEXT,
          service_type TEXT,
          service_name TEXT,
          service_version TEXT,
          service_extra TEXT
          )""")

      #
      c.execute("""CREATE TABLE client_devices
        (date TEXT,
          timestamp INTEGER,
          client_mac TEXT,
          device_vendor TEXT,
          device_model TEXT,
          device_extra TEXT
          )""")

      self.conn.commit()
    else:
      self.conn = sqlite3.connect(p)
      self.conn.text_factory = str

    # --
    # let's roll
    while True:

      action,table,values,outqueue = self.events_queue.get()

      try:
        if action == 'insert':

          c = self.conn.cursor()
          query = "INSERT INTO %s VALUES (%s)"%(table,','.join(['?' for v in values]))
          c.execute(query,values)
          self.conn.commit()

        elif action == 'fetch':
          
          _where,_orderby,_limit = values

          def _ef(fmt,s):
            if s is None:
              return ''
            else:
              return fmt%s

          where = _ef("WHERE %s",_where)
          orderby = _ef("ORDER BY %s",_orderby)
          limit = _ef("LIMIT %s",_limit)

          c = self.conn.cursor()
          query = "SELECT * FROM %s"%' '.join((table,where,orderby,limit))
          print query
          c.execute(query)
          
          # push results into queue
          outqueue.put([row for row in c])

        else:
          pass
      except Exception as e:
        self.app.log("Database: %s"%e)

        if outqueue is not None:
          outqueue.put(None)

  def get_timestamp(self):
    return time.time()

  def get_date(self):
    return time.asctime()

  def insert_values(self, table, values):
    self.events_queue.put(('insert',table,[('' if v is None else v) for v in values],None))

  def fetch_last_requests(self, rtype, num):
    queue = Queue()
    where = None
    if rtype == 'all':
      where = None 
    self.events_queue.put(('fetch','service_request',[where,"timestamp desc",num],queue))

    vs = queue.get(block=True,timeout=None)

    header = ('date','timestamp','client_mac','service_name','service_request','service_uri','service_params','service_header','was_faked')
    
    if vs is None:
      vs = [[] for h in header]

    return [dict(zip(header,v)) for v in vs]

  def new_ap_connection(self, ap_bssid, ap_essid, client_mac):
    self.insert_values('ap_connections', (
        self.get_date(),
        self.get_timestamp(), 
        ap_bssid,
        ap_essid,
        client_mac))

  def new_dhcp_lease(self, client_mac, client_ip, client_name):
    self.insert_values('dhcp_leases', (
      self.get_date(),
      self.get_timestamp(), 
      client_mac,
      client_ip,
      client_name))

  def new_client_credentials(self, service_login, service_password, service_uri, client_mac):
    self.insert_values('client_credentials', (
      self.get_date(),
      self.get_timestamp(),
      service_login,
      service_password,
      service_uri,
      client_mac))
  
  def new_service_request(self, 
    client_mac,
    service_name,
    service_request,
    service_uri,
    service_params,
    service_header,
    was_faked):

    self.insert_values('service_request', (
      self.get_date(),
      self.get_timestamp(),
      client_mac,
      service_name,
      service_request,
      service_uri,
      service_params,
      service_header,
      1 if was_faked else 0))

  def new_service(self, client_mac, service_type, service_name, service_version, service_extra):
     self.insert_values('client_services', (
      self.get_date(),
      self.get_timestamp(),
      client_mac,
      service_type,
      service_name,
      service_version,
      service_extra))

  def new_device(self, client_mac, device_vendor, device_model, device_extra):
    self.insert_values('client_devices', (
      self.get_date(),
      self.get_timestamp(),
      client_mac,
      device_vendor,
      device_model,
      device_extra))

