#!/usr/bin/env python

import simplekml
import json, os, sys, time

def databerries_to_kml(post_dump, kml_file):
  
  kml = simplekml.Kml()

  objs = json.loads(open(post_dump,'r').read())
  for obj in objs:
    lat,lon = obj['latitude'],obj['longitude']
    ts = int(obj['timestamp'])
    
    asctime = time.asctime(time.localtime(time.time()))
    kml.newpoint(name=asctime, coords=[(lon,lat)])

  kml.save(kml_file)

if __name__ == '__main__':
  databerries_to_kml(sys.argv[1], sys.argv[2])

