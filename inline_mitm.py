import mitmproxy

from mitmproxy.models import decoded
import json

def response(context, flow):

  with decoded(flow.response):
    if flow.request.pretty_host == 'api.openweathermap.org':
      obj = json.loads(flow.response.content)

      if flow.request.path.startswith("/data/2.5/weather"):
        obj["weather"][0]['id'] = '901'
        obj["weather"][0]['icon'] = '11d'
        obj["main"]["temp"] = -273.15
        obj["main"]["description"] = "On est foutus"

        obj["name"] = "\\_o<"
      elif flow.request.path.startswith("/data/2.5/forecast"):
        for e in obj['list']:
          e['clouds'] = 100
          e['temp'] = {"min": -20, "max": -10, "eve": -10, "morn": -20, "night": -15, "day": -10}
          e['weather'][0]['id'] = "901"
          e['weather'][0]['icon'] = "11d"

      flow.response.content = json.dumps(obj)


  flow.reply()
