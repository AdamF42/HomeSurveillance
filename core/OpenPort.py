import subprocess
import urllib.request
import re


def getExternalIp():
    # get the external ip
    with urllib.request.urlopen('http://whatismyip.org/homepage/') as info:
        s = info.read()
    ip = re.findall(
        '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
        s.decode("UTF-8")
        ).pop(0)
    return ip


# def getExternalIp():
#     process = subprocess.Popen(
#       [
#           "upnpc",
#           "-l"
#       ],
#       stdout=subprocess.PIPE,
#       stderr=subprocess.PIPE
#     )
#     (out, err) = process.communicate()

def openPort(internalport, internalip, routerport):
    process = subprocess.Popen(
      [
          "upnpc",
          "-a",
          internalip,
          internalport,
          routerport,
          "TCP"
      ],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE
    )
    (out, err) = process.communicate()
    # print(out)
    # print(err)
    # add error check


def closePort(routerport):
    process = subprocess.Popen(
      [
          "upnpc",
          "-d",
          routerport,
          "TCP"
      ],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE
    )
    (out, err) = process.communicate()
    # add error check
