#! /usr/bin/python
"""
    Code from https://gist.github.com/toolness/3073310

    Before using this script, you'll need to create a private
    key and certificate file using OpenSSL. Create the ca.key
    file with:

        openssl genrsa -des3 -out ca.key 4096

    Then, create the ca.crt file with:

        openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

    Put those files in the same directory as this script.

    Finally, edit the values in this script's OPENSSL_CONFIG_TEMPLATE
    variable to taste.
"""
import json
import os
# import sys
import hashlib
import subprocess
import datetime
from shutil import copyfile

# import configparser

STUNNEL_CORE_GLOBAL_CONFIG_TEMPLATE = """
; ************************************************
; * Global options *
;*************************************************
; Debugging stuff (may useful for troubleshooting)
debug = 7
output = stunnel.log
; *************************************************
; * Single Cam options *
;**************************************************
"""

STUNNEL_CORE_CONFIG_TEMPLATE = """
[%(Cam)s]
key = %(absolute)s/%(Cam)s.key
cert = %(absolute)s/%(Cam)s.cert
client = yes
accept = %(outport)s
connect = %(camaddr)s:%(inport)s
"""

STUNNEL_CAM_CONFIG_TEMPLATE = """
[%(Cam)s]
key = %(Cam)s.key
cert = %(Cam)s.cert
CAfile = ca.crt
client = no
debug = 7
verify = 2
accept = %(inport)s
connect = %(camaddr)s:8080
"""

OPENSSL_CONFIG_TEMPLATE = """
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C                      = IT
ST                     = ER
L                      = Bologna
O                      = Toolness
OU                     = Experimental Software Authority
CN                     = %(domain)s
emailAddress           = sample@example.it

[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = %(domain)s
DNS.2 = *.%(domain)s
"""

MYDIR = os.path.abspath(os.path.dirname(__file__))
OPENSSL = '/usr/bin/openssl'
KEY_SIZE = 1024
DAYS = 3650
CA_CERT = 'ca.crt'
CA_KEY = 'ca.key'

# Extra X509 args. Consider using e.g. ('-passin', 'pass:blah') if your
# CA password is 'blah'. For more information, see:
#
# http://www.openssl.org/docs/apps/openssl.html#PASS_PHRASE_ARGUMENTS
X509_EXTRA_ARGS = ()


def openssl(*args):
    cmdline = [OPENSSL] + list(args)
    subprocess.check_call(cmdline)


def gencert(domain, name, rootdir=MYDIR, keysize=KEY_SIZE, days=DAYS,
            ca_cert=CA_CERT, ca_key=CA_KEY):
    def dfile(ext):
        return os.path.join(name, '%s.%s' % (name, ext))

    os.chdir(rootdir)
    # Check if the Cam# directory already exists
    os.makedirs(name, exist_ok=True)
    # Check if the certificates exists, if not generate them
    if not os.path.exists(dfile('key')):
        openssl('genrsa', '-out', dfile('key'), str(keysize))

    config = open(dfile('config'), 'w')
    config.write(OPENSSL_CONFIG_TEMPLATE % {'domain': domain})
    config.close()

    openssl('req', '-new', '-key', dfile('key'), '-out', dfile('request'),
            '-config', dfile('config'))

    openssl('x509', '-req', '-days', str(days), '-in', dfile('request'),
            '-CA', ca_cert, '-CAkey', ca_key,
            '-set_serial',
            '0x%s' % hashlib.md5((domain +
                                 str(datetime.datetime.now())).encode('utf-8')).hexdigest(),
            '-out', dfile('cert'),
            '-extensions', 'v3_req', '-extfile', dfile('config'),
            *X509_EXTRA_ARGS)
    print("Done. The private key is at {}, the cert is at {}, "
          "the CA cert is at {}.".format(dfile('key'), dfile('cert'), ca_cert))


def createstunnelconf():
    config = open("stunnel.conf", 'w')
    config.write(STUNNEL_CORE_GLOBAL_CONFIG_TEMPLATE)
    config.close()


def addstunnelclient(name, outport, camaddr, inport, rootdir=MYDIR):

    os.chdir(rootdir)
    os.makedirs(name, exist_ok=True)
    # if stunnel.conf do not exist then generate stunne.conf header
    if not os.path.exists("stunnel.conf"):
        createstunnelconf()

    config = open("stunnel.conf", 'a')
    config.write(STUNNEL_CORE_CONFIG_TEMPLATE % {'Cam': name,
                 'absolute': rootdir, 'outport': outport, 'inport': inport,
                 'camaddr': camaddr})
    config.close()


# def addstunnelcam(name, outport, camaddr, inport, rootdir=MYDIR):
#     os.chdir(os.path.join(rootdir, name))
#
#     config = open("stunnel.conf", 'w')
#     config.write(STUNNEL_CAM_CONFIG_TEMPLATE % {'Cam': name,
#                  'absolute': rootdir, 'outport': outport, 'inport': inport,
#                  'camaddr': camaddr})
#     config.close()

def addstunnelcam(name, camaddr, inport, rootdir=MYDIR):
    os.chdir(os.path.join(rootdir, name))

    config = open("stunnel.conf", 'w')
    config.write(STUNNEL_CAM_CONFIG_TEMPLATE % {'Cam': name,
                 'absolute': rootdir, 'inport': inport, 'camaddr': camaddr})
    config.close()


if __name__ == "__main__":

    # load configuration file
    config = json.load(open('../config.json', 'r'))
    in_port = 1234
    # out_port = 8081
    # generate certificates for all Cam
    for cam in config["cams"]:
        cam_configuration_port = config["cams"][cam]["port"]
        caddr = config["cams"][cam]["addr"]
        # generate certificates for Cam
        gencert(caddr, cam)
        # add Cam to Core stunnel.config
        addstunnelclient(cam, cam_configuration_port, caddr, str(in_port))
        # create stunnel.config for Cam
        addstunnelcam(cam, caddr, str(in_port))
        # copy the ca.crt in Cam folder
        copyfile("../ca.crt", "ca.crt")
        # in_port += 1
        # out_port += 1
    # generate the Core certificate
    gencert(config["general"]["internalIp"], "core")
