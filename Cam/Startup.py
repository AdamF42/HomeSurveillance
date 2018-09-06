import time
# import threading
from gpiozero import MotionSensor
import os
import signal
import logging
import logging.handlers
import sys
from CONST import *
import paho.mqtt.client as mqtt
import json
import subprocess
import socket
from threading import Thread, Event
import traceback


# ################################# Log Stuff #################################
os.makedirs('logs', exist_ok=True)  # Python > 3.2
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
fh = logging.handlers.TimedRotatingFileHandler(
    filename='logs/system.log', when='D', backupCount=7)
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)