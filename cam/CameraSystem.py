#!/usr/bin/env python3
""" Sample of MQTT code is from:
    https://github.com/PacktPublishing/MQTT-Essentials-A-Lightweight-IoT-Protocol
"""
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
from threading import Thread, Condition
import traceback


# ################################# Log Stuff #################################
# create logging dir if it do not exist
os.makedirs('logs', exist_ok=True)  # Python>3.2
# create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.handlers.TimedRotatingFileHandler(
                        filename='logs/system.log', when='D', backupCount=7)
fh.setLevel(logging.DEBUG)
# create console handler
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)
# ############################# MQTT Client Info ##############################
certificates_path = "/home/pi/certificates"
ca_certificate = os.path.join(certificates_path, "ca.crt")
client_certificate = os.path.join(certificates_path, "cam01.crt")
client_key = os.path.join(certificates_path, "cam01.key")
mqtt_server_host = "192.168.1.222"
mqtt_server_port = 8883
mqtt_keepalive = 60
# ########################## Camera Streaming Port ############################
# port = 8080


class PirSensor(Thread):
    """ A deamon thread that monitor a pir sensor setted on a channel. It
    provides a mechanism to make the caller aware of detection even if it is
    running in background. You need to use the is_detected function in order
    to use the deamon, otherwise it will be stuck on a condition.wait(). """

    def __init__(self, channel):
        Thread.__init__(self)
        # condition variable will be used to sync the value read operation
        self.is_read = Condition()
        # set the value to read to false
        self.motion_detected = False
        # set up pin as input
        self.pir = MotionSensor(channel)
        # terminate this thread when main program finishes
        self.daemon = True
        # start thread running
        self.start()

    def is_detected(self):
            # ###################### Acquire the lock #######################
            self.is_read.acquire()
            # save the detection variable value
            retvalue = self.motion_detected
            if self.motion_detected is True:
                # set the detection variable to false
                self.motion_detected = False
            # notifies that the value was read
            self.is_read.notify()
            # ####################### Relese the lock #######################
            self.is_read.release()
            return retvalue

    def run(self):
        while True:
            try:
                # wait until the motion sensor is activated
                self.pir.wait_for_motion()
                logger.info("Detected")
                # ##################### Acquire the lock ######################
                self.is_read.acquire()
                # releases the lock, blocks the current execution until notify
                self.is_read.wait()
                # set the detection variable to true
                self.motion_detected = True
                # ###################### Relese the lock ######################
                self.is_read.release()
                # Pause the cycle until the motion sensor is deactivated
                self.pir.wait_for_no_motion()
                logger.info("Not Detected")

            except (ValueError):
                logger.error("Impossible to read pir sensor")
                break


class NetworkError(RuntimeError):
    pass


def retryer(max_retries=30, timeout=5):
    def wraps(func):
        exceptions = (
            socket.herror,
            socket.gaierror,
            socket.timeout,
            ConnectionError
        )

        def inner(*args, **kwargs):
            for i in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                except exceptions:
                    time.sleep(timeout)
                    continue
                else:
                    return result
            else:
                raise NetworkError
        return inner
    return wraps


class Camera:
    """ add description
    """

    mjpg_streamer_pid = None
    active_instance = None

    def __init__(self, name):
        """ inizilize the mjpg-streamer as subprocess.

        You shoud first export the mjpg-streamer installation
        folder doing export LD_LIBRARY_PATH="$(pwd)"     """

        self.port = 8080
        self.name = name
        # set the streaming variable to False: we're not streaming
        self._streaming = False
        # start mjpg-streamer
        self._stream_process = subprocess.Popen(
          [
              "mjpg_streamer",
              "-i",
              "input_raspicam.so",
              "-o",
              "output_http.so -p 8080"
          ],
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE
        )
        # (out,err) = self._stream_process.communicate()
        # get the mjpg_streamer daemon pid
        # self.pid = int(re.findall('\d+', str(err, 'utf-8')).pop(0))
        self.mjpg_streamer_pid = self._stream_process.pid
        # ############# Wait for mjpg_streamer to start streaming #############
        try:
            self.socket_read_check()
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
            logger.error("Could not read from socket")
            sys.exit(1)
        # pause the mjpg_streamer deamon
        os.kill(self.mjpg_streamer_pid, signal.SIGSTOP)
        #######################################################################

    @retryer(max_retries=10, timeout=0.5)
    def socket_read_check(self):
        # Get hostaname
        hostname = socket.gethostname()
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        server_address = (hostname, self.port)
        sock.connect(server_address)
        # send the HTTP request to try to read from mjpg-streamer port
        sock.send(b'GET /?action=stream HTTP/1.0\r\n\r\n')
        while True:
            data = sock.recv(81920)
            if len(data) > 0:
                break
            time.sleep(0.5)
        sock.close()

    def is_streaming(self):
        if self._streaming:
            return True
        else:
            return False

    def stream_start(self):
        logger.info("Start streaming")
        # continue exectute mjpg_streamer
        os.kill(self.mjpg_streamer_pid, signal.SIGCONT)
        # check if mjpg_streamer is streaming
        try:
            self.socket_read_check()
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
            logger.error("mjpg_streamer is not streaming")
            sys.exit(1)
        self._streaming = True

    def stream_stop(self):
        # stop the mjpg_streamer deamon
        os.kill(self.mjpg_streamer_pid, signal.SIGSTOP)
        logger.info("Stop streaming")
        self._streaming = False

    # def getStreamerPid(self):
    #     return self.pid


class MsgProcessor:
    """The MsgProcessor object initiate a conection to the MQTT broker, then
    continuously check received messages and reply.
    The publish_message method can be used to send messages. """

    commands_topic = ""
    processed_commands_topic = ""
    motion_detection_topic = ""
    active_instance = None

    def __init__(self, camera):
        self.name = camera.name
        self.camera = camera
        MsgProcessor.commands_topic = "commands/{}".format(self.name)
        MsgProcessor.processed_commands_topic = "processedcommands/{}".format(
            self.name)
        MsgProcessor.motion_detection_topic = "motiondeteciontopic/{}".format(
            self.name)
        self.client = mqtt.Client(protocol=mqtt.MQTTv311)
        self.client.on_connect = MsgProcessor.on_connect
        self.client.on_message = MsgProcessor.on_message
        self.client.on_subscribe = MsgProcessor.on_subscribe
        self.client.on_publish = MsgProcessor.on_publish
        self.client.tls_set(ca_certs=ca_certificate,
                            certfile=client_certificate,
                            keyfile=client_key)
        self.client.connect(host=mqtt_server_host,
                            port=mqtt_server_port,
                            keepalive=mqtt_keepalive)
        MsgProcessor.active_instance = self

    @staticmethod
    def on_publish(client, userdata, mid):
        logger.debug("Published message id: {}".format(mid))

    @staticmethod
    def on_disconnect(client, userdata, rc):
        logger.error("{} disconnected".format(
            MsgProcessor.active_instance.name))

    @staticmethod
    def on_connect(client, userdata, flags, rc):
        """ Called when the client receives the CONNACK from the broker """
        logger.info("Connected to broker at: {}".format(
            mqtt_server_host))
        # subscribe to the broker to receive cmd from Core
        client.subscribe(
            MsgProcessor.commands_topic,
            qos=2)

    @staticmethod
    def on_subscribe(client, userdata, mid, granted_qos):
        logger.info("Subscribed with QoS: {}".format(granted_qos[0]))

    @staticmethod
    def on_message(client, userdata, msg):
        """ Called when the client receives the PUBLISH msg from the broker """
        # check if it is a command
        if msg.topic == MsgProcessor.commands_topic:
            # decode the message payload
            payload_string = msg.payload.decode('utf-8')
            logger.info("Received the msg: {0}".format(payload_string))
            try:
                # Deserialize s (a str, bytes or bytearray instance containing
                # a JSON document) to a Python object
                message_dictionary = json.loads(payload_string)
                if COMMAND_KEY in message_dictionary:
                    command = message_dictionary[COMMAND_KEY]
                    camera = MsgProcessor.active_instance.camera
                    is_command_processed = False
                    if command == CMD_STREAM_START:
                        camera.stream_start()
                        is_command_processed = True
                    elif command == CMD_STREAM_STOP:
                        camera.stream_stop()
                        is_command_processed = True
                    if is_command_processed:
                        MsgProcessor.active_instance.pub_msg(
                            message_dictionary)
                    else:
                        logger.warn("Unknown command.")
            except json.JSONDecodeError:
                # Impossible to deserialize JSON object
                logger.error("Impossible to deserialize JSON object.")

    def pub_msg(self, message):
        """ Send message to the Core """
        logger.debug(message)
        response_message = json.dumps({
                SUCCESFULLY_PROCESSED_COMMAND_KEY:
                message[COMMAND_KEY]
                })
        return self.client.publish(
                topic=self.__class__.processed_commands_topic,
                payload=response_message
                )

    def send_alert(self):
        """ Send alert msg to the Core """
        response_message = json.dumps({
                ALERT_KEY:
                MOTION_DETECTED
                })
        return self.client.publish(
            topic=self.__class__.motion_detection_topic,
            payload=response_message
            )

    def process_commands(self):
        self.client.loop()


if __name__ == "__main__":

    # create a Camera object
    camera = Camera("cam01")
    # create a pir sensor thread
    sensor = PirSensor(17)
    # create a MsgProcessor object
    processor = MsgProcessor(camera)

    def signal_handler(signum, frame):
        logger.debug("Received signal {}".format(signum))
        os.kill(os.getpid(), signal.SIGKILL)

    # register signal handler
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        # check if the motion sensor detected something
        if sensor.is_detected() and not camera.is_streaming():
            # send the alert
            processor.send_alert()
            logger.info("Alert Sent")
        # check if there is some message in the buffer
        processor.process_commands()
