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
from threading import Thread, Event
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
port = 8080


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
              "input_raspicam.so -rot 180 -fps 5",
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
        # It require too much time. Better not to check.
        # # check if mjpg_streamer is streaming
        # try:
        #     self.socket_read_check()
        # except Exception as e:
        #     logger.error(str(e))
        #     logger.error(traceback.format_exc())
        #     logger.error("mjpg_streamer is not streaming")
        #     sys.exit(1)
        self._streaming = True

    def stream_stop(self):
        # stop the mjpg_streamer deamon
        os.kill(self.mjpg_streamer_pid, signal.SIGSTOP)
        logger.info("Stop streaming")
        self._streaming = False


class MQTTmsgProcessor:
    """The MQTTmsgProcessor object initiate a conection to the MQTT broker, then
    continuously check received messages and reply.
    The publish_message method can be used to send messages. """

    commands_topic = ""
    processed_commands_topic = ""
    motion_detection_topic = ""
    active_instance = None

    def __init__(self, camera):
        self.name = camera.name
        self.camera = camera
        MQTTmsgProcessor.commands_topic = "commands/{}".format(self.name)
        MQTTmsgProcessor.processed_commands_topic = "processedcommands/{}".format(
            self.name)
        MQTTmsgProcessor.motion_detection_topic = "motiondeteciontopic/{}".format(
            self.name)
        self.client = mqtt.Client(protocol=mqtt.MQTTv311)
        self.client.on_connect = MQTTmsgProcessor.on_connect
        self.client.on_message = MQTTmsgProcessor.on_message
        self.client.on_subscribe = MQTTmsgProcessor.on_subscribe
        # self.client.on_publish = MQTTmsgProcessor.on_publish
        self.client.tls_set(ca_certs=ca_certificate,
                            certfile=client_certificate,
                            keyfile=client_key)
        self.client.connect(host=mqtt_server_host,
                            port=mqtt_server_port,
                            keepalive=mqtt_keepalive)
        self.is_streaming = Event()
        self.is_streaming.set()
        MQTTmsgProcessor.active_instance = self

    def wait_for_stop_streaming(self):
        logger.info("Waiting for Core to unlock...")
        MQTTmsgProcessor.active_instance.is_streaming.wait()

    # @staticmethod
    # def on_publish(client, userdata, mid):
    #     logger.debug("Published message id: {}".format(mid))

    @staticmethod
    def on_disconnect(client, userdata, rc):
        logger.error("{} disconnected".format(
            MQTTmsgProcessor.active_instance.name))

    @staticmethod
    def on_connect(client, userdata, flags, rc):
        """ Called when the client receives the CONNACK from the broker """
        logger.info("Connected to broker at: {}".format(
            mqtt_server_host))
        # subscribe to the broker to receive cmd from Core
        client.subscribe(
            MQTTmsgProcessor.commands_topic,
            qos=2)

    @staticmethod
    def on_subscribe(client, userdata, mid, granted_qos):
        logger.info("Subscribed with QoS: {}".format(granted_qos[0]))

    @staticmethod
    def on_message(client, userdata, msg):

        """ Called when the client receives the PUBLISH msg from the broker
        """
        # check if it is a command
        if msg.topic == MQTTmsgProcessor.commands_topic:
            # decode the message payload
            payload_string = msg.payload.decode('utf-8')
            try:
                # Deserialize s (a str, bytes or bytearray instance containing
                # a JSON document) to a Python object
                message_dictionary = json.loads(payload_string)
                if COMMAND_KEY in message_dictionary:
                    command = message_dictionary[COMMAND_KEY]
                    camera = MQTTmsgProcessor.active_instance.camera
                    is_command_processed = False
                    if command == CMD_STREAM_START:
                        logger.info("Received the msg: {0}".format(command))


                        # # Reset the internal flag to false. Subsequently,
                        # # threads calling wait() will block until set() is
                        # # called to set the internal flag to true again.
                        # MQTTmsgProcessor.active_instance.is_streaming.clear()

                        camera.stream_start()
                        is_command_processed = True
                    elif command == CMD_STREAM_STOP:
                        logger.info("Received the msg: {0}".format(command))

                        # Set the internal flag to true. All threads waiting
                        # for it to become true are awakened. Threads that call
                        # wait() once the flag is true will not block at all.
                        # MQTTmsgProcessor.active_instance.is_streaming.set()

                        # logger.debug(
                        #    "Event is True: Waiting Threads can proceed")
                        camera.stream_stop()
                        is_command_processed = True
                    if is_command_processed:
                        MQTTmsgProcessor.active_instance.pub_msg(
                            message_dictionary)
                    else:
                        logger.warn("Unknown command.")
            except json.JSONDecodeError:
                # Impossible to deserialize JSON object
                logger.error("Impossible to deserialize JSON object.")

    def pub_msg(self, message):
        """ Send message to the Core """
        # logger.debug(message)
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
        # MQTTmsgProcessor.active_instance.is_streaming.wait()
        response_message = json.dumps({
                ALERT_KEY:
                MOTION_DETECTED
                })
        return self.client.publish(
            topic=self.__class__.motion_detection_topic,
            payload=response_message
            )

    def getMQTTUpdates(self):

        logger.info("Starting looping")
        self.client.loop_start()


if __name__ == "__main__":
    # streaming = Event()
    # streaming.set()
    # create a Camera object
    camera = Camera("cam01")
    # create a pir sensor thread
    sensor = MotionSensor(17)
    # create a MQTTmsgProcessor object
    processor = MQTTmsgProcessor(camera)

    # create a thread to handle the mqtt messages
    mqtt_thread = Thread(
        target=processor.getMQTTUpdates, name="MQTTCoreCli")
    mqtt_thread.daemon = True
    mqtt_thread.start()

    def signal_handler(signum, frame):
        logger.debug("Received signal {}".format(signum))
        os.kill(os.getpid(), signal.SIGKILL)

    # register signal handler
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        # # Reset the internal flag to false. Subsequently,
        # # threads calling wait() will block until set() is
        # # called to set the internal flag to true again.
        # MQTTmsgProcessor.active_instance.is_streaming.clear()


        # logger.debug("Event is False")
        # logger.debug("Waiting for motion...")
        sensor.wait_for_motion()
        logger.info("Motion Detected!")
        if not camera.is_streaming():
            processor.send_alert()
            logger.info("Alert Sent!")
        sensor.wait_for_no_motion()
        # processor.wait_for_stop_streaming()
