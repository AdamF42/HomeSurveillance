"""Inspired to:
- https://github.com/scaidermern/piCamBot
- https://github.com/FutureSharks/rpi-security
"""
from CONST import *
import json
import logging
import logging.handlers
import os
import signal
import sys
import telegram
import threading
import time
import traceback
from OpenPort import getExternalIp, openPort, closePort
import paho.mqtt.client as mqtt
from imutils.video import VideoStream
import cv2
import logging
from telegram.error import NetworkError
# import subprocess

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


class Detector():
    """ Init a MobileNet-SSD network using OpenCV deep learning module.
    Code inspired by OpenCV example at:
    https://github.com/opencv/opencv/blob/master/samples/dnn/mobilenet_ssd_python.py
    weights and prototxt from:
    https://github.com/chuanqi305/MobileNet-SSD/issues/35
    """
    def __init__(self, prototxt, weights, setconfidence):
        self.setconfidence = setconfidence
        # load serialized model from disk
        self.net = cv2.dnn.readNetFromCaffe(prototxt, weights)
        logger.info('Model {} loaded'.format(weights))

    def analyzeVideo(self, src):
        """ Read frames from input src, convert them into a blob and pass
        it through the network to obtain the detections
        and predictions.
        The iteration variable set the max nuber of frames
        to read before return. """
        logger.debug("Start analyzing video from {}".format(src))
        vs = VideoStream(src).start()
        # max number of frames we want to read
        iterations = 10
        # loop over the frames from the video stream
        for x in range(0, iterations):
            try:
                frame = vs.read()
                # grab the frame dimensions and convert it to a blob
                # image = cv2.resize(frame, (300, 300))
                # scalefactor =  0.007843
                # size = (300, 300)
                # mean = 127.5 is subtracted from every channel (R,G;B) of the
                # image
                blob = cv2.dnn.blobFromImage(cv2.resize(frame, (300, 300)),
                                             0.007843, (300, 300), 127.5)
                self.net.setInput(blob)
                detections = self.net.forward()
                # loop over the detections
                for i in range(detections.shape[2]):
                    # extract the confidence (probability) associated with
                    # the prediction
                    confidence = detections[0, 0, i, 2]
                    # check if the associated confidence is greater then the
                    # one we setted
                    if confidence > self.setconfidence:
                        # extract the index of the class label from the
                        # detections
                        class_id = int(detections[0, 0, i, 1])
                        # class_id 15 means person
                        if class_id == 15:
                            logger.info("Human detected")
                            vs.stop()
                            return True

            except Exception as e:
                logger.error(str(e))
                logger.error(traceback.format_exc())
                logger.error("Could not analyze video from {}".format(src))
                vs.stop()
                break
        vs.stop()
        return False


class coreSys:
    """ The coreSys create the check if a cam send an alert then warn the user.
    """
    commands_topic = ""
    processed_commands_topic = ""
    motion_detection_topic = ""
    active_instance = None

    def __init__(self):
        self.config = None
        # id for keeping track of the last seen message
        self.update_id = None
        # streaming flag
        self.is_streaming = False
        # flag to check is the sys is on
        self.is_active = False
        # create telegram bot instance
        self.bot = None
        # create mqtt client instance
        self.client = mqtt.Client(protocol=mqtt.MQTTv311)
        # initialize the topics to subscribe
        self.commands_topic = "commands/"
        self.processed_commands_topic = "processedcommands"
        self.motion_detection_topic = "motiondeteciontopic"
        self.cmd_stream = threading.Event()
        self.cmd_stream.set()
        self.link = ""
        coreSys.active_instance = self
        self.process = None
        # thread = threading.Thread(target=self.run, args=())
        # thread.daemon = True                            # Daemonize thread
        # thread.start()                                  # Start the execution

    def run(self):
        """ Initialize a thread to get telegram updates, a tread to get
        MQTT updates and then check if they're alive """
        # #################### Load the configuration file ####################
        try:
            self.config = json.load(open('config.json', 'r'))
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
            logger.error("Could not parse config file")
            sys.exit(1)
        # Get project root directory
        ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

        # ##################### Initialize the Detectior ######################
        self.d_path = self.config['human_detection']['detectionPath']
        self.d_path = os.path.join(
            ROOT_DIR,
            self.config['human_detection']['detectionPath'])
        self.detector = Detector(
            os.path.join(
                self.d_path, self.config['human_detection']['prototxt']),
            os.path.join(self.d_path, self.config['human_detection']['model']),
            self.config['human_detection']['confidence']
            )

        # ############### Initialize the MQTT client settings #################
        self.client.on_connect = coreSys.on_connect
        self.client.on_message = coreSys.on_message
        self.client.on_subscribe = coreSys.on_subscribe
        certificates_path = ca_certificate = os.path.join(
                    ROOT_DIR,
                    self.config['certificates']['certificatesPath'])
        ca_certificate = os.path.join(
            certificates_path,
            self.config['certificates']['ca_certificate']
            )
        # logger.debug(ca_certificate)
        client_certificate = os.path.join(
            certificates_path,
            self.config['certificates']['client_certificate']
            )
        # logger.debug(client_certificate)
        client_key = os.path.join(
            certificates_path,
            self.config['certificates']['client_key']
            )
        # logger.debug(client_key)
        self.client.tls_set(
            ca_certs=ca_certificate,
            certfile=client_certificate,
            keyfile=client_key
            )
        # try to connect to the mqtt broker
        try:
            self.client.connect(
                host=self.config['mqtt']['serverAddr'],
                port=self.config['mqtt']['serverPort'],
                keepalive=self.config['mqtt']['mqttKeepalive']
                )
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
            logger.error("Could connect to MQTT broker")
            sys.exit(1)

        # ##################### Setup the signal handler ######################
        signal.signal(signal.SIGHUP, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGQUIT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # #################### Initialize the Telegram Bot ####################
        try:
            self.bot = telegram.Bot(self.config['telegram']['token'])
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
            logger.error("Could not connect to telegram API")
            sys.exit(1)

        # ###################### Setup backgroud threads ######################
        threads = []

        # set up telegram thread
        telegram_thread = threading.Thread(
            target=self.getTelegramUpdates, name="TelegramBot")
        telegram_thread.daemon = True
        telegram_thread.start()
        threads.append(telegram_thread)

        # set up the mqtt msg processor
        mqtt_thread = threading.Thread(
            target=self.getMQTTClientUpdates, name="MQTTCoreCli")
        mqtt_thread.daemon = True
        mqtt_thread.start()
        threads.append(mqtt_thread)

        # ######################## Setup Main thread ##########################
        while True:
            time.sleep(5)
            # check if all threads are still alive
            for thread in threads:
                if thread.isAlive():
                    continue
                # something went wrong, bailing out
                msg = 'Thread "%s" died, terminating now.' % thread.name
                logger.error(msg)

                for owner_id in self.config['telegram']['ids']:
                    try:
                        self.bot.sendMessage(chat_id=owner_id, text=msg)
                    except Exception as e:
                        logger.error(str(e))
                        pass
                sys.exit(1)

    def signal_handler(self, signal, err):
        """ Handle the signals """
        msg = 'Caught signal {}, terminating now.'.format(signal)
        logger.error(msg)
        # enshure we close all ports
        for cam in self.config["cams"]:
            try:
                closePort(self.config['cams'][cam]['externalPort'])
            except Exception as e:
                logger.error(str(e))
                logger.error(traceback.format_exc())
                logger.error(
                    "Impossible to close port {}".format(
                     self.config['cams'][cam]['externalPort']))
        # block video stream from all cameras
        for cam in self.config["cams"]:
            try:
                self.publish_command(CMD_STREAM_STOP, cam)
            except Exception as e:
                logger.error(str(e))
                logger.error(traceback.format_exc())
                logger.error(
                    "Impossible to stop stop strem from {}".format(cam))
        for owner_id in self.config['telegram']['ids']:
            try:
                self.bot.sendMessage(chat_id=owner_id, text=msg)
            except Exception as e:
                logger.error(str(e))
                logger.error(traceback.format_exc())
                logger.error("Impossible to warn user {}".format(owner_id))
        sys.exit(1)

    def getMQTTClientUpdates(self):
        """ Start the Paho client.loop_forever.
         This method blocks the thread and also
         handles automatic reconnects.
        """
        logger.info('Setting up MQTT Client thread')
        self.client.loop_forever()

    def getTelegramUpdates(self):
        logger.info('Setting up Telegram Bot thread')
        while True:
            try:
                # offset: request updates after the last update_id
                # timeout: how long to poll for messages
                for update in self.bot.getUpdates(
                        offset=self.update_id, timeout=10):
                    # self.chat_id = update.message.chat_id
                    self.update_id = update.update_id + 1
                    # skip updates without a message
                    if not update.message:
                        continue
                    message = update.message
                    # skip messages from non-owner
                    if message.from_user.id not in self.config['telegram']['ids']:
                        logger.warn(
                            'Message from unknown user "{}": "%{}"'.format(
                                            message.from_user, message.text))
                        message.reply_text("You're not allowed to use this service")
                        continue
                    logger.info('Received msg from "{}": "{}"'.format(
                                    message.from_user.username, message.text))
                    self.process_command(message)
            except NetworkError as e:
                logger.warn(NetworkError)
                time.sleep(5)
            except Exception as e:
                logger.warn(str(e))
                logger.warn(traceback.format_exc())
                time.sleep(1)

    def process_command(self, message):
        cmd = message.text.lower().rstrip()
        if cmd == '/start':
            # ignore default start command
            return
        if cmd == '/stream':
            self.command_stream(message)
        elif cmd == '/stop':
            self.command_stop(message)
        elif cmd == '/enable':
            self.command_enable()
        elif cmd == '/disable':
            self.command_disable()
        else:
            logger.warn('Unknown command: "%s"' % message.text)

    def command_enable(self):
        self.is_active = True
        logger.info("System Enabled")
        # inform all users
        for owner_id in self.config['telegram']['ids']:
            self.bot.sendMessage(chat_id=owner_id, text="System Activated")

    def command_disable(self):
        self.is_active = False
        logger.info("System Disabled")
        # inform all users
        for owner_id in self.config['telegram']['ids']:
            self.bot.sendMessage(chat_id=owner_id, text="System Deactivated")

    def command_stream(self, message):
        # check if we're streaming
        if self.is_streaming:
            # if we're already streaming then send to the user the streaming links
            message.reply_text('Already streaming at: \n'+self.link)
            return
        internal_ip = self.config['general']['internal_ip']
        ip = getExternalIp()
        for cam in self.config["cams"]:
            openPort(self.config['cams'][cam]['port'], internal_ip, self.config['cams'][cam]['externalPort'])
            self.link += cam+" at: "+ip + ":" + self.config['cams'][cam]['externalPort']+"/?action=stream\n"
        message.reply_text(self.link)
        self.streamAllStart()
        self.is_streaming = True

    def command_stop(self, message):
        # check if we're streaming
        if not self.is_streaming:
            # if not, warn the user
            message.reply_text('It is not streaming!')
            return
        message.reply_text('Disabling streaming...')
        for cam in self.config["cams"]:
            closePort(self.config['cams'][cam]['externalPort'])
        self.streamAllStop()
        self.is_streaming = False
        self.link = ""
        message.reply_text("Closed")

    @staticmethod
    def on_connect(client, userdata, flags, rc):
        """ Called when the client receives the CONNACK from the broker """
        logger.info("Connect result: {}".format(mqtt.connack_string(rc)))
        coreSys.active_instance.client.subscribe([
            (coreSys.active_instance.processed_commands_topic+"/#", 2),
            (coreSys.active_instance.motion_detection_topic+"/#", 2)
            ])

    @staticmethod
    def on_subscribe(client, userdata, mid, granted_qos):
        logger.info("Subscribed with QoS: {}".format(granted_qos[0]))

    @staticmethod
    def on_message(client, userdata, msg):
        """ Called when the client receives the PUBLISH msg from the broker """
        payload_string = msg.payload.decode('utf-8')
        # print(payload_string)
        topic = msg.topic.split('/')
        camera = topic.pop(1)
        root_topic = topic.pop(0)
        if root_topic == coreSys.active_instance.processed_commands_topic:
            if payload_string.count(CMD_STREAM_START) > 0:
                logger.info("The Cam {0} has started to stream".format(camera))
                # check if the stream is required by the user or by the camera,
                # if it is required by the cam, the streaming variable is False
                if not coreSys.active_instance.is_streaming:
                    # we need to call the detector
                    if coreSys.active_instance.detector.analyzeVideo(
                            coreSys.active_instance.config['cams'][camera]["src"]):
                        # alert the user(s)
                        for owner_id in coreSys.active_instance.config['telegram']['ids']:
                            try:
                                coreSys.active_instance.bot.sendMessage(
                                    chat_id=owner_id, text="Alert from camera "+camera)
                                logger.info("Sent alert from camera "+camera)
                            except Exception as e:
                                logger.error(str(e))
                                pass
                    # stop the stream
                    coreSys.active_instance.publish_command(
                        CMD_STREAM_STOP, camera)
                    logger.info("stop the stream")
            elif payload_string.count(CMD_STREAM_STOP) > 0:
                logger.info("The camera has succesfully stopped stream")

        elif root_topic == coreSys.active_instance.motion_detection_topic and coreSys.active_instance.is_active:
            logger.info("Received: {} from {}".format(payload_string, camera))
            coreSys.active_instance.publish_command(CMD_STREAM_START, camera)

    @staticmethod
    def on_publish(client, userdata, mid):
        logger.debug("Published message id: {}".format(mid))

    def publish_command(self, command_name, camera_name):
        logger.debug("publish_command")
        command_message = json.dumps({COMMAND_KEY: command_name})
        result = self.client.publish(
            topic=self.commands_topic+camera_name,
            payload=command_message, qos=2
            )
        return result

    def streamAllStart(self):
        logger.debug("streamAllStart")
        for cam in self.config["cams"]:
            self.publish_command(CMD_STREAM_START, cam)

    def streamAllStop(self):
        logger.debug("streamAllStop")
        for cam in self.config["cams"]:
            self.publish_command(CMD_STREAM_STOP, cam)

    def commandCameraList(self, message):
        text = ""
        for cam in self.config["cams"]:
            text += cam+"\n"
        message.reply_text(text)


if __name__ == '__main__':

    system = coreSys()
    system.run()
