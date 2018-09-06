
#!/usr/bin/env python
"""
CoreSystem used to get the stream from Cams.

TODO: Redesign the telegram bot using telegram.ext

Inspired by projects at:
https://github.com/scaidermern/piCamBot
https://github.com/FutureSharks/rpi-security
https://github.com/tomasbjerre/RaspberrySurveillance
https://github.com/OmkarPathak/Smart-Surveillance-System-using-Raspberry-Pi
"""
from CONST import *
import json
import logging
import logging.handlers
import os
import signal
import sys
import telegram
from telegram import KeyboardButton, ReplyKeyboardMarkup
import threading
import time
import traceback
from OpenPort import getExternalIp, openPort, closePort
import paho.mqtt.client as mqtt
from imutils.video import VideoStream
import imutils
import cv2
import logging
from telegram.error import NetworkError
from multiprocessing import Queue
from multiprocessing import Process
# from multiprocessing import Process, Lock
# import multiprocessing as mp

FRAME_PROCESSORS = 4
INPUT_QUEUE_SIZE = 2
# ################################# Log Stuff #################################
# Get project root directory
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
# create logging dir if it does not exist
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
# formatter = logging.Formatter(
#     '%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s')
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(processName)s - %(threadName)s - %(message)s')
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
    inQueue = None
    outQueue = None
    saveQueue = None

    def __init__(self, prototxt, weights, setconfidence):
        self.setconfidence = setconfidence
        # load serialized model from disk
        self.net = cv2.dnn.readNetFromCaffe(prototxt, weights)
        # logger.debug('Model {} loaded'.format(weights))
        # Queue used to save frames on disk
        self.saveQueue = Queue(maxsize=1)
        # Queue used to store maxsize frames.
        # The frame processor thread will read and process them
        self.inQueue = Queue(maxsize=INPUT_QUEUE_SIZE)
        # Queue used to store detections. Since the reader thread is a way
        # faster then the writer one, the maxsize is set to 1
        self.outQueue = Queue(maxsize=1)
        self.process_frame = threading.Event()
        self.process_frame.set()
        self.net_lock = threading.Lock()
        # self.net_lock = Lock()
        # self.save_frames = threading.Event()
        # self.save_frames.clear()

    def save_frames(self):
        # create img dir if it does not exist
        os.makedirs('img', exist_ok=True)
        img_dir = os.path.join(ROOT_DIR, 'img')
        os.chdir(img_dir)
        while True:
            # logger.debug("WAITING...")
            frame = self.saveQueue.get(True)
            # logger.debug(frame)
            name = "IMG_{}.jpg".format(time.strftime("%d_%X"))
            cv2.imwrite(name, frame)
            # logger.debug("saved {}".format(name))
            time.sleep(10)

    def process_frames(self):
        """Wait for frames in the input queue, convert them into a blob and
        pass them through the network.
        Finally store detections and predictions in the output queue.
        """

        while True:
            # wait until is requeired
            # if not self.process_frame.isSet():
            #     logger.debug("process waiting...")
            # TODO: block the process if we detect something
            # self.process_frame.wait()

            # wait until a frame is available
            frame = self.inQueue.get(True)
            # blobFromImage (image, scalefactor, size, mean)
            # image = cv2.resize(frame, (300, 300))
            # scalefactor =  0.007843
            # size = (300, 300)
            # mean = 127.5 is subtracted from every channel (R,G;B) of the
            # image
            blob = cv2.dnn.blobFromImage(
                    cv2.resize(frame, (300, 300)), 0.007843, (300, 300), 127.5)

            self.net_lock.acquire()
            # ####################### CRITICAL SECTION ########################
            try:
                # logger.debug("Locking")
                # pass the blob through the network and obtain the detections
                # and predictions
                self.net.setInput(blob)
                detections = self.net.forward()
            finally:
                # logger.debug('Not locking')
                self.net_lock.release()
            # ###################### NON-CRITICAL SECTION #####################
            # put the detections into the output queue
            self.outQueue.put(detections, True)
            # logger.debug("Detection Inserted!!!")

    def analyze_video(self, src):
        """ Read frames from input src, insert them in an input queue,
        then check if the output queue contain a detection

        The iteration variable set the max nuber of frames
        to read before return. """

        logger.debug("Analyzing video from {}".format(src))

        vs = VideoStream(src).start()
        # max number of frames we want to read
        iterations = 8
        dummi = 5*iterations
        # loop over the frames from the video stream
        while iterations > 0:
            dummi -= 1
            try:
                detections = None
                frame = vs.read()
                frame = imutils.resize(frame, width=400)
                # logger.debug("Iteration: {}".format(8-iterations))

                # if the save queue is not full, insert
                # the current frame to store it
                if not self.saveQueue.full():
                    self.saveQueue.put(frame)

                # if the input queue is not full, insert the current frame
                if not self.inQueue.full():
                    self.inQueue.put(frame)
                    # logger.debug("inserted frame")

                # unlock the frame processor thread
                if not self.process_frame.isSet():
                    self.process_frame.set()

                # if the output queue is not empty, get the detections
                if not self.outQueue.empty():
                    detections = self.outQueue.get()
                    # we get a detection, so we decrease th max number
                    # of frames to analyze
                    iterations -= 1

                if detections is not None:
                    for i in range(detections.shape[2]):
                        # extract the confidence (probability) associated with
                        # the prediction
                        confidence = detections[0, 0, i, 2]
                        # check if the associated confidence is greater then
                        # the one we setted
                        if confidence > self.setconfidence:
                            # extract the index of the class label from the
                            # detections
                            class_id = int(detections[0, 0, i, 1])
                            # class_id 15 means person
                            if class_id == 15:
                                # logger.info("Human detected")
                                vs.stop()
                                # stop the frame processor thread
                                self.process_frame.clear()
                                # logger.debug("process flag is false")
                                while not self.inQueue.empty():
                                    self.inQueue.get()
                                # logger.debug("True: InQueue is empty")
                                while not self.outQueue.empty():
                                    self.outQueue.get()
                                # logger.debug("True: OutQueue is empty")
                                # TODO: find a better way;  bad idea
                                # stop the stream

                                logger.debug("Finish")
                                return True
                # Wait to avoid reading the same frame
                # TODO: find a better way to do it
                time.sleep(.2)
            except Exception as e:
                logger.error(str(e))
                logger.error(traceback.format_exc())
                logger.error("Could not analyze video from {}".format(src))
                vs.stop()
                break
        vs.stop()
        # stop the frame processor threads
        self.process_frame.clear()
        # clean the input queue
        while not self.inQueue.empty():
            self.inQueue.get()
        # logger.debug("False: InQueue is empty")
        while not self.outQueue.empty():
            self.outQueue.get()
        # logger.debug("False: OutQueue is empty")
        logger.debug("Finish")
        return False


class coreSys:
    """ The coreSys start:
    - a threat to get cmd from user through the Telegram Bot
    - a thread to get msg from the cams
    - a thread to process frames
    Then check for other threads to be alive
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

    def run(self):
        """ Read the configuration file and use the information to setup the
        telegram bot, the mqtt client and the detector
        """
        # #################### Load the configuration file ####################
        try:
            self.config = json.load(open('config.json', 'r'))
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
            logger.error("Could not parse config file")
            sys.exit(1)

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
        # self.detector.analyze_video(None)
        # ################ Set up the frame processor threads #################
        for x in range(0, FRAME_PROCESSORS):
            name = "FrameProcessor{}".format(x)
            # mp.set_start_method('spawn')
            frame_processor_thread = Process(
                target=self.detector.process_frames, name=name)
            frame_processor_thread.daemon = True
            frame_processor_thread.start()

        # ##################### Initialize the MQTT client ####################
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

        # #################### Initialize the Telegram Bot ####################
        try:
            self.bot = telegram.Bot(self.config['telegram']['token'])
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
            logger.error("Could not connect to telegram API")
            sys.exit(1)

        # ########################### Set up threads  #########################
        threads = []


        # for x in range(0, 2):
        #     name = "FrameProcessor{}".format(x)
        #     frame_processor_thread = threading.Thread(
        #         target=self.detector.process_frames, name=name)
        #     frame_processor_thread.daemon = True
        #     frame_processor_thread.start()
        #     threads.append(frame_processor_thread)

        # ################### Set up the frame saver thread ###################
        frame_saver_thread = threading.Thread(
            target=self.detector.save_frames, name="FrameSaver")
        frame_saver_thread.daemon = True
        frame_saver_thread.start()
        threads.append(frame_saver_thread)

        # ##################### Set up the telegram thread ####################
        telegram_thread = threading.Thread(
            target=self.getTelegramUpdates, name="TelegramBot")
        telegram_thread.daemon = True
        telegram_thread.start()
        threads.append(telegram_thread)

        # ################### Set up the mqtt client thread ###################
        mqtt_thread = threading.Thread(
            target=self.getMQTTClientUpdates, name="MQTTCoreCli")
        mqtt_thread.daemon = True
        mqtt_thread.start()
        threads.append(mqtt_thread)

        # ############# Inform the user(s) the system is available ############
        keyboard = [
            [
                KeyboardButton('Enable'),
                KeyboardButton('Disable')],
            [
                KeyboardButton('Stream'),
                KeyboardButton('Stop')
            ]
        ]
        for owner_id in self.config['telegram']['ids']:
            try:
                reply_markup = ReplyKeyboardMarkup(keyboard)
                self.bot.sendMessage(chat_id=owner_id,
                                     reply_markup=reply_markup,
                                     text=" System is available.")
            except Exception as e:
                logger.error(str(e))
                pass

        # ##################### Setup the signal handler ######################
        signal.signal(signal.SIGHUP, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGQUIT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # ###################### Setup the Main thread ########################
        while True:
            time.sleep(5)
            # logger.debug("TEST")
            # check if all threads are still alive
            for thread in threads:
                if thread.isAlive():
                    continue
                # some thread died
                msg = 'Thread {} died, system is not available.'.format(
                    thread.name)
                logger.error(msg)
                # inform the user(s)
                for owner_id in self.config['telegram']['ids']:
                    try:
                        self.bot.sendMessage(chat_id=owner_id, text=msg)
                    except Exception as e:
                        logger.error(str(e))
                        pass
                sys.exit(1)

    def signal_handler(self, signal, err):
        """ Handle the signals """
        msg = 'Caught signal {}, system is not available.'.format(signal)
        logger.error(msg)
        # enshure we close all ports
        for cam in self.config["cams"]:
            try:
                closePort(self.config['cams'][cam]['external_port'])
            except Exception as e:
                logger.error(str(e))
                logger.error(traceback.format_exc())
                logger.error(
                    "Impossible to close port {}".format(
                     self.config['cams'][cam]['external_port']))
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
        # logger.debug(cmd)
        # logger.debug(cmd is "enable")
        if cmd == '/start':
            self.command_start(message)
        elif cmd == 'stream':
            self.command_stream(message)
        elif cmd == 'stop':
            self.command_stop(message)
        elif cmd == "enable":
            self.command_enable()
        elif cmd == "disable":
            self.command_disable()
        else:
            logger.warn('Unknown command: {}'.format(message.text))

    def command_start(self, message):
        keyboard = [
            [
                KeyboardButton('Enable'),
                KeyboardButton('Disable')],
            [
                KeyboardButton('Stream'),
                KeyboardButton('Stop')
            ]
        ]
        reply_markup = ReplyKeyboardMarkup(keyboard)
        message.reply_text('Please choose:', reply_markup=reply_markup)

    def command_enable(self):
        self.is_active = True
        # inform all users
        for owner_id in self.config['telegram']['ids']:
            self.bot.sendMessage(chat_id=owner_id, text="System Activated")
        self.streamAllStop()
        logger.info("System Enabled")

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
        # TODO: Check if the cameras are connected
        # UNLOCK the cams...
        self.streamAllStop()
        internal_ip = self.config['general']['internal_ip']
        ip = getExternalIp()
        for cam in self.config["cams"]:
            openPort(
                self.config['cams'][cam]['port'],
                internal_ip,
                self.config['cams'][cam]['external_port']
                )
            self.link += cam+" at: "+ip + ":" + self.config['cams'][cam]['external_port']+"/?action=stream\n"
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
            closePort(self.config['cams'][cam]['external_port'])
        self.streamAllStop()
        self.is_streaming = False
        self.link = ""
        message.reply_text("Disabled")

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
                logger.info("{0} is streaming".format(camera))
                # check if the stream is required by the user or by the system,
                # if it is required by the system, the streaming variable is False
                if not coreSys.active_instance.is_streaming:
                    # we need to call the detector, if it return true,
                    # then warn the user
                    if coreSys.active_instance.detector.analyze_video(
                            coreSys.active_instance.config['cams'][camera]["src"]):
                        # alert the user(s)
                        for owner_id in coreSys.active_instance.config['telegram']['ids']:
                            try:
                                coreSys.active_instance.bot.sendMessage(
                                    chat_id=owner_id,
                                    text="Alert from camera "+camera)
                                # logger.info("Intrusion in camera "+camera)
                                # for debug
                                time.sleep(1)
                            except Exception as e:
                                logger.error(str(e))
                                pass
                    # stop the stream
                    coreSys.active_instance.publish_command(
                        CMD_STREAM_STOP, camera)
            elif payload_string.count(CMD_STREAM_STOP) > 0:
                logger.info("{0} is not streaming".format(camera))

        elif root_topic == coreSys.active_instance.motion_detection_topic and coreSys.active_instance.is_active:
            logger.info("{}: ALERT  ".format(payload_string, camera))
            coreSys.active_instance.publish_command(CMD_STREAM_START, camera)

    # @staticmethod
    # def on_publish(client, userdata, mid):
    #     logger.debug("Published message id: {}".format(mid))


    def publish_command(self, command_name, camera_name):
        # logger.debug("publish_command")
        command_message = json.dumps({COMMAND_KEY: command_name})
        result = self.client.publish(
            topic=self.commands_topic+camera_name,
            payload=command_message, qos=2
            )
        return result

    def streamAllStart(self):
        # logger.debug("streamAllStart")
        for cam in self.config["cams"]:
            self.publish_command(CMD_STREAM_START, cam)

    def streamAllStop(self):
        # logger.debug("streamAllStop")
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
