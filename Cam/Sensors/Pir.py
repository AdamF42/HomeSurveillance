import json

from Cam.Startup import logger


class Pir:
    active_instance = None

    def __init__(self, mqtt_client, gpio_switch, name):
        self.__client = mqtt_client
        self.__client.on_connect = self.__on_connect
        self.__client.on_disconnect = self.__on_disconnect
        self.__client.on_subscribe = self.__on_subscribe
        self.__client.on_message = self.__on_message
        self.__commands_topic = "switch/command/{}".format(name)
        self.__processed_commands_topic = "switch/precessed_command/{}".format(name)
        self.__motion_detection_topic = "motiondeteciontopic/{}".format(name)
        self.__switch_channel = gpio_switch
        Pir.active_instance = self

    @staticmethod
    def __on_connect(__client, userdata, flags, rc):
        """ Called when the client receives the CONNACK from the broker """
        logger.info("Connected to broker ")
        __client.subscribe(
            Pir.active_instance.__commands_topic,
            qos=2)

    @staticmethod
    def __on_subscribe(__client, userdata, mid, granted_qos):
        logger.info("Subscribed with QoS: {}".format(granted_qos[0]))

    @staticmethod
    def __on_disconnect(self, __client, userdata, flags, rc):
        logger.error("{} disconnected".format(
            Pir.active_instance.__name))

    def process_commands(self):
        logger.info("Start processing: {0}".format(self.__name))
        self.__client.loop_forever()

    @staticmethod
    def __on_message(__client, userdata, msg):
        """ Called when the client receives the PUBLISH msg from the broker """
        # check if it is a command
        if msg.topic == Pir.active_instance.__commands_topic:
            # decode the message payload
            payload_string = msg.payload.decode('utf-8')
            logger.info("Received the msg: {0}".format(payload_string))
            try:
                message_dictionary = json.loads(payload_string)
                if command_key in message_dictionary:
                    command = message_dictionary[command_key]
                    is_command_processed = False
                    if command == cmd_turn_on:
                        Switch.active_instance.__switch_channel.on()
                        is_command_processed = True
                        logger.info("Command {0} executed".format(command))
                    elif command == cmd_turn_off:
                        Switch.active_instance.__switch_channel.off()
                        is_command_processed = True
                        logger.info("Command {0} executed".format(command))
                    if is_command_processed:
                        # TODO: remove hardcoded command string
                        response_message = json.dumps({
                            "SUCCESSFULLY_PROCESSED_COMMAND_KEY":
                                command_key
                        })
                        return Pir.active_instance.__client.publish(
                            topic=Pir.active_instance.__processed_commands_topic,
                            payload=response_message
                        )
                        logger.error("TODO Switch.active_instance.pub_msg( message_dictionary)")
                    else:
                        logger.error("Unknown command.")
            except json.JSONDecodeError:
                # Impossible to deserialize JSON object
                logger.error("Impossible to deserialize JSON object.")

    @property
    def is_alive(self):
        return True

    @property
    def send_alert(self):
        """ Send alert msg to the Core """
        response_message = json.dumps({
            "ALERT_KEY":
                "MOTION_DETECTED"
        })
        return self.__client.publish(
            topic=self.__motion_detection_topic,
            payload=response_message
        )
# TODO:
# while true
#     if activated then wait for motion
#     else pause thread
