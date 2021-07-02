import json
import sys; sys.path.append('../protocols')
from scapy.all import *
from protocol_crypto import *
from Key import Key
from protocol_send import Sender
from multiprocessing import Process
from server_proxy import server1
import configparser


def key_manager():
    """
    Manages the communication regarding the keys.
    :return: key object.
    """
    key = Key(1, [])
    key.send_keys(2)

    return key


def send_pack_forword(key):
    """
    The function is run as a process.
    It receive every packet from the servers and send it to the next machine.
    :param key: key object
    """
    s = Sender(key, 1)
    s.receive_pack()
    s.send_packet(2)


def main():
    logging.info('Start the program')

    # Responsible for all signatures
    key = key_manager()

    logging.info('Send the keys')

    # Opens the config file
    config = configparser.ConfigParser()
    config.read('config.ini')

    p = [Process(target=server1, args=(type_pack, int(port), config[type_pack]['First Response'],))
         for type_pack in config if type_pack != 'DEFAULT'
         for port in json.loads(config[type_pack]['Port'])]

    p.append(Process(target=send_pack_forword, args=(key,)))

    # Starts all the process that should work
    for process in p:
        process.start()


if __name__ == '__main__':
    main()
