import sys; sys.path.append('../protocols')
import json
from scapy.all import *
from protocol_crypto import *
from Key import Key
from protocol_send import Sender
from multiprocessing import Process, Queue
from server_proxy import server1
import configparser


def key_manager():
    """
    Manages the communication regarding the keys.
    :return: key object.
    """
    key = Key(1, [])
    key.send_keys(2)
    logging.info('Send the keys')

    return key


def send_pack_forword(q):
    """
    The function is run as a process.
    It receive every packet from the servers and send it to the next machine.
    :param key: json key object
    """
    # Responsible for all signatures
    key = key_manager()
    s = Sender(key, 1, q)
    s.receive_pack()
    s.send_packet(2)


def main():
    logging.info('Start the program')

    # Opens the config file
    config = configparser.ConfigParser()
    config.read('config.ini')
    q = Queue()
    p = [Process(target=server1, args=(type_pack, int(port), q))
         for type_pack in config if type_pack != 'DEFAULT'
         for port in json.loads(config[type_pack]['Port'])]
    p.append(Process(target=send_pack_forword, args=(q,)))

    # Starts all the process that should work
    for process in p:
        process.start()


if __name__ == '__main__':
    main()
