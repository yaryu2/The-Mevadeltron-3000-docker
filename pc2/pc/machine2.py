import sys; sys.path.append('../protocols')
import json
from protocolDB import DB
from scapy.all import *
from sql_manage import *
from Key import DBKey
from multiprocessing import Process
from protocol_send import Sender
import configparser

SUS = []


def send_ip(key, ip, port, protocol):
    """
    This function update in the DB every packet that received.
    :param key: object key
    :param ip: the ip of the client.
    :param port: the port of the client.
    :param protocol: the type of the packet that the client send.
    """
    data = json.dumps([ip, port, protocol])
    signature = key.create_signature(data + '1')

    pack_add = IP(dst='255.255.255.255') / \
               UDP(dport=2223, sport=2223) / \
               DB(len_sign=len(signature), cmd=1, send_num=2, param=signature + data)

    send(pack_add)


def receive_sus_list(key):
    """
    The function is run as a process.
    Waiting for the update of the DB about the the suspicious IP
    :param key: object key.
    """
    global SUS
    while True:
        pack = sniff(lfilter=filter_pack, count=1)[0]

        if pack[DB].send_num == 5:
            signature, data = pack[DB].param[:pack[DB].len_sign], pack[DB].param[pack[DB].len_sign:]

            if key.verify_data_db(data + str(pack[DB].cmd), signature):
                SUS = [str(ip) for ip in json.loads(data)]
                print(SUS)


def key_manager():
    """
    Manages the communication regarding the keys and then with the DB.
    :return: DBkey object.
    """
    key = DBKey(2, [1], 5)
    key.receive_all_keys()
    key.send_keys(3)
    
    key.send_db_key()
    key.receive_db_key()

    return key


def filter_pack(pack):
    """
    filter the packets
    :param pack: packet that received
    :return: boolean - true if the packet is DB packet, otherwise False
    """
    return UDP in pack and DB in pack


def main():
    logging.info('Start the program')

    # Responsible for all signatures
    key = key_manager()

    logging.info('key managment finished')

    # Opens the config file
    config = configparser.ConfigParser()
    config.read('config.ini')

    # Receive the packet from machine1
    s = Sender(key, 2)
    s.receive_pack()

    s.queue[0].show()

    # Verify the signature
    if s.verify_data([1]):
        # Update the DB
        #send_ip(key, s.get_src_ip(), s.get_src_port, s.get_type())

        # Checking the validation of the pack
        if s.get_data() in json.loads(config[s.get_type()]['White List']) and s.get_src_ip() not in SUS:
            s.queue[0].show()
            s.send_protocol_pack(3)

    # Open process that receive from the DB all the sus ip
    p = [Process(target=receive_sus_list, args=(key,))]
    for process in p:
        process.start()


if __name__ == '__main__':
    main()
