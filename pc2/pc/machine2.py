import sys; sys.path.append('../protocols')
import json
from protocolDB import DB
from scapy.all import *
from sql_manage import *
from Key import DBKey
from multiprocessing import Process, Queue
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

    pack_add = Ether(dst='98:98:98:44:44:44') / \
               IP(dst='172.16.104.15') / \
               UDP() / \
               DB(len_sign=len(signature), cmd=1, send_num=2, param=signature + data.encode())

    conf.iface = 'eth2'
    sendp(pack_add)


def filter_db(pack):
    return UDP in pack and pack[IP].src='172.16.104.15'

def receive_sus_list(key):
    """
    The function is run as a process.
    Waiting for the update of the DB about the the suspicious IP
    :param key: object key.
    """
    global SUS
    while True:
        conf.iface = 'eth2'
        pack = sniff(iface='eth2', lfilter=filter_db, count=1)[0]
        pack.show2()
        if pack[DB].send_num == 5:
            signature, data = pack[DB].param[:pack[DB].len_sign], pack[DB].param[pack[DB].len_sign:].decode()

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
    logging.info('key managment finished')
    return key


def filter_pack(pack):
    """
    filter the packets
    :param pack: packet that received
    :return: boolean - true if the packet is DB packet, otherwise False
    """
    return UDP in pack and DB in pack


def send_pack_forword(key):
    """
    The function is run as a process.
    It receive every packet from the servers and send it to the next machine.
    :param key: json key object
    """
    # Responsible for all signatures
    logging.info('send_pack_forword')
    s = Sender(key, 2)
    s.receive_pack()
    return s


def main():
    logging.info('Start the program')

    # Responsible for all signatures
    key = key_manager()

    # Opens the config file
    config = configparser.ConfigParser()
    config.read('config.ini')

    s = send_pack_forword(key)

    # Verify the signature
    if s.verify_data([1]):
        # Update the DB
        send_ip(key, s.get_src_ip(), s.get_src_port(), s.get_type())
        logging.info('send to DB')

        # Checking the validation of the pack
        if s.get_data() in json.loads(config[s.get_type()]['White List']) and s.get_src_ip() not in SUS:
            s.send_protocol_pack(3, s.get_sign())

    # Open process that receive from the DB all the sus ip
    p = [Process(target=receive_sus_list, args=(key,))]
    for process in p:
        process.start()


if __name__ == '__main__':
    main()
