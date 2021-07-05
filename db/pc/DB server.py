import sys; sys.path.append('../protocols')
from Key import DBKey
from scapy.all import *
from protocolDB import DB
import json
import ddos
from multiprocessing import Process
from sql_manage import *
import portscan

logging.basicConfig(level=logging.INFO)
SUS = []


def receive_sus():
    """
    Searching for new suspicious IP
    :return: boolean - True if there is new suspicious IP otherwise False.
    """
    global SUS
    s = open('sus_list.txt', 'r').readlines()

    if s != SUS:
        SUS = s
        return False

    return True


def send_sus_list(key):
    """
    The function run as a Process.
    If another suspicious IP is found, it inform the machine2.
    :param key: DBkey object
    """
    while True:
        if not receive_sus():
            signature = key.create_signature(json.dumps(SUS) + '2')

            pack_send = Ether(dst='98:98:98:22:22:22') / \
                        IP(dst='172.16.104.16') / \
                        UDP(dport=2223, sport=2223) / \
                        DB(len_sign=len(signature), cmd=2,
                           send_num=5, param=signature + json.dumps(SUS).encode())

            conf.iface='eth0'
            sendp(pack_send)


def add(pack, key):
    """
    The function updates the DB on a new package
    :param pack: new packet that received
    :param key: DBkey object
    """
    if pack[DB].send_num == 2:
        signature, data = pack[DB].param[:pack[DB].len_sign], pack[DB].param[pack[DB].len_sign:].decode()
        
        if key.verify_data_db(data + str(pack[DB].cmd), signature):
            ip, port, protocol = json.loads(data)

            try:
                update_sql(ip, port)

            except:
                add_values(ip, port, 1, str(time.time()), protocol)


def filter_pack(pack):
    """
    filter the packets
    :param pack: packet that received
    :return: boolean - true if the packet is DB packet, otherwise False
    """
    return UDP in pack and pack[IP].dst == '172.16.104.15'


def key_manager():
    """
    Manages the communication regarding the machine2's key.
    :return: key object.
    """
    key = DBKey(5, [], 2)
    key.receive_db_key()
    key.send_db_key()
    return key

def handle_machine2(key):
    while True:  
        pack = sniff(iface='eth0', lfilter=filter_pack, count=1)[0]
        add(pack, key)

def main():
    logging.info('Start the program')

    # Responsible for all signatures
    key = key_manager()

    # Check valid and update the DB
    

    p = [Process(target=ddos.main),
         # Process(target=portscan.main()),
         Process(target=send_sus_list, args=(key,)), 
         Process(target=handle_machine2, args=(key,))]

    for process in p:
        process.start()


if __name__ == '__main__':
    main()
