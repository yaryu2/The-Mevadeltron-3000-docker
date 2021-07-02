import sys; sys.path.append('../protocols')
from protocol_crypto import *
from scapy.all import *
from Key import Key
from ftplib import FTP
from protocol_send import Sender


dict_ip_server = {
    'FTP': 'ftp.us.debian.org'
}


def key_manager():
    """
    Manages the communication regarding the keys.
    :return: key object.
    """
    key = Key(3, [1, 2])
    key.receive_all_keys()

    return key


def main():
    logging.info('Start the program')

    # Responsible for all signatures
    key = key_manager()

    logging.info('Got the key')

    # Receive the packet from machine2
    s = Sender(key, 3)
    s.receive_pack()
    s.queue[0].show()
    # Verify the signatures
    if s.verify_signs([2, 1]):
        logging.info('received and verify')

        # Convert internal protocol to original protocol
        ip, cmd = s.convert_p2o()
        ftp = FTP(dict_ip_server[ip])
        ftp.sendcmd(cmd)


if __name__ == '__main__':
    main()
