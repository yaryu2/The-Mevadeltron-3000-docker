from sql_manage import *
import time
import threading
import logging
import json
import configparser


logging.basicConfig(format='%(message)s', level=logging.WARNING, filename='sus_list.log')
BLACK_LIST = []


def check_count():
    """
    This function run as a Process.
    Scans the DB and looks for anomalies in the amount of messages a particular computer sends (by config file).
    """

    config = configparser.ConfigParser()
    config.read('config.ini')

    while True:
        try:
            for user in get_count_request():
                ip, count, protocol = str(user[0][0]), user[1][0], str(user[2][0])
                if count >= int(config[protocol]['Count Request']) and ip not in BLACK_LIST:
                    BLACK_LIST.append(ip)
                    logging.warning(ip)

        except Exception as e:
            logging.debug(e)


def delete_by_time():
    """
    This function run as a Process.
    Deletes the IP if no minute deviation is found since the first packet sent by it
    """
    while True:
        try:
            now = time.time()
            for user in get_time_start():
                ip, start, protocol = str(user[0][0]), user[1][0], str(user[2][0])
                
                if now - start >= 60 and ip not in BLACK_LIST:
                    delete_ip(ip)

        except Exception as e:
            logging.info(e)


def main():
    threads = [threading.Thread(target=check_count), threading.Thread(target=delete_by_time)]
    for thread in threads:
        thread.start()
