from sql_manage import *
import threading
import logging
import json
import configparser


logging.basicConfig(level=logging.INFO)
BLACK_LIST = []


def inform_about_sus():
    """When there is new suspicious IP it updates the sus_list.txt on the new IP"""
    with open('sus_list.txt', 'r') as sus_file:
        sus = json.loads(sus_file.read())

    [BLACK_LIST.append(i) for i in sus if i not in BLACK_LIST]

    with open('sus_list.txt', 'w') as sus_file:
        sus_file.write(json.dumps(BLACK_LIST))


def check_port():
    """
    This function run as a Process.
    Scans the DB and Checks if there is a deviation in the fields of the port (by config file).
    """
    config = configparser.ConfigParser()
    config.read('config.ini')

    while True:
        try:
            for user in get_all_ip():
                ip, protocol, port = str(user[0][0]), str(user[1][0]), user[2][0]
                if port not in json.loads(config[protocol]['Port']) and ip not in BLACK_LIST:
                    BLACK_LIST.append(ip)
                    inform_about_sus()

                    logging.info(str(BLACK_LIST))

        except Exception as e:
            logging.debug(e)


def main():
    threading.Thread(target=check_port).start()


if __name__ == '__main__':
    inform_about_sus()
