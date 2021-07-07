from sql_manage import *
import json
import configparser
import logging
from collections import Counter

logging.basicConfig(format='%(message)s', level=logging.WARNING, filename='sus_list.log')


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

                if str(port) not in json.loads(config[protocol]['Port']):
                    logging.warning(ip)

            ips = dict(Counter([ip[0] for ip in get_ips()]))
            for ip, value in ips.items():
                if value >= int(config['DEFAULT']['max_view_ip']):
                    logging.warning(ip)

        except Exception as e:
            logging.info(e)


def main():
    check_port()


if __name__ == '__main__':
    main()
