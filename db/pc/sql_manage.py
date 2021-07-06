import sqlite3
import logging

logging.basicConfig(format='%(message)s', level=logging.WARNING, filename='sus_list.log')


def create_table():
    """Create a new table in the DB"""
    sql = sqlite3.connect('data.db')
    cursor = sql.cursor()
    logging.debug("Successfully Connected to SQLite")

    cursor.execute(
        '''CREATE TABLE Status
            ([ip] text, [port] integer, [count_requests] integer, [t_start] integer, [protocol] text)'''
                   )

    cursor.close()


def add_values(ip, port, count_requests, t_start, protocol):
    """
    Add all new values to the data base.
    :param ip: source IP of the sender.
    :param port: source port of the sender.
    :param count_requests: this value is 1 by default.
    :param t_start: the time that the first packet from this port and IP send.
    :param protocol: the type of the packet.
    """
    sql = sqlite3.connect('data.db')
    cursor = sql.cursor()

    logging.debug("Successfully Connected to SQLite")

    sqlite_insert_query = """INSERT INTO Status
                          (ip, port, count_requests, t_start, protocol)
                           VALUES 
                          (?, ?, ?, ?, ?)"""

    data = (ip, port, count_requests, t_start, protocol)

    cursor.execute(sqlite_insert_query, data)
    sql.commit()

    cursor.close()


def update_sql(ip, port):
    """
    Increase the count_request value in the IP and the port located.
    :param ip: source IP of the sender.
    :param port: source port of the sender.
    """
    sql = sqlite3.connect('data.db')
    cursor = sql.cursor()

    count_request_cmd = """SELECT count_requests FROM Status WHERE ip = ? AND port = ?"""
    cursor.execute(count_request_cmd, [ip, port])
    count_request = cursor.fetchall()[0][0] + 1

    sql_update_query = """Update Status set count_requests = ? where ip = ? AND port = ?"""
    data = (count_request, ip, port)

    cursor.execute(sql_update_query, data)
    sql.commit()

    logging.debug("Record Updated successfully")

    cursor.close()


def delete_ip(ip):
    """
    Delete IP from the table if its not found as suspicious in 1 min
    :param ip: source IP of the sender.
    """
    sql = sqlite3.connect('data.db')
    cursor = sql.cursor()

    # Deleting single record now
    sql_delete_query = """DELETE from Status where ip = ?"""

    cursor.execute(sql_delete_query, [ip])
    sql.commit()

    logging.debug("Record deleted successfully ")

    cursor.close()
    sql.close()


def get_count_request():
    """
    Get the count_request from the DB.
    :return: list that contain ip, count_requests, protocol
    """
    sql = sqlite3.connect('data.db')
    cursor = sql.cursor()

    get_ip = """SELECT ip FROM Status"""

    ip = cursor.execute(get_ip).fetchall()

    get_count = """SELECT count_requests FROM Status"""

    count_requests = cursor.execute(get_count).fetchall()

    get_protocol = """SELECT protocol FROM Status"""

    protocol = cursor.execute(get_protocol).fetchall()

    cursor.close()
    sql.close()

    return zip(ip, count_requests, protocol)


def get_time_start():
    """
    Get the time start from the DB.
    :return: list that contain ip, time, protocol
    """
    sql = sqlite3.connect('data.db')
    cursor = sql.cursor()

    get_ip = """SELECT ip FROM Status"""

    ip = cursor.execute(get_ip).fetchall()

    get_time = """SELECT t_start FROM Status"""

    time = cursor.execute(get_time).fetchall()

    get_protocol = """SELECT protocol FROM Status"""

    protocol = cursor.execute(get_protocol).fetchall()

    cursor.close()

    return zip(ip, time, protocol)


def get_all_ip():
    """
    Get the IPs from the DB.
    :return: list that contain ip, protocol, port
    """
    sql = sqlite3.connect('data.db')

    cursor = sql.cursor()

    get_ip = """SELECT ip FROM Status"""

    ip = cursor.execute(get_ip).fetchall()

    get_protocol = """SELECT protocol FROM Status"""

    protocol = cursor.execute(get_protocol).fetchall()

    get_port = """SELECT port FROM Status"""

    port = cursor.execute(get_port).fetchall()

    cursor.close()

    return zip(ip, protocol, port)


def get_ips():
    """
    Get the IPs from the DB.
    :return: list that contain ip, protocol, port
    """
    sql = sqlite3.connect('data.db')

    cursor = sql.cursor()

    get_ip = """SELECT ip FROM Status"""

    ip = cursor.execute(get_ip).fetchall()

    cursor.close()

    return ip


from collections import Counter
ips = Counter([ip[0] for ip in get_ips()])

print(ips)