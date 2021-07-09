import sys; sys.path.append('../protocols')
from protocol_pack import PACK
from scapy.all import *
from select import select
from time import sleep
from multiprocessing import Queue


def open_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', int(port)))
    s.listen(1)
    return s


def create_pack(c, data, port, addr, type_pack, q):
    ss = StreamSocket(c, Raw)
    request = ss.sr1(Raw("220\r\n".encode()))

    pack_layer = PACK(
        sport=addr[1],
        dport=port,
        src_IP=addr[0],
        type=type_pack,
        data=request
    )

    q.put(pack_layer)


def multi(port, type_pack, q, data=''):
    server = open_server(port)
    clients = []
    try:
        while True:
            rlist, wlist, xlist = select([server] + clients, [], [])

            for current_client in rlist:
                if current_client is server:
                    c, addr = current_client.accept()
                    create_pack(c, data, port, addr, type_pack, q)
    except KeyboardInterrupt:
        server.close()


if __name__ == '__main__':
    multi(21, 'FTP', Queue(), "220\r\n")
