import sys; sys.path.append('../protocols')
from protocol_pack import PACK
from scapy.all import *
from select import select


def open_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 21))
    s.listen(1)
    return s.accept()


def create_pack(c, data, port, addr, type_pack):
    ss = StreamSocket(c, Raw)
    request = ss.sr1(Raw(data))

    pack_layer = PACK(
        sport=addr[1],
        dport=port,
        src_IP=addr[0],
        type=type_pack,
        data=request
    )

    pack_layer.show()

    return IP(dst='255.255.255.255') / UDP(sport=2323, dport=9000) / pack_layer


def multi(port, type_pack, data=''):
    server = open_server(port)
    clients = []
    pack_to_send = []

    while True:
        rlist, wlist, xlist = select([server] + clients[0], [], [])

        for current_socket in rlist:
            if current_socket is server:
                c, addr = current_socket.accept()
                pack_to_send.append(create_pack(c, data, port, addr, type_pack))
                clients.append([c, addr])

            else:
                ss = StreamSocket(current_socket, Raw)
                request = ss.sr1(Raw(data))


def server1(type_pack, port, q):
    # print('start')
    # c, addr = open_server(port)
    # print('fucking did it')
    # ss = StreamSocket(c, Raw)
    # request = ss.sr1(Raw(data))

    addr = ('127.0.0.1', 55555)
    request = 'LIST'

    pack_layer = PACK(
        sport=addr[1],
        dport=port,
        src_IP=addr[0],
        type=type_pack,
        data=request
    )

    q.put(pack_layer)


if __name__ == '__main__':
    server1('FTP', 21, "220\r\n")
