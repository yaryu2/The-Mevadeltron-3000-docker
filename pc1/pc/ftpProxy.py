import sys; sys.path.append('../protocols')
from protocol_pack import PACK
from scapy.all import *


def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 21))
    s.listen(1)
    c, addr = s.accept()
    print(c)
    ss = StreamSocket(c, Raw)
    request = ss.sr1(Raw("220\r\n"))

    ftp = PACK(
        sport=addr[1],
        dport=21,
        src_IP=addr[0],
        type='FTP',
        data=request
    )

    ftp.show()

    pack = IP(dst='255.255.255.255') / UDP(sport=23233, dport=9000) / ftp
    pack.show2()
    send(pack)


if __name__ == '__main__':
    main()
