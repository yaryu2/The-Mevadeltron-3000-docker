from scapy.all import *
from Key import Key
from protocol_pack import PACK
import json

dict_port = {
    1: 9000,
    2: 9001,
    3: 9002
}
dict_p2t = {
    20: 'FTP',
    21: 'FTP'
}


class Sender:
    def __init__(self, key, id):
        # Object key.
        self.key = key

        # The identify of the machine.
        self.id = id

        # A queue of packets to answer them.
        self.queue = []

    def filter_pack(self, pack):
        """
        filter the packets
        :param pack: packet that received
        :return: boolean - true if the packet is DB packet, otherwise False
        """
        return UDP in pack and pack[IP].dport == '172.16.101.12'

    def receive_pack(self):
        """Filter and receive the packets"""
        conf.iface = 'eth0'
        self.queue.append(sniff(iface='eth0', count=1)[0])
        self.queue[0].show2()

    def create_signature(self, data):
        """Create signature from the data and the key"""
        return self.key.create_signature(''.join(x for x in data if x.isalpha()))

    def add_signature(self, data):
        """Add signature on another signature"""
        return self.key.create_signature(str(''.join(x for x in data if x.isalpha())[:127]))

    def get_data(self):
        """Return the data from the packet from the head of the queue"""
        return ''.join(x for x in self.queue[0][PACK].data if x.isalpha())

    def get_type(self):
        """Return the type of the the packet from the head of the queue"""
        return self.queue[0][PACK].type

    def get_src_ip(self):
        """Return the type of the the packet from the head of the queue"""
        return self.queue[0][PACK].src_IP

    def get_src_port(self):
        """Return the type of the the packet from the head of the queue"""
        return self.queue[0][PACK].sport

    def convert_i2p(self, id, port, p):
        """Convert the packet from the input protocol to internal protocol"""
        return \
            IP(dst='255.255.255.255') / \
            UDP(dport=dict_port[id]) / \
            PACK(
                sport=p[PACK].sport,
                dport=port,
                src_IP=p[PACK].src_IP,
                type=dict_p2t[port],
                data=p[PACK].data,
                sign=self.create_signature(p[PACK].data)
            )

    def fill_with_sign(self, id, p, data):
        """Add another signature to the packet."""
        return \
            IP(dst='255.255.255.255') / \
            UDP(dport=dict_port[id]) / \
            PACK(
                sport=p[PACK].sport,
                dport=p[PACK].dport,
                src_IP=p[PACK].src_IP,
                type=p[PACK].type,
                data=p[PACK].data,
                sign=json.dumps([self.add_signature(data), p[PACK].sign, p[PACK].sign])
            )

    def send_packet(self, id):
        """Send the packets from input protocol."""
        p = self.queue.pop()
        p.show()
        port = p[PACK].dport
        send(self.convert_i2p(id, port, p))

    def send_protocol_pack(self, id, data=''):
        """Send the packets from internal protocol"""
        p = self.queue.pop()
        send(self.fill_with_sign(id, p, data))

    def verify_signs(self, path):
        """Check that the signatures is valid"""
        p = self.queue[0]
        signature = [str(sign) for sign in json.loads(p[PACK].sign)]
        sign = [signature[1][:127], [''.join(x for x in p[PACK].data if x.isalpha())]]
        return self.key.verify_data(sign, [p[PACK].sign], path)

    def verify_data(self, path):
        """Check that the data is valid"""
        p = self.queue[0]
        return self.key.verify_data([''.join(x for x in p[PACK].data if x.isalpha())], [p[PACK].sign], path)

    def convert_p2o(self):
        """Convert the packet from the internal protocol to output protocol"""
        p = self.queue.pop()
        return [p[PACK].type, ''.join(x for x in p[PACK].data if x.isalpha())]
