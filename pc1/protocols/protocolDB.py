from scapy.all import *


class DB(Packet):
    """This is the DB protocol with machine2."""
    name = 'db'
    fields_desc = [
        #   len of the signature.
        ShortField("len_sign", 0),

        #   type of command => 1 - Add // 2 - Response.
        IntEnumField("cmd", 1, {1: "Add", 2: "Response"}),

        #   the machine number that send the packet.
        ShortField("send_num", 0),

        #   all the params in json format (data and signature).
        StrField('param', '')
    ]


bind_layers(UDP, DB, dport=2223)
bind_layers(UDP, DB, sport=2223)
split_layers(UDP, DNS, sport=53)
