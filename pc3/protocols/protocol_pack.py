from scapy.all import *


class StrFixedLenField(StrField):
    def addfield(self, pkt, s, val):
        return s + struct.pack("%is" % self.length, self.i2m(pkt, val))

    def getfield(self, pkt, s):
        return s[self.length:], self.m2i(pkt, s[:self.length])


def vlenq2str(l):
    s = [l & 0x7F]
    l = l >> 7
    while l > 0:
        s.append(0x80 | (l & 0x7F))
        l = l >> 7
    s.reverse()
    return bytes(bytearray(s))


def str2vlenq(s=b""):
    i = l = 0
    while i < len(s) and ord(s[i:i + 1]) & 0x80:
        l = l << 7
        l = l + (ord(s[i:i + 1]) & 0x7F)
        i = i + 1
    if i == len(s):
        warning("Broken vlenq: no ending byte")
    l = l << 7
    l = l + (ord(s[i:i + 1]) & 0x7F)

    return s[i + 1:], l


class VarLenQField(Field):
    """ variable length quantities """
    __slots__ = ["fld"]

    def __init__(self, name, default, fld):
        Field.__init__(self, name, default)
        self.fld = fld

    def i2m(self, pkt, x):
        if x is None:
            f = pkt.get_field(self.fld)
            x = f.i2len(pkt, pkt.getfieldval(self.fld))
            x = vlenq2str(x)
        return raw(x)

    def m2i(self, pkt, x):
        if s is None:
            return None, 0
        return str2vlenq(x)[1]

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return str2vlenq(s)


class PACK(Packet):
    """
    This is the internal protocol.
    Every request from the clint converted to this protocol.
    """
    name = "pack"
    fields_desc = [
        #   destination port from the request packet.
        ShortField("dport", 0),

        #   source port from the request packet.
        ShortField("sport", 0),

        #   source IP from the request packet, and its length.
        VarLenQField("len", None, "src_IP"),
        StrLenField("src_IP", "", length_from=lambda pkt: pkt.len),

        #   the type of the request packet, and its length.
        VarLenQField("len1", None, "type"),
        StrLenField("type", "", length_from=lambda pkt: pkt.len1),

        #   the raw from the request packet, and its length.
        VarLenQField("len2", None, "data"),
        StrLenField("data", "", length_from=lambda pkt: pkt.len2),

        #   the signature that created, and its length.
        VarLenQField("len3", None, "sign"),
        StrLenField("sign", "", length_from=lambda pkt: pkt.len3),

        #   the signature that created, and its length.
        VarLenQField("len5", None, "sign2"),
        StrLenField("sign2", "", length_from=lambda pkt: pkt.len5),

        #   the raw from the request packet, and its length.
        VarLenQField("len4", None, "data2"),
        StrLenField("data2", "", length_from=lambda pkt: pkt.len4)
        ]


bind_layers(UDP, PACK, dport=9000)
bind_layers(UDP, PACK, dport=9001)
bind_layers(UDP, PACK, dport=9002)
split_layers(UDP, DNS, sport=53)
