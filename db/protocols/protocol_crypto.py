from Crypto.PublicKey import RSA
from Crypto import Random
import base64
from scapy.all import *


def rsa_keys():
    """
    Create rsa keys.
    :return: public and private keys.
    """
    length = 1024
    private_key = RSA.generate(length, Random.new().read)
    public_key = private_key.publickey()
    return private_key, public_key


def verify(public_key, data, signature):
    """
    Check if the signature compatible with the data.
    :param public_key: public key of who send the data.
    :param data: the data that create the signature.
    :param signature: the signature that created by the data and the private key of the sender.
    :return: boolian - True if the signature compatible with the data, otherwise False.
    """
    return public_key.verify(data, (int(base64.b64decode(signature)),))


def sign(private_key, data):
    """
    Create the signature.
    :param private_key: private key of who send the data.
    :param data: the data that create the signature.
    :return: the signature in base64.
    """
    return base64.b64encode(str((private_key.sign(data, ''))[0]).encode())


def create_rsa_from_keys(key):
    """
    Create RSA object from the string key.
    :param key: plain text of the key in base64.
    :return: RSA object that contain the key.
    """
    return RSA.importKey((key))


def send_keys(public, ip, mac):
    """
    Send the public key to other machines.
    :param public: public key
    :param port: which port to send the key.
    """
    conf.iface = 'eth0'
    p = Ether(dst=mac) / IP(dst=ip) / UDP() / Raw(public)
    sendp(p)

def filter_pack_key_db(pack):
    return UDP in pack and pack[IP].dst == '172.16.104.15'

def receive_keys_db():
    """
    Receive the keys from other machines.
    :return: the key from other machines.
    """
    conf.iface = 'eth0'
    p = sniff(iface='eth0', lfilter=filter_pack_key_db, count=1)[0]
    return p[Raw].load.decode()