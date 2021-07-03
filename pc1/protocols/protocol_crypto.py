from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
from scapy.all import *


def rsa_keys():
    """
    Create rsa keys.
    :return: public and private keys.
    """
    keyPair = RSA.generate(bits=1024)
    pubKey = keyPair.publickey()
    return keyPair, pubKey.public_key()


def verify(public_key, data, signature):
    """
    Check if the signature compatible with the data.
    :param public_key: public key of who send the data.
    :param data: the data that create the signature.
    :param signature: the signature that created by the data and the private key of the sender.
    :return: boolian - True if the signature compatible with the data, otherwise False.
    """
    hash = SHA256.new(data.encode())
    verifier = PKCS115_SigScheme(public_key)
    try:
        verifier.verify(hash, signature)
        return True
    except:
        return False


def sign(private_key, data):
    """
    Create the signature.
    :param private_key: private key of who send the data.
    :param data: the data that create the signature.
    :return: the signature in base64.
    """
    hash = SHA256.new(data.encode())
    signer = PKCS115_SigScheme(private_key)
    return signer.sign(hash)


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
    conf.iface = 'eth1'
    p = Ether(dst=mac) / IP(dst=ip) / UDP() / Raw(public)
    sendp(p)
