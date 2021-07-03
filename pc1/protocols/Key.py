from protocol_crypto import *
import logging
import json

Machines = {
    1: 8053,
    2: 8023,
    3: 8033,
    4: 8044,
    5: 8000
}

IP = {
    1: "172.16.101.12",
    2: "172.16.102.13",
}



MAC ={
    1: '98:98:98:22:22:22',
    2: '98:98:98:33:33:33',
}


logging.basicConfig(level=logging.DEBUG)


def create_keys():
    """
    Create private and public keys.
    Set them as self parameter.
    """
    return rsa_keys()


class Key:
    def __init__(self, id, ports):
        #   id - The number of the machine
        self.id = id

        #   s_port - The source port of the machine
        self.s_port = Machines[self.id]

        #   private/public_key - Keys that created by the function 'create_keys()'
        self.private_key, self.public_key = create_keys()

        #   ports - The port that sends to the current machine
        self.ports = ports

        #   dictionary - receive all the port as key and keys of others machines as a value
        self.keys = {}

    def receive_all_keys(self):
        """
        Receive keys from all the ports that inside ports-list.
        Add those keys to keys-dictionary parameter
        """
        data = receive_keys()
        keys = json.loads(data)

        for port, key in zip(self.ports, keys):
            self.keys[port] = create_rsa_from_keys(key)

    def send_keys(self, port):
        """
        Send the public key to everyone who in ports-list.
        :param port: which machine is after the current machine.
        """
        msg = [value.exportKey().decode() for value in self.keys.values()]
        msg.append(self.public_key.exportKey().decode())

        if len(msg) > 2:
            msg = msg[-2:]
        print(msg)
        send_keys(json.dumps(msg), '172.16.101.12', '98:98:98:22:22:22')

    def create_signature(self, data):
        """
        Create signature from the data and the private key.
        :param data: must be string and no more than 128 bytes (length of the string)
        :return: return the signature that created.
        """
        return sign(self.private_key, data)

    def verify_data(self, data, signature, path):
        """
        if the data created the signature the return value will be True, otherwise False.
        :param data: list of strings that each string created the signature.
        :param signature: list of signature that created by the data.
        :param path: list that contain the path that the packet did (to know which public key should I use)
        :return: boolean.
        """
        for machine_id, current_data, current_signature in zip(path, data, signature):
            if not verify(self.keys[machine_id], current_data, current_signature):
                return False

        return True


class DBKey(Key):
    def __init__(self, id, ports, port):
        Key.__init__(self, id, ports)
        # port - The port that sends to the current machine.
        self.port = port

        # db_key - the key that responsible about the db.
        self.db_key = None

    def send_db_key(self):
        """
        Send the public key between machine2 and the db-server.
        """
        send_keys(self.public_key.exportKey().decode(), IP[self.port], Machines[self.port])

    def receive_db_key(self):
        """
        Receive key from machine2/db-server the ports.
        Add this key to db_key parameter.
        """
        key = receive_keys(self.s_port)
        self.db_key = create_rsa_from_keys(key)

    def verify_data_db(self, data, signature):
        """
        if the data created the signature the return value will be True, otherwise False.
        :param data: string that created the signature.
        :param signature: signature that created by the data.
        :return: boolean.
        """
        return verify(self.db_key, data, signature)


split_layers(UDP, DNS)