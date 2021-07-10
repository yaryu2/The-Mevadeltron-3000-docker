import socket

def main(cmd):
    s = socket.socket()
    s.bind(('0.0.0.0', 5000))
    s.listen()
    s.accept()
    s.send(cmd.encode())
