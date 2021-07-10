import socket

s = socket.socket()
s.connect(('127.0.0.1', 5000))
print(s.recv(8))
# s = socket.socket()
# s.bind(('0.0.0.0', 5000))
# s.listen()
# s.accept()