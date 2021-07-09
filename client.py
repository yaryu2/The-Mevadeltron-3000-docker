from ftplib import FTP

print('nah')
f = FTP('127.0.0.1')
print('yey')
f.sendcmd('LIST')
print('lol')