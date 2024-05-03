import socket

sox = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
print(sox)

while True:
 print(sox.recvfrom(65565))
