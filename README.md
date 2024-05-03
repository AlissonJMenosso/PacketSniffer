# [Basic Sniffer](https://github.com/CarterPry/PacketSniffer/blob/main/basicSniffer.py) script

This Python-based packet sniffer utilizes an INET raw socket to capture packets. Below is a guide on how it works and how to use it:

- We use an INET raw socket to capture packets.
- Raw sockets can only send and receive IP packets, covering layers 3-4 and the application layer.
- **Warning:** Most operating systems will require root access to utilize a raw socket as it provides low-level access to network protocols.
- **Note:** The behavior of the socket API can vary depending on the operating system (Windows, Mac, or Linux).

## Creating the Socket

Initially, we create an INET family socket:

Z
sox = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
Z

- Zsocket.AF_INETZ specifies the use of IPv4 addresses.
- Zsocket.SOCK_RAWZ sets the socket to operate at a low-level, allowing manipulation and access to network packets.
- Zsocket.IPPROTO_TCPZ indicates that the TCP protocol will be used with the socket.

## Parameters Explained

#### Parameter 1: Address Family

This parameter describes the address family. We use IPv4, but there are other options available:


| Address Family   | Description                             |
|------------------|-----------------------------------------|
| AF_LOCAL         | Local communication                     |
| AF_UNIX          | Unix domain sockets                     |
| AF_INET          | IP version 4                            |
| AF_INET6         | IP version 6                            |
| AF_IPX           | Novell IPX                              |
| AF_NETLINK       | Kernel user-interface device            |
| AF_X25           | Reserved for X.25 project               |
| AF_AX25          | Amateur Radio AX.25                     |
| AF_APPLETALK     | AppleTalk DDP                           |
| AF_PACKET        | Low-level packet interface              |
| AF_ALG           | Interface to kernel crypto API          |


#### Parameter 2: Socket Type
We use a raw socket, but other types are available:

| Socket Type      | Description                                   |
|------------------|-----------------------------------------------|
| SOCK_STREAM      | Stream (connection) socket                    |
| SOCK_DGRAM       | Datagram (connection-less) socket             |
| SOCK_RAW         | Raw socket                                    |
| SOCK_RDM         | Reliably delivered message                    |
| SOCK_SEQPACKET   | Sequential packet socket                      |
| SOCK_PACKET      | Linux-specific method for packet manipulation |


#### Parameter 3: Protocol
The protocol used must match the family of the socket. We chose TCP, but UDP is another common choice.

## Infinite Loop for Data Reception
To continuously receive data, we create an infinite loop:
```
while True:
    print(sox.recvfrom(65565))
```

**Note:** Running the program may initially produce messy outputs, but this can be cleaned up for better readability.

# [Basic Sniffer](https://github.com/CarterPry/PacketSniffer/blob/main/parsingSniffer.py) script
