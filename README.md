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

**Note:** Running the program will have a messy output like this, but this can be cleaned up for better readability.
```
\xe7\xfa\'zApa\xbf\x19U\xf9\xe7\xbalV4\xe1\x03\xf8\xcd-\x07\xb6%\x94\xc7\xa3\x03\xdc\x8cQ\x88X\xab\xd5\x06\\\x95\xe0\x87\xa9\xce\xaf\xc0\x9b\xf4\x0ei\xa9\xbc\x0b\xfd=\x8emr\xfcU\x81\x85\xb4\x9a\xf6"t\xd6M-\x1fh\x05\xe7$\x1b\xac\x08\xb0\x85\xdbP5\xad\x1f\xeb\x17\x0b\x85g.e\x05P\x1b,\xce\xd0Q\xa4\xab\xd3\xa6tv\xa4{.\xcd\xfe\t\xb4;\xd3\x9a.ED\xe3\x1cq\x12\xeb>hp\x10\xe6\x9f\xcb\xfb\r\x8c\xf1w\xb9\xc1\xd8\x02\r\xef\xb0q\x15q\n[\xde\r\xa9P\xe08\t_\xa4\xe7\x89m\x0e\x9f\xc2\xddaJL\n\x05\xbb\x90\xe4A\xda\x12\x1a\xf9[\xd8\x9f\xb1^\x19\xb9\xd4\xe9\xa4c\xc0Doz\xb5G\xd3 \x87\x0b\xe1d\x99\x9e\x08\xeb\xb6\xae\x86_@\x98\r\x91)|\xb1\x91r\x9f\xe5\xe4%R\r\xab9\xd6\xea\x04\x92H\x8e;5\xb3\x13\xe5V\xa7\xc8x\xa2\x87\xf5\x99\xb1Y\x05l\xdf\x8dQ\xde\x8bI)~\xeab\xe2\x18\x9d\tA\xd7\x01K\xf1\x18\x7f\xe3|\x9c\xae\xfdr'
```

# [Basic Sniffer](https://github.com/CarterPry/PacketSniffer/blob/main/parsingSniffer.py) script
