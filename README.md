# [Basic Sniffer](https://github.com/CarterPry/PacketSniffer/blob/main/basicSniffer.py) script

This Python-based packet sniffer utilizes an INET raw socket to capture packets. Below is a guide on how it works and how to use it:
- Both scripts are for Linux environments only.
- We use an INET raw socket to capture packets.
- Raw sockets can only send and receive IP packets, meaning layers 3-4 and the application layer.
- **Warning:** Most OS's will require root access to run a raw socket for it is low-level access to network protocols.
- **Note:** The behavior of the socket API can be very different depending on the OS you use (Windows, Mac, or Linux).

## Creating the Socket

First we create an INET family socket:
```
sox = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
```
- Zsocket.AF_INETZ = Specifies to use IPv4 addresses.
- Zsocket.SOCK_RAWZ = Sets the socket to be raw, which means we can operate at a low level and manipulate/access network packets.
- Zsocket.IPPROTO_TCPZ = TCP will be used with the socket.

## Parameters Explained
#### Parameter 1: Address Family
This parameter describes the address family. We used IPv4, but you can use the options like these:

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
The protocol used for this has to match the family of the socket. For example, we are using IPv4 here, so only IP protocols can be used, like TCP.

## Infinite Loop for Data Reception
To continuously receive data, we create an infinite loop:
```
while True:
    print(sox.recvfrom(65565))
```
The 'recvfrom' function is running on our socket, which essentially just receives data through it with the max buffer size of '65565'. Meaning we should be able to capture packets of all sizes. No discrimination here.
**Note:** Running the program will have a messy output like this, but this can be cleaned up for better readability.
```
\xe7\xfa\'zApa\xbf\x19U\xf9\xe7\xbalV4\xe1\x03\xf8\xcd-\x07\xb6%\x94\xc7\xa3\x03\xdc\x8cQ\x88X\xab\xd5\x06\\\x95\xe0\x87\xa9\xce\xaf\xc0\x9b\xf4\x0ei\xa9\xbc\x0b\xfd=\x8emr\xfcU\x81\x85\xb4\x9a\xf6"t\xd6M-\x1fh\x05\xe7$\x1b\xac\x08\xb0\x85\xdbP5\xad\x1f\xeb\x17\x0b\x85g.e\x05P\x1b,\xce\xd0Q\xa4\xab\xd3\xa6tv\xa4{.\xcd\xfe\t\xb4;\xd3\x9a.ED\xe3\x1cq\x12\xeb>hp\x10\xe6\x9f\xcb\xfb\r\x8c\xf1w\xb9\xc1\xd8\x02\r\xef\xb0q\x15q\n[\xde\r\xa9P\xe08\t_\xa4\xe7\x89m\x0e\x9f\xc2\xddaJL\n\x05\xbb\x90\xe4A\xda\x12\x1a\xf9[\xd8\x9f\xb1^\x19\xb9\xd4\xe9\xa4c\xc0Doz\xb5G\xd3 \x87\x0b\xe1d\x99\x9e\x08\xeb\xb6\xae\x86_@\x98\r\x91)|\xb1\x91r\x9f\xe5\xe4%R\r\xab9\xd6\xea\x04\x92H\x8e;5\xb3\x13\xe5V\xa7\xc8x\xa2\x87\xf5\x99\xb1Y\x05l\xdf\x8dQ\xde\x8bI)~\xeab\xe2\x18\x9d\tA\xd7\x01K\xf1\x18\x7f\xe3|\x9c\xae\xfdr'
```

# [Basic Sniffer](https://github.com/CarterPry/PacketSniffer/blob/main/parsingSniffer.py) script
## Understanding Packet Structures
To understand the functions, you should know the basic structures of Ethernet and IP packets:

<p align="center">
  <img src="https://static.javatpoint.com/tutorial/computer-network/images/ethernet-frame-format.png" alt="Frame Header" width="250" height="400" />
</p>

- **Ethernet Frame**: The frame includes:
  - **Destination Address**: The first 6 bytes represent the destination MAC address.
  - **Source Address**: The next 6 bytes are the source MAC address.
  - **EtherType**: The last 2 bytes are the protocols used, such as IPv4, IPv6, ARP, etc.


<p align="center">
  <img src="https://www.pynetlabs.com/wp-content/uploads/2023/12/ipv4-header-image.jpeg" alt="IP Header" width="250" height="400" />
</p>

- **IP Header (RFC 791)**: The IP packet includes:
  - **Version and Header Length**: The first byte contains the protocol version and header length.
  - **Type of Service**: Specifies how an upper-layer protocol would like a current datagram to be handled.
  - **Total Length**: The length of the entire IP packet.
  - **Identification, Flags, Fragment Offset**: Used for fragmenting or reassembling IP packets.
  - **Time To Live (TTL)**: How long the packet's lifetime is.
  - **Protocol**: Indicates the protocol used in the data of the IP packet.
  - **Header Checksum**: IP header integrity.
  - **Source and Destination IP Addresses**: The origin and destination of the packet.

## Function Descriptions

### Ethernet Header Parsing
The `ethernetHeader(raw)` function parses the Ethernet frame from all of the raw packet data:
```
def ethernetHeader(raw):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw[:14]) #Specifying the 6 bytes Source and 6 bytes Destination Mac, leaving the last 2 for the Ether type.
    destMac = GrabMacAddr(dest)     # Converts raw data into readable strings 
    srcMac = GrabMacAddr(src)       # Converts raw data into readable strings
    proto = socket.htons(prototype) #Sort from network byte order to host byte order
    data = raw[14:]                 # Slicing off the rest that is most likely IP 
    return destMac, srcMac, proto, data
```

### IPv4 Header Parsing
The `ipv4Header(raw)` function extracts and parses the IP header from all the packet data:
```
def ipv4Header(raw):
    versionLength = raw[0]           # First byte contains version and header length
    version = versionLength >> 4     # Shift right by 4 bits
    headerLength = (versionLength & 15) * 4     # Skip 8 bytes, read 1 byte for ttl, 1 byte for proto, skip 2 bytes, and read 4 bytes each for src and dest IPs
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw[:20])
    srcIP = grabIP(src)         # Converts raw data into readable strings
    destIP = grabIP(target)     # Converts raw data into readable strings
    data = raw[headerLength:]   # Slice off the IP header to only have data left
    return version, headerLength, ttl, proto, srcIP, destIP, data
```

## Running the Scripts
You will need root privileges to run the raw sockets for how much access it needs.
**Again this is meant for a Linux environment**
```
sudo python3 parsingSniffer.py
```

**Note:** The script will continuously print out parsed packets until manually stopped.
