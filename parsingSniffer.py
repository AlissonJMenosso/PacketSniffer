import socket
import struct
from struct import unpack





def GrabMacAddr(bytesAddr):
    return ':'.join(format(b, '02x') for b in bytesAddr) #Just turns the MAC into a readable format



def grabIP(bytesAddr):
    return '.'.join(map(str, bytesAddr))    #Turns the IP address into a readable format



def ethernetHeader(raw):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw[:14]) #Specifying the 6 bytes Source and 6 bytes Destination Mac, leaving the last 2 for the Ether type. (Order of bytes is crucial)
    destMac = GrabMacAddr(dest)     # Converts raw data into readable strings 
    srcMac = GrabMacAddr(src)       # Converts raw data into readable strings
    proto = socket.htons(prototype) #Sort from network byte order to host byte order
    data = raw[14:]                 # Slicing off the rest that is most likely IP 
    return destMac, srcMac, proto, data



def ipv4Header(raw):
    versionLength = raw[0]           # First byte contains version and header length
    version = versionLength >> 4     # Shift right by 4 bits
    headerLength = (versionLength & 15) * 4     # Skip 8 bytes, read 1 byte for ttl (Time to live), 1 byte for proto (protocol), skip 2 bytes, and read 4 bytes each for src and dest IPs
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw[:20])
    srcIP = grabIP(src)         # Converts raw data into readable strings
    destIP = grabIP(target)     # Converts raw data into readable strings
    data = raw[headerLength:]   # Slice off the IP header to only have data left
    return version, headerLength, ttl, proto, srcIP, destIP, data



def main():
    s = socket.socket(
        socket.AF_PACKET,       # All layer 2 network packets
        socket.SOCK_RAW,        # Specifying the raw packet
        socket.ntohs(0x0003))   #This tells linux systems to capture everything, including ethernet frames

    try:
        while True:
            raw, addr = s.recvfrom(65535)   # Excepts all packet sizes
            eth = ethernetHeader(raw)       # Calling the ethHeader function
            print('\n--------------------------------------------------------------------------------------------------------')
            print('\nEthernet Frame:')
            print('\tDestination MAC: {}, \n\tSource MAC: {}, \n\tProtocol: {}'.format(eth[0], eth[1], eth[2]))
            
            if eth[2] == 8:         # Check to see if Ethernet frame has an IPv4 packet, 8 refers to IPv4
                ipv4 = ipv4Header(eth[3])   # Calling the ethHeader function
                print('\n')
                print('IPv4 Packet:')
                print('\tVersion: {}, \n\tHeader Length: {},\n\tTTL: {}'.format(ipv4[0], ipv4[1], ipv4[2]))
                print('\tProtocol: {},\n\tSource IP: {}, \n\tDestination IP: {}'.format(ipv4[3], ipv4[4], ipv4[5]))
            
            #Didn't make a checker for an IPv6 packet

    except KeyboardInterrupt:
        print('Stopped by the User')
        exit(0)


if __name__ == '__main__':
    main()