import socket
import struct

def GrabMacAddr(bytesAddr):
    return ':'.join(format(b, '02x') for b in bytesAddr) # Just turns the MAC into a readable format

def grabIP(bytesAddr):
    return '.'.join(map(str, bytesAddr)) # Turns the IP address into a readable format

def grabIPv6(bytesAddr):
    return ':'.join(format(struct.unpack('!H', bytesAddr[i:i+2])[0], '04x') for i in range(0, 16, 2)) # Convert raw bytes to IPv6 format

def ethernetHeader(raw):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw[:14]) # Specify the 6 bytes Source and 6 bytes Destination Mac, leaving the last 2 for the Ether type. (Order of bytes is crucial)
    destMac = GrabMacAddr(dest) # Converts raw data into readable strings 
    srcMac = GrabMacAddr(src) # Converts raw data into readable strings
    proto = socket.htons(prototype) # Sort from network byte order to host byte order
    data = raw[14:] # Slice off the rest that is most likely IP 
    return destMac, srcMac, proto, data

def ipv4Header(raw):
    versionLength = raw[0] # First byte contains version and header length
    version = versionLength >> 4 # Shift right by 4 bits
    headerLength = (versionLength & 15) * 4 # Calculate header length
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw[:20])
    srcIP = grabIP(src) # Converts raw data into readable strings
    destIP = grabIP(target) # Converts raw data into readable strings
    data = raw[headerLength:] # Slice off the IP header to only have data left
    return version, headerLength, ttl, proto, srcIP, destIP, data

def ipv6Header(raw):
    version_traffic_flow = struct.unpack('!I', raw[:4])[0]
    version = (version_traffic_flow >> 28) & 0xF
    payload_length, next_header, hop_limit, src, target = struct.unpack('! H B B 16s 16s', raw[4:40])
    srcIP = grabIPv6(src) # Converts raw data into readable strings
    destIP = grabIPv6(target) # Converts raw data into readable strings
    data = raw[40:] # Slice off the IP header to only have data left
    return version, payload_length, next_header, hop_limit, srcIP, destIP, data

def icmpHeader(raw):
    icmp_type, code, checksum = struct.unpack('! B B H', raw[:4])
    return icmp_type, code, checksum, raw[4:]

def udpHeader(raw):
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', raw[:8])
    data = raw[8:]
    return src_port, dest_port, length, checksum, data

def main():
    s = socket.socket(
        socket.AF_PACKET, # All layer 2 network packets
        socket.SOCK_RAW, # Specifying the raw packet
        socket.ntohs(0x0003)) # This tells Linux systems to capture everything, including Ethernet frames

    try:
        while True:
            raw, addr = s.recvfrom(65535) # Accept all packet sizes
            eth = ethernetHeader(raw) # Call the ethHeader function
            print('\n--------------------------------------------------------------------------------------------------------')
            print('\nEthernet Frame:')
            print('\tDestination MAC: {}, \n\tSource MAC: {}, \n\tProtocol: {}'.format(eth[0], eth[1], eth[2]))
            
            if eth[2] == 8: # Check to see if Ethernet frame has an IPv4 packet
                ipv4 = ipv4Header(eth[3]) # Call the ipv4Header function
                print('\nIPv4 Packet:')
                print('\tVersion: {}, \n\tHeader Length: {},\n\tTTL: {}'.format(ipv4[0], ipv4[1], ipv4[2]))
                print('\tProtocol: {},\n\tSource IP: {}, \n\tDestination IP: {}'.format(ipv4[3], ipv4[4], ipv4[5]))
                
                if ipv4[3] == 1: # Check if the protocol is ICMP
                    icmp = icmpHeader(ipv4[6]) # Call the icmpHeader function
                    print('\nICMP Packet:')
                    print('\tType: {}, \n\tCode: {}, \n\tChecksum: {}'.format(icmp[0], icmp[1], icmp[2]))
                
                elif ipv4[3] == 17: # Check if the protocol is UDP
                    udp = udpHeader(ipv4[6]) # Call the udpHeader function
                    print('\nUDP Packet:')
                    print('\tSource Port: {}, \n\tDestination Port: {}, \n\tLength: {}, \n\tChecksum: {}'.format(udp[0], udp[1], udp[2], udp[3]))
            
            elif eth[2] == 56710: # Check to see if Ethernet frame has an IPv6 packet
                ipv6 = ipv6Header(eth[3]) # Call the ipv6Header function
                print('\nIPv6 Packet:')
                print('\tVersion: {}, \n\tPayload Length: {}, \n\tNext Header: {}, \n\tHop Limit: {}'.format(ipv6[0], ipv6[1], ipv6[2], ipv6[3]))
                print('\tSource IP: {}, \n\tDestination IP: {}'.format(ipv6[4], ipv6[5]))
                
                if ipv6[2] == 58: # Check if the next header is ICMPv6
                    icmpv6 = icmpHeader(ipv6[6]) # Call the icmpHeader function
                    print('\nICMPv6 Packet:')
                    print('\tType: {}, \n\tCode: {}, \n\tChecksum: {}'.format(icmpv6[0], icmpv6[1], icmpv6[2]))
                
                elif ipv6[2] == 17: # Check if the next header is UDP
                    udp = udpHeader(ipv6[6]) # Call the udpHeader function
                    print('\nUDP Packet:')
                    print('\tSource Port: {}, \n\tDestination Port: {}, \n\tLength: {}, \n\tChecksum: {}'.format(udp[0], udp[1], udp[2], udp[3]))

    except KeyboardInterrupt:
        print('Stopped by the User')
        exit(0)

if __name__ == '__main__':
    main()
