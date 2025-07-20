from scapy.all import IP, TCP, Ether, wrpcap
import random

def generate_syn_flood_pcap(num_packets, output_file):
    packets = []
    target_ip = "192.168.1.100"  # Target IP address for the simulated attack
    target_port = 80  # Target port (e.g., HTTP)

    for _ in range(num_packets):
        source_ip = "10.0.0." + str(random.randint(1, 254))
        source_port = random.randint(1024, 65535)
        
        # Craft a SYN packet
        ip_layer = IP(src=source_ip, dst=target_ip)
        tcp_layer = TCP(sport=source_port, dport=target_port, flags="S")
        packet = ip_layer / tcp_layer
        packets.append(packet)

    wrpcap(output_file, packets)
    print(f"Generated {num_packets} SYN packets to {target_ip}:{target_port} in {output_file}")

if __name__ == "__main__":
    generate_syn_flood_pcap(10000, "syn_flood.pcap")
