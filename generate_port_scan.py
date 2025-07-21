from scapy.all import IP, TCP, send
import random

def generate_port_scan(target_ip, start_port, end_port):
    print(f"Generating port scan traffic to {target_ip} from port {start_port} to {end_port}...")
    for dport in range(start_port, end_port + 1):
        sport = random.randint(1024, 65535)
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(sport=sport, dport=dport, flags="S")
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)
    print("Port scan traffic generation complete.")

if __name__ == "__main__":
    # Example usage: Scan ports 1-100 on 192.168.1.100
    generate_port_scan("192.168.1.100", 1, 100)
