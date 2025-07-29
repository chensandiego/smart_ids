from scapy.all import IP, TCP, Raw, send

def generate_sql_injection(target_ip, target_port):
    payload = "GET /search?query=' OR 1=1 -- HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=payload)
    send(pkt)
    print(f"Sent SQL Injection test packet to {target_ip}:{target_port}")

def generate_xss(target_ip, target_port):
    payload = "GET /comment?text=<script>alert('XSS')</script> HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=payload)
    send(pkt)
    print(f"Sent XSS test packet to {target_ip}:{target_port}")

if __name__ == "__main__":
    target_ip = "127.0.0.1"
    target_port = 80
    generate_sql_injection(target_ip, target_port)
    generate_xss(target_ip, target_port)
