from __future__ import annotations

import argparse
import random
import time
from datetime import datetime
import requests

SRC_IPS = [f'192.168.1.{i}' for i in range(10, 120)]
DST_IPS = ['8.8.8.8', '1.1.1.1', '172.16.0.5', '10.0.0.12', '192.168.1.1']
PROTOCOLS = ['TCP', 'UDP', 'ICMP']
ATTACK_PORTS = [21, 22, 53, 80, 443, 8080, 3389, 4444]
FLAGS = ['SYN', 'ACK', 'PSH,ACK', 'FIN,ACK', 'RST', 'SYN,ACK']

# making a random flow
def make_flow() -> dict:
    attack_mode = random.random() < 0.30
    protocol = random.choices(PROTOCOLS, weights=[0.65, 0.25, 0.10])[0]
    src_port = random.randint(1024, 65535)
    dst_port = random.choice(ATTACK_PORTS if attack_mode else [53, 80, 123, 443, 8080, random.randint(1024, 65535)])
    duration = round(random.uniform(0.2, 55.0 if attack_mode else 18.0), 2)
    total_packets = random.randint(60, 220) if attack_mode else random.randint(4, 65)
    avg_packet_size = round(random.uniform(250, 1200), 2)
    total_bytes = int(total_packets * avg_packet_size)
    packets_src_to_dst = random.randint(max(1, total_packets // 3), total_packets)
    packets_dst_to_src = max(0, total_packets - packets_src_to_dst)
    bytes_src_to_dst = int(total_bytes * random.uniform(0.45, 0.85))
    bytes_dst_to_src = max(0, total_bytes - bytes_src_to_dst)
    packet_rate = round(total_packets / max(duration, 0.1), 2)
    byte_rate = round(total_bytes / max(duration, 0.1), 2)
    label = 'attack' if attack_mode else 'benign'
    if attack_mode and protocol == 'ICMP':
        packet_rate = round(packet_rate * random.uniform(1.5, 3.5), 2)
        byte_rate = round(byte_rate * random.uniform(1.2, 2.8), 2)
    return {
        'src_ip': random.choice(SRC_IPS),
        'dst_ip': random.choice(DST_IPS),
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'duration': duration,
        'total_packets': total_packets,
        'total_bytes': total_bytes,
        'packets_src_to_dst': packets_src_to_dst,
        'packets_dst_to_src': packets_dst_to_src,
        'bytes_src_to_dst': bytes_src_to_dst,
        'bytes_dst_to_src': bytes_dst_to_src,
        'packet_rate': packet_rate,
        'byte_rate': byte_rate,
        'avg_packet_size': avg_packet_size,
        'tcp_flags': random.choice(FLAGS),
        'label': label,
        'emitted_at': datetime.now().isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description='Network flow simulator')

    # The simulator uses the default values either way
    # So endpoint is http://127.0.0.1:5000/api/ingest, batch size is always 8 per flow and it always waits 3 seconds
    # There will be passed to cmd
    parser.add_argument('--target', default='http://127.0.0.1:5000/api/ingest')
    parser.add_argument('--batch-size', type=int, default=8)
    parser.add_argument('--interval', type=float, default=3.0)
    args = parser.parse_args()

    print(f'Starting simulator. Sending to {args.target}')
    while True:
        batch = [make_flow() for _ in range(args.batch_size)]
        try:
            # Makes post request
            response = requests.post(args.target, json={'flows': batch}, timeout=10)
            print(f'[{datetime.now().strftime("%H:%M:%S")}] Sent {len(batch)} flows -> {response.status_code}')
        except Exception as exc:
            print(f'[{datetime.now().strftime("%H:%M:%S")}] Send failed: {exc}')
        # wait 3 seconds
        time.sleep(args.interval)


if __name__ == '__main__':
    main()

