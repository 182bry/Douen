# from __future__ import annotations

# import argparse
# import random
# import time
# from datetime import datetime
# import requests

# SRC_IPS = [f'192.168.1.{i}' for i in range(10, 120)]
# DST_IPS = ['8.8.8.8', '1.1.1.1', '172.16.0.5', '10.0.0.12', '192.168.1.1']
# PROTOCOLS = ['TCP', 'UDP', 'ICMP']
# ATTACK_PORTS = [21, 22, 53, 80, 443, 8080, 3389, 4444]
# FLAGS = ['SYN', 'ACK', 'PSH,ACK', 'FIN,ACK', 'RST', 'SYN,ACK']

# # making a random flow
# def make_flow() -> dict:
#     attack_mode = random.random() < 0.30
#     protocol = random.choices(PROTOCOLS, weights=[0.65, 0.25, 0.10])[0]
#     src_port = random.randint(1024, 65535)
#     dst_port = random.choice(ATTACK_PORTS if attack_mode else [53, 80, 123, 443, 8080, random.randint(1024, 65535)])
#     duration = round(random.uniform(0.2, 55.0 if attack_mode else 18.0), 2)
#     total_packets = random.randint(60, 220) if attack_mode else random.randint(4, 65)
#     avg_packet_size = round(random.uniform(250, 1200), 2)
#     total_bytes = int(total_packets * avg_packet_size)
#     packets_src_to_dst = random.randint(max(1, total_packets // 3), total_packets)
#     packets_dst_to_src = max(0, total_packets - packets_src_to_dst)
#     bytes_src_to_dst = int(total_bytes * random.uniform(0.45, 0.85))
#     bytes_dst_to_src = max(0, total_bytes - bytes_src_to_dst)
#     packet_rate = round(total_packets / max(duration, 0.1), 2)
#     byte_rate = round(total_bytes / max(duration, 0.1), 2)
#     label = 'attack' if attack_mode else 'benign'
#     if attack_mode and protocol == 'ICMP':
#         packet_rate = round(packet_rate * random.uniform(1.5, 3.5), 2)
#         byte_rate = round(byte_rate * random.uniform(1.2, 2.8), 2)
#     return {
#         'src_ip': random.choice(SRC_IPS),
#         'dst_ip': random.choice(DST_IPS),
#         'src_port': src_port,
#         'dst_port': dst_port,
#         'protocol': protocol,
#         'duration': duration,
#         'total_packets': total_packets,
#         'total_bytes': total_bytes,
#         'packets_src_to_dst': packets_src_to_dst,
#         'packets_dst_to_src': packets_dst_to_src,
#         'bytes_src_to_dst': bytes_src_to_dst,
#         'bytes_dst_to_src': bytes_dst_to_src,
#         'packet_rate': packet_rate,
#         'byte_rate': byte_rate,
#         'avg_packet_size': avg_packet_size,
#         'tcp_flags': random.choice(FLAGS),
#         'label': label,
#         'emitted_at': datetime.now().isoformat(),
#     }


# def main():
#     parser = argparse.ArgumentParser(description='Network flow simulator')

#     # The simulator uses the default values either way
#     # So endpoint is http://127.0.0.1:5000/api/ingest, batch size is always 8 per flow and it always waits 3 seconds
#     # There will be passed to cmd
#     parser.add_argument('--target', default='http://127.0.0.1:5000/api/ingest')
#     parser.add_argument('--batch-size', type=int, default=8)
#     parser.add_argument('--interval', type=float, default=3.0)
#     args = parser.parse_args()

#     print(f'Starting simulator. Sending to {args.target}')
#     while True:
#         batch = [make_flow() for _ in range(args.batch_size)]
#         try:
#             # Makes post request
#             response = requests.post(args.target, json={'flows': batch}, timeout=10)
#             print(f'[{datetime.now().strftime("%H:%M:%S")}] Sent {len(batch)} flows -> {response.status_code}')
#         except Exception as exc:
#             print(f'[{datetime.now().strftime("%H:%M:%S")}] Send failed: {exc}')
#         # wait 3 seconds
#         time.sleep(args.interval)


# if __name__ == '__main__':
#     main()

import argparse
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

import requests
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


@dataclass
class FlowState:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    total_packets: int = 0
    total_bytes: int = 0
    packets_src_to_dst: int = 0
    packets_dst_to_src: int = 0
    bytes_src_to_dst: int = 0
    bytes_dst_to_src: int = 0
    tcp_flags_seen: set = field(default_factory=set)

    def update(self, pkt_len: int, forward: bool, tcp_flags: Optional[str]) -> None:
        now = time.time()
        self.last_seen = now
        self.total_packets += 1
        self.total_bytes += pkt_len

        if forward:
            self.packets_src_to_dst += 1
            self.bytes_src_to_dst += pkt_len
        else:
            self.packets_dst_to_src += 1
            self.bytes_dst_to_src += pkt_len

        if tcp_flags:
            self.tcp_flags_seen.add(tcp_flags)

    def to_flow_dict(self) -> dict:
        duration = max(self.last_seen - self.start_time, 0.001)
        packet_rate = self.total_packets / duration
        byte_rate = self.total_bytes / duration
        avg_packet_size = self.total_bytes / self.total_packets if self.total_packets else 0.0

        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration": round(duration, 4),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "packets_src_to_dst": self.packets_src_to_dst,
            "packets_dst_to_src": self.packets_dst_to_src,
            "bytes_src_to_dst": self.bytes_src_to_dst,
            "bytes_dst_to_src": self.bytes_dst_to_src,
            "packet_rate": round(packet_rate, 4),
            "byte_rate": round(byte_rate, 4),
            "avg_packet_size": round(avg_packet_size, 4),
            "tcp_flags": ",".join(sorted(self.tcp_flags_seen)) if self.tcp_flags_seen else "NONE",
            "label": "unknown",
        }


class FlowSender:
    def __init__(
        self,
        api_url: str,
        flush_interval: float = 1.0,
        idle_timeout: float = 5.0,
        request_timeout: float = 3.0,
    ) -> None:
        self.api_url = api_url
        self.flush_interval = flush_interval
        self.idle_timeout = idle_timeout
        self.request_timeout = request_timeout

        self.flows: Dict[Tuple[str, int, str, int, str], FlowState] = {}
        self.lock = threading.Lock()
        self.running = True

    def canonical_key(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> Tuple[Tuple[str, int], Tuple[str, int], str]:
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a <= b:
            return a, b, protocol
        return b, a, protocol

    def process_packet(self, pkt) -> None:
        if IP not in pkt:
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        pkt_len = len(pkt)

        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        tcp_flags = None

        if TCP in pkt:
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        else:
            return

        key = self.canonical_key(src_ip, src_port, dst_ip, dst_port, protocol)
        forward = key[0] == (src_ip, src_port)

        with self.lock:
            if key not in self.flows:
                # Keep the lexicographically first endpoint as src_* for consistency
                flow_src_ip, flow_src_port = key[0]
                flow_dst_ip, flow_dst_port = key[1]
                now = time.time()
                self.flows[key] = FlowState(
                    src_ip=flow_src_ip,
                    dst_ip=flow_dst_ip,
                    src_port=flow_src_port,
                    dst_port=flow_dst_port,
                    protocol=protocol,
                    start_time=now,
                    last_seen=now,
                )

            self.flows[key].update(pkt_len=pkt_len, forward=forward, tcp_flags=tcp_flags)

    def post_flow(self, flow: dict) -> None:
        try:
            response = requests.post(self.api_url, json={'flows': [flow]}, timeout=self.request_timeout)
            response.raise_for_status()
            print(f"Sent flow: {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} [{flow['protocol']}]")
        except requests.RequestException as exc:
            print(f"Failed to send flow: {exc}")

    def flush_worker(self) -> None:
        while self.running:
            time.sleep(self.flush_interval)
            now = time.time()
            ready = []

            with self.lock:
                expired_keys = [
                    key
                    for key, flow in self.flows.items()
                    if (now - flow.last_seen) >= self.idle_timeout
                ]
                for key in expired_keys:
                    ready.append(self.flows.pop(key).to_flow_dict())

            for flow in ready:
                self.post_flow(flow)

    def flush_all(self) -> None:
        with self.lock:
            remaining = [flow.to_flow_dict() for flow in self.flows.values()]
            self.flows.clear()

        for flow in remaining:
            self.post_flow(flow)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Capture local Windows packet metadata, convert it into flows, and send flows to a local Flask API."
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:5000/api/ingest",
        help="Local ingest endpoint.",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Optional interface name. Leave blank to use Scapy default.",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=5.0,
        help="Seconds of inactivity before a flow is emitted.",
    )
    parser.add_argument(
        "--flush-interval",
        type=float,
        default=1.0,
        help="How often expired flows are checked.",
    )
    parser.add_argument(
        "--bpf",
        default="ip and (tcp or udp)",
        help="Capture filter.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    sender = FlowSender(
        api_url=args.target,
        flush_interval=args.flush_interval,
        idle_timeout=args.idle_timeout,
    )

    flush_thread = threading.Thread(target=sender.flush_worker, daemon=True)
    flush_thread.start()

    print("Starting live capture...")
    print(f"Sending flows to: {args.target}")
    if args.iface:
        print(f"Interface: {args.iface}")
    print(f"Filter: {args.bpf}")
    print("Press Ctrl+C to stop.")

    try:
        sniff(
            iface=args.iface,
            filter=args.bpf,
            prn=sender.process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        sender.running = False
        sender.flush_all()


if __name__ == "__main__":
    main()
