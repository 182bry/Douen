import requests

flows = []
for i in range(15):
    flows.append({
        'src_ip': f'10.0.{i}.1',
        'dst_ip': '192.168.1.1',
        'src_port': 4444,
        'dst_port': 22,
        'protocol': 'TCP',
        'duration': 0.1,
        'total_packets': 200,
        'total_bytes': 150000,
        'packets_src_to_dst': 180,
        'packets_dst_to_src': 20,
        'bytes_src_to_dst': 140000,
        'bytes_dst_to_src': 10000,
        'packet_rate': 500.0,
        'byte_rate': 300000.0,
        'avg_packet_size': 750.0,
        'tcp_flags': 'SYN',
        'label': 'unknown'
    })

r = requests.post('http://127.0.0.1:5000/api/ingest', json={'flows': flows})
print(r.json())