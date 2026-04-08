from pathlib import Path
import joblib
import pandas as pd
from sklearn.dummy import DummyClassifier

EXPECTED_COLUMNS = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'duration',
    'total_packets', 'total_bytes', 'packets_src_to_dst', 'packets_dst_to_src',
    'bytes_src_to_dst', 'bytes_dst_to_src', 'packet_rate', 'byte_rate',
    'avg_packet_size', 'tcp_flags', 'label'
]


def build_frame(n=12):
    rows = []
    for i in range(n):
        rows.append({
            'src_ip': f'192.168.1.{i+10}',
            'dst_ip': '8.8.8.8',
            'src_port': 1000 + i,
            'dst_port': 80 if i % 2 == 0 else 22,
            'protocol': 'TCP',
            'duration': float(i + 1),
            'total_packets': 10 + i,
            'total_bytes': 5000 + (i * 100),
            'packets_src_to_dst': 5 + i,
            'packets_dst_to_src': 5,
            'bytes_src_to_dst': 2500 + (i * 50),
            'bytes_dst_to_src': 2500,
            'packet_rate': 20.0 + i,
            'byte_rate': 3000.0 + i,
            'avg_packet_size': 500.0,
            'tcp_flags': 'SYN,ACK',
            'label': 'benign' if i % 2 == 0 else 'attack',
        })
    return pd.DataFrame(rows, columns=EXPECTED_COLUMNS)


def main():
    # Training dummy models in place of our actual models for now
    model_dir = Path(__file__).resolve().parents[1] / 'app' / 'trained_models'
    model_dir.mkdir(parents=True, exist_ok=True)
    X = build_frame()
    y_binary = [0, 1] * 6
    y_multi = ['benign', 'brute_force', 'benign', 'dos', 'benign', 'portscan'] * 2
    binary = DummyClassifier(strategy='most_frequent').fit(X, y_binary)
    multi = DummyClassifier(strategy='most_frequent').fit(X, y_multi)
    joblib.dump(binary, model_dir / 'binary_model.pkl')
    joblib.dump(multi, model_dir / 'multiclass_model.pkl')
    print('Dummy model files created.')


if __name__ == '__main__':
    main()
