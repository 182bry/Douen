from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple
import joblib
import pandas as pd

EXPECTED_COLUMNS = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'duration',
    'total_packets', 'total_bytes', 'packets_src_to_dst', 'packets_dst_to_src',
    'bytes_src_to_dst', 'bytes_dst_to_src', 'packet_rate', 'byte_rate',
    'avg_packet_size', 'tcp_flags', 'label'
]

PLACEHOLDER_ATTACKS = [
    'benign', 'dos', 'ddos', 'portscan', 'bot', 'brute_force', 'infiltration',
    'web_attack', 'ftp_patator', 'ssh_patator', 'generic', 'exploits', 'fuzzers',
    'backdoor', 'worms', 'reconnaissance'
]



class PredictionResult:
    def __init__(self, is_not_benign, binary_label, attack_label):
        self.is_not_benign = is_not_benign
        self.binary_label = binary_label
        self.attack_label = attack_label

# Both MockBinaryModel and MockMultiClassModel are fallbacks incase the model files arent found
class MockBinaryModel:
    def predict(self, frame: pd.DataFrame):
        flow = frame.iloc[0]
        score = 0
        if float(flow['packet_rate']) > 80:
            score += 1
        if float(flow['byte_rate']) > 50000:
            score += 1
        if int(flow['total_packets']) > 120:
            score += 1
        if str(flow['protocol']).upper() == 'ICMP':
            score += 1
        if int(flow['dst_port']) in {21, 22, 23, 3389, 4444, 8080}:
            score += 1
        return [1 if score >= 2 else 0]


class MockMultiClassModel:
    def predict(self, frame: pd.DataFrame):
        flow = frame.iloc[0]
        if str(flow['protocol']).upper() == 'ICMP' and float(flow['packet_rate']) > 100:
            return ['ddos']
        if int(flow['dst_port']) in {21, 22} and float(flow['packet_rate']) > 40:
            return ['brute_force']
        if int(flow['dst_port']) in {80, 443, 8080} and int(flow['total_packets']) > 90:
            return ['web_attack']
        if int(flow['dst_port']) in {53, 161}:
            return ['reconnaissance']
        if int(flow['dst_port']) in {3389, 4444}:
            return ['bot']
        if int(flow['total_packets']) > 140:
            return ['dos']
        return ['benign']


class ModelService:
    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir)

        # Try to load models from directory or just use mocks
        self.binary_model = self._load(self.model_dir / 'binary_model.pkl', MockBinaryModel())
        self.multiclass_model = self._load(self.model_dir / 'multiclass_model.pkl', MockMultiClassModel())
    

    def _load(self, path: Path, fallback):
        if path.exists():
            try:
                return joblib.load(path)
            except Exception:
                return fallback
        return fallback

    # convert a flow to a pandas dataframe
    def _prepare_frame(self, flow: Dict):
        row = {column: flow.get(column, 0) for column in EXPECTED_COLUMNS}
        return pd.DataFrame([row], columns=EXPECTED_COLUMNS)

    def predict(self, flow: Dict):
        frame = self._prepare_frame(flow)
        binary_pred = self.binary_model.predict(frame)[0]
        attack_pred = self.multiclass_model.predict(frame)[0]
        is_not_benign = bool(binary_pred)
        binary_label = 'NOT BENIGN' if is_not_benign else 'BENIGN'
        attack_label = str(attack_pred)
        if not is_not_benign:
            attack_label = 'benign'
        return PredictionResult(
            is_not_benign=is_not_benign,
            binary_label=binary_label,
            attack_label=attack_label,
        )
