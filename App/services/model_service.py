from __future__ import annotations

from pathlib import Path
from typing import Dict

import joblib
import pandas as pd

EXPECTED_COLUMNS = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'duration',
    'total_packets', 'total_bytes', 'packets_src_to_dst', 'packets_dst_to_src',
    'bytes_src_to_dst', 'bytes_dst_to_src', 'packet_rate', 'byte_rate',
    'avg_packet_size', 'tcp_flags', 'label'
]

'''
Mock model classes. Pre model stage
'''
class PredictionResult:
    def __init__(self, is_not_benign, binary_label, attack_label):
        self.is_not_benign = is_not_benign
        self.binary_label = binary_label
        self.attack_label = attack_label


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
        return [1 if score >= 1 else 0]


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


class MockAnomalyModel:
    def predict(self, frame: pd.DataFrame):
        flow = frame.iloc[0]
        noisy = float(flow['packet_rate']) > 120 or int(flow['total_packets']) > 180
        return [-1 if noisy else 1]


class ModelService:
    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir)
        self.binary_model = None
        self.multiclass_model = None
        self.anomaly_model = None
        self.current_binary_name = 'binary_model.pkl'
        self.current_multi_name = 'multiclass_model.pkl'
        self.current_anomaly_name = 'anomaly_model.pkl'
        self.load_selected_models(self.current_binary_name, self.current_multi_name)

    def load_from_path(self, path: Path, fallback):
        '''
        Load model from given path

        Attempt to load model from path. If not, use the fall back (DummyModels)
        '''

        if path.exists():
            try:
                return joblib.load(path)
            except Exception:
                return fallback
        return fallback

    def load_named(self, file_name: str, fallback):
        '''
        Load model with given file name only

        Make the path with file name and call load_from_path
        '''

        if not file_name:
            return fallback
        preferred = self.model_dir / file_name

        if preferred.exists():
            return self.load_from_path(preferred, fallback)

        return fallback

    def available_model_files(self):
        '''
        Used to show the list of available models in the folder
        '''

        names = set()
        for directory in [self.model_dir]:
            if directory.exists():
                for path in directory.glob('*.pkl'):
                    names.add(path.name)
        defaults = {'binary_model.pkl', 'multiclass_model.pkl', 'anomaly_model.pkl'}
        return sorted(names | defaults)

    def load_selected_models(self, binary_name: str, anomaly_name: str):
        self.current_binary_name = binary_name or 'binary_model.pkl'
        self.current_multi_name = anomaly_name or 'multiclass_model.pkl'
        self.current_anomaly_name = anomaly_name or 'anomaly_model.pkl'
        self.binary_model = self.load_named(self.current_binary_name, MockBinaryModel())
        self.multiclass_model = self.load_named(self.current_multi_name, MockMultiClassModel())
        self.anomaly_model = self.load_named(self.current_anomaly_name, MockAnomalyModel())

    def model_summary(self, simulator_mode: bool):
        if simulator_mode:
            return (
                'Simulator mode is active. The app is using the simulator sender and the saved simulator state. '
                'No real network capture is running right now.'
            )
        return (
            f'Live network mode is active. Binary model: {self.current_binary_name}. '
            f'Attack or anomaly model: {self.current_multi_name}. '
            'The app will look for sklearn model files in trained_models first and then in models.'
        )

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


model_service = ModelService(Path(__file__).resolve().parents[2] / 'trained_models')
