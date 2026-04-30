from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import requests

from .state import app_state


class SecurityPipelineClient:
    def __init__(self):
        self.process = None
        self.root = Path(__file__).resolve().parents[2]

    def base_url(self):
        return str(app_state.server_settings.get('security_api_url', 'http://127.0.0.1:5001')).rstrip('/')

    def headers(self):
        api_key = str(app_state.server_settings.get('security_api_key', '') or '')
        if not api_key:
            return {}
        return {'X-API-Key': api_key}

    def health_url(self):
        return f'{self.base_url()}/health'

    def analyze_url(self):
        return f'{self.base_url()}/api/v1/security/analyze'

    def is_running(self):
        '''
        Checks if the detection API is reachable.
        '''
        try:
            response = requests.get(self.health_url(), headers=self.headers(), timeout=1.5)
            return response.ok
        except Exception:
            return False

    def start_pipeline(self):
        '''
        Starts the detection API if it is not already reachable.
        '''
        if self.is_running():
            return True, 'Detection pipeline is already running.'

        if self.process and self.process.poll() is None:
            for _ in range(8):
                if self.is_running():
                    return True, 'Detection pipeline is already running.'
                time.sleep(0.25)
            return False, 'Detection pipeline process is running but not responding.'

        env = os.environ.copy()
        env.setdefault('BINARY_MODEL_PATH', str(self.root / 'models' / 'xgboost_binary.pkl'))
        env.setdefault('MULTICLASS_MODEL_PATH', str(self.root / 'models' / 'xgboost_multiclass.pkl'))
        env.setdefault('ANOMALY_MODEL_PATH', str(self.root / 'models' / 'isolation_forest.pkl'))
        env.setdefault('SECURITY_API_KEY', str(app_state.server_settings.get('security_api_key', '') or ''))

        cmd = [sys.executable, '-m', 'src.security_api']
        self.process = subprocess.Popen(cmd, cwd=str(self.root), env=env)

        for _ in range(20):
            if self.is_running():
                return True, f'Detection pipeline started with PID {self.process.pid}.'
            time.sleep(0.25)

        return False, 'Detection pipeline did not respond after starting.'

    def flatten_flow(self, flow: Dict):
        '''
        Moves model feature values to the top level for the detection API.
        '''
        prepared = dict(flow)
        model_features = prepared.pop('model_features', None)
        if isinstance(model_features, dict):
            prepared.update(model_features)
        prepared.setdefault('timestamp', prepared.get('received_at'))
        return prepared

    def analyze(self, flows: List[Dict]) -> Tuple[bool, Dict, str]:
        '''
        Sends a batch of flows to the detection API.
        '''
        ok, message = self.start_pipeline()
        if not ok:
            return False, {}, message

        payload = {
            'flows': [self.flatten_flow(flow) for flow in flows],
            'correlation_window_minutes': int(app_state.server_settings.get('correlation_window_minutes', 5) or 5),
        }

        try:
            response = requests.post(
                self.analyze_url(),
                json=payload,
                headers=self.headers(),
                timeout=15,
            )
            response.raise_for_status()
            return True, response.json(), 'Detection pipeline returned a result.'
        except Exception as exc:
            return False, {}, f'Detection pipeline request failed: {exc}'

    def summary_text(self):
        '''
        Returns text used by the settings status panel.
        '''
        if self.is_running():
            return f'Detection pipeline API is reachable at {self.base_url()}.'
        return f'Detection pipeline API is not reachable at {self.base_url()}.'


security_pipeline_client = SecurityPipelineClient()
