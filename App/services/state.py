from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any, Dict, List

'''
App state class
Alot of the code are simple operations
'''

def _default_server_settings() -> Dict[str, Any]:
    flask_host = '127.0.0.1'
    flask_port = 5000
    sender_target = f'http://{flask_host}:{flask_port}/api/ingest'
    return {
        'flask_host': flask_host,
        'flask_port': flask_port,
        'llm_base_url': 'https://synapse.sergiomathurin.com/v1',
        'llm_model': 'llama3.3-70b-instruct',
        'llm_api_key': '',
        'poll_seconds': 3,
        'sender_target': sender_target,
        'simulator_mode': True,
        'binary_model_name': 'binary_model.pkl',
        'anomaly_model_name': 'multiclass_model.pkl',
    }


def _default_sender_status() -> Dict[str, Any]:
    return {
        'running': False,
        'last_seen': None,
        'last_batch_size': 0,
        'mode': 'idle',
        'message': 'Stream has not started yet.',
        'source': 'simulator',
    }


@dataclass
class ModeState:
    total_flows: int = 0
    benign_count: int = 0
    not_benign_count: int = 0
    latest_alert: str = 'No alerts yet.'
    latest_llm_insight: str = 'No insight yet. Start the stream to receive data.'
    feed: List[str] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    not_benign_flows: List[str] = field(default_factory=list)
    processed_flows: List[Dict[str, Any]] = field(default_factory=list)
    insight_history: List[str] = field(default_factory=list)

    def trim(self):
        self.feed = self.feed[:250]
        self.alerts = self.alerts[:150]
        self.not_benign_flows = self.not_benign_flows[:150]
        self.processed_flows = self.processed_flows[-5000:]
        self.insight_history = self.insight_history[:250]

    def add_feed_line(self, line: str):
        self.feed.insert(0, line)
        self.feed = self.feed[:250]

    def add_alert(self, line: str):
        self.alerts.insert(0, line)
        self.alerts = self.alerts[:150]
        self.latest_alert = line

    def add_not_benign(self, line: str):
        self.not_benign_flows.insert(0, line)
        self.not_benign_flows = self.not_benign_flows[:150]

    def add_processed_flow(self, flow: Dict[str, Any]):
        self.processed_flows.append(flow)
        self.processed_flows = self.processed_flows[-5000:]

    def add_insight(self, line: str):
        if not line:
            return
        self.latest_llm_insight = line
        if not self.insight_history or self.insight_history[0] != line:
            self.insight_history.insert(0, line)
            self.insight_history = self.insight_history[:250]


@dataclass
class AppState:
    lock: Lock = field(default_factory=Lock)
    server_settings: Dict[str, Any] = field(default_factory=_default_server_settings)
    sender_status: Dict[str, Any] = field(default_factory=_default_sender_status)
    simulator_process_pid: int | None = None
    live_process_pid: int | None = None
    llm_last_run: datetime | None = None
    active_mode: str = 'simulator'
    simulator_state: ModeState = field(default_factory=ModeState)
    network_state: ModeState = field(default_factory=ModeState) 

    def active_store(self) -> ModeState:
        return self.simulator_state if self.active_mode == 'simulator' else self.network_state

    def other_store(self) -> ModeState:
        return self.network_state if self.active_mode == 'simulator' else self.simulator_state

    @property
    def total_flows(self) -> int:
        return self.active_store().total_flows

    @property
    def benign_count(self) -> int:
        return self.active_store().benign_count

    @property
    def not_benign_count(self) -> int:
        return self.active_store().not_benign_count

    @property
    def latest_alert(self) -> str:
        return self.active_store().latest_alert

    @property
    def latest_llm_insight(self) -> str:
        return self.active_store().latest_llm_insight

    def set_latest_llm_insight(self, line: str):
        self.active_store().add_insight(line)

    def sync_targets(self):
        host = str(self.server_settings.get('flask_host', '127.0.0.1'))
        try:
            port = int(self.server_settings.get('flask_port', 5000))
        except Exception:
            port = 5000
        self.server_settings['flask_host'] = host
        self.server_settings['flask_port'] = port
        self.server_settings['sender_target'] = f'http://{host}:{port}/api/ingest'

    def set_mode_from_settings(self):
        self.active_mode = 'simulator' if self.server_settings.get('simulator_mode', True) else 'network'
        self.sender_status['source'] = self.active_mode

    def update_sender_seen(self, batch_size: int):
        self.sender_status.update({
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_batch_size': batch_size,
            'message': f'Last batch received successfully ({batch_size} flows).',
            'source': self.active_mode,
        })

    def add_feed_line(self, line: str):
        self.active_store().add_feed_line(line)

    def add_alert(self, line: str):
        self.active_store().add_alert(line)

    def add_not_benign(self, line: str):
        self.active_store().add_not_benign(line)

    def add_processed_flow(self, flow: Dict[str, Any]):
        self.active_store().add_processed_flow(flow)

    def serializable_dict(self) -> Dict[str, Any]:
        data = {
            'server_settings': dict(self.server_settings),
            'sender_status': dict(self.sender_status),
            'simulator_process_pid': self.simulator_process_pid,
            'live_process_pid': self.live_process_pid,
            'llm_last_run': self.llm_last_run.isoformat() if self.llm_last_run else None,
            'active_mode': self.active_mode,
            'simulator_state': self.simulator_state.__dict__.copy(),
            'network_state': self.network_state.__dict__.copy(),
        }
        return data

    def snapshot(self) -> Dict[str, Any]:
        store = self.active_store()
        from .plot_service import (
            build_60s_series,
            build_minute_series,
            build_24h_series,
            build_day_series,
            build_attack_counts,
        )

        recent_flows = list(store.processed_flows)
        return {
            'summary': {
                'now': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_flows': store.total_flows,
                'benign_count': store.benign_count,
                'not_benign_count': store.not_benign_count,
                'latest_alert': store.latest_alert,
                'active_mode': self.active_mode,
            },
            'feed': list(store.feed),
            'alerts': list(store.alerts),
            'not_benign_flows': list(store.not_benign_flows),
            'processed_flows': recent_flows,
            'insight_history': list(store.insight_history),
            'sender_status': dict(self.sender_status),
            'settings': dict(self.server_settings),
            'llm_insight': store.latest_llm_insight,
            'charts': {
                'traffic_60s': build_60s_series(recent_flows),
                'traffic_per_minute': build_minute_series(recent_flows),
                'traffic_24h': build_24h_series(recent_flows),
                'traffic_per_day': build_day_series(recent_flows),
                'attack_counts': build_attack_counts(recent_flows),
            },
            'stores': {
                'simulator': {
                    'total_flows': self.simulator_state.total_flows,
                    'benign_count': self.simulator_state.benign_count,
                    'not_benign_count': self.simulator_state.not_benign_count,
                },
                'network': {
                    'total_flows': self.network_state.total_flows,
                    'benign_count': self.network_state.benign_count,
                    'not_benign_count': self.network_state.not_benign_count,
                },
            },
        }


app_state = AppState()
