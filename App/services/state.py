from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List


@dataclass
class AppState:
    lock: Lock = field(default_factory=Lock)
    total_flows: int = 0
    benign_count: int = 0
    not_benign_count: int = 0
    latest_alert: str = 'No alerts yet.'
    latest_llm_insight: str = 'No insight yet. Start the simulator or post flow data.'
    feed: deque = field(default_factory=lambda: deque(maxlen=250))
    alerts: deque = field(default_factory=lambda: deque(maxlen=150))
    not_benign_flows: deque = field(default_factory=lambda: deque(maxlen=150))
    processed_flows: deque = field(default_factory=lambda: deque(maxlen=5000))
    per_second_points: deque = field(default_factory=lambda: deque(maxlen=60))
    per_hour_points: deque = field(default_factory=lambda: deque(maxlen=24))
    attack_counter: Counter = field(default_factory=Counter)
    server_settings: Dict[str, Any] = field(default_factory=lambda: {
        'flask_host': '127.0.0.1',
        'flask_port': 5000,
        'llm_base_url': 'https://synapse.sergiomathurin.com/v1',
        'llm_model': 'llama3.3-70b-instruct',
        'poll_seconds': 3,
        'sender_target': 'http://127.0.0.1:5000/api/ingest',
    })
    sender_status: Dict[str, Any] = field(default_factory=lambda: {
        'running': False,
        'last_seen': None,
        'last_batch_size': 0,
        'mode': 'idle',
        'message': 'Simulator has not connected yet.',
    })
    simulator_process_pid: int | None = None
    llm_last_run: datetime | None = None

    def update_sender_seen(self, batch_size: int):
        self.sender_status.update({
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_batch_size': batch_size,
            'message': f'Last batch received successfully ({batch_size} flows).',
        })

    def add_feed_line(self, line: str):
        self.feed.appendleft(line)

    def add_alert(self, line: str):
        self.alerts.appendleft(line)
        self.latest_alert = line

    def add_not_benign(self, line: str):
        self.not_benign_flows.appendleft(line)

    def snapshot(self) -> Dict[str, Any]:
        return {
            'summary': {
                'now': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_flows': self.total_flows,
                'benign_count': self.benign_count,
                'not_benign_count': self.not_benign_count,
                'latest_alert': self.latest_alert,
            },
            'feed': list(self.feed),
            'alerts': list(self.alerts),
            'not_benign_flows': list(self.not_benign_flows),
            'sender_status': dict(self.sender_status),
            'settings': dict(self.server_settings),
            'llm_insight': self.latest_llm_insight,
            'charts': {
                'traffic_60s': list(self.per_second_points),
                'traffic_24h': list(self.per_hour_points),
                'attack_counts': dict(self.attack_counter),
            },
        }

# create state defined above
app_state = AppState()
