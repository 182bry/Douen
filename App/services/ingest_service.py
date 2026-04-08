from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from .llm_service import LLMService
from .model_service import ModelService
from .plot_service import build_24h_series, build_60s_series, build_attack_counts
from .state import app_state # get state
from ..config import Config

model_service = ModelService(Config.MODEL_DIR)
llm_service = LLMService(app_state)


class IngestService:

    def process_batch(self, flows: List[Dict]):
        accepted = 0
        with app_state.lock:
            # update number of flows (using current length of flows), last seen and message
            app_state.update_sender_seen(len(flows))
            for raw_flow in flows:
                accepted += 1
                flow = self._normalize_flow(raw_flow)
                prediction = model_service.predict(flow)
                flow['binary_label'] = prediction.binary_label
                flow['attack_label'] = prediction.attack_label
                flow['received_at'] = datetime.now().isoformat()

                # keeping track of total flows, total benign and total non-benign
                app_state.total_flows += 1
                if prediction.is_not_benign:
                    app_state.not_benign_count += 1
                else:
                    app_state.benign_count += 1

                # adding lines to live feed
                feed_line = self._format_feed_line(flow)
                app_state.add_feed_line(feed_line)
                app_state.processed_flows.append(flow)

                # lines classified as not-benign as saved separately aswell
                if prediction.is_not_benign:
                    suspicious_line = self._format_suspicious_line(flow)
                    app_state.add_not_benign(suspicious_line)
                    app_state.add_alert(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - IRREGULAR FLOW DETECTED.")
                    app_state.add_alert(
                        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - POTENTIAL {prediction.attack_label.upper()} DETECTED."
                    )

            # Clear and store values for some values
            recent_flows = list(app_state.processed_flows)
            app_state.per_second_points.clear()
            app_state.per_second_points.extend(build_60s_series(recent_flows))
            app_state.per_hour_points.clear()
            app_state.per_hour_points.extend(build_24h_series(recent_flows))
            app_state.attack_counter.clear()
            app_state.attack_counter.update(build_attack_counts(recent_flows))
            llm_service.maybe_refresh_insight()
        return {'accepted': accepted}

    def _normalize_flow(self, flow: Dict):
        normalized = dict(flow)
        defaults = {
            'src_ip': '192.168.1.10',
            'dst_ip': '192.168.1.1',
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'TCP',
            'duration': 0.0,
            'total_packets': 0,
            'total_bytes': 0,
            'packets_src_to_dst': 0,
            'packets_dst_to_src': 0,
            'bytes_src_to_dst': 0,
            'bytes_dst_to_src': 0,
            'packet_rate': 0.0,
            'byte_rate': 0.0,
            'avg_packet_size': 0.0,
            'tcp_flags': 'SYN',
            'label': 'unknown',
        }
        for key, value in defaults.items():
            # adds a default value if a value doesnt exist in the flow dict
            normalized.setdefault(key, value)
        numeric_keys = [
            'src_port', 'dst_port', 'duration', 'total_packets', 'total_bytes',
            'packets_src_to_dst', 'packets_dst_to_src', 'bytes_src_to_dst',
            'bytes_dst_to_src', 'packet_rate', 'byte_rate', 'avg_packet_size'
        ]
        for key in numeric_keys:
            # enforces float type to numeric values that are expect to be float. Otherwise, force integer
            if key in {'duration', 'packet_rate', 'byte_rate', 'avg_packet_size'}:
                normalized[key] = float(normalized[key])
            else:
                normalized[key] = int(float(normalized[key]))
        # force string
        normalized['protocol'] = str(normalized['protocol']).upper()
        normalized['tcp_flags'] = str(normalized['tcp_flags'])
        normalized['label'] = str(normalized['label'])
        return normalized

    # format line for live feed
    def _format_feed_line(self, flow: Dict) -> str:
        return (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {flow['src_ip']}:{flow['src_port']} -> "
            f"{flow['dst_ip']}:{flow['dst_port']} | {flow['protocol']} | "
            f"packets={flow['total_packets']} | bytes={flow['total_bytes']} | "
            f"duration={flow['duration']:.2f}s | {flow['binary_label']} | {flow['attack_label']}"
        )

    # format suspision line for non-benign feed
    def _format_suspicious_line(self, flow: Dict) -> str:
        return (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {flow['src_port']} | {flow['dst_port']} | "
            f"{flow['duration']:.2f}s | {flow['total_bytes']} bytes | {flow['attack_label']}"
        )


ingest_service = IngestService()
