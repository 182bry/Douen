from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from .llm_service import LLMService
from .security_pipeline_client import security_pipeline_client
from .state import app_state
from .state_manager import save_state

llm_service = LLMService(app_state)


class SimplePrediction:
    def __init__(self, prediction: Dict | None = None):
        self.has_prediction = bool(prediction)
        prediction = prediction or {}
        self.binary_prediction = int(prediction.get('binary_prediction', 0) or 0)
        self.anomaly_flag = int(prediction.get('anomaly_flag', 0) or 0)
        self.attack_label = str(prediction.get('attack_type') or prediction.get('multiclass_label') or 'BENIGN')
        self.is_not_benign = bool(prediction.get('is_not_benign', False))
        if not self.has_prediction:
            self.attack_label = 'unclassified'
            self.binary_label = 'UNCLASSIFIED'
        elif not self.is_not_benign:
            self.attack_label = 'benign'
            self.binary_label = 'BENIGN'
        else:
            self.binary_label = 'NOT BENIGN'
        self.binary_confidence = float(prediction.get('binary_confidence', 0.0) or 0.0)
        self.multiclass_confidence = float(prediction.get('multiclass_confidence', 0.0) or 0.0)
        self.anomaly_score = float(prediction.get('anomaly_score', 0.0) or 0.0)


class IngestService:
    '''
    This class is for taking input and adding the the app state.
    That include the process of normalizing flows, creating 
    necessary datapoints, producing LLM insights and updating the 
    state.
    '''

    def process_batch(self, flows: List[Dict]):
        '''
        Processes a batch of flows.

        1) Normalize all accepted flows
        2) Send the batch to the detection pipeline API
        3) Store prediction, alert, and correlation output in the app state
        4) Refresh the insight text and save the state
        '''

        accepted = 0
        normalized_flows = []
        for raw_flow in flows:
            normalized_flows.append(self.normalize_flow(raw_flow))

        pipeline_ok, pipeline_result, pipeline_message = security_pipeline_client.analyze(normalized_flows)
        predictions = self.predictions_by_row(pipeline_result.get('predictions', []))
        alerts = pipeline_result.get('alerts', []) if pipeline_ok else []
        incidents = pipeline_result.get('incidents', []) if pipeline_ok else []
        alert_map = self.alerts_by_row(alerts)
        correlation_lines = self.format_correlation_lines(incidents)

        with app_state.lock:
            app_state.update_sender_seen(len(flows))
            store = app_state.active_store()
            store.set_pipeline_summary(pipeline_result.get('summary', {}), pipeline_message)

            if not pipeline_ok:
                app_state.add_alert(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {pipeline_message}")

            for row_index, flow in enumerate(normalized_flows):
                accepted += 1
                prediction = SimplePrediction(predictions.get(row_index))
                flow['binary_label'] = prediction.binary_label
                flow['attack_label'] = prediction.attack_label
                flow['binary_prediction'] = prediction.binary_prediction
                flow['binary_confidence'] = prediction.binary_confidence
                flow['multiclass_confidence'] = prediction.multiclass_confidence
                flow['anomaly_flag'] = prediction.anomaly_flag
                flow['anomaly_score'] = prediction.anomaly_score
                flow['received_at'] = datetime.now().isoformat()
                flow['mode'] = app_state.active_mode

                store.total_flows += 1
                if prediction.has_prediction:
                    if prediction.is_not_benign:
                        store.not_benign_count += 1
                    else:
                        store.benign_count += 1

                feed_line = self.format_feed_line(flow)
                app_state.add_feed_line(feed_line)
                app_state.add_processed_flow(flow)

                alert = alert_map.get(row_index)
                if alert:
                    suspicious_line = self.format_suspicious_line(flow, alert)
                    app_state.add_not_benign(suspicious_line)
                    app_state.add_alert_record(alert)
                    app_state.add_alert(self.format_alert_line(alert))

            app_state.set_incident_records(incidents)
            app_state.set_correlation_output(correlation_lines)
            llm_service.maybe_refresh_insight()
            save_state()

        return {'accepted': accepted}

    def predictions_by_row(self, predictions: List[Dict]):
        '''
        Makes prediction lookup by row index.
        '''
        lookup = {}
        for prediction in predictions:
            try:
                lookup[int(prediction.get('row_index', 0))] = prediction
            except Exception:
                continue
        return lookup

    def alerts_by_row(self, alerts: List[Dict]):
        '''
        Makes alert lookup by row index.
        '''
        lookup = {}
        for alert in alerts:
            try:
                lookup[int(alert.get('row_index', 0))] = alert
            except Exception:
                continue
        return lookup

    def normalize_flow(self, flow: Dict):
        '''
        Create a standardized flow.

        1) set default values if the value doesnt exist
        2) ensures float for duration, packet_rate, byte_rate and average packet size. Other values are converted to int
        3) ensures that protocol is a string with and all letters are
        capitalized, tcp_flags is a string and label is a string
        '''
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
            normalized.setdefault(key, value)

        numeric_keys = [
            'src_port', 'dst_port', 'duration', 'total_packets', 'total_bytes',
            'packets_src_to_dst', 'packets_dst_to_src', 'bytes_src_to_dst',
            'bytes_dst_to_src', 'packet_rate', 'byte_rate', 'avg_packet_size'
        ]
        for key in numeric_keys:
            if key in {'duration', 'packet_rate', 'byte_rate', 'avg_packet_size'}:
                normalized[key] = float(normalized[key])
            else:
                normalized[key] = int(float(normalized[key]))

        normalized['protocol'] = str(normalized['protocol']).upper()
        normalized['tcp_flags'] = str(normalized['tcp_flags'])
        normalized['label'] = str(normalized['label'])
        if 'timestamp' not in normalized:
            normalized['timestamp'] = datetime.now().isoformat()
        return normalized

    def format_feed_line(self, flow: Dict) -> str:
        '''
        Format line for client
        '''
        return (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {flow['src_ip']}:{flow['src_port']} -> "
            f"{flow['dst_ip']}:{flow['dst_port']} | {flow['protocol']} | "
            f"packets={flow['total_packets']} | bytes={flow['total_bytes']} | "
            f"duration={flow['duration']:.2f}s | {flow['binary_label']} | {flow['attack_label']}"
        )

    def format_suspicious_line(self, flow: Dict, alert: Dict | None = None) -> str:
        '''
        Format line for client
        '''
        severity = (alert or {}).get('severity', 'unknown')
        return (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {flow['src_port']} | {flow['dst_port']} | "
            f"{flow['duration']:.2f}s | {flow['total_bytes']} bytes | {flow['attack_label']} | severity={severity}"
        )

    def format_alert_line(self, alert: Dict) -> str:
        '''
        Format one alert from the detection pipeline.
        '''
        return (
            f"{alert.get('timestamp', datetime.now().isoformat())} - "
            f"{str(alert.get('severity', 'unknown')).upper()} {alert.get('attack_type', 'UNKNOWN')} "
            f"from {alert.get('source_ip', 'unknown')} to {alert.get('destination_ip', 'unknown')}"
        )

    def format_correlation_lines(self, incidents: List[Dict]):
        '''
        Format incident records from the correlation process.
        '''
        lines = []
        for incident in incidents:
            attacks = ', '.join(incident.get('attack_types', [])) or incident.get('primary_attack_type', 'UNKNOWN')
            lines.append(
                f"{incident.get('incident_id', 'incident')} | {incident.get('severity', 'unknown').upper()} | "
                f"{incident.get('source_ip', 'unknown')} -> {incident.get('destination_ip', 'unknown')} | "
                f"{incident.get('alert_count', 0)} alerts | {attacks}"
            )
        return lines


ingest_service = IngestService()
