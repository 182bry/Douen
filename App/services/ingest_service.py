from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from ..config import Config
from .llm_service import LLMService
from .model_service import model_service
from .state import app_state
from .state_manager import save_state

llm_service = LLMService(app_state)


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

        1) keep track of accepted flows. Flows are accepted in batches/windows
        2) acquire lock before starting
        3) update the last time a flow was seen by the state
        4) take the current active mode (state; ModeState) from the app state (stores some metrics)
        5) with the current batch of accepted flows, go through each one and:
            -> incrememnt number of flows
            -> normalize flow (flow)
            -> use the model to make binary and multiclass predictions (prediction)
            -> create 4 datapoints required and add to line
            -> increment current mode total_flows
            -> incrememnt benign/not beningn counts
            -> create feed line, add the line to the state's stored feed lines and add flow to state
            -> when a flow is classified as not benign by both the binary classifier
               and the multiclass, it is processed and considered a suspicious
               line. It will be added to the list of
               not_benign_flows in the current mode state through add_not_benign
               and a new alert is also added
        6) now, the llm service is called which uses the LLMService class
           maybe_refresh_insight 
        7) save state
        8) return with number of accepted flows
        '''
        accepted = 0
        with app_state.lock:
            app_state.update_sender_seen(len(flows))
            store = app_state.active_store()
            for raw_flow in flows:
                accepted += 1
                flow = self.normalize_flow(raw_flow)
                prediction = model_service.predict(flow)
                flow['binary_label'] = prediction.binary_label
                flow['attack_label'] = prediction.attack_label
                flow['received_at'] = datetime.now().isoformat()
                flow['mode'] = app_state.active_mode
                
                store.total_flows += 1
                if prediction.is_not_benign:
                    store.not_benign_count += 1
                else:
                    store.benign_count += 1

                feed_line = self.format_feed_line(flow)
                app_state.add_feed_line(feed_line)
                app_state.add_processed_flow(flow)

                if prediction.is_not_benign and prediction.attack_label.lower() != 'benign':
                    suspicious_line = self.format_suspicious_line(flow)
                    app_state.add_not_benign(suspicious_line)
                    app_state.add_alert(
                        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - IRREGULAR FLOW DETECTED."
                    )
                    app_state.add_alert(
                        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - POTENTIAL {prediction.attack_label.upper()} DETECTED."
                    )
            llm_service.maybe_refresh_insight()
            save_state()
        return {'accepted': accepted}

    def normalize_flow(self, flow: Dict):

        '''
        Create a standardized flow.

        1) set default values if the value doesnt exist
        2) ensures float for duration, packet_rate, byte_rate and average packet size. Other values are converted to int
        3) ensures that protocol is a string with and all letters are
        capitalized, tcp_flags is a string and label is a string
        '''

        # 1)
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

        # 2)
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

        # 3)
        normalized['protocol'] = str(normalized['protocol']).upper()
        normalized['tcp_flags'] = str(normalized['tcp_flags'])
        normalized['label'] = str(normalized['label'])

        return normalized

    def format_feed_line(self, flow: Dict) -> str:
        '''
        Format line for client

        1) format the line for the front end that will output read flows
        '''

        # 1)
        return (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {flow['src_ip']}:{flow['src_port']} -> "
            f"{flow['dst_ip']}:{flow['dst_port']} | {flow['protocol']} | "
            f"packets={flow['total_packets']} | bytes={flow['total_bytes']} | "
            f"duration={flow['duration']:.2f}s | {flow['binary_label']} | {flow['attack_label']}"
        )

    def format_suspicious_line(self, flow: Dict) -> str:

        '''
        Format line for client

        1) format the line for the front end that will output suspicous flows
        '''
        # 1)
        return (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {flow['src_port']} | {flow['dst_port']} | "
            f"{flow['duration']:.2f}s | {flow['total_bytes']} bytes | {flow['attack_label']}"
        )


ingest_service = IngestService()
