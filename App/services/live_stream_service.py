from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List

import requests

from .state import app_state
from .state_manager import save_state


FLOW_FEATURE_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
    'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
    'Idle Std', 'Idle Max', 'Idle Min'
]


def clean_number(value: float | int) -> float:
    '''
    Makes sure a calculated value stays finite before sending it.
    '''

    try:
        value = float(value)
    except Exception:
        return 0.0

    if not math.isfinite(value):
        return 0.0
    return value


def safe_divide(top: float | int, bottom: float | int) -> float:
    '''
    Small helper for division where zero might happen.
    '''

    bottom = clean_number(bottom)
    if bottom == 0:
        return 0.0
    return clean_number(top) / bottom


def list_sum(values: List[float | int]) -> float:
    '''
    Sum function kept separate so the stats code stays readable.
    '''

    if not values:
        return 0.0
    return float(sum(values))


def list_mean(values: List[float | int]) -> float:
    '''
    Average of a list. Empty lists return 0.
    '''

    if not values:
        return 0.0
    return list_sum(values) / len(values)


def list_variance(values: List[float | int]) -> float:
    '''
    Sample variance. With only one value, there is no spread yet.
    '''

    if len(values) <= 1:
        return 0.0

    mean_value = list_mean(values)
    return sum((float(value) - mean_value) ** 2 for value in values) / (len(values) - 1)


def list_std(values: List[float | int]) -> float:
    '''
    Standard deviation for the values stored in the flow.
    '''

    return math.sqrt(list_variance(values))


def min_or_zero(values: List[float | int]) -> float:
    '''
    Min value, but empty lists should not break the flow.
    '''

    if not values:
        return 0.0
    return float(min(values))


def max_or_zero(values: List[float | int]) -> float:
    '''
    Max value, but empty lists should not break the flow.
    '''

    if not values:
        return 0.0
    return float(max(values))


def seconds_to_microseconds(value: float | int) -> float:
    '''
    Converts seconds to microseconds for duration and IAT fields.
    '''

    return clean_number(value) * 1_000_000.0


def list_seconds_to_microseconds(values: List[float | int]) -> List[float]:
    '''
    Converts a list of time differences from seconds to microseconds.
    '''

    return [seconds_to_microseconds(value) for value in values]


def round_flow_value(value: float | int, digits: int = 6) -> float:
    '''
    Keeps the output readable and avoids sending messy float values.
    '''

    return round(clean_number(value), digits)


@dataclass
class BulkTracker:

    '''
    This keeps bulk transfer values for one direction.
    '''

    timeout: float = 1.0
    min_packets: int = 4
    current_start: float | None = None
    current_last: float | None = None
    current_packets: int = 0
    current_bytes: int = 0
    bulk_count: int = 0
    bulk_packets: int = 0
    bulk_bytes: int = 0
    bulk_duration: float = 0.0

    def update(self, pkt_len: int, timestamp: float):
        '''
        Adds a packet to the current bulk group or starts a new one.

        1) Start the first group if it does not exist
        2) If the time gap is too large, close the current group
        3) Add the packet to the active group
        '''

        # 1) Start the first group if it does not exist
        if self.current_start is None or self.current_last is None:
            self.current_start = timestamp
            self.current_last = timestamp
            self.current_packets = 1
            self.current_bytes = pkt_len
            return

        # 2) If the time gap is too large, close the current group
        if (timestamp - self.current_last) > self.timeout:
            self.close_current()
            self.current_start = timestamp
            self.current_last = timestamp
            self.current_packets = 1
            self.current_bytes = pkt_len
            return

        # 3) Add the packet to the active group
        self.current_last = timestamp
        self.current_packets += 1
        self.current_bytes += pkt_len

    def close_current(self):
        '''
        Closes the current bulk group if it is large enough to count.
        '''

        if self.current_start is None or self.current_last is None:
            return

        duration = max(self.current_last - self.current_start, 0.0)

        if self.current_packets >= self.min_packets and duration > 0:
            self.bulk_count += 1
            self.bulk_packets += self.current_packets
            self.bulk_bytes += self.current_bytes
            self.bulk_duration += duration

        self.current_start = None
        self.current_last = None
        self.current_packets = 0
        self.current_bytes = 0

    def to_values(self):
        '''
        Returns average bytes, packets, and rate for the bulk data.
        '''

        self.close_current()

        avg_bytes = safe_divide(self.bulk_bytes, self.bulk_count)
        avg_packets = safe_divide(self.bulk_packets, self.bulk_count)
        avg_rate = safe_divide(self.bulk_bytes, self.bulk_duration)

        return avg_bytes, avg_packets, avg_rate


# keeps packet info until it turns into a flow
@dataclass
class LiveFlowState:

    '''
    This class is the skeleton of a live flow.
    It stores packet values used for the flow feature columns.
    '''

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    total_packets: int = 0
    total_bytes: int = 0
    packets_src_to_dst: int = 0
    packets_dst_to_src: int = 0
    bytes_src_to_dst: int = 0
    bytes_dst_to_src: int = 0
    tcp_flags_seen: set = field(default_factory=set)

    fwd_packet_lengths: List[int] = field(default_factory=list)
    bwd_packet_lengths: List[int] = field(default_factory=list)
    packet_lengths: List[int] = field(default_factory=list)

    flow_iats: List[float] = field(default_factory=list)
    fwd_iats: List[float] = field(default_factory=list)
    bwd_iats: List[float] = field(default_factory=list)

    last_packet_time: float | None = None
    first_fwd_time: float | None = None
    last_fwd_time: float | None = None
    first_bwd_time: float | None = None
    last_bwd_time: float | None = None

    fwd_psh_flags: int = 0
    bwd_psh_flags: int = 0
    fwd_urg_flags: int = 0
    bwd_urg_flags: int = 0

    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0

    fwd_header_length: int = 0
    bwd_header_length: int = 0
    init_win_bytes_forward: int = -1
    init_win_bytes_backward: int = -1
    act_data_pkt_fwd: int = 0
    min_seg_size_forward: int = 0

    active_idle_threshold: float = 5.0
    subflow_timeout: float = 1.0
    active_start: float | None = None
    active_times: List[float] = field(default_factory=list)
    idle_times: List[float] = field(default_factory=list)
    subflow_count: int = 1

    fwd_bulk_tracker: BulkTracker = field(default_factory=BulkTracker)
    bwd_bulk_tracker: BulkTracker = field(default_factory=BulkTracker)

    def update_time_features(self, timestamp: float, forward: bool):
        '''
        Updates IAT, active, idle, and subflow timing values.

        1) Calculate flow IAT from the previous packet
        2) Split active and idle periods when the gap is large
        3) Keep IAT values for the packet direction
        4) Count subflow breaks
        '''

        # 1) Calculate flow IAT from the previous packet
        if self.last_packet_time is not None:
            gap = max(timestamp - self.last_packet_time, 0.0)
            self.flow_iats.append(gap)

            # 2) Split active and idle periods when the gap is large
            if gap > self.active_idle_threshold:
                active_time = max(self.last_packet_time - (self.active_start or self.last_packet_time), 0.0)
                self.active_times.append(active_time)
                self.idle_times.append(gap)
                self.active_start = timestamp

            # 4) Count subflow breaks
            if gap > self.subflow_timeout:
                self.subflow_count += 1
        else:
            self.active_start = timestamp

        # 3) Keep IAT values for the packet direction
        if forward:
            if self.first_fwd_time is None:
                self.first_fwd_time = timestamp
            if self.last_fwd_time is not None:
                self.fwd_iats.append(max(timestamp - self.last_fwd_time, 0.0))
            self.last_fwd_time = timestamp
        else:
            if self.first_bwd_time is None:
                self.first_bwd_time = timestamp
            if self.last_bwd_time is not None:
                self.bwd_iats.append(max(timestamp - self.last_bwd_time, 0.0))
            self.last_bwd_time = timestamp

        self.last_packet_time = timestamp

    def update_flag_features(self, tcp_flags: str | None, forward: bool):
        '''
        Updates the TCP flag counts.

        1) Save the raw flag string for the simple UI field
        2) Count each TCP flag
        3) Count forward/backward PSH and URG flags separately
        '''

        if not tcp_flags:
            return

        flags = str(tcp_flags)

        # 1) Save the raw flag string for the simple UI field
        self.tcp_flags_seen.add(flags)

        # 2) Count each TCP flag
        if 'F' in flags:
            self.fin_count += 1
        if 'S' in flags:
            self.syn_count += 1
        if 'R' in flags:
            self.rst_count += 1
        if 'P' in flags:
            self.psh_count += 1
        if 'A' in flags:
            self.ack_count += 1
        if 'U' in flags:
            self.urg_count += 1
        if 'C' in flags:
            self.cwe_count += 1
        if 'E' in flags:
            self.ece_count += 1

        # 3) Count forward/backward PSH and URG flags separately
        if forward and 'P' in flags:
            self.fwd_psh_flags += 1
        elif not forward and 'P' in flags:
            self.bwd_psh_flags += 1

        if forward and 'U' in flags:
            self.fwd_urg_flags += 1
        elif not forward and 'U' in flags:
            self.bwd_urg_flags += 1

    def _close_active_period(self):
        '''
        Adds the last active period before the flow is converted to a dict.
        '''

        if self.active_start is None or self.last_seen is None:
            return

        active_time = max(self.last_seen - self.active_start, 0.0)

        if active_time > 0:
            self.active_times.append(active_time)
            self.active_start = self.last_seen

    # updates one flow with one packet
    def update(
        self,
        pkt_len: int,
        forward: bool,
        timestamp: float,
        tcp_flags: str | None = None,
        header_len: int = 0,
        window_size: int | None = None,
        payload_len: int = 0,
    ):
        '''
        Just updates datapoints outside of the raw network data captured.

        The forward parameter is acquired from the process_packet function.
        Since the captured flows are bidirectional, it is used to update the
        number of packets and size of packets sent forward and backward.

        This updates ONE bidirectional flow

        1) update last seen of the flow instance
        2) Update timing values
        3) Check the packet direction and update the appropriate values
        4) Update packet length lists
        5) Update TCP flags and header values
        6) Update bulk transfer values
        '''

        # 1) update last seen of the flow instance
        timestamp = clean_number(timestamp)
        self.last_seen = timestamp
        self.total_packets += 1
        self.total_bytes += pkt_len

        # 2) Update timing values
        self.update_time_features(timestamp, forward)

        # 3) Check the packet direction and update the appropriate values
        if forward:
            self.packets_src_to_dst += 1
            self.bytes_src_to_dst += pkt_len
            self.fwd_packet_lengths.append(pkt_len)
            self.fwd_header_length += header_len
            self.fwd_bulk_tracker.update(pkt_len, timestamp)

            if window_size is not None and self.init_win_bytes_forward == -1:
                self.init_win_bytes_forward = int(window_size)

            if header_len > 0:
                if self.min_seg_size_forward == 0:
                    self.min_seg_size_forward = header_len
                else:
                    self.min_seg_size_forward = min(self.min_seg_size_forward, header_len)

            if payload_len > 0:
                self.act_data_pkt_fwd += 1
        else:
            self.packets_dst_to_src += 1
            self.bytes_dst_to_src += pkt_len
            self.bwd_packet_lengths.append(pkt_len)
            self.bwd_header_length += header_len
            self.bwd_bulk_tracker.update(pkt_len, timestamp)

            if window_size is not None and self.init_win_bytes_backward == -1:
                self.init_win_bytes_backward = int(window_size)

        # 4) Update packet length lists
        self.packet_lengths.append(pkt_len)

        # 5) Update TCP flags and header values
        self.update_flag_features(tcp_flags, forward)

        # 6) Bulk transfer values are updated in the direction block.

    def to_feature_dict(self):
        '''
        Make a detailed feature dictionary from one flow.

        1) Calculate duration and packet rate values
        2) Calculate packet length stats
        3) Calculate IAT stats
        4) Calculate bulk, subflow, active, and idle values
        5) Return the values using the flow feature column names
        '''

        # 1) Calculate duration and packet rate values
        self._close_active_period()

        duration_seconds = max(self.last_seen - self.start_time, 0.000001)
        duration_microseconds = seconds_to_microseconds(duration_seconds)

        flow_bytes_per_second = safe_divide(self.total_bytes, duration_seconds)
        flow_packets_per_second = safe_divide(self.total_packets, duration_seconds)
        fwd_packets_per_second = safe_divide(self.packets_src_to_dst, duration_seconds)
        bwd_packets_per_second = safe_divide(self.packets_dst_to_src, duration_seconds)

        # 2) Calculate packet length stats
        fwd_len_mean = list_mean(self.fwd_packet_lengths)
        bwd_len_mean = list_mean(self.bwd_packet_lengths)
        all_len_mean = list_mean(self.packet_lengths)
        all_len_variance = list_variance(self.packet_lengths)

        # 3) Calculate IAT stats
        flow_iats_us = list_seconds_to_microseconds(self.flow_iats)
        fwd_iats_us = list_seconds_to_microseconds(self.fwd_iats)
        bwd_iats_us = list_seconds_to_microseconds(self.bwd_iats)

        fwd_iat_total = 0.0
        if self.first_fwd_time is not None and self.last_fwd_time is not None:
            fwd_iat_total = seconds_to_microseconds(max(self.last_fwd_time - self.first_fwd_time, 0.0))

        bwd_iat_total = 0.0
        if self.first_bwd_time is not None and self.last_bwd_time is not None:
            bwd_iat_total = seconds_to_microseconds(max(self.last_bwd_time - self.first_bwd_time, 0.0))

        # 4) Calculate bulk, subflow, active, and idle values
        fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate = self.fwd_bulk_tracker.to_values()
        bwd_avg_bytes_bulk, bwd_avg_packets_bulk, bwd_avg_bulk_rate = self.bwd_bulk_tracker.to_values()

        subflow_count = max(self.subflow_count, 1)

        active_us = list_seconds_to_microseconds(self.active_times)
        idle_us = list_seconds_to_microseconds(self.idle_times)

        # 5) Return the values using the flow feature column names
        features = {
            'Destination Port': self.dst_port,
            'Flow Duration': duration_microseconds,
            'Total Fwd Packets': self.packets_src_to_dst,
            'Total Backward Packets': self.packets_dst_to_src,
            'Total Length of Fwd Packets': self.bytes_src_to_dst,
            'Total Length of Bwd Packets': self.bytes_dst_to_src,
            'Fwd Packet Length Max': max_or_zero(self.fwd_packet_lengths),
            'Fwd Packet Length Min': min_or_zero(self.fwd_packet_lengths),
            'Fwd Packet Length Mean': fwd_len_mean,
            'Fwd Packet Length Std': list_std(self.fwd_packet_lengths),
            'Bwd Packet Length Max': max_or_zero(self.bwd_packet_lengths),
            'Bwd Packet Length Min': min_or_zero(self.bwd_packet_lengths),
            'Bwd Packet Length Mean': bwd_len_mean,
            'Bwd Packet Length Std': list_std(self.bwd_packet_lengths),
            'Flow Bytes/s': flow_bytes_per_second,
            'Flow Packets/s': flow_packets_per_second,
            'Flow IAT Mean': list_mean(flow_iats_us),
            'Flow IAT Std': list_std(flow_iats_us),
            'Flow IAT Max': max_or_zero(flow_iats_us),
            'Flow IAT Min': min_or_zero(flow_iats_us),
            'Fwd IAT Total': fwd_iat_total,
            'Fwd IAT Mean': list_mean(fwd_iats_us),
            'Fwd IAT Std': list_std(fwd_iats_us),
            'Fwd IAT Max': max_or_zero(fwd_iats_us),
            'Fwd IAT Min': min_or_zero(fwd_iats_us),
            'Bwd IAT Total': bwd_iat_total,
            'Bwd IAT Mean': list_mean(bwd_iats_us),
            'Bwd IAT Std': list_std(bwd_iats_us),
            'Bwd IAT Max': max_or_zero(bwd_iats_us),
            'Bwd IAT Min': min_or_zero(bwd_iats_us),
            'Fwd PSH Flags': self.fwd_psh_flags,
            'Bwd PSH Flags': self.bwd_psh_flags,
            'Fwd URG Flags': self.fwd_urg_flags,
            'Bwd URG Flags': self.bwd_urg_flags,
            'Fwd Header Length': self.fwd_header_length,
            'Bwd Header Length': self.bwd_header_length,
            'Fwd Packets/s': fwd_packets_per_second,
            'Bwd Packets/s': bwd_packets_per_second,
            'Min Packet Length': min_or_zero(self.packet_lengths),
            'Max Packet Length': max_or_zero(self.packet_lengths),
            'Packet Length Mean': all_len_mean,
            'Packet Length Std': list_std(self.packet_lengths),
            'Packet Length Variance': all_len_variance,
            'FIN Flag Count': self.fin_count,
            'SYN Flag Count': self.syn_count,
            'RST Flag Count': self.rst_count,
            'PSH Flag Count': self.psh_count,
            'ACK Flag Count': self.ack_count,
            'URG Flag Count': self.urg_count,
            'CWE Flag Count': self.cwe_count,
            'ECE Flag Count': self.ece_count,
            'Down/Up Ratio': safe_divide(self.packets_dst_to_src, self.packets_src_to_dst),
            'Average Packet Size': safe_divide(self.total_bytes, self.total_packets),
            'Avg Fwd Segment Size': fwd_len_mean,
            'Avg Bwd Segment Size': bwd_len_mean,
            'Fwd Header Length.1': self.fwd_header_length,
            'Fwd Avg Bytes/Bulk': fwd_avg_bytes_bulk,
            'Fwd Avg Packets/Bulk': fwd_avg_packets_bulk,
            'Fwd Avg Bulk Rate': fwd_avg_bulk_rate,
            'Bwd Avg Bytes/Bulk': bwd_avg_bytes_bulk,
            'Bwd Avg Packets/Bulk': bwd_avg_packets_bulk,
            'Bwd Avg Bulk Rate': bwd_avg_bulk_rate,
            'Subflow Fwd Packets': safe_divide(self.packets_src_to_dst, subflow_count),
            'Subflow Fwd Bytes': safe_divide(self.bytes_src_to_dst, subflow_count),
            'Subflow Bwd Packets': safe_divide(self.packets_dst_to_src, subflow_count),
            'Subflow Bwd Bytes': safe_divide(self.bytes_dst_to_src, subflow_count),
            'Init_Win_bytes_forward': self.init_win_bytes_forward,
            'Init_Win_bytes_backward': self.init_win_bytes_backward,
            'act_data_pkt_fwd': self.act_data_pkt_fwd,
            'min_seg_size_forward': self.min_seg_size_forward,
            'Active Mean': list_mean(active_us),
            'Active Std': list_std(active_us),
            'Active Max': max_or_zero(active_us),
            'Active Min': min_or_zero(active_us),
            'Idle Mean': list_mean(idle_us),
            'Idle Std': list_std(idle_us),
            'Idle Max': max_or_zero(idle_us),
            'Idle Min': min_or_zero(idle_us),
        }

        return {column: round_flow_value(features.get(column, 0.0)) for column in FLOW_FEATURE_COLUMNS}

    # returns one flow dict ready to post to flask
    def to_dict(self):
        '''
        Make a dict of a single flow

        1) Calculate the flow feature values
        2) Keep the simple fields for the dashboard
        3) Add the flow feature values under their own key
        4) Return one flow dict ready to send
        '''

        # 1) Calculate the flow feature values
        model_features = self.to_feature_dict()

        # 2) Keep the simple fields for the dashboard
        duration = max(self.last_seen - self.start_time, 0.000001)
        packet_rate = safe_divide(self.total_packets, duration)
        byte_rate = safe_divide(self.total_bytes, duration)
        avg_packet_size = safe_divide(self.total_bytes, self.total_packets)

        flow = {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'duration': round_flow_value(duration, 4),
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_src_to_dst': self.packets_src_to_dst,
            'packets_dst_to_src': self.packets_dst_to_src,
            'bytes_src_to_dst': self.bytes_src_to_dst,
            'bytes_dst_to_src': self.bytes_dst_to_src,
            'packet_rate': round_flow_value(packet_rate, 4),
            'byte_rate': round_flow_value(byte_rate, 4),
            'avg_packet_size': round_flow_value(avg_packet_size, 4),
            'tcp_flags': ','.join(sorted(self.tcp_flags_seen)) if self.tcp_flags_seen else 'NONE',
            'label': 'unknown',
        }

        # 3) Add the flow feature values under their own key
        #    This keeps the top-level flow format working normally.
        flow['model_features'] = model_features

        # 4) Return one flow dict ready to send
        return flow


class LiveStreamService:

    '''
    Each flow tuple (each tuple is an ip and port) maps to a LiveFlowState object.
    The flow dict (self.flows: Dict[tuple, LiveFlowState]) here is a buffer. It is
    cleared after each interval.
    '''
    def __init__(self):
        self.sniffer = None
        self.flush_thread = None
        self.running = False
        self.flows: Dict[tuple, LiveFlowState] = {}
        self.lock = threading.Lock()
        self.idle_timeout = 5.0
        self.flush_interval = 1.0
        self.request_timeout = 5.0


    def determine_key(self, src_ip, src_port, dst_ip, dst_port, protocol):
        '''
        Just determines a standard key convention to identify flows.


        1) If the IP and Port combination is lexicographically smaller
        use it first in the key.
        '''
        left = (src_ip, int(src_port))
        right = (dst_ip, int(dst_port))

        # 1)
        if left <= right:
            return left, right, protocol
        return right, left, protocol

    def get_packet_length(self, pkt, ip):
        '''
        Gets the length used for the flow.
        len(ip) avoids counting the ethernet header when it is present.
        '''

        try:
            return int(len(ip))
        except Exception:
            return int(len(pkt))

    def get_tcp_payload_length(self, pkt, tcp):
        '''
        Gets TCP payload length.
        This helps separate real data packets from plain ACK packets.
        '''

        try:
            return int(len(tcp.payload))
        except Exception:
            try:
                return int(len(bytes(tcp.payload)))
            except Exception:
                return 0

    # takes packets from scapy and groups them into flows
    def process_packet(self, pkt):

        '''
        Function passed to the scapy AsyncSniffer

        Packets read by scapy are a stack of objects which
        should include TCP or UDP. They hold the port numbers
        which we need.

        1) Try to import scapy
        2) If an IP object doesnt exist, abort
        3) Start building the flow
        4) if a TCP or UDP object doesnt exist, abort
        5) Create a key to make the process of updating a specific flow
        within the buffer easy.
        6) Create the flow if it does not already exist
        7) Work out if this packet is forward or backward
        8) Update the flow

        '''

        # 1) Try to import scapy
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except Exception:
            return

        # 2) If an IP object doesnt exist, abort
        if IP not in pkt:
            return

        # 3) Start building the flow
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        pkt_len = self.get_packet_length(pkt, ip)
        timestamp = clean_number(getattr(pkt, 'time', time.time()))
        protocol = 'OTHER' # just other on creation
        src_port = 0
        dst_port = 0
        tcp_flags = None
        header_len = 0
        window_size = None
        payload_len = 0

        # 4) if a TCP or UDP object doesnt exist, abort
        if TCP in pkt:
            tcp = pkt[TCP]
            protocol = 'TCP'
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = str(tcp.flags)
            header_len = int((tcp.dataofs or 5) * 4)
            window_size = int(tcp.window)
            payload_len = self.get_tcp_payload_length(pkt, tcp)
        elif UDP in pkt:
            udp = pkt[UDP]
            protocol = 'UDP'
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            header_len = 8
        else:
            return

        # 5) Create a key to make the process of updating a specific flow
        # within the buffer easy. The key function will return a
        # standard key given both source and destination ips and ports so it
        # can identify bidirectional flows.
        key = self.determine_key(src_ip, src_port, dst_ip, dst_port, protocol)

        # 6)
        # Either add key and LiveFlowState to buffer or just update if it is found
        # in buffer. The first packet creates the stored flow direction.
        with self.lock:
            if key not in self.flows:
                self.flows[key] = LiveFlowState(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=timestamp,
                    last_seen=timestamp,
                )

            flow = self.flows[key]

            # 7) Determine if this packet is forward or backward
            forward = (
                flow.src_ip == src_ip
                and flow.src_port == src_port
                and flow.dst_ip == dst_ip
                and flow.dst_port == dst_port
            )

            # 8) Update the flow
            flow.update(
                pkt_len=pkt_len,
                forward=forward,
                timestamp=timestamp,
                tcp_flags=tcp_flags,
                header_len=header_len,
                window_size=window_size,
                payload_len=payload_len,
            )

    def post_flow(self, flow):
        '''
        Just posts a flow to the local flask host

        1) get the app state's current server settings
        2) Try to create a post request with the flow. Uses raise_for_status()
        just to check for error
        3) Return false and the exception if the post request fails.
        '''

        # 1) get the app state's current server settings
        target = app_state.server_settings.get('sender_target', 'http://127.0.0.1:5000/api/ingest')
        try:

            # 2) Try to create a post request with the flow. Uses raise_for_status()
            # just to check for error
            response = requests.post(target, json={'flows': [flow]}, timeout=self.request_timeout)
            response.raise_for_status()
            return True, ''
        except Exception as exc:

            # 3) Return false and the exception if the post request fails.
            return False, str(exc)


    def flush_worker(self):
        '''
        flush_worker() is ran on its own Thread in the start() function

        The LiveStreamService flows dict acts as a buffer.

        1) Uses a while loop to execute the flush process while self.running
        is true
        2) Forces the process to sleep for the duration of the interval
        3) Acquires a lock for the flush process. Firstly, create a list
        to keep the old keys that are used to identify a flow. This will be
        used to clear the buffer
        4) Goes through the key flow pairs stored currently in the buffer
        Once it is in the buffer, the flow is added to a "ready" list that
        keeps the information we need. Each key is added to the old_keys list
        5) Once that process is done, we exit the lock code block and the
        flows with the keys in old_keys are removed from self.flows
        6) Each flow in the ready list is now posted using the post_flow function

        '''

        #1) Uses a while loop to execute the flush process while self.running
        # is true
        while self.running:

            # 2) Forces the process to sleep for the duration of the interval
            time.sleep(self.flush_interval)
            now = time.time()
            ready = []

            # 3) Acquires a lock for the flush process. Firstly, create a list
            with self.lock:
                old_keys = []
                for key, flow in self.flows.items():
                    # 4) Goes through the key flow pairs stored currently in the buffer
                    #    Once it is in the buffer, the flow is added to a "ready" list that
                    #    keeps the information we need. Each key is added to the old_keys list
                    if (now - flow.last_seen) >= self.idle_timeout:
                        ready.append(flow.to_dict())
                        old_keys.append(key)
                # 5) Once that process is done, we exit the lock code block and the
                #    flows with the keys in old_keys are removed from self.flows
                for key in old_keys:
                    self.flows.pop(key, None)

            # 6) Each flow in the ready list is now posted using the post_flow function
            for flow in ready:
                ok, error = self.post_flow(flow)
                if not ok:
                    app_state.sender_status['message'] = f'Live stream send failed: {error}'

    def flush_all(self):
        '''
        flush_all() is ran in the stop() function.

        1) Create a list to store all remaining flows.
        2) Acquire lock, store the remaining flows and clear the buffer
        3) Post each flow

        '''

        # 1) Create a list to store all remaining flows.
        remaining = []

        # 2) Acquire lock, store the remaining flows and clear the buffer
        with self.lock:
            for flow in self.flows.values():
                remaining.append(flow.to_dict())
            self.flows.clear()
            app_state.sender_status['message'] = f'Buffer clear. Wait for completion of the flush.'

        # 3) Post each flow
        for flow in remaining:
            ok, error = self.post_flow(flow)
            if not ok:
                app_state.sender_status['message'] = f'Live stream send failed: {error}'

    def start(self):

        '''
        Starts the scappy AsyncSniffer and sends a message to the client to
        indicate starting.

        1) First, check if it is running
        2) If not running, import AsyncSniffer.
        3) Update object and app/client status of sender
        4) Start
        5) Start flush_worker on its own thread
        6) Send messages to client and save the state
        7) If starting the process fails, set running to false and
        update the sender message to reflect the failure

        '''
        # 1) First, check if it is running
        if self.running:
            return False, 'Live network stream is already running.'

        # 2) If not running, import AsyncSniffer.
        try:
            from scapy.all import AsyncSniffer
        except Exception:
            app_state.sender_status.update({
                'running': False,
                'mode': 'idle',
                'source': 'network',
                'message': 'Live network stream needs scapy installed first.',
            })
            save_state()
            return False, 'Live network stream needs scapy installed first.'

        # 3) Update object and send message to client
        self.running = True
        self.flows = {}
        app_state.sender_status.update({
            'running': True,
            'mode': 'streaming',
            'source': 'network',
            'message': 'Starting live network stream...',
        })

        # 4) Start
        try:
            # i) AsynceSniffer parameter prn is used to call a specific function and
            # pass the captured packet through it. So it looks like process_packet(pkt)
            self.sniffer = AsyncSniffer(prn=self.process_packet, store=False)
            self.sniffer.start()
            # 5) Start flush_worker on its own thread
            self.flush_thread = threading.Thread(target=self.flush_worker, daemon=True)
            self.flush_thread.start()
            app_state.live_process_pid = None
            # 6) Send messages to client and save the state
            app_state.sender_status['message'] = 'Live network stream started.'
            save_state()
            return True, 'Live network stream started.'
        except Exception as exc:
            # 7) If starting the process fails, set running to false and
            # update the sender message to reflect the failure
            self.running = False
            self.sniffer = None
            app_state.sender_status.update({
                'running': False,
                'mode': 'idle',
                'source': 'network',
                'message': f'Live network stream could not start: {exc}',
            })
            save_state()
            return False, f'Live network stream could not start: {exc}'

    # stops packet capture and posts the last flows
    def stop(self):

        '''
        Stops the stream

        1) Check if the stream isnt running
        2) Set running to false
        3) Stop the sniffer
        4) Remove the sniffer from the state
        5) Flush any remaining flows in the buffer
        6) update the sender the a message reflecting the stop

        '''

        #1) Check if the stream isnt running
        if not self.running:
            app_state.sender_status.update({
                'running': False,
                'mode': 'idle',
                'source': 'network',
                'message': 'Live network stream is not running.',
            })
            save_state()
            return False, 'Live network stream is not running.'

        # 2) Set running to false
        self.running = False

        # 3) Stop the sniffer
        try:
            if self.sniffer is not None:
                self.sniffer.stop()
        except Exception:
            pass

        # 4) Remove the sniffer from the state
        self.sniffer = None
        # 5) Flush any remaining flows in the buffer
        self.flush_all()

        # 6) update the sender the a message reflecting the stop
        app_state.sender_status.update({
            'running': False,
            'mode': 'idle',
            'source': 'network',
            'message': 'Live network stream stopped.',
        })
        save_state()
        return True, 'Live network stream stopped.'


live_stream_service = LiveStreamService()
