from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict

import requests

from .state import app_state
from .state_manager import save_state

from datetime import datetime


# keeps packet info until it turns into a flow
@dataclass
class LiveFlowState:

    '''
    This class is the skeleton of a live flow
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

    # updates one flow with one packet
    def update(self, pkt_len: int, forward: bool, tcp_flags: str | None = None):
        '''
        Just updates some datapoints outside of the raw network data captured

        The forward parameter is acquired from the process_packet function.
        Since the captured flows are bidirectional, it is used to update the
        number of packets and size of packet of the packets sent to the source
        and from the source (the source is canonical).

        This updates ONE bidirectional flow

        1) update last seen of the flow instance
        2) Check the packet direction and update the appropriate values
        3) If the TCP flag is given, store it.
        '''

        # 1) update last seen of the flow instance
        now = time.time()
        self.last_seen = now
        self.total_packets += 1
        self.total_bytes += pkt_len

        # 2) Check the packet direction and update the appropriate values
        if forward:
            self.packets_src_to_dst += 1
            self.bytes_src_to_dst += pkt_len
        else:
            self.packets_dst_to_src += 1
            self.bytes_dst_to_src += pkt_len

        # 3) If the TCP flag is given, store it.
        if tcp_flags:
            self.tcp_flags_seen.add(str(tcp_flags))

    # returns one flow dict ready to post to flask
    def to_dict(self):
        '''
        Make a dict of a single flow

        1) Calculate some important metrics to add to date before sending
        2) Return the LiveFlowState object data.
        '''
        
        # 1) Calculate some important metrics to add to date before sending
        duration = max(self.last_seen - self.start_time, 0.001)
        packet_rate = self.total_packets / duration
        byte_rate = self.total_bytes / duration
        avg_packet_size = self.total_bytes / self.total_packets if self.total_packets else 0.0

        # 2) Return the LiveFlowState object data.
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'duration': round(duration, 4),
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_src_to_dst': self.packets_src_to_dst,
            'packets_dst_to_src': self.packets_dst_to_src,
            'bytes_src_to_dst': self.bytes_src_to_dst,
            'bytes_dst_to_src': self.bytes_dst_to_src,
            'packet_rate': round(packet_rate, 4),
            'byte_rate': round(byte_rate, 4),
            'avg_packet_size': round(avg_packet_size, 4),
            'tcp_flags': ','.join(sorted(self.tcp_flags_seen)) if self.tcp_flags_seen else 'NONE',
            'label': 'unknown',
        }


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
        Once an IP is lexicographically smaller, it will be considered
        the standard start

        1) If the IP and Port combination is lexicographically smaller
        it is considered the start IP and Port.
        '''
        left = (src_ip, int(src_port))
        right = (dst_ip, int(dst_port))

        # 1)
        if left <= right:
            return left, right, protocol
        return right, left, protocol

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
        pkt_len = len(pkt)
        protocol = 'OTHER' # just other on creation
        src_port = 0
        dst_port = 0
        tcp_flags = None

        # 4) if a TCP or UDP object doesnt exist, abort
        if TCP in pkt:
            protocol = 'TCP'
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            protocol = 'UDP'
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        else:
            return
        
        # 5) Create a key to make the process of updating a specific flow
        # within the buffer easy. The canonical key function will return a
        # standard key given both source and destination ips and ports so it
        # identify bidirectional flows

        # Standard ordering method used to avoid complications with knowing exactly
        # which IP is the local machine's (eg. across multiple interfaces). With this
        # implementation, the actual local IP does not matter.
        key = self.determine_key(src_ip, src_port, dst_ip, dst_port, protocol)
        forward = key[0] == (src_ip, src_port)
        
        # 6)
        # Either add key and LiveFlowState to buffer or just update if it is found
        # in buffer
        with self.lock:
            if key not in self.flows:
                now = time.time()
                flow_src_ip, flow_src_port = key[0]
                flow_dst_ip, flow_dst_port = key[1]
                self.flows[key] = LiveFlowState(
                    src_ip=flow_src_ip,
                    dst_ip=flow_dst_ip,
                    src_port=flow_src_port,
                    dst_port=flow_dst_port,
                    protocol=protocol,
                    start_time=now,
                    last_seen=now,
                )

            self.flows[key].update(pkt_len, forward, tcp_flags)

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
        5) Once that process is done, we exit the lock code block (lock released)
        and the flows with the keys in old_keys are removed from self.flows
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
                # 5) Once that process is done, we exit the lock code block (lock released)
                #    and the flows with the keys in old_keys are removed from self.flows
                for key in old_keys:
                    self.flows.pop(key, None)

            # 6) Each flow in the ready list is now posted using the post_flow function
            for flow in ready:
                ok, error = self.post_flow(flow)
                if not ok:
                    app_state.sender_status['message'] = f'Live stream send failed: {error}'

    def flush_all(self):
        '''
        flush_all() is ran in the stop() function

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
