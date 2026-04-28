from __future__ import annotations

import atexit
import base64
import hashlib
import hmac
import json
import secrets
from pathlib import Path
from typing import Any, Dict

from .state import AppState, ModeState, app_state

STATE_FILE = Path(__file__).resolve().parents[2] / 'state.dat'
STATE_ID = 'douen_app_state'
STATE_KEY = hashlib.sha256(STATE_ID.encode('utf-8')).digest()


# makes bytes that are not plain text on disk

def xor_keystream(data: bytes, nonce: bytes):
    '''
    Text to sha256 ciphertext. Convert by blocks
    '''
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hashlib.sha256(STATE_KEY + nonce + counter.to_bytes(4, 'big')).digest()
        out.extend(block)
        counter += 1
    stream = bytes(out[:len(data)])
    return bytes(a ^ b for a, b in zip(data, stream))


# returns bytes ready to store

def encrypt_data(payload: Dict[str, Any]):

    '''
    Convert payload to ciphertext and return
    '''
    raw = json.dumps(payload).encode('utf-8')
    nonce = secrets.token_bytes(16)
    ciphertext = xor_keystream(raw, nonce)
    tag = hmac.new(STATE_KEY, nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(nonce + tag + ciphertext)


# returns dict from stored bytes

def decrypt_data(encoded: bytes):
    '''
    Decrypt stored state
    '''
    packed = base64.b64decode(encoded)
    nonce = packed[:16]
    tag = packed[16:48]
    ciphertext = packed[48:]
    good_tag = hmac.new(STATE_KEY, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, good_tag):
        raise ValueError('Saved state failed integrity check')
    raw = xor_keystream(ciphertext, nonce)
    return json.loads(raw.decode('utf-8'))


class StateWrapper:
    def __init__(self, state: AppState, state_file: Path | None = None):
        self.app_state = state
        self.state_file = state_file or STATE_FILE

    # returns the current state object
    def get_state(self):
        return self.app_state

    # writes the state to state.dat
    def write_state(self):
        '''
        Write the state to file using sha256
        '''
        payload = self.app_state.serializable_dict()
        encrypted = encrypt_data(payload)
        self.state_file.write_bytes(encrypted)
        return True

    # reads the state file and loads it back into the app state
    def read_state(self):

        '''
        Read state from file and update app state
        '''
        if not self.state_file.exists():
            return self.app_state
        try:
            payload = decrypt_data(self.state_file.read_bytes())
        except Exception:
            return self.app_state

        self.app_state.server_settings.update(payload.get('server_settings', {}))
        self.app_state.sender_status.update(payload.get('sender_status', {}))
        self.app_state.simulator_process_pid = None
        self.app_state.live_process_pid = None
        self.app_state.llm_last_run = None
        self.app_state.active_mode = payload.get('active_mode', 'simulator')

        sim_data = payload.get('simulator_state', {})
        net_data = payload.get('network_state', {})
        self.app_state.simulator_state = ModeState(**{k: sim_data.get(k, getattr(ModeState(), k)) for k in ModeState().__dict__.keys()})
        self.app_state.network_state = ModeState(**{k: net_data.get(k, getattr(ModeState(), k)) for k in ModeState().__dict__.keys()})
        self.app_state.simulator_state.trim()
        self.app_state.network_state.trim()

        self.app_state.sync_targets()
        self.app_state.set_mode_from_settings()
        self.app_state.sender_status['running'] = False
        self.app_state.sender_status['mode'] = 'idle'
        self.app_state.sender_status['message'] = 'Saved state loaded. Stream is currently stopped.'
        return self.app_state


state_wrapper = StateWrapper(app_state)
write_state = state_wrapper.write_state
read_state = state_wrapper.read_state
get_state = state_wrapper.get_state


def initialize_state():
    read_state()
    atexit.register(write_state)
    return app_state


def save_state():
    return write_state()
