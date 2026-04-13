from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .state import app_state


class SimulatorManager:
    def __init__(self):
        self.process = None

    def start(self):
        # dont start if the process exists and polling is in progress
        if self.process and self.process.poll() is None:
            return False, 'Simulator is already running.'
        # get root directory
        root = Path(__file__).resolve().parents[2]

        # load simulator script
        script = root / 'simulator' / 'simulate_sender.py'

        # get current target from state
        target = app_state.server_settings.get('sender_target', 'http://127.0.0.1:5000/api/ingest')

        # run simulation script with target as a parameter
        cmd = [sys.executable, str(script), '--target', target]

        # for running a script outside of the current one
        self.process = subprocess.Popen(cmd, cwd=str(root))

        #update state
        app_state.sender_status.update({
            'running': True,
            'mode': 'simulator',
            'message': 'Simulator started from Flask.',
        })
        app_state.simulator_process_pid = self.process.pid
        return True, f'Simulator started with PID {self.process.pid}.'

    def stop(self):
        if not self.process or self.process.poll() is not None:
            app_state.sender_status.update({'running': False, 'message': 'Simulator is not running.'})
            return False, 'Simulator is not running.'
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except Exception:
            self.process.kill()
        pid = self.process.pid
        self.process = None
        app_state.sender_status.update({
            'running': False,
            'mode': 'idle',
            'message': 'Simulator stopped.',
        })
        app_state.simulator_process_pid = None
        return True, f'Simulator with PID {pid} stopped.'

# create an instance
simulator_manager = SimulatorManager()
