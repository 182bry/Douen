from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .live_stream_service import live_stream_service
from .model_service import model_service
from .state import app_state
from .state_manager import save_state


class SimulatorManager:
    def __init__(self):
        self.process = None

    def stop_existing(self):
        '''
        Kill the simulator subprocess when done with simulator
        '''
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
        self.process = None
        app_state.simulator_process_pid = None

    # starts either simulator mode or live network mode
    def start(self):

        '''
        Start simulator

        1) Do some set up (stop old process, save root path, ensures mode is set
        acquires target from server settings)
        2) If simulator mode is active, run the simulate sender script
        3) Update state
        4) Start the stream service (with simulator input) for processing
        '''

        # 1) Do some set up (stop old process, save root path, ensures mode is set
        # acquires target from server settings)
        
        self.stop_existing()
        root = Path(__file__).resolve().parents[2]
        simulator_mode = app_state.server_settings.get('simulator_mode', True)
        app_state.set_mode_from_settings()
        target = app_state.server_settings.get('sender_target', 'http://127.0.0.1:5000/api/ingest')

        # 2) If simulator mode is active, run the simulate sender script
        if simulator_mode:
            script = root / 'simulator' / 'simulate_sender.py'
            cmd = [sys.executable, str(script), '--target', target]
            self.process = subprocess.Popen(cmd, cwd=str(root))
            # 3) Update state
            app_state.sender_status.update({
                'running': True,
                'mode': 'streaming',
                'source': 'simulator',
                'message': 'Simulator stream started from Flask.',
            })
            app_state.simulator_process_pid = self.process.pid
            app_state.live_process_pid = None
            save_state()
            return True, f'Simulator stream started with PID {self.process.pid}.'

        # 4) Start the stream service (with simulator input) for processing
        app_state.live_process_pid = None
        return live_stream_service.start()

  
    def stop(self):

        '''
        Stop the simulator (and stream) and update app settings
        '''
        if app_state.server_settings.get('simulator_mode', True):
            if not self.process or self.process.poll() is not None:
                app_state.sender_status.update({
                    'running': False,
                    'mode': 'idle',
                    'source': 'simulator',
                    'message': 'Stream is not running.',
                })
                save_state()
                return False, 'Stream is not running.'

            pid = self.process.pid
            self.stop_existing()
            app_state.sender_status.update({
                'running': False,
                'mode': 'idle',
                'source': 'simulator',
                'message': 'Simulator stream stopped.',
            })
            save_state()
            return True, f'Simulator stream with PID {pid} stopped.'

        return live_stream_service.stop()

    # gives the text box a quick model summary
    def model_metrics_text(self):
        '''
        Set appropriate model summary on client
        '''
        return model_service.model_summary(app_state.server_settings.get('simulator_mode', True))


simulator_manager = SimulatorManager()
