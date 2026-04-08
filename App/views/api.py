from __future__ import annotations

from flask import Blueprint, jsonify, request
from openai import OpenAI

from ..services.ingest_service import ingest_service
from ..services.simulator_manager import simulator_manager
from ..services.state import app_state

api_views = Blueprint('api', __name__)


@api_views.post('/ingest')
def ingest():
    payload = request.get_json(silent=True) or {}
    flows = payload.get('flows', [])
    if not isinstance(flows, list):
        return jsonify({'error': 'flows must be a list'}), 400
    result = ingest_service.process_batch(flows)
    return jsonify({'status': 'ok', **result})


@api_views.get('/dashboard-data')
def dashboard_data():
    return jsonify(app_state.snapshot())


@api_views.get('/visualization-data')
def visualization_data():
    snapshot = app_state.snapshot()
    return jsonify({
        'charts': snapshot['charts'],
        'llm_insight': snapshot['llm_insight'],
        'latest_alert': snapshot['summary']['latest_alert'],
    })


@api_views.get('/status')
def status():
    return jsonify(app_state.snapshot())


@api_views.post('/settings')
def update_settings():
    payload = request.get_json(silent=True) or {}
    allowed = {'flask_host', 'flask_port', 'poll_seconds', 'llm_base_url', 'llm_api_key', 'llm_model', 'sender_target'}
    with app_state.lock:
        for key, value in payload.items():
            if key in allowed:
                app_state.server_settings[key] = value
    return jsonify({'status': 'ok', 'settings': app_state.server_settings})


@api_views.post('/simulator/start')
def start_simulator():
    ok, message = simulator_manager.start()
    return jsonify({'status': ok, 'message': message})


@api_views.post('/simulator/stop')
def stop_simulator():
    ok, message = simulator_manager.stop()
    return jsonify({'status': ok, 'message': message})


@api_views.post('/llm/test')
def llm_test():
    settings = app_state.server_settings
    api_key = settings.get('llm_api_key', '')
    base_url = settings.get('llm_base_url', '')
    model = settings.get('llm_model', 'llama3.3-70b-instruct')
    if not api_key:
        return jsonify({'status': False, 'message': 'No LLM API key configured.'}), 400
    try:
        client = OpenAI(base_url=base_url, api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[{'role': 'user', 'content': 'Reply with: Synapse connection successful.'}],
            max_tokens=20,
            temperature=0,
        )
        return jsonify({
            'status': True,
            'message': response.choices[0].message.content.strip(),
        })
    except Exception as exc:
        return jsonify({'status': False, 'message': str(exc)}), 500
