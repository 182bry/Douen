from __future__ import annotations

from flask import Blueprint, jsonify, request
from openai import OpenAI

from ..services.ingest_service import ingest_service
from ..services.model_service import model_service
from ..services.plot_service import build_report_bundle
from ..services.report_service import save_report_pdf
from ..services.simulator_manager import simulator_manager
from ..services.state import app_state
from ..services.state_manager import save_state

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


@api_views.get('/report-data')
def report_data():
    snapshot = app_state.snapshot()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    bundle = build_report_bundle(snapshot['processed_flows'], start_date, end_date)
    return jsonify({
        'summary': snapshot['summary'],
        'settings': snapshot['settings'],
        'charts': {
            'per_second': bundle['per_second'],
            'per_minute': bundle['per_minute'],
            'per_hour': bundle['per_hour'],
            'per_day': bundle['per_day'],
            'attack_counts': bundle['attack_counts'],
        },
        'individual_days': bundle['individual_days'],
        'insight_history': snapshot['insight_history'],
        'alerts': snapshot['alerts'],
        'flows': snapshot['feed'],
        'selected_total': len(bundle['selected_flows']),
        'latest_alert': snapshot['summary']['latest_alert'],
    })


@api_views.get('/report-export')
def report_export():
    snapshot = app_state.snapshot()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    file_path = save_report_pdf(snapshot, start_date, end_date)
    opened = False
    open_error = ''
    try:
        import os
        if hasattr(os, 'startfile'):
            os.startfile(file_path)
            opened = True
    except Exception as exc:
        open_error = str(exc)
    return jsonify({
        'status': True,
        'message': 'PDF exported.',
        'file_path': file_path,
        'opened': opened,
        'open_error': open_error,
    })


@api_views.get('/status')
def status():
    snapshot = app_state.snapshot()
    snapshot['available_models'] = model_service.available_model_files()
    snapshot['model_summary_text'] = simulator_manager.model_metrics_text()
    return jsonify(snapshot)


@api_views.post('/settings')
def update_settings():
    payload = request.get_json(silent=True) or {}
    allowed = {
        'poll_seconds', 'llm_base_url', 'llm_api_key', 'llm_model',
        'binary_model_name', 'anomaly_model_name', 'simulator_mode'
    }
    with app_state.lock:
        for key, value in payload.items():
            if key in allowed:
                app_state.server_settings[key] = value
        app_state.sync_targets()
        app_state.set_mode_from_settings()
        model_service.load_selected_models(
            app_state.server_settings.get('binary_model_name', 'binary_model.pkl'),
            app_state.server_settings.get('anomaly_model_name', 'multiclass_model.pkl'),
        )
        save_state()
    return jsonify({'status': 'ok', 'settings': app_state.server_settings, 'message': 'Settings saved.'})


@api_views.post('/stream/start')
def start_stream():
    ok, message = simulator_manager.start()
    return jsonify({'status': ok, 'message': message})


@api_views.post('/stream/stop')
def stop_stream():
    ok, message = simulator_manager.stop()
    return jsonify({'status': ok, 'message': message})


@api_views.post('/simulator/start')
def start_simulator():
    return start_stream()


@api_views.post('/simulator/stop')
def stop_simulator():
    return stop_stream()


@api_views.post('/llm/test')
def llm_test():
    settings = app_state.server_settings
    api_key = settings.get('llm_api_key', '')
    base_url = settings.get('llm_base_url', '')
    model = settings.get('llm_model', 'llama3.3-70b-instruct')
    if not api_key or not base_url:
        return jsonify({'status': False, 'message': 'LLM key or URL is invalid. Please check settings'}), 400
    try:
        client = OpenAI(base_url=base_url, api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[{'role': 'user', 'content': 'Reply with: Synapse connection successful.'}],
            max_tokens=20,
            temperature=0,
        )
        return jsonify({'status': True, 'message': response.choices[0].message.content.strip()})
    except Exception:
        return jsonify({'status': False, 'message': 'LLM key or URL is invalid. Please check settings'}), 500


@api_views.get('/alerts-data')
def alerts_data():
    snapshot = app_state.snapshot()
    attack_counts = snapshot['charts']['attack_counts']
    alerts_list = snapshot['alerts']
    critical = sum(1 for a in alerts_list if 'CRITICAL' in a.upper() or 'DDOS' in a.upper())
    high = sum(1 for a in alerts_list if 'HIGH' in a.upper() or 'DOS' in a.upper())
    medium = sum(1 for a in alerts_list if 'POTENTIAL' in a.upper())
    low = len(alerts_list) - critical - high - medium
    return jsonify({
        'alerts': alerts_list,
        'not_benign_flows': snapshot['not_benign_flows'],
        'attack_counts': attack_counts,
        'severity_counts': {
            'critical': max(critical, 0),
            'high': max(high, 0),
            'medium': max(medium, 0),
            'low': max(low, 0),
        },
        'total_alerts': len(alerts_list),
    })
