from __future__ import annotations

import os
from pathlib import Path
import queue
import sys
import threading
import time
import uuid
import numpy as np

from flask import Flask, Response, jsonify, request, stream_with_context
from flask_cors import CORS
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address


# Resolve the project root and add it to sys.path so local modules can be imported
# reliably when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.service import SecurityAnalysisService


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


# Read an integer from the environment. If the variable is missing or invalid,
# fall back to the provided default.
def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default


# Read a string from the environment, using the provided default when missing.
def _env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


# External configuration for API security, request limits, runtime behavior,
# and optional model paths.
API_KEY = _env_str("SECURITY_API_KEY", "")
MAX_FLOWS_PER_REQUEST = _env_int("MAX_FLOWS_PER_REQUEST", 5_000)
MAX_CONTENT_LENGTH_MB = _env_int("MAX_CONTENT_LENGTH_MB", 16)
# RATE_LIMIT = _env_str("RATE_LIMIT", "1200 per minute")
DEFAULT_WINDOW_MINUTES = _env_int("DEFAULT_WINDOW_MINUTES", 5)
RETENTION_MINUTES = _env_int("RETENTION_MINUTES", 60)
# HOST = _env_str("FLASK_HOST", "127.0.0.1")
# PORT = _env_int(5001, 8080)
DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

BINARY_MODEL_PATH = _env_str("BINARY_MODEL_PATH", "")
MULTICLASS_MODEL_PATH = _env_str("MULTICLASS_MODEL_PATH", "")
ANOMALY_MODEL_PATH = _env_str("ANOMALY_MODEL_PATH", "")


# ---------------------------------------------------------------------------
# Async job store
# ---------------------------------------------------------------------------

# In-memory job registry used by the async analysis endpoints.
# Each job stores a status plus either a result or an error message.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


# Register a new async job before worker execution starts.
def _register_job(job_id: str) -> None:
    with _jobs_lock:
        _jobs[job_id] = {"status": "pending", "result": None, "error": None}


# Mark a job as complete and attach the analysis result.
def _complete_job(job_id: str, result: dict) -> None:
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id]["status"] = "complete"
            _jobs[job_id]["result"] = result


# Mark a job as failed and preserve the failure reason for polling clients.
def _fail_job(job_id: str, error: str) -> None:
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"] = error


# Return a shallow copy of a stored job so callers do not mutate shared state.
def _get_job(job_id: str) -> dict | None:
    with _jobs_lock:
        return dict(_jobs[job_id]) if job_id in _jobs else None


# ---------------------------------------------------------------------------
# SSE subscriber registry
# ---------------------------------------------------------------------------

# Connected Server-Sent Events subscribers. Each subscriber gets its own queue
# so broadcasts do not block the request thread.
_sse_subscribers: list[queue.Queue] = []
_sse_lock = threading.Lock()


# Fan out an SSE message to all connected subscribers.
# Queues that can no longer accept messages are treated as stale and removed.
def _broadcast_sse(event_type: str, data: str) -> None:
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(f"event: {event_type}\ndata: {data}\n\n")
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


# Build and configure the Flask application and all of its routes.
def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH_MB * 1024 * 1024

    # Global rate limiting for the API. Memory storage is fine for local/dev
    # usage, but a shared backend would be needed in multi-instance deployment.
    # limiter = Limiter(
    #     key_func=get_remote_address,
    #     app=app,
    #     default_limits=[RATE_LIMIT],
    #     storage_uri="memory://",
    # )

    # Build service kwargs only with values that were explicitly configured.
    # This lets the service decide its own defaults when model paths are absent.
    service_kwargs: dict = {
        "default_window_minutes": DEFAULT_WINDOW_MINUTES,
        "retention_minutes": RETENTION_MINUTES,
    }
    if BINARY_MODEL_PATH:
        service_kwargs["binary_model_path"] = BINARY_MODEL_PATH
    if MULTICLASS_MODEL_PATH:
        service_kwargs["multiclass_model_path"] = MULTICLASS_MODEL_PATH
    if ANOMALY_MODEL_PATH:
        service_kwargs["anomaly_model_path"] = ANOMALY_MODEL_PATH

    service = SecurityAnalysisService(**service_kwargs)

    # Lightweight in-memory counters exposed through /stats.
    _stats: dict[str, int] = {
        "flows_received": 0,
        "alerts_generated": 0,
        "requests_analyzed": 0,
    }
    _stats_lock = threading.Lock()

    # -----------------------------------------------------------------------
    # Auth middleware
    # -----------------------------------------------------------------------

    @app.before_request
    def _require_api_key() -> Response | None:
        # Enforce API key auth only when a key is configured.
        # Health and sample endpoints remain open for basic connectivity checks.
        if not API_KEY:
            return None
        if request.endpoint in ("healthcheck", "sample_payload"):
            return None
        provided = request.headers.get("X-API-Key", "")
        if provided != API_KEY:
            return jsonify({"error": "Unauthorized."}), 401
        return None

    # -----------------------------------------------------------------------
    # Request / response logging
    # -----------------------------------------------------------------------

    @app.before_request
    def _log_request() -> None:
        # Log each inbound request for observability and debugging.
        app.logger.info(
            "→ %s %s from %s", request.method, request.path, request.remote_addr
        )

    @app.after_request
    def _log_response(response: Response) -> Response:
        # Log the outbound status code paired with the original request.
        app.logger.info(
            "← %s %s %s", request.method, request.path, response.status_code
        )
        return response

    # -----------------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------------

    # Validate the incoming flow batch before handing it to the service layer.
    # Returns the parsed flow list and either None or an error response tuple.
    def _validate_flows(payload: dict) -> tuple[list, Response | None]:
        flows = payload.get("flows", [])
        if not isinstance(flows, list):
            return [], (jsonify({"error": "'flows' must be a JSON array."}), 400)
        if len(flows) == 0:
            return [], (
                jsonify({"error": "'flows' must contain at least one entry."}),
                400,
            )
        if len(flows) > MAX_FLOWS_PER_REQUEST:
            return [], (
                jsonify(
                    {
                        "error": f"Batch too large. Maximum {MAX_FLOWS_PER_REQUEST} flows per request."
                    }
                ),
                413,
            )
        return flows, None

    # -----------------------------------------------------------------------
    # Routes — infrastructure
    # -----------------------------------------------------------------------

    @app.get("/health")
    def healthcheck():
        # Minimal liveness endpoint for uptime checks and container probes.
        return jsonify({"status": "ok", "service": "security-layer"})

    @app.get("/api/v1/mitre/catalog")
    def mitre_catalog():
        # Expose the MITRE mapping/catalog from the service layer.
        return jsonify(service.mitre_catalog())

    @app.get("/api/v1/security/stats")
    def stats():
        # Return aggregate counters plus a snapshot of currently open incidents
        # grouped by severity.
        with _stats_lock:
            snapshot = dict(_stats)
        open_incidents = service.list_active_incidents()
        severity_counts: dict[str, int] = {}
        for incident in open_incidents:
            sev = incident.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return jsonify(
            {
                **snapshot,
                "incidents_open": len(open_incidents),
                "incidents_by_severity": severity_counts,
            }
        )

    # -----------------------------------------------------------------------
    # Routes — incidents
    # -----------------------------------------------------------------------

    @app.get("/api/v1/security/incidents")
    def list_incidents():
        # List all currently active incidents.
        return jsonify({"incidents": service.list_active_incidents()})

    @app.get("/api/v1/security/incidents/<incident_id>")
    def get_incident(incident_id: str):
        # Fetch a single incident by ID from the current active set.
        incidents = service.list_active_incidents()
        match = next((i for i in incidents if i["incident_id"] == incident_id), None)
        if match is None:
            return jsonify({"error": "Incident not found."}), 404
        return jsonify(match)

    @app.patch("/api/v1/security/incidents/<incident_id>")
    def update_incident(incident_id: str):
        # Allow clients to move an incident through a controlled set of states.
        body = request.get_json(silent=True) or {}
        allowed_statuses = {"open", "acknowledged", "resolved"}
        new_status = body.get("status")
        if new_status not in allowed_statuses:
            return jsonify(
                {"error": f"'status' must be one of {sorted(allowed_statuses)}."}
            ), 400

        updated = service.update_incident_status(incident_id, new_status)
        if updated is None:
            return jsonify({"error": "Incident not found."}), 404
        return jsonify(updated)

    @app.post("/api/v1/security/incidents/<incident_id>/dismiss")
    def dismiss_incident(incident_id: str):
        # Convenience endpoint for resolving an incident without sending a PATCH
        # payload.
        dismissed = service.update_incident_status(incident_id, "resolved")
        if dismissed is None:
            return jsonify({"error": "Incident not found."}), 404
        return jsonify({"incident_id": incident_id, "status": "resolved"})

    # -----------------------------------------------------------------------
    # Routes — synchronous analysis
    # -----------------------------------------------------------------------

    def make_json_safe(value):
        '''
        Converts common NumPy values into normal Python values.
        '''

        if isinstance(value, dict):
            return {key: make_json_safe(item) for key, item in value.items()}

        if isinstance(value, list):
            return [make_json_safe(item) for item in value]

        if isinstance(value, tuple):
            return [make_json_safe(item) for item in value]

        if isinstance(value, np.integer):
            return int(value)

        if isinstance(value, np.floating):
            return float(value)

        if isinstance(value, np.bool_):
            return bool(value)

        return value

    @app.post("/api/v1/security/analyze")
    # @limiter.limit("3000 per minute")
    def analyze_flows():
        # Parse the request body and reject malformed or missing JSON early.
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify(
                {
                    "error": "Request body must be valid JSON with Content-Type: application/json."
                }
            ), 400

        flows, err = _validate_flows(payload)
        if err:
            return err

        correlation_window_minutes = payload.get("correlation_window_minutes")

        try:
            # Hand the batch to the service layer for scoring, classification,
            # correlation, and incident generation.
            result = service.analyze_flows(
                flows=flows,
                correlation_window_minutes=correlation_window_minutes,
            )
        except (TypeError, ValueError, FileNotFoundError) as exc:
            # Treat expected input/configuration failures as client errors.
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            # Unexpected failures are logged server-side and returned as 500s.
            app.logger.exception("Unhandled error during analysis")
            return jsonify(
                {"error": "Security analysis failed.", "details": str(exc)}
            ), 500

        # Update aggregate counters after a successful analysis run.
        with _stats_lock:
            _stats["flows_received"] += len(flows)
            _stats["alerts_generated"] += result["summary"]["alerts_generated"]
            _stats["requests_analyzed"] += 1

        import json

        # Notify SSE clients that a synchronous analysis completed.
        _broadcast_sse("analysis_complete", json.dumps(result["summary"]))

        print(f'**************** DEBUGGING ******************** RESULT => {result}')
        safe_result = make_json_safe(result)
        print(f'**************** DEBUGGING ******************** RESULT AFTER => {safe_result}')

        return jsonify(safe_result)

    # -----------------------------------------------------------------------
    # Routes — asynchronous analysis
    # -----------------------------------------------------------------------

    @app.post("/api/v1/security/analyze/async")
    # @limiter.limit("3000 per minute")
    def analyze_flows_async():
        # Accept the request, validate it, then hand work off to a background
        # thread so clients can poll for completion.
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify(
                {
                    "error": "Request body must be valid JSON with Content-Type: application/json."
                }
            ), 400

        flows, err = _validate_flows(payload)
        if err:
            return err

        correlation_window_minutes = payload.get("correlation_window_minutes")
        job_id = uuid.uuid4().hex
        _register_job(job_id)

        def _worker():
            try:
                # Run the same analysis pipeline used by the synchronous route.
                result = service.analyze_flows(
                    flows=flows,
                    correlation_window_minutes=correlation_window_minutes,
                )
                with _stats_lock:
                    _stats["flows_received"] += len(flows)
                    _stats["alerts_generated"] += result["summary"]["alerts_generated"]
                    _stats["requests_analyzed"] += 1

                import json

                # Push a completion event to SSE listeners and persist the final
                # job result for polling clients.
                _broadcast_sse(
                    "analysis_complete",
                    json.dumps({**result["summary"], "job_id": job_id}),
                )
                _complete_job(job_id, result)
            except Exception as exc:
                # Failures are logged and recorded so the client sees a terminal
                # job state instead of hanging forever.
                app.logger.exception("Async analysis worker failed for job %s", job_id)
                _fail_job(job_id, str(exc))

        threading.Thread(target=_worker, daemon=True).start()
        return jsonify({"job_id": job_id, "status": "pending"}), 202

    @app.get("/api/v1/security/analyze/async/<job_id>")
    def async_job_result(job_id: str):
        # Poll the current state of an async analysis job.
        job = _get_job(job_id)
        if job is None:
            return jsonify({"error": "Job not found."}), 404
        if job["status"] == "pending":
            return jsonify({"job_id": job_id, "status": "pending"}), 202
        if job["status"] == "failed":
            return jsonify(
                {"job_id": job_id, "status": "failed", "error": job["error"]}
            ), 500
        return jsonify(
            {"job_id": job_id, "status": "complete", "result": job["result"]}
        )

    # -----------------------------------------------------------------------
    # Routes — SSE stream
    # -----------------------------------------------------------------------

    @app.get("/api/v1/security/stream")
    def stream():
        # Give each connected client its own bounded queue so slow consumers do
        # not block broadcast delivery to everyone else.
        q: queue.Queue = queue.Queue(maxsize=100)
        with _sse_lock:
            _sse_subscribers.append(q)

        @stream_with_context
        def _generate():
            # Send an initial connection event immediately so clients know the
            # stream is live.
            yield 'event: connected\ndata: {"status": "streaming"}\n\n'
            try:
                while True:
                    try:
                        # Forward queued events as they arrive.
                        message = q.get(timeout=20)
                        yield message
                    except queue.Empty:
                        # Emit a heartbeat to keep intermediaries and clients
                        # from treating the stream as idle/dead.
                        yield ": heartbeat\n\n"
            finally:
                # Always unregister the queue when the client disconnects.
                with _sse_lock:
                    try:
                        _sse_subscribers.remove(q)
                    except ValueError:
                        pass

        return Response(
            _generate(),
            mimetype="text/event-stream",
            headers={
                # Prevent proxies from caching or buffering the event stream.
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # -----------------------------------------------------------------------
    # Routes — sample payload
    # -----------------------------------------------------------------------

    @app.get("/api/v1/security/sample-payload")
    def sample_payload():
        # Return a minimal example payload clients can use to test the analysis
        # endpoints or understand the expected shape of input data.
        return jsonify(
            {
                "flows": [
                    {
                        "Flow Duration": 112233.0,
                        "Total Fwd Packets": 24,
                        "Total Backward Packets": 18,
                        "Flow Bytes/s": 14500.2,
                        "Flow Packets/s": 120.5,
                        "SYN Flag Count": 1,
                        "ACK Flag Count": 1,
                        "timestamp": "2026-04-01T10:15:00Z",
                        "src_ip": "10.0.10.15",
                        "dst_ip": "172.16.1.20",
                        "src_port": 51515,
                        "dst_port": 80,
                        "sensor_id": "edge-collector-1",
                        "flow_id": "demo-flow-001",
                    }
                ],
                "correlation_window_minutes": 5,
            }
        )

    return app


# Create the Flask app at import time so WSGI servers can discover it.
app = create_app()

if __name__ == "__main__":
    # Local development entry point.
    app.run(host="127.0.0.1", port=5001, debug=DEBUG)