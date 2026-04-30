from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from threading import Lock
from typing import Any
import uuid

import joblib
import numpy as np
import pandas as pd

from src.mitre import MITRE_ATTACK_LIBRARY, build_attack_progression, get_mitre_mapping


# Resolve project root for default model paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Default locations of trained models
DEFAULT_BINARY_MODEL_PATH = PROJECT_ROOT / "models" / "xgboost_binary.pkl"
DEFAULT_MULTICLASS_MODEL_PATH = PROJECT_ROOT / "models" / "xgboost_multiclass.pkl"
DEFAULT_ANOMALY_MODEL_PATH = PROJECT_ROOT / "models" / "isolation_forest.pkl"


# Fields that should NOT be treated as model features (metadata only)
RESERVED_METADATA_FIELDS = {
    "flow_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "sensor_id",
    "asset_id",
    "hostname",
    "username",
    "label",
    "Label",
    "dataset",
    "source_file",
    "source_split",
}


# Base severity scores per attack type before dynamic adjustments
SEVERITY_BASE_SCORE = {
    "UNKNOWN_ANOMALY": 45,
    "PortScan": 50,
    "WebAttack_BruteForce": 60,
    "WebAttack_XSS": 60,
    "FTP-Patator": 70,
    "SSH-Patator": 70,
    "WebAttack_SQLInjection": 80,
    "Bot": 80,
    "Infiltration": 85,
    "DoS Hulk": 85,
    "DoS GoldenEye": 85,
    "DoS slowloris": 85,
    "DoS Slowhttptest": 85,
    "Heartbleed": 90,
    "DDoS": 95,
}


class SecurityAnalysisService:
    """
    Core analysis engine:
    - Loads ML models
    - Scores incoming flow batches
    - Builds alerts
    - Correlates alerts into incidents
    - Enriches incidents with MITRE ATT&CK context
    """

    def __init__(
        self,
        binary_model_path: str | Path = DEFAULT_BINARY_MODEL_PATH,
        multiclass_model_path: str | Path = DEFAULT_MULTICLASS_MODEL_PATH,
        anomaly_model_path: str | Path = DEFAULT_ANOMALY_MODEL_PATH,
        default_window_minutes: int = 5,
        retention_minutes: int = 60,
    ) -> None:
        # Load models from disk
        self.binary_model = self._load_model(binary_model_path)
        self.multiclass_model, self.multiclass_label_map = self._load_multiclass_model(
            multiclass_model_path
        )
        self.anomaly_model = self._load_model(anomaly_model_path)

        # Determine expected feature schema from models
        self.expected_features = self._resolve_expected_features()

        # Correlation + retention configuration
        self.default_window_minutes = default_window_minutes
        self.retention_minutes = retention_minutes

        # In-memory incident store (thread-safe)
        self._incidents: dict[str, dict] = {}
        self._lock = Lock()

    @staticmethod
    def _load_model(model_path: str | Path) -> Any:
        # Load a serialized model, fail fast if missing
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        return joblib.load(path)

    @staticmethod
    def _load_multiclass_model(model_path: str | Path) -> tuple[Any, dict | None]:
        # Multiclass model may optionally include a label mapping
        loaded_object = SecurityAnalysisService._load_model(model_path)

        if isinstance(loaded_object, dict) and "model" in loaded_object:
            return loaded_object["model"], loaded_object.get("id_to_label")

        return loaded_object, None

    def _resolve_expected_features(self) -> list[str]:
        # Extract feature names from any of the models (they should share schema)
        for model in (self.binary_model, self.multiclass_model, self.anomaly_model):
            if hasattr(model, "feature_names_in_"):
                return list(model.feature_names_in_)

        raise ValueError(
            "The loaded models do not expose feature names. "
            "Re-train them with DataFrame inputs or define the feature schema explicitly."
        )

    def _prepare_batch(self, flows: list[dict]) -> tuple[pd.DataFrame, pd.DataFrame]:
        # Convert raw JSON flows into feature matrix + metadata
        if not flows:
            raise ValueError("At least one flow record is required.")

        payload_frame = pd.DataFrame(flows)
        if payload_frame.empty:
            raise ValueError("The input payload did not contain any usable flow rows.")

        # Separate metadata from ML features
        metadata_columns = [
            column
            for column in payload_frame.columns
            if column in RESERVED_METADATA_FIELDS
        ]
        metadata = (
            payload_frame[metadata_columns].copy()
            if metadata_columns
            else pd.DataFrame(index=payload_frame.index)
        )

        # Align input with expected model features
        features = payload_frame.reindex(
            columns=self.expected_features, fill_value=0
        ).copy()
        features = features.apply(pd.to_numeric, errors="coerce").fillna(0.0)

        return features, metadata

    @staticmethod
    def _predict_confidence(
        model: Any, features: pd.DataFrame
    ) -> tuple[np.ndarray, np.ndarray]:
        # Run predictions and extract confidence if available
        predictions = model.predict(features)

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(features)
            confidence = probabilities.max(axis=1)
        else:
            confidence = np.ones(len(predictions), dtype=float)

        return np.asarray(predictions), np.asarray(confidence, dtype=float)

    def _predict_batch(self, features: pd.DataFrame) -> pd.DataFrame:
        # Run all models (binary, multiclass, anomaly) in one pass
        binary_predictions, binary_confidence = self._predict_confidence(
            self.binary_model, features
        )
        multiclass_predictions, multiclass_confidence = self._predict_confidence(
            self.multiclass_model, features
        )

        # Map numeric labels to human-readable attack types if mapping exists
        if self.multiclass_label_map:
            multiclass_labels = (
                pd.Series(multiclass_predictions)
                .map(self.multiclass_label_map)
                .fillna("UNKNOWN")
            )
        else:
            multiclass_labels = pd.Series(multiclass_predictions, dtype="object")

        # Anomaly detection (-1 = anomaly)
        anomaly_predictions = self.anomaly_model.predict(features)
        anomaly_flag = (anomaly_predictions == -1).astype(int)

        if hasattr(self.anomaly_model, "decision_function"):
            anomaly_score = -self.anomaly_model.decision_function(features)
        else:
            anomaly_score = np.zeros(len(features), dtype=float)

        return pd.DataFrame(
            {
                "binary_prediction": binary_predictions.astype(int),
                "binary_confidence": np.round(binary_confidence, 4),
                "multiclass_label": multiclass_labels.values,
                "multiclass_confidence": np.round(multiclass_confidence, 4),
                "anomaly_flag": anomaly_flag.astype(int),
                "anomaly_score": np.round(anomaly_score, 4),
            }
        )

    @staticmethod
    def _parse_timestamp(raw_timestamp: object) -> datetime:
        # Normalize timestamps to UTC, fallback to current time if invalid
        if raw_timestamp is None or pd.isna(raw_timestamp):
            return datetime.now(timezone.utc)

        timestamp_text = str(raw_timestamp).strip()
        if not timestamp_text:
            return datetime.now(timezone.utc)

        try:
            return datetime.fromisoformat(
                timestamp_text.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except ValueError:
            return datetime.now(timezone.utc)

    @staticmethod
    def _resolve_attack_type(prediction_row: pd.Series) -> str:
        # Decide final attack type using binary + multiclass + anomaly outputs
        if int(prediction_row["binary_prediction"]) == 1:
            label = str(prediction_row["multiclass_label"])
            return label if label and label != "BENIGN" else "SUSPICIOUS_ACTIVITY"

        if int(prediction_row["anomaly_flag"]) == 1:
            return "UNKNOWN_ANOMALY"

        return "BENIGN"

    @staticmethod
    def _severity_score(attack_type: str, prediction_row: pd.Series) -> int:
        # Combine base severity with model confidence and anomaly score
        score = SEVERITY_BASE_SCORE.get(attack_type, 55)
        score += int(float(prediction_row["binary_confidence"]) * 10)
        score += int(float(prediction_row["anomaly_score"]) * 5)

        if int(prediction_row["anomaly_flag"]) == 1:
            score += 5

        return max(0, min(score, 100))

    @staticmethod
    def _severity_label(score: int) -> str:
        # Map numeric severity to human-readable levels
        if score >= 90:
            return "critical"
        if score >= 75:
            return "high"
        if score >= 55:
            return "medium"
        return "low"

    @staticmethod
    def _reasoning(attack_type: str, prediction_row: pd.Series) -> list[str]:
        # Generate human-readable explanation for why an alert was raised
        reasons = []

        if int(prediction_row["binary_prediction"]) == 1:
            reasons.append(
                f"Binary detector marked the flow as malicious with confidence {float(prediction_row['binary_confidence']):.2f}."
            )

        if attack_type not in {"BENIGN", "UNKNOWN_ANOMALY", "SUSPICIOUS_ACTIVITY"}:
            reasons.append(
                f"Multiclass detector associated the flow with '{attack_type}' at confidence {float(prediction_row['multiclass_confidence']):.2f}."
            )

        if int(prediction_row["anomaly_flag"]) == 1:
            reasons.append(
                f"Isolation Forest also flagged the flow as anomalous with score {float(prediction_row['anomaly_score']):.2f}."
            )

        if not reasons:
            reasons.append("The flow stayed below alerting thresholds.")

        return reasons

    @staticmethod
    def _value_or_default(value: object, default: object = None) -> object:
        # Normalize missing or empty values
        if value is None or pd.isna(value):
            return default
        if isinstance(value, str) and not value.strip():
            return default
        return value

    def _build_alert(
        self, row_index: int, metadata_row: pd.Series, prediction_row: pd.Series
    ) -> dict | None:
        # Construct an alert object from prediction + metadata
        attack_type = self._resolve_attack_type(prediction_row)
        if attack_type == "BENIGN":
            return None

        event_timestamp = self._parse_timestamp(metadata_row.get("timestamp"))
        severity_score = self._severity_score(attack_type, prediction_row)
        anomaly_only = attack_type == "UNKNOWN_ANOMALY"

        return {
            "alert_id": f"alert-{uuid.uuid4().hex[:12]}",
            "row_index": row_index,
            "flow_id": self._value_or_default(
                metadata_row.get("flow_id"), f"flow-{row_index}"
            ),
            "timestamp": event_timestamp.isoformat(),
            "source_ip": self._value_or_default(metadata_row.get("src_ip"), "unknown"),
            "destination_ip": self._value_or_default(
                metadata_row.get("dst_ip"), "unknown"
            ),
            "source_port": self._value_or_default(metadata_row.get("src_port")),
            "destination_port": self._value_or_default(metadata_row.get("dst_port")),
            "sensor_id": self._value_or_default(
                metadata_row.get("sensor_id"), "unspecified"
            ),
            "asset_id": self._value_or_default(metadata_row.get("asset_id")),
            "hostname": self._value_or_default(metadata_row.get("hostname")),
            "username": self._value_or_default(metadata_row.get("username")),
            "attack_type": attack_type,
            "detection_type": "anomaly" if anomaly_only else "classified_attack",
            "severity": self._severity_label(severity_score),
            "severity_score": severity_score,
            "binary_prediction": int(prediction_row["binary_prediction"]),
            "binary_confidence": float(prediction_row["binary_confidence"]),
            "multiclass_confidence": float(prediction_row["multiclass_confidence"]),
            "anomaly_flag": int(prediction_row["anomaly_flag"]),
            "anomaly_score": float(prediction_row["anomaly_score"]),
            "reasoning": self._reasoning(attack_type, prediction_row),
            "mitre": get_mitre_mapping(attack_type, anomaly_only=anomaly_only),
        }

    @staticmethod
    def _bucket_start(timestamp: datetime, window_minutes: int) -> datetime:
        # Align timestamp to correlation window bucket
        bucket_minute = (timestamp.minute // window_minutes) * window_minutes
        return timestamp.replace(minute=bucket_minute, second=0, microsecond=0)

    def _group_key(self, alert: dict, window_minutes: int) -> tuple[str, str, str, str]:
        # Group alerts by source/destination/sensor/time bucket
        bucket_start = self._bucket_start(
            self._parse_timestamp(alert["timestamp"]), window_minutes
        )
        source = str(alert.get("source_ip") or "unknown")
        destination = str(alert.get("destination_ip") or "unknown")
        sensor_id = str(alert.get("sensor_id") or "unspecified")
        return source, destination, sensor_id, bucket_start.isoformat()

    @staticmethod
    def _incident_id(group_key: tuple[str, str, str, str]) -> str:
        # Deterministically generate incident ID from grouping key
        digest = hashlib.sha1("|".join(group_key).encode("utf-8")).hexdigest()[:14]
        return f"incident-{digest}"

    def _build_incident(
        self,
        group_key: tuple[str, str, str, str],
        alerts: list[dict],
        window_minutes: int,
    ) -> dict:
        # Build a correlated incident from grouped alerts
        sorted_alerts = sorted(alerts, key=lambda item: item["timestamp"])
        unique_attack_types = sorted({alert["attack_type"] for alert in sorted_alerts})
        highest_severity_alert = max(
            sorted_alerts, key=lambda item: item["severity_score"]
        )

        return {
            "incident_id": self._incident_id(group_key),
            "source_ip": group_key[0],
            "destination_ip": group_key[1],
            "sensor_id": group_key[2],
            "window_start": group_key[3],
            "window_minutes": window_minutes,
            "first_seen": sorted_alerts[0]["timestamp"],
            "last_seen": sorted_alerts[-1]["timestamp"],
            "alert_count": len(sorted_alerts),
            "suppressed_duplicates": max(
                len(sorted_alerts) - len(unique_attack_types), 0
            ),
            "attack_types": unique_attack_types,
            "primary_attack_type": highest_severity_alert["attack_type"],
            "severity": highest_severity_alert["severity"],
            "severity_score": highest_severity_alert["severity_score"],
            "mitre_attack_steps": build_attack_progression(unique_attack_types),
            "alerts": sorted_alerts,
            "status": "open",
        }

    def _upsert_incidents(self, incidents: list[dict]) -> list[dict]:
        # Merge new incidents into in-memory store and remove expired ones
        now = datetime.now(timezone.utc)
        retention_cutoff = now - timedelta(minutes=self.retention_minutes)

        with self._lock:
            expired_ids = []
            for incident_id, stored_incident in self._incidents.items():
                last_seen = self._parse_timestamp(stored_incident["last_seen"])
                if last_seen < retention_cutoff:
                    expired_ids.append(incident_id)

            for incident_id in expired_ids:
                self._incidents.pop(incident_id, None)

            for incident in incidents:
                existing = self._incidents.get(incident["incident_id"])
                if existing is None:
                    self._incidents[incident["incident_id"]] = incident
                    continue

                # Merge alerts into existing incident instead of duplicating
                existing_alert_ids = {alert["alert_id"] for alert in existing["alerts"]}
                new_alerts = [
                    alert
                    for alert in incident["alerts"]
                    if alert["alert_id"] not in existing_alert_ids
                ]

                if not new_alerts:
                    continue

                existing["alerts"].extend(new_alerts)
                existing["alerts"].sort(key=lambda item: item["timestamp"])
                existing["first_seen"] = min(
                    existing["first_seen"], incident["first_seen"]
                )
                existing["last_seen"] = max(
                    existing["last_seen"], incident["last_seen"]
                )
                existing["alert_count"] = len(existing["alerts"])

                unique_attack_types = sorted(
                    {alert["attack_type"] for alert in existing["alerts"]}
                )
                existing["attack_types"] = unique_attack_types
                existing["suppressed_duplicates"] = max(
                    existing["alert_count"] - len(unique_attack_types), 0
                )

                highest_severity_alert = max(
                    existing["alerts"], key=lambda item: item["severity_score"]
                )
                existing["primary_attack_type"] = highest_severity_alert["attack_type"]
                existing["severity"] = highest_severity_alert["severity"]
                existing["severity_score"] = highest_severity_alert["severity_score"]
                existing["mitre_attack_steps"] = build_attack_progression(
                    unique_attack_types
                )

            return sorted(
                self._incidents.values(),
                key=lambda item: item["last_seen"],
                reverse=True,
            )

    def analyze_flows(
        self, flows: list[dict], correlation_window_minutes: int | None = None
    ) -> dict:
        # Main pipeline: preprocess → predict → alert → correlate → return summary
        effective_window = correlation_window_minutes or self.default_window_minutes
        effective_window = int(effective_window)
        if effective_window <= 0:
            raise ValueError("correlation_window_minutes must be a positive integer.")

        features, metadata = self._prepare_batch(flows)
        predictions = self._predict_batch(features)

        alerts = []
        prediction_records = []
        for row_index, prediction_row in predictions.iterrows():
            metadata_row = (
                metadata.loc[row_index]
                if not metadata.empty
                else pd.Series(dtype="object")
            )
            attack_type = self._resolve_attack_type(prediction_row)
            prediction_records.append(
                {
                    "row_index": int(row_index),
                    "binary_prediction": int(prediction_row["binary_prediction"]),
                    "binary_confidence": float(prediction_row["binary_confidence"]),
                    "multiclass_label": str(prediction_row["multiclass_label"]),
                    "multiclass_confidence": float(prediction_row["multiclass_confidence"]),
                    "anomaly_flag": int(prediction_row["anomaly_flag"]),
                    "anomaly_score": float(prediction_row["anomaly_score"]),
                    "attack_type": attack_type,
                    "is_not_benign": attack_type != "BENIGN",
                }
            )
            alert = self._build_alert(row_index, metadata_row, prediction_row)
            if alert is not None:
                alerts.append(alert)

        # Correlate alerts into incidents
        grouped_alerts: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
        for alert in alerts:
            grouped_alerts[self._group_key(alert, effective_window)].append(alert)

        incidents = [
            self._build_incident(group_key, grouped, effective_window)
            for group_key, grouped in grouped_alerts.items()
        ]
        incidents = self._upsert_incidents(incidents)

        return {
            "summary": {
                "flows_received": len(flows),
                "alerts_generated": len(alerts),
                "incidents_open": len(incidents),
                "attack_type_counts": dict(
                    Counter(alert["attack_type"] for alert in alerts)
                ),
            },
            "predictions": prediction_records,
            "alerts": alerts,
            "incidents": incidents,
        }

    def list_active_incidents(self) -> list[dict]:
        # Return all currently active incidents (sorted by recency)
        with self._lock:
            return sorted(
                self._incidents.values(),
                key=lambda item: item["last_seen"],
                reverse=True,
            )

    def update_incident_status(self, incident_id: str, status: str) -> dict | None:
        # Update incident lifecycle status (open → acknowledged → resolved)
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                return None
        incident["status"] = status
        return dict(incident)

    @staticmethod
    def mitre_catalog() -> dict:
        # Return available MITRE mappings for external use
        return {"attack_types": MITRE_ATTACK_LIBRARY}
