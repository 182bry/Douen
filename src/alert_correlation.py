import argparse
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

from src.config.settings import ALERTS_RAW, ALERTS_CORRELATED, PROCESSED_DIR


# Config — tunable thresholds

TIME_WINDOW_SECONDS   = 60      # group alerts within this window
ALERT_THRESHOLD       = 3       # min alerts in window to create a correlated event
HIGH_SEVERITY_COUNT   = 10      # alerts in window → HIGH severity
CRITICAL_COUNT        = 25      # alerts in window → CRITICAL severity
SUPPRESSION_MINUTES   = 5       # suppress repeated alerts from same source after escalation

# MITRE ATT&CK mapping for CICIDS2017 attack types
MITRE_MAP = {
    "DDoS"                  : ("T1498", "Network Denial of Service",           "Impact"),
    "DoS Hulk"              : ("T1499", "Endpoint Denial of Service",          "Impact"),
    "DoS GoldenEye"         : ("T1499", "Endpoint Denial of Service",          "Impact"),
    "DoS slowloris"         : ("T1499", "Endpoint Denial of Service",          "Impact"),
    "DoS Slowhttptest"      : ("T1499", "Endpoint Denial of Service",          "Impact"),
    "PortScan"              : ("T1046", "Network Service Discovery",           "Discovery"),
    "FTP-Patator"           : ("T1110", "Brute Force",                         "Credential Access"),
    "SSH-Patator"           : ("T1110", "Brute Force",                         "Credential Access"),
    "Bot"                   : ("T1071", "Application Layer Protocol",          "Command and Control"),
    "WebAttack_BruteForce"  : ("T1110", "Brute Force",                         "Credential Access"),
    "WebAttack_XSS"         : ("T1059", "Scripting",                           "Execution"),
    "WebAttack_SQLInjection": ("T1190", "Exploit Public-Facing Application",   "Initial Access"),
    "Infiltration"          : ("T1078", "Valid Accounts",                      "Defense Evasion"),
    "Heartbleed"            : ("T1190", "Exploit Public-Facing Application",   "Initial Access"),
    "BENIGN"                : ("—",     "—",                                   "—"),
}


# Helpers

def assign_severity(count):
    if count >= CRITICAL_COUNT:
        return "CRITICAL"
    elif count >= HIGH_SEVERITY_COUNT:
        return "HIGH"
    elif count >= ALERT_THRESHOLD:
        return "MEDIUM"
    else:
        return "LOW"


def get_mitre(label):
    entry = MITRE_MAP.get(label, ("T????", "Unknown Technique", "Unknown Tactic"))
    return entry


def generate_demo_predictions(n=5000, seed=42):
    """
    Generates a realistic synthetic predictions CSV for demo/testing.
    Columns: timestamp, src_ip, dst_ip, dst_port, protocol, predicted_label, confidence
    """
    random.seed(seed)
    np.random.seed(seed)

    labels      = list(MITRE_MAP.keys())
    # Weighted: mostly BENIGN, then DDoS/PortScan heavy, rest sparse
    weights     = [0.55, 0.08, 0.07, 0.04, 0.03, 0.04, 0.03, 0.03,
                   0.02, 0.02, 0.02, 0.01, 0.01, 0.01, 0.00]
    weights     = [w / sum(weights) for w in weights]

    base_time   = datetime(2024, 1, 15, 9, 0, 0)
    src_ips     = [f"192.168.{random.randint(1,5)}.{random.randint(1,254)}" for _ in range(40)]
    # Give 5 IPs attacker-like behaviour (concentrated alerts)
    attacker_ips = src_ips[:5]

    rows = []
    for i in range(n):
        ts = base_time + timedelta(seconds=random.randint(0, 3600))

        # Attackers generate attack traffic; normal hosts mostly BENIGN
        if random.random() < 0.15:
            src = random.choice(attacker_ips)
            label = random.choices(
                [l for l in labels if l != "BENIGN"],
                k=1
            )[0]
        else:
            src = random.choice(src_ips)
            label = random.choices(labels, weights=weights, k=1)[0]

        confidence = round(random.uniform(0.55, 0.99), 3)

        rows.append({
            "timestamp"       : ts,
            "src_ip"          : src,
            "dst_ip"          : f"10.0.0.{random.randint(1, 20)}",
            "dst_port"        : random.choice([80, 443, 22, 21, 8080, 3306]),
            "protocol"        : random.choice(["TCP", "UDP", "ICMP"]),
            "predicted_label" : label,
            "confidence"      : confidence,
        })

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    df.to_csv(ALERTS_RAW, index=False)
    print(f"Demo predictions saved to: {ALERTS_RAW}  ({len(df):,} rows)")
    return df


# Core correlation engine

def correlate_alerts(df):
    """
    Groups raw alerts by source IP within TIME_WINDOW_SECONDS buckets.
    Produces one correlated event per (src_ip × time_bucket × attack_type).
    """

    # Filter out benign — only alert on actual detections
    attack_df = df[df["predicted_label"] != "BENIGN"].copy()
    print(f"Raw attack alerts   : {len(attack_df):,}  "
          f"(out of {len(df):,} total predictions)")

    if attack_df.empty:
        print("No attack alerts to correlate.")
        return pd.DataFrame()

    attack_df["timestamp"] = pd.to_datetime(attack_df["timestamp"])

    # Create time bucket (floor to TIME_WINDOW_SECONDS)
    bucket_seconds = TIME_WINDOW_SECONDS
    attack_df["time_bucket"] = attack_df["timestamp"].apply(
        lambda t: t.replace(
            second=(t.second // bucket_seconds) * bucket_seconds,
            microsecond=0
        )
    )

    # Group: src_ip + time_bucket + attack type
    grouped = (
        attack_df
        .groupby(["src_ip", "time_bucket", "predicted_label"])
        .agg(
            alert_count    = ("predicted_label", "count"),
            avg_confidence = ("confidence",       "mean"),
            first_seen     = ("timestamp",        "min"),
            last_seen      = ("timestamp",        "max"),
            dst_ports      = ("dst_port",         lambda x: sorted(set(x))),
            protocols      = ("protocol",         lambda x: sorted(set(x))),
        )
        .reset_index()
    )

    # Apply alert threshold — suppress noise below threshold
    correlated = grouped[grouped["alert_count"] >= ALERT_THRESHOLD].copy()
    suppressed_count = len(grouped) - len(correlated)

    # Assign severity
    correlated["severity"] = correlated["alert_count"].apply(assign_severity)

    # Attach MITRE ATT&CK info
    mitre_info = correlated["predicted_label"].apply(
        lambda l: pd.Series({
            "mitre_id"    : get_mitre(l)[0],
            "technique"   : get_mitre(l)[1],
            "tactic"      : get_mitre(l)[2],
        })
    )
    correlated = pd.concat([correlated, mitre_info], axis=1)

    # Round confidence
    correlated["avg_confidence"] = correlated["avg_confidence"].round(3)

    # Sort by severity then alert count
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    correlated["_sev_order"] = correlated["severity"].map(severity_order)
    correlated = (
        correlated
        .sort_values(["_sev_order", "alert_count"], ascending=[True, False])
        .drop(columns=["_sev_order"])
        .reset_index(drop=True)
    )

    correlated.to_csv(ALERTS_CORRELATED, index=False)

    return correlated, suppressed_count


# Reporting

def print_report(correlated, suppressed_count, raw_attack_count):
    print("\n" + "=" * 60)
    print("  ALERT CORRELATION REPORT")
    print("=" * 60)

    noise_reduction = (1 - len(correlated) / max(raw_attack_count, 1)) * 100
    print(f"\nRaw attack alerts     : {raw_attack_count:,}")
    print(f"Suppressed (noise)    : {suppressed_count:,}")
    print(f"Correlated events     : {len(correlated):,}")
    print(f"Noise reduction       : {noise_reduction:.1f}%")

    print("\nSeverity breakdown:")
    sev_counts = correlated["severity"].value_counts()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts.get(sev, 0)
        bar = "█" * min(count, 40)
        print(f"  {sev:<10}: {count:>4}  {bar}")

    print("\nTop attacking IPs:")
    top_ips = (
        correlated.groupby("src_ip")["alert_count"]
        .sum()
        .nlargest(10)
        .reset_index()
    )
    print(top_ips.to_string(index=False))

    print("\nAttack type summary:")
    attack_summary = (
        correlated.groupby(["predicted_label", "mitre_id", "tactic"])
        .agg(events=("alert_count", "count"), total_alerts=("alert_count", "sum"))
        .sort_values("total_alerts", ascending=False)
        .reset_index()
    )
    print(attack_summary.to_string(index=False))

    if len(correlated) > 0:
        critical = correlated[correlated["severity"] == "CRITICAL"]
        if len(critical) > 0:
            print("\n⚠  CRITICAL EVENTS:")
            cols = ["src_ip", "predicted_label", "alert_count",
                    "avg_confidence", "first_seen", "mitre_id", "technique"]
            print(critical[cols].head(10).to_string(index=False))

    print(f"\nFull correlated alert log saved to: {ALERTS_CORRELATED}")


# Main

def main():
    parser = argparse.ArgumentParser(description="Alert correlation engine for IDS predictions.")
    parser.add_argument(
        "--predictions", type=str, default=None,
        help="Path to CSV with columns: timestamp, src_ip, dst_port, protocol, predicted_label, confidence"
    )
    parser.add_argument(
        "--generate-demo", action="store_true",
        help="Generate synthetic demo predictions and run correlation"
    )
    args = parser.parse_args()

    if args.generate_demo:
        print("Generating demo predictions...")
        df = generate_demo_predictions(n=5000)
    elif args.predictions:
        print(f"Loading predictions from: {args.predictions}")
        df = pd.read_csv(args.predictions)
    else:
        # Default: try ALERTS_RAW, else generate demo
        if os.path.exists(ALERTS_RAW):
            print(f"Loading predictions from: {ALERTS_RAW}")
            df = pd.read_csv(ALERTS_RAW)
        else:
            print("No prediction file found. Generating demo data...")
            df = generate_demo_predictions(n=5000)

    raw_attack_count = (df["predicted_label"] != "BENIGN").sum()

    print("\nRunning alert correlation...")
    result = correlate_alerts(df)

    if isinstance(result, tuple):
        correlated, suppressed_count = result
        print_report(correlated, suppressed_count, raw_attack_count)
    else:
        print("No correlated alerts produced.")


if __name__ == "__main__":
    main()