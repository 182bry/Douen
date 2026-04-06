from __future__ import annotations

from copy import deepcopy


TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


MITRE_ATTACK_LIBRARY = {
    "PortScan": {
        "summary": "The flow pattern is consistent with adversary service discovery prior to exploitation.",
        "tactics": [{"id": "TA0043", "name": "Reconnaissance"}],
        "techniques": [{"id": "T1595", "name": "Active Scanning"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Reconnaissance",
                "technique_id": "T1595",
                "technique": "Active Scanning",
                "description": "The adversary probes reachable hosts and open services to identify viable targets.",
            }
        ],
    },
    "FTP-Patator": {
        "summary": "Repeated login attempts suggest password guessing against exposed FTP services.",
        "tactics": [{"id": "TA0006", "name": "Credential Access"}],
        "techniques": [{"id": "T1110", "name": "Brute Force"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Credential Access",
                "technique_id": "T1110",
                "technique": "Brute Force",
                "description": "The adversary cycles credentials against an FTP login surface.",
            }
        ],
    },
    "SSH-Patator": {
        "summary": "Repeated authentication failures are aligned with SSH brute-force activity.",
        "tactics": [{"id": "TA0006", "name": "Credential Access"}],
        "techniques": [{"id": "T1110", "name": "Brute Force"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Credential Access",
                "technique_id": "T1110",
                "technique": "Brute Force",
                "description": "The adversary attempts to recover valid SSH credentials through repeated guesses.",
            }
        ],
    },
    "WebAttack_BruteForce": {
        "summary": "The traffic resembles credential stuffing or brute-force attempts against a web-facing login.",
        "tactics": [
            {"id": "TA0006", "name": "Credential Access"},
            {"id": "TA0001", "name": "Initial Access"},
        ],
        "techniques": [
            {"id": "T1110", "name": "Brute Force"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
        ],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Credential Access",
                "technique_id": "T1110",
                "technique": "Brute Force",
                "description": "The adversary targets a web authentication workflow with repeated guesses.",
            },
            {
                "step": 2,
                "phase": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "Successful credential compromise can become a path into the application environment.",
            },
        ],
    },
    "WebAttack_SQLInjection": {
        "summary": "The activity maps to exploitation of a public-facing application through malicious input.",
        "tactics": [
            {"id": "TA0001", "name": "Initial Access"},
            {"id": "TA0009", "name": "Collection"},
        ],
        "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "The adversary sends crafted SQL payloads to abuse exposed application logic.",
            },
            {
                "step": 2,
                "phase": "Collection",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "A successful injection can expose or extract application data from the backing store.",
            },
        ],
    },
    "WebAttack_XSS": {
        "summary": "The traffic suggests input-driven exploitation of a public-facing application.",
        "tactics": [
            {"id": "TA0001", "name": "Initial Access"},
            {"id": "TA0002", "name": "Execution"},
        ],
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1059.007", "name": "JavaScript"},
        ],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "The adversary abuses unsafe input handling on the exposed web application.",
            },
            {
                "step": 2,
                "phase": "Execution",
                "technique_id": "T1059.007",
                "technique": "JavaScript",
                "description": "Injected script can execute in a victim browser if the payload is reflected or stored.",
            },
        ],
    },
    "Infiltration": {
        "summary": "This label points to follow-on malicious activity after initial compromise or payload delivery.",
        "tactics": [
            {"id": "TA0001", "name": "Initial Access"},
            {"id": "TA0011", "name": "Command and Control"},
        ],
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1071", "name": "Application Layer Protocol"},
        ],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "The adversary gains a foothold through an exposed service or application path.",
            },
            {
                "step": 2,
                "phase": "Command and Control",
                "technique_id": "T1071",
                "technique": "Application Layer Protocol",
                "description": "Follow-on traffic suggests post-compromise communications over common application protocols.",
            },
        ],
    },
    "Bot": {
        "summary": "The communication pattern suggests a compromised host participating in botnet activity.",
        "tactics": [{"id": "TA0011", "name": "Command and Control"}],
        "techniques": [{"id": "T1071", "name": "Application Layer Protocol"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Command and Control",
                "technique_id": "T1071",
                "technique": "Application Layer Protocol",
                "description": "The compromised host appears to maintain command-and-control traffic with an operator.",
            }
        ],
    },
    "Heartbleed": {
        "summary": "The flow aligns with exploitation of a vulnerable public-facing service.",
        "tactics": [
            {"id": "TA0001", "name": "Initial Access"},
            {"id": "TA0006", "name": "Credential Access"},
        ],
        "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "The adversary attempts to abuse a vulnerable service exposed to the network.",
            },
            {
                "step": 2,
                "phase": "Credential Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "description": "Memory disclosure from the exploit can expose session material or secrets.",
            },
        ],
    },
    "DDoS": {
        "summary": "The event reflects an availability attack intended to saturate network capacity.",
        "tactics": [{"id": "TA0040", "name": "Impact"}],
        "techniques": [{"id": "T1498", "name": "Network Denial of Service"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Impact",
                "technique_id": "T1498",
                "technique": "Network Denial of Service",
                "description": "Distributed traffic volume is used to degrade or disrupt a service.",
            }
        ],
    },
    "DoS Hulk": {
        "summary": "The flow suggests a high-rate denial-of-service attempt against a service endpoint.",
        "tactics": [{"id": "TA0040", "name": "Impact"}],
        "techniques": [{"id": "T1499", "name": "Endpoint Denial of Service"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Impact",
                "technique_id": "T1499",
                "technique": "Endpoint Denial of Service",
                "description": "The adversary attempts to exhaust application or host resources on the target.",
            }
        ],
    },
    "DoS GoldenEye": {
        "summary": "The traffic pattern is consistent with an application-layer denial-of-service attempt.",
        "tactics": [{"id": "TA0040", "name": "Impact"}],
        "techniques": [{"id": "T1499", "name": "Endpoint Denial of Service"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Impact",
                "technique_id": "T1499",
                "technique": "Endpoint Denial of Service",
                "description": "The adversary targets server-side resources to degrade service availability.",
            }
        ],
    },
    "DoS slowloris": {
        "summary": "The event resembles slow HTTP connection abuse aimed at tying up server sockets.",
        "tactics": [{"id": "TA0040", "name": "Impact"}],
        "techniques": [{"id": "T1499", "name": "Endpoint Denial of Service"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Impact",
                "technique_id": "T1499",
                "technique": "Endpoint Denial of Service",
                "description": "The adversary holds connections open to exhaust the target's available capacity.",
            }
        ],
    },
    "DoS Slowhttptest": {
        "summary": "The observed pattern matches slow-request flooding against an application endpoint.",
        "tactics": [{"id": "TA0040", "name": "Impact"}],
        "techniques": [{"id": "T1499", "name": "Endpoint Denial of Service"}],
        "attack_steps": [
            {
                "step": 1,
                "phase": "Impact",
                "technique_id": "T1499",
                "technique": "Endpoint Denial of Service",
                "description": "Slow or partial requests are used to keep server resources occupied.",
            }
        ],
    },
}


UNKNOWN_ANOMALY_PLAYBOOK = {
    "summary": "An anomaly was detected, but there is not enough signal to map it to a single ATT&CK technique.",
    "tactics": [],
    "techniques": [],
    "attack_steps": [
        {
            "step": 1,
            "phase": "Triage",
            "technique_id": None,
            "technique": None,
            "description": "Review the anomalous flow, enrich it with host and identity telemetry, and assign a final ATT&CK mapping.",
        }
    ],
}


def get_mitre_mapping(attack_type: str, anomaly_only: bool = False) -> dict:
    """
    Return the ATT&CK-oriented playbook for a detected attack label.
    """
    if anomaly_only and attack_type not in MITRE_ATTACK_LIBRARY:
        return deepcopy(UNKNOWN_ANOMALY_PLAYBOOK)

    entry = MITRE_ATTACK_LIBRARY.get(attack_type)
    if entry is None:
        return deepcopy(UNKNOWN_ANOMALY_PLAYBOOK)

    return deepcopy(entry)


def build_attack_progression(attack_types: list[str]) -> list[dict]:
    """
    Combine ATT&CK steps from multiple attack types into a single ordered story.
    """
    steps = []
    seen = set()

    for attack_type in attack_types:
        for step in get_mitre_mapping(attack_type).get("attack_steps", []):
            key = (step["phase"], step.get("technique_id"), step["description"])
            if key in seen:
                continue
            seen.add(key)
            steps.append(step)

    def sort_key(step: dict) -> tuple[int, str]:
        phase = step.get("phase") or "Triage"
        try:
            phase_index = TACTIC_ORDER.index(phase)
        except ValueError:
            phase_index = len(TACTIC_ORDER)
        return phase_index, step.get("technique_id") or ""

    ordered_steps = sorted(steps, key=sort_key)

    for index, step in enumerate(ordered_steps, start=1):
        step["step"] = index

    return ordered_steps
