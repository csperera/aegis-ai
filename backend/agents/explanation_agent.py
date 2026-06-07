import random
from backend.core.schema import ThreatEvent


TEMPLATES = {
    "DDoS": {
        "explanation": (
            "This event exhibits characteristics consistent with a Distributed Denial-of-Service attack. "
            "The source IP {src_ip} is generating an abnormally high packet rate toward {dst_ip}, "
            "with a risk score of {risk_score:.2f} indicating near-certain malicious intent. "
            "The traffic pattern suggests an attempt to exhaust target resources and disrupt service availability. "
            "Immediate containment is recommended to prevent downstream impact."
        ),
        "action": (
            "1. Block source IP {src_ip} at the perimeter firewall immediately. "
            "2. Engage upstream ISP for traffic scrubbing if volumetric attack is confirmed. "
            "3. Activate DDoS mitigation appliance or cloud scrubbing service. "
            "4. Notify NOC and escalate to Incident Response team. "
            "5. Capture full packet trace for forensic analysis."
        ),
        "trace": [
            "Anomalously high packet-per-second rate detected",
            "Low byte-per-packet ratio consistent with flood traffic",
            "One-directional traffic with minimal server response",
            "Risk score {risk_score:.2f} exceeds CRITICAL threshold",
        ],
    },
    "BruteForce": {
        "explanation": (
            "This event indicates a brute-force credential attack originating from {src_ip} targeting port {dst_port} on {dst_ip}. "
            "The repeated connection attempts with a risk score of {risk_score:.2f} suggest automated password spraying or dictionary attack tooling. "
            "Destination port {dst_port} is a commonly targeted administrative service. "
            "If successful, this could result in unauthorized access and lateral movement within the network."
        ),
        "action": (
            "1. Block source IP {src_ip} immediately and add to threat intelligence blocklist. "
            "2. Enforce account lockout policy on targeted service at {dst_ip}:{dst_port}. "
            "3. Review authentication logs for any successful logins from this source. "
            "4. Enable MFA on all exposed administrative services. "
            "5. Notify the asset owner of {dst_ip} and initiate credential rotation."
        ),
        "trace": [
            "High connection attempt rate to single destination port",
            "Destination port {dst_port} is a known administrative service target",
            "Traffic pattern consistent with automated attack tooling",
            "Risk score {risk_score:.2f} indicates high-confidence threat",
        ],
    },
    "WebAttack": {
        "explanation": (
            "This event reflects a web application attack from {src_ip} targeting {dst_ip} on port {dst_port}. "
            "The traffic pattern with risk score {risk_score:.2f} is consistent with exploitation attempts including SQL injection, XSS, or brute-force against web authentication. "
            "Web application attacks can lead to data exfiltration, account compromise, or remote code execution. "
            "The targeted service should be isolated and inspected immediately."
        ),
        "action": (
            "1. Block source IP {src_ip} at the WAF and perimeter firewall. "
            "2. Review web application logs on {dst_ip} for successful exploit indicators. "
            "3. Check database integrity for signs of SQL injection compromise. "
            "4. Patch or virtually patch the targeted web application. "
            "5. Escalate to application security team for full vulnerability assessment."
        ),
        "trace": [
            "Abnormal HTTP request patterns detected",
            "Destination port {dst_port} indicates web application targeting",
            "Traffic volume and pattern consistent with automated web attack tools",
            "Risk score {risk_score:.2f} exceeds HIGH severity threshold",
        ],
    },
    "Botnet": {
        "explanation": (
            "This event suggests botnet command-and-control (C2) communication from {src_ip} to {dst_ip}. "
            "The periodic, low-volume traffic pattern with risk score {risk_score:.2f} is characteristic of a compromised host beaconing to a C2 server. "
            "If confirmed, this indicates the source host is already compromised and part of a botnet infrastructure. "
            "Immediate isolation of the source host is critical to prevent further spread and data exfiltration."
        ),
        "action": (
            "1. Immediately isolate host at {src_ip} from the network. "
            "2. Preserve forensic image of the compromised host before remediation. "
            "3. Block C2 destination {dst_ip} at all egress points. "
            "4. Scan adjacent network segments for similar beaconing patterns. "
            "5. Initiate full incident response procedure and notify stakeholders."
        ),
        "trace": [
            "Periodic beaconing pattern detected at regular intervals",
            "Low-volume encrypted traffic consistent with C2 communication",
            "Destination IP flagged for botnet infrastructure association",
            "Risk score {risk_score:.2f} confirms high-confidence compromise",
        ],
    },
    "Reconnaissance": {
        "explanation": (
            "This event indicates network reconnaissance activity originating from {src_ip} scanning {dst_ip}. "
            "The systematic port scanning pattern with risk score {risk_score:.2f} suggests an attacker mapping the network topology and identifying open services. "
            "Reconnaissance is typically a precursor to targeted exploitation and should be treated as an early warning indicator. "
            "The source IP should be blocked and monitored across all network segments."
        ),
        "action": (
            "1. Block source IP {src_ip} at the perimeter and add to watchlist. "
            "2. Review firewall rules to ensure unnecessary ports are not exposed on {dst_ip}. "
            "3. Check threat intelligence feeds for {src_ip} association with known threat actors. "
            "4. Increase logging verbosity on {dst_ip} for the next 24 hours. "
            "5. Alert network security team to monitor for follow-up exploitation attempts."
        ),
        "trace": [
            "Systematic port scanning pattern across multiple destination ports",
            "High connection attempt rate with minimal data transfer",
            "Traffic pattern consistent with nmap or similar scanning tools",
            "Risk score {risk_score:.2f} indicates confirmed malicious reconnaissance",
        ],
    },
    "Infiltration": {
        "explanation": (
            "This event is indicative of an active infiltration or data exfiltration attempt from {src_ip} targeting {dst_ip}. "
            "With a risk score of {risk_score:.2f}, this represents one of the highest-severity threat categories. "
            "The traffic pattern suggests an attacker with existing network access attempting to exfiltrate sensitive data or establish persistent access. "
            "This requires immediate escalation to the incident response team and executive notification."
        ),
        "action": (
            "1. CRITICAL: Immediately isolate affected segment containing {dst_ip}. "
            "2. Engage incident response team and executive stakeholders immediately. "
            "3. Preserve all network logs and packet captures for forensic analysis. "
            "4. Identify and revoke any credentials that may have been compromised. "
            "5. Assess data exposure and prepare breach notification if required by compliance obligations."
        ),
        "trace": [
            "Unusual outbound data transfer volume detected",
            "Traffic pattern inconsistent with normal baseline behavior",
            "Destination {dst_ip} not in approved communication whitelist",
            "Risk score {risk_score:.2f} — highest severity classification triggered",
        ],
    },
    "Benign": {
        "explanation": (
            "This event from {src_ip} to {dst_ip} has been classified as benign traffic with a risk score of {risk_score:.2f}. "
            "The traffic characteristics are consistent with normal network activity and no malicious indicators were detected. "
            "No immediate action is required, though this event has been logged for baseline profiling purposes."
        ),
        "action": "No action required. Continue standard monitoring.",
        "trace": [
            "Risk score {risk_score:.2f} below suspicious threshold",
            "Traffic pattern consistent with normal baseline activity",
            "No heuristic rules triggered",
        ],
    },
}

DEFAULT_TEMPLATE = {
    "explanation": (
        "This event from {src_ip} targeting {dst_ip} has been flagged with a risk score of {risk_score:.2f}. "
        "The attack family is classified as {attack_family} and the triage system has assigned {severity} severity. "
        "The event exhibits anomalous characteristics that deviate from baseline network behavior. "
        "Manual analyst review is recommended to determine the appropriate response."
    ),
    "action": (
        "1. Review the full event context and correlated logs for {src_ip}. "
        "2. Check threat intelligence feeds for known indicators associated with this source. "
        "3. Monitor destination {dst_ip} for follow-up activity. "
        "4. Escalate to senior analyst if additional suspicious activity is observed."
    ),
    "trace": [
        "Risk score {risk_score:.2f} flagged by XGBoost detection model",
        "Attack family: {attack_family}",
        "Severity assigned: {severity}",
    ],
}


class ExplanationAgent:
    def run(self, event: ThreatEvent) -> ThreatEvent:
        family = event.attack_family or "Benign"
        template = TEMPLATES.get(family, DEFAULT_TEMPLATE)

        fmt = {
            "src_ip":        event.src_ip or "unknown",
            "dst_ip":        event.dst_ip or "unknown",
            "src_port":      event.src_port or 0,
            "dst_port":      event.dst_port or 0,
            "protocol":      event.protocol or "TCP",
            "risk_score":    event.risk_score or 0.0,
            "attack_family": family,
            "severity":      event.severity or "UNKNOWN",
        }

        event.llm_explanation    = template["explanation"].format(**fmt)
        event.recommended_action = template["action"].format(**fmt)
        event.reasoning_trace    = [t.format(**fmt) for t in template["trace"]]
        event.analyst_summary    = f"{family} activity detected from {fmt['src_ip']} — {event.triage_decision or 'REVIEW'}"
        event.confidence         = round(event.risk_score or 0.5, 2)

        return event