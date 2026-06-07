from backend.core.schema import ThreatEvent

DDOS_FAMILIES      = {"DDoS", "Botnet", "Infiltration"}
BRUTEFORCE_FAMILIES = {"BruteForce", "WebAttack"}
SENSITIVE_PORTS    = {22, 3389, 445, 21, 23, 3306, 5432}


class TriageAgent:
    def run(self, event: ThreatEvent) -> ThreatEvent:
        risk   = event.risk_score or 0.0
        family = event.attack_family or "Benign"
        rules: list[str] = []

        # --- Rule engine (using real CICIDS2017 feature names) ---

        # R1: High flow rate — key DDoS indicator
        flow_bytes = event.features.get("Flow Bytes/s", 0.0)
        if flow_bytes > 2.0:  # scaled value
            rules.append("R1_HIGH_FLOW_RATE")

        # R2: Sensitive port targeted
        if event.dst_port in SENSITIVE_PORTS:
            rules.append("R2_SENSITIVE_PORT_TARGET")

        # R3: One-way traffic — SYN flood / reconnaissance indicator
        fwd_iat = event.features.get("Fwd IAT Total", 0.0)
        bwd_iat = event.features.get("Bwd IAT Total", 0.0)
        if fwd_iat > 1.0 and bwd_iat == 0.0:
            rules.append("R3_ONE_WAY_TRAFFIC")

        # R4: High packet length variance — payload anomaly
        pkt_var = event.features.get("Packet Length Variance", 0.0)
        if pkt_var > 2.0:
            rules.append("R4_PACKET_LENGTH_ANOMALY")

        # R5: Long idle periods — beaconing / C2 indicator
        idle_mean = event.features.get("Idle Mean", 0.0)
        if idle_mean > 2.0:
            rules.append("R5_LONG_IDLE_PERIODS")

        # R6: Very short flow duration — scan or flood
        flow_dur = event.features.get("Flow Duration", 0.0)
        if flow_dur < -0.5:  # below mean in scaled space = very short
            rules.append("R6_SHORT_FLOW_DURATION")

        # R7: Large backward payload — data exfiltration indicator
        bwd_bytes = event.features.get("Total Length of Bwd Packets", 0.0)
        if bwd_bytes > 2.0:
            rules.append("R7_LARGE_BACKWARD_PAYLOAD")

        rules = list(dict.fromkeys(rules))  # deduplicate preserving order


        # --- Severity mapping ---
        if risk >= 0.9 and family in DDOS_FAMILIES:
            severity = "CRITICAL"
        elif risk >= 0.85 and family in BRUTEFORCE_FAMILIES:
            severity = "CRITICAL"
        elif risk >= 0.8 or family in BRUTEFORCE_FAMILIES:
            severity = "HIGH"
        elif risk >= 0.6:
            severity = "MEDIUM"
        elif risk >= 0.4:
            severity = "LOW"
        else:
            severity = "INFO"

        # Rule bumps
        if "R2_SENSITIVE_PORT_TARGET" in rules and severity in {"LOW", "INFO"}:
            severity = "MEDIUM"
        if "R7_LARGE_BACKWARD_PAYLOAD" in rules and severity in {"MEDIUM"}:
            severity = "HIGH"
        if len(rules) >= 3 and severity == "HIGH":
            severity = "CRITICAL"

        # --- Triage decision ---
        if severity in {"CRITICAL", "HIGH"}:
            decision = "ESCALATE"
        elif severity == "MEDIUM":
            decision = "MONITOR"
        else:
            decision = "IGNORE"

        # --- Attack hypothesis ---
        hypothesis = self._hypothesize(family, rules, event)

        event.severity        = severity
        event.triage_decision = decision
        event.rules_triggered = rules
        event.attack_hypothesis = hypothesis
        return event

    def _hypothesize(self, family: str, rules: list[str], event: ThreatEvent) -> str:
        port = event.dst_port or 0

        if family == "DDoS" and "R1_HIGH_FLOW_RATE" in rules:
            return "Volumetric DDoS flood detected — high flow rate targeting service availability."
        if family == "DDoS" and "R6_SHORT_FLOW_DURATION" in rules:
            return "DDoS attack with rapid connection cycling — possible SYN flood."
        if family == "BruteForce" and port == 22:
            return "SSH brute-force credential attack against administrative service."
        if family == "BruteForce" and port == 3389:
            return "RDP brute-force credential attack — possible remote desktop compromise attempt."
        if family == "BruteForce":
            return "Automated credential stuffing or brute-force attack detected."
        if family == "WebAttack":
            return "Web application attack detected — possible SQLi, XSS, or auth bypass attempt."
        if family == "Botnet" and "R5_LONG_IDLE_PERIODS" in rules:
            return "Botnet C2 beaconing pattern — compromised host phoning home at regular intervals."
        if family == "Botnet":
            return "Botnet activity detected — possible C2 communication or lateral movement."
        if family == "Reconnaissance" and "R6_SHORT_FLOW_DURATION" in rules:
            return "Active port scanning detected — attacker mapping network topology."
        if family == "Reconnaissance":
            return "Network reconnaissance activity — systematic probing of target services."
        if family == "Infiltration" and "R7_LARGE_BACKWARD_PAYLOAD" in rules:
            return "Infiltration with large data transfer — potential exfiltration in progress."
        if family == "Infiltration":
            return "Infiltration attempt detected — attacker may have existing network foothold."
        if event.is_suspicious:
            return "Anomalous traffic pattern detected — does not match known baseline behavior."
        return "Likely benign traffic — no significant threat indicators."