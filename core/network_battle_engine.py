"""
DataWatchDawgs — Network Battle Engine
=======================================
Orchestrates full dual-layer battles (application + network) and powers
the four additional use-cases enabled by integrating attack_sim:

  Use 1 — Extended Red Agent: Both app-layer (Red Agent) and network-layer
           (Network Agent) attacks fire in the same battle round.

  Use 3 — SOC Training Platform: SOC analyst reviews live attack traffic,
           attempts detection; DataWatchDawgs scores response speed & accuracy.

  Use 4 — WAF/Firewall Verification: attack_sim fires network traffic;
           Blue Agent proposes firewall rules; Red verifies they block it.

  Use 5 — Continuous Red Team Automation: Runs every attack type nightly,
           on every deploy, on every firewall rule change.
"""

import logging
import os
import time
from typing import Callable, Optional

from agents.network_agent import (
    NetworkAgent,
    NetworkExploitResult,
    NetworkDetectionPatch,
    NETWORK_ATTACK_META,
    FALLBACK_DETECTION_PATCHES,
)
from agents.referee import Referee

logger = logging.getLogger("dwd.net_engine")


# ── Network CVE-equivalent descriptors ───────────────────────────────────────

NETWORK_VULN_DB = {
    "port_scan": {
        "id": "NET-PSCAN-001",
        "name": "TCP Port Scan — Network Reconnaissance",
        "cvss": 5.3,
        "type": "Medium",
        "type_key": "port_scan",
        "desc": "Sequential TCP connect probes enumerate open services for further targeting.",
        "layer": "network",
        "payloads": [
            "TCP SYN scan ports=22,80,443 speed=fast",
            "TCP SYN scan ports=1-1024 speed=stealth",
            "TCP SYN scan ports=3306,5432,6379,27017 (database ports)",
            "TCP SYN scan ports=8080,8443,8888 (app ports)",
            "TCP SYN scan ports=22,23,3389 (remote access)",
        ],
    },
    "brute_force": {
        "id": "NET-BRUTE-001",
        "name": "HTTP Brute Force — Credential Stuffing",
        "cvss": 7.5,
        "type": "High",
        "type_key": "brute_force",
        "desc": "Automated wordlist-driven password guessing against HTTP login endpoint.",
        "layer": "auth",
        "payloads": [
            "POST /login username=admin password=<wordlist>",
            "POST /login username=admin password=<rockyou.txt subset>",
            "POST /api/auth username=root password=<wordlist>",
            "POST /wp-login.php username=admin password=<wordlist>",
            "POST /login username=administrator password=<wordlist>",
        ],
    },
    "c2_beacon": {
        "id": "NET-C2-001",
        "name": "C2 Beaconing — Malware Check-in",
        "cvss": 8.1,
        "type": "High",
        "type_key": "c2_beacon",
        "desc": "Periodic HTTP POST beacons to external C2 server simulating malware check-in.",
        "layer": "malware",
        "payloads": [
            "POST <c2-server> interval=5s jitter=±30% payload=JSON",
            "POST <c2-server> interval=30s jitter=±30% UA=randomised",
            "POST <c2-server> interval=60s beacon seq+timestamp",
            "POST <c2-server> interval=5s host-id in payload",
            "POST <c2-server> interval=10s binary-encoded payload",
        ],
    },
    "data_exfiltration": {
        "id": "NET-EXFIL-001",
        "name": "Data Exfiltration — Suspicious Egress",
        "cvss": 8.6,
        "type": "High",
        "type_key": "data_exfiltration",
        "desc": "High-entropy binary chunks sent outbound via HTTP POST or raw TCP.",
        "layer": "egress",
        "payloads": [
            "HTTP POST 512B×10 random binary chunks",
            "HTTP POST 1024B×50 random binary chunks",
            "TCP raw 1024B×20 to external host",
            "HTTP POST 2048B×25 high-entropy data",
            "TCP raw 512B×100 slow-drip exfiltration",
        ],
    },
    "traffic_flood": {
        "id": "NET-FLOOD-001",
        "name": "Traffic Flood — Volumetric DoS",
        "cvss": 7.5,
        "type": "High",
        "type_key": "traffic_flood",
        "desc": "Multi-threaded HTTP GET flood simulating DoS/DDoS volumetric attack.",
        "layer": "volumetric",
        "payloads": [
            "HTTP GET 50 req/s × 5 threads × 10s",
            "HTTP GET 100 req/s × 10 threads × 10s",
            "HTTP GET 200 req/s × 5 threads × 10s",
            "HTTP GET 50 req/s × 20 threads × 10s",
            "HTTP GET 100 req/s × 5 threads × 20s",
        ],
    },
}


def _make_cve_compat(net_vuln: dict) -> dict:
    """Return a dict shaped like BattleEngine's CVE_DB entries for Referee compatibility."""
    return net_vuln  # already has id, name, cvss, type, type_key, desc, payloads


class NetworkBattleEngine:
    """
    Runs network-layer battles (Use 1, 3, 4, 5).

    This engine is designed to run standalone (Use 3/4/5) OR to be called by
    the main BattleEngine to extend each app-layer battle with a network phase.
    """

    # Paths on SentinelAI's target_server per attack type
    _SENTINEL_PATHS = {
        "brute_force":       "/login",
        "c2_beacon":         "/beacon",
        "data_exfiltration": "/upload",
        "traffic_flood":     "/",
        "port_scan":         None,
    }

    def __init__(
        self,
        max_rounds: int = 5,
        target: str = "127.0.0.1",
        port: int = 6100,
        emit_fn: Optional[Callable] = None,
    ):
        self.max_rounds = max_rounds
        self.target = target
        self.port = port
        self.emit = emit_fn or (lambda ev, data: None)
        self.network_agent = NetworkAgent(target=target, port=port)
        self.referee = Referee()
        self.battles = []

    # ─────────────────────────────────────────────────────────────────────
    # Use 1 — Extend Red Agent's attack types
    # Called by BattleEngine after each app-layer round to add network layer
    # ─────────────────────────────────────────────────────────────────────

    def run_network_phase(
        self,
        attack_type: str,
        round_num: int,
        target_url: Optional[str] = None,
        options: Optional[dict] = None,
    ) -> dict:
        """
        Fire one network-layer attack and return the result dict.
        Designed to be injected into an existing BattleEngine round.
        """
        meta = NETWORK_ATTACK_META.get(attack_type, {})
        self._log("INFO", "network:", "la-red",
                  f"[Network Layer] Round {round_num}: Firing {attack_type} "
                  f"({meta.get('layer','?')} layer) against {target_url or self.target}")

        # Route to correct SentinelAI endpoint path
        _path = self._SENTINEL_PATHS.get(attack_type)
        _base = target_url or f"http://{self.target}:{self.port}"
        if _path and _path != "/":
            from urllib.parse import urlparse as _up
            if _up(_base).path in ("", "/"):
                _base = _base.rstrip("/") + _path
        full_url = _base

        exploit = self.network_agent.attack(
            attack_type=attack_type,
            round_num=round_num,
            target_url=full_url,
            options=options,
        )

        if exploit.success:
            self._log("ERROR", "network:", "la-red",
                      f"[Network Layer] {attack_type.upper()} UNDETECTED — "
                      f"{exploit.evidence[:80]}")
        else:
            self._log("SUCCESS", "network:", "la-red",
                      f"[Network Layer] {attack_type.upper()} detected/blocked — "
                      f"{exploit.evidence[:80]}")

        return exploit.to_dict()

    # ─────────────────────────────────────────────────────────────────────
    # Use 3 — SOC Training Platform
    # ─────────────────────────────────────────────────────────────────────

    def run_soc_training(self, attack_type: str, soc_response: Optional[dict] = None) -> dict:
        """
        SOC training mode: fire attack, score the analyst's detection response.

        Parameters
        ----------
        attack_type : str
            Which network attack to fire.
        soc_response : dict, optional
            Analyst's response: {"detected": bool, "rule_proposed": str, "response_time_s": float}
        """
        battle_id = f"SOC-{int(time.time())}-{attack_type.upper()}"
        vuln = NETWORK_VULN_DB.get(attack_type, NETWORK_VULN_DB["port_scan"])
        started = time.time()

        self._emit("battle_start", {
            "battle_id": battle_id, "mode": "soc_training",
            "attack_type": attack_type, "layer": vuln["layer"],
        })
        self._log("INFO", "soc-trainer:", "la-orch",
                  f"SOC Training — {attack_type} ({vuln['layer']} layer) — live fire started")

        # Fire the attack
        exploit = self.network_agent.attack(attack_type, round_num=1)
        self._emit("network_attack", exploit.to_dict())

        # Score the SOC response
        score = self._score_soc_response(exploit, soc_response or {})

        # Blue proposes what detection rules they should have had
        detection_patch = self.network_agent.propose_detection(attack_type, round_num=1)
        self._emit("blue_patch", detection_patch.to_dict())

        self._log(
            "SUCCESS" if score["caught"] else "ERROR",
            "soc-trainer:", "la-orch",
            f"SOC Score: {score['score']:.0%} — "
            f"{'CAUGHT' if score['caught'] else 'MISSED'} — "
            f"response time: {score.get('response_time_s', '?')}s",
        )

        record = {
            "battle_id": battle_id,
            "mode": "soc_training",
            "attack_type": attack_type,
            "layer": vuln["layer"],
            "exploit": exploit.to_dict(),
            "detection_patch": detection_patch.to_dict(),
            "soc_score": score,
            "duration": round(time.time() - started, 1),
        }
        self.battles.append(record)
        self._emit("battle_complete", record)
        return record

    def _score_soc_response(self, exploit: NetworkExploitResult, soc_response: dict) -> dict:
        """Score a SOC analyst's detection response."""
        detected = soc_response.get("detected", False)
        rule = soc_response.get("rule_proposed", "")
        resp_time = soc_response.get("response_time_s", 999)

        # Expected IOC from metadata
        meta = NETWORK_ATTACK_META.get(exploit.vuln_type, {})
        expected_ioc = meta.get("ioc", "")

        # Scoring rubric
        score = 0.0
        details = []

        if detected and exploit.success:
            score += 0.5
            details.append("✅ Correctly detected unblocked attack (+50%)")
        elif not detected and not exploit.success:
            score += 0.4
            details.append("✅ Attack was blocked — no detection needed (+40%)")
        elif detected and not exploit.success:
            score += 0.3
            details.append("⚠️ Flagged but attack was already blocked (+30%)")
        else:
            details.append("❌ Failed to detect active unblocked attack (+0%)")

        # Response time bonus
        if resp_time < 30:
            score += 0.3
            details.append(f"✅ Fast response <30s (+30%)")
        elif resp_time < 120:
            score += 0.15
            details.append(f"⚠️ Moderate response {resp_time:.0f}s (+15%)")
        else:
            details.append(f"❌ Slow response {resp_time:.0f}s (+0%)")

        # Rule quality check (keyword match against known good rules)
        good_keywords = {
            "port_scan":         ["threshold", "ports", "syn", "iptables", "rate"],
            "brute_force":       ["rate", "limit", "lockout", "429", "401"],
            "c2_beacon":         ["egress", "beacon", "interval", "periodic", "outbound"],
            "data_exfiltration": ["entropy", "dlp", "egress", "bytes", "block"],
            "traffic_flood":     ["rate", "limit", "hashlimit", "rps", "429"],
        }
        keywords = good_keywords.get(exploit.vuln_type, [])
        rule_lower = rule.lower()
        hits = sum(1 for kw in keywords if kw in rule_lower)
        if hits >= 3:
            score += 0.2
            details.append(f"✅ Rule covers key detection terms (+20%)")
        elif hits >= 1:
            score += 0.1
            details.append(f"⚠️ Rule partially covers detection ({hits}/{len(keywords)} terms) (+10%)")
        else:
            details.append("❌ Rule missing detection keywords (+0%)")

        return {
            "score": min(score, 1.0),
            "caught": detected,
            "response_time_s": resp_time,
            "details": details,
            "expected_ioc": expected_ioc,
        }

    # ─────────────────────────────────────────────────────────────────────
    # Use 4 — Firewall / WAF Rule Verification
    # ─────────────────────────────────────────────────────────────────────

    def run_firewall_verification(
        self,
        attack_type: str,
        proposed_rule: Optional[str] = None,
    ) -> dict:
        """
        Workflow:
          1. attack_sim fires network traffic
          2. Blue Agent proposes a detection/firewall rule
          3. Red Agent (Network Agent) verifies the rule blocks the traffic
          4. Referee signs the result
        """
        battle_id = f"WAF-{int(time.time())}-{attack_type.upper()}"
        vuln = NETWORK_VULN_DB.get(attack_type, NETWORK_VULN_DB["port_scan"])
        started = time.time()

        self._emit("battle_start", {
            "battle_id": battle_id, "mode": "firewall_verification",
            "attack_type": attack_type,
        })
        self._log("INFO", "waf-verify:", "la-orch",
                  f"WAF Verification — {attack_type} — starting {self.max_rounds}-round test")

        rounds = []
        red_feedback = None
        final_verdict = None

        for round_num in range(1, self.max_rounds + 1):
            # Blue: propose detection patch
            self._emit("round_phase", {"round": round_num, "phase": "blue"})
            detection_patch = self.network_agent.propose_detection(
                attack_type, round_num, red_feedback
            )
            if proposed_rule and round_num == 1:
                # Incorporate user-supplied rule into first-round patch
                detection_patch.patch_code = proposed_rule + "\n\n# Auto-generated additions:\n" + detection_patch.patch_code
            self._emit("blue_patch", detection_patch.to_dict())
            self._log("INFO", "blue:", "la-blue",
                      f"Round {round_num}: Detection rule {detection_patch.patch_id} — "
                      f"type={detection_patch.patch_type} confidence={detection_patch.confidence:.0%}")

            # Red: fire attack again (simulates "does the rule block it?")
            self._emit("round_phase", {"round": round_num, "phase": "red"})
            exploit = self.network_agent.attack(attack_type, round_num)
            self._emit("network_attack", exploit.to_dict())

            if exploit.success:
                self._log("ERROR", "network:", "la-red",
                          f"Round {round_num}: Rule BYPASSED — {exploit.evidence[:80]}")
            else:
                self._log("SUCCESS", "network:", "la-red",
                          f"Round {round_num}: Rule HOLDS — attack blocked")

            # Referee judges
            self._emit("round_phase", {"round": round_num, "phase": "referee"})
            # Adapt for Referee (expects app-layer CVE shape)
            cve_compat = _make_cve_compat(vuln)
            # Referee expects a Patch; wrap detection_patch
            from agents.blue_agent import Patch
            patch_compat = Patch(
                patch_id=detection_patch.patch_id,
                round_num=detection_patch.round_num,
                root_cause=detection_patch.root_cause,
                patch_code=detection_patch.patch_code,
                patch_type=detection_patch.patch_type,
                why_it_works=detection_patch.why_it_works,
                confidence=detection_patch.confidence,
                bypass_vectors=detection_patch.bypass_vectors,
            )
            verdict = self.referee.judge(cve_compat, patch_compat, exploit, round_num)
            self._emit("referee_verdict", verdict.to_dict())
            final_verdict = verdict
            red_feedback = exploit.to_feedback()

            rounds.append({
                "round": round_num,
                "detection_patch": detection_patch.to_dict(),
                "exploit": exploit.to_dict(),
                "verdict": verdict.to_dict(),
            })

            self._log(
                "SUCCESS" if verdict.is_pass else "ERROR",
                "waf-verify:", "la-orch",
                f"Round {round_num}: REFEREE → {verdict.emoji} {verdict.verdict} "
                f"({verdict.patch_effectiveness:.0%} effective)",
            )

            if verdict.is_pass:
                self._log("SUCCESS", "waf-verify:", "la-orch",
                          f"Rule VERIFIED in {round_num} round(s) — safe to deploy")
                break

        record = {
            "battle_id": battle_id,
            "mode": "firewall_verification",
            "attack_type": attack_type,
            "layer": vuln["layer"],
            "final_verdict": final_verdict.verdict if final_verdict else "FAIL",
            "patch_effectiveness": final_verdict.patch_effectiveness if final_verdict else 0.0,
            "signature": final_verdict.signature if final_verdict else "",
            "rounds": rounds,
            "total_rounds": len(rounds),
            "duration": round(time.time() - started, 1),
        }
        self.battles.append(record)
        self._emit("battle_complete", record)
        return record

    # ─────────────────────────────────────────────────────────────────────
    # Use 5 — Continuous Red Team Automation
    # Runs all network attack types in sequence; returns a consolidated report
    # ─────────────────────────────────────────────────────────────────────

    def run_full_red_team(
        self,
        target_url: Optional[str] = None,
        options_map: Optional[dict] = None,
    ) -> dict:
        """
        Run every network attack type in sequence.
        Returns a consolidated red-team report suitable for nightly CI/CD runs.

        Parameters
        ----------
        target_url : str, optional
            Override target for all attacks.
        options_map : dict, optional
            Per-attack-type option overrides, e.g.:
            {"brute_force": {"delay": 0.1}, "traffic_flood": {"rps": 100}}
        """
        campaign_id = f"REDTEAM-{int(time.time())}"
        started = time.time()
        options_map = options_map or {}

        self._emit("battle_start", {
            "battle_id": campaign_id,
            "mode": "full_red_team",
            "attacks": list(NETWORK_VULN_DB),
        })
        self._log("INFO", "red-team:", "la-orch",
                  f"🔴 Continuous Red Team Campaign {campaign_id} — "
                  f"{len(NETWORK_VULN_DB)} attack types")

        results = {}
        undetected = []
        detected = []

        for attack_type, vuln in NETWORK_VULN_DB.items():
            self._log("INFO", "red-team:", "la-red",
                      f"► Firing {attack_type.upper()} ({vuln['layer']} layer)…")

            exploit = self.network_agent.attack(
                attack_type=attack_type,
                round_num=1,
                target_url=target_url,
                options=options_map.get(attack_type),
            )
            results[attack_type] = exploit.to_dict()

            if exploit.success:
                undetected.append(attack_type)
                self._log("ERROR", "red-team:", "la-red",
                          f"  ❌ {attack_type.upper()} UNDETECTED — {exploit.evidence[:70]}")
            else:
                detected.append(attack_type)
                self._log("SUCCESS", "red-team:", "la-red",
                          f"  ✅ {attack_type.upper()} blocked — {exploit.evidence[:70]}")

        duration = round(time.time() - started, 1)
        total = len(NETWORK_VULN_DB)
        pass_rate = len(detected) / total if total else 0

        summary = {
            "campaign_id": campaign_id,
            "mode": "full_red_team",
            "target": target_url or self.target,
            "total_attacks": total,
            "detected": len(detected),
            "undetected": len(undetected),
            "pass_rate": round(pass_rate, 3),
            "undetected_attacks": undetected,
            "detected_attacks": detected,
            "results": results,
            "duration": duration,
            "timestamp": time.time(),
        }

        self._log(
            "SUCCESS" if pass_rate == 1.0 else ("WARNING" if pass_rate >= 0.6 else "ERROR"),
            "red-team:", "la-orch",
            f"Campaign complete: {len(detected)}/{total} attacks detected "
            f"({pass_rate:.0%}) in {duration}s",
        )

        if undetected:
            self._log("WARNING", "red-team:", "la-orch",
                      f"UNDETECTED: {', '.join(undetected)} — add detection rules immediately")

        self.battles.append(summary)
        self._emit("battle_complete", summary)
        self._save_audit(summary)
        return summary

    # ─────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────

    def _emit(self, event, data):
        try:
            self.emit(event, data)
        except Exception:
            pass

    def _log(self, level, agent, agent_class, msg):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        lvc = {
            "INFO": "lv-info", "SUCCESS": "lv-success",
            "ERROR": "lv-error", "WARNING": "lv-warn",
        }.get(level, "lv-info")
        self._emit("op_log", {
            "ts": ts, "lv": level, "lvc": lvc,
            "ag": agent, "ac": agent_class, "msg": msg,
        })

    def _save_audit(self, record):
        os.makedirs("audit_logs", exist_ok=True)
        import json
        path = f"audit_logs/{record.get('campaign_id', 'NET-' + str(int(time.time())))}.json"
        with open(path, "w") as f:
            json.dump(record, f, indent=2, default=str)
        logger.info("Network audit saved: %s", path)

    def get_stats(self):
        total = len(self.battles)
        return {
            "total_network_battles": total,
            "modes_run": list({b.get("mode", "?") for b in self.battles}),
        }
