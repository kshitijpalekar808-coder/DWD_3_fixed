"""
DataWatchDawgs — Network Agent
==============================
Integrates the attack_sim network-layer toolkit (port_scan, brute_force,
c2_beacon, data_exfiltration, traffic_flood) into DataWatchDawgs as a first-
class attack agent that runs alongside — and extends — the existing Red Agent.

Layer coverage after integration
---------------------------------
  DataWatchDawgs Red Agent     NetworkAgent (from attack_sim)
  ─────────────────────────    ──────────────────────────────
  SQLi  (application layer)  + Port scan       (network layer)
  XSS   (application layer)  + Brute force     (auth layer)
  RCE   (application layer)  + C2 beaconing    (malware layer)
  SSRF  (application layer)  + Data exfil      (egress layer)
  Path  (application layer)  + Traffic flood   (volumetric layer)

Use-cases enabled
------------------
  Use 1 — Extended Red Agent attack types (both layers in one battle)
  Use 3 — SOC training platform (live-fire detection scoring)
  Use 4 — Firewall / WAF rule verification
  Use 5 — Continuous automated red teaming
"""

import importlib
import logging
import os
import sys
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

# Make sure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger("dwd.network")

# ── Attack mode registry (mirrors attack_sim MODULE_MAP) ─────────────────────
_MODULE_MAP = {
    "port_scan":        ("network_sim.modules.port_scan",        "PortScanSimulator"),
    "brute_force":      ("network_sim.modules.brute_force",      "BruteForceSimulator"),
    "c2_beacon":        ("network_sim.modules.c2_beacon",        "C2BeaconSimulator"),
    "data_exfiltration":("network_sim.modules.data_exfiltration","DataExfiltrationSimulator"),
    "traffic_flood":    ("network_sim.modules.traffic_flood",     "TrafficFloodSimulator"),
}

# Human-readable metadata for each network attack type
NETWORK_ATTACK_META = {
    "port_scan": {
        "id":    "NET-PSCAN-001",
        "name":  "TCP Port Scan — Network Reconnaissance",
        "layer": "network",
        "desc":  "Sequential TCP connect probes across port range to enumerate open services.",
        "ioc":   "Rapid sequential connection attempts to many ports from single source.",
        "detection_rules": [
            "Alert if >50 unique dst_ports from single src_ip in 10s",
            "Flag SYN packets with no data payload across >30 ports",
            "Block source IP after threshold breach (firewall rule)",
        ],
    },
    "brute_force": {
        "id":    "NET-BRUTE-001",
        "name":  "HTTP Brute Force — Credential Stuffing",
        "layer": "auth",
        "desc":  "Repeated HTTP POST login attempts with wordlist-driven password guessing.",
        "ioc":   "Many failed auth attempts (HTTP 401/403) from single IP in short window.",
        "detection_rules": [
            "Alert if >10 failed logins from same IP in 60s",
            "Rate-limit login endpoint to 5 req/min per IP",
            "Lock account after 5 consecutive failures",
        ],
    },
    "c2_beacon": {
        "id":    "NET-C2-001",
        "name":  "C2 Beaconing — Malware Check-in Simulation",
        "layer": "malware",
        "desc":  "Periodic outbound HTTP POSTs with jitter mimicking RAT/botnet C2 beacons.",
        "ioc":   "Near-constant-interval outbound requests to unusual host with JSON body.",
        "detection_rules": [
            "Alert on periodic outbound HTTP to non-whitelisted external IP",
            "Flag User-Agent strings not matching known browser fingerprints",
            "Block egress to IPs with no DNS PTR record",
        ],
    },
    "data_exfiltration": {
        "id":    "NET-EXFIL-001",
        "name":  "Data Exfiltration — Suspicious Egress",
        "layer": "egress",
        "desc":  "High-entropy binary data sent outbound via HTTP POST or raw TCP.",
        "ioc":   "Large volume of high-entropy outbound data to external host.",
        "detection_rules": [
            "Alert on outbound POST body >10 KB with high entropy (>7.5 bits/byte)",
            "Flag hosts sending >100 MB outbound to single external IP in 1 hour",
            "DLP rule: block raw TCP egress on non-standard ports",
        ],
    },
    "traffic_flood": {
        "id":    "NET-FLOOD-001",
        "name":  "Traffic Flood — Volumetric DoS",
        "layer": "volumetric",
        "desc":  "Multi-threaded HTTP GET flood to simulate DoS/DDoS attack pattern.",
        "ioc":   "Request rate spike far above baseline from single source.",
        "detection_rules": [
            "Alert if single src_ip exceeds 200 req/s to any endpoint",
            "Rate-limit to 50 req/s per IP at WAF/load-balancer",
            "Auto-null-route source prefix after 5s of sustained flood",
        ],
    },
}

# Default module options — safe for lab use
_DEFAULT_OPTIONS: Dict[str, Dict[str, Any]] = {
    "port_scan":         {"ports": "22,80,443,8080,8443,3306,5432,6379", "speed": "fast"},
    "brute_force":       {"delay": 0.2},
    "c2_beacon":         {"duration": 20, "interval": 5},
    "data_exfiltration": {"chunk_size": 512, "chunk_count": 10, "protocol": "http"},
    "traffic_flood":     {"duration": 10, "rps": 50, "threads": 5},
}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class NetworkExploitResult:
    """Mirrors ExploitResult from red_agent.py so the Referee can consume it uniformly."""
    exploit_id: str
    round_num: int
    vuln_type: str          # e.g. "port_scan"
    payload_used: str       # human description of what was fired
    technique: str          # attack_sim module name
    strategy: str
    success: bool
    evidence: str
    why_patch_failed: str
    payloads_tried: int
    http_status: int = 0
    response_snippet: str = ""
    # Network-specific extras
    layer: str = "network"
    stats: dict = field(default_factory=dict)
    detection_rules: list = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}

    def to_feedback(self):
        if not self.success:
            return (
                f"Network layer: {self.technique} generated {self.stats.get('packets_sent', 0)} "
                f"packets — all detected/blocked. Layer: {self.layer}."
            )
        return (
            f"NETWORK ATTACK UNDETECTED\n"
            f"Technique: {self.technique}\n"
            f"Layer: {self.layer}\n"
            f"Evidence: {self.evidence}\n"
            f"Packets sent: {self.stats.get('packets_sent', 0)}\n"
            f"Bytes sent: {self.stats.get('bytes_sent', 0)}\n"
            f"Why detection failed: {self.why_patch_failed}"
        )


# ── Detection Patch dataclass (mirrors Patch from blue_agent.py) ─────────────

@dataclass
class NetworkDetectionPatch:
    """
    Blue Agent's response to a network-layer attack.
    Proposes detection rules instead of code patches.
    """
    patch_id: str
    round_num: int
    root_cause: str
    patch_code: str         # detection rules / firewall config
    patch_type: str         # "firewall_rule" | "ids_rule" | "rate_limit" | "egress_filter"
    why_it_works: str
    confidence: float
    bypass_vectors: list
    layer: str = "network"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}


# ── Fallback detection patches (used when no LLM is available) ───────────────

FALLBACK_DETECTION_PATCHES = {
    "port_scan": [
        {
            "root_cause": "No threshold on unique destination ports per source IP per time window",
            "patch_code": (
                "# IDS Rule (Suricata / Snort)\n"
                "alert tcp any any -> $HOME_NET any "
                "(msg:\"Port Scan Detected\"; "
                "threshold: type both, track by_src, count 30, seconds 10; "
                "classtype:network-scan; sid:9000001;)\n\n"
                "# Firewall rate-limit (iptables)\n"
                "iptables -A INPUT -p tcp --syn -m recent --name portscan "
                "--set -j ACCEPT\n"
                "iptables -A INPUT -p tcp --syn -m recent --name portscan "
                "--rcheck --seconds 10 --hitcount 30 -j DROP"
            ),
            "patch_type": "ids_rule",
            "why_it_works": (
                "Threshold-based IDS rule triggers after 30 unique port probes from one "
                "source in 10 s. Firewall rule null-routes the scanner."
            ),
            "confidence": 0.87,
            "bypass_vectors": ["Ultra-slow stealth scan spread over hours"],
        },
        {
            "root_cause": "SYN packets with no established state allowed through stateless firewall",
            "patch_code": (
                "# Stateful firewall — only allow established/related\n"
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                "iptables -A INPUT -m state --state NEW -p tcp "
                "--dport 22 -j ACCEPT   # only whitelisted ports\n"
                "iptables -A INPUT -j DROP"
            ),
            "patch_type": "firewall_rule",
            "why_it_works": (
                "Stateful packet inspection drops SYN to non-whitelisted ports. "
                "Scanner receives no response, making enumeration blind."
            ),
            "confidence": 0.93,
            "bypass_vectors": [],
        },
    ],
    "brute_force": [
        {
            "root_cause": "Login endpoint has no per-IP rate limiting or account lockout",
            "patch_code": (
                "# Flask-Limiter rate limit\n"
                "from flask_limiter import Limiter\n"
                "limiter = Limiter(app, key_func=get_remote_address)\n\n"
                "@app.route('/login', methods=['POST'])\n"
                "@limiter.limit('5 per minute')\n"
                "def login(): ...\n\n"
                "# Account lockout after 5 consecutive failures\n"
                "if failed_attempts[username] >= 5:\n"
                "    account_locked_until[username] = time.time() + 900  # 15 min"
            ),
            "patch_type": "rate_limit",
            "why_it_works": (
                "Rate limiting caps attempts to 5/min per IP, making 1000-entry "
                "wordlist take 3+ hours. Account lockout caps per-account exposure."
            ),
            "confidence": 0.91,
            "bypass_vectors": ["Distributed brute force across many IPs"],
        },
        {
            "root_cause": "No CAPTCHA or MFA — credential stuffing succeeds at scale",
            "patch_code": (
                "# Add TOTP MFA (pyotp)\n"
                "import pyotp\n"
                "def verify_mfa(secret, token):\n"
                "    totp = pyotp.TOTP(secret)\n"
                "    return totp.verify(token, valid_window=1)\n\n"
                "# Require MFA on every login attempt\n"
                "if not verify_mfa(user.mfa_secret, request.form['mfa_token']):\n"
                "    abort(401)"
            ),
            "patch_type": "code",
            "why_it_works": (
                "TOTP MFA requires physical device possession — even a correct password "
                "cannot authenticate without the rotating 30 s OTP."
            ),
            "confidence": 0.97,
            "bypass_vectors": ["SIM-swap attacks on SMS MFA (use TOTP/hardware key)"],
        },
    ],
    "c2_beacon": [
        {
            "root_cause": "No egress filtering — outbound HTTP to arbitrary IPs allowed",
            "patch_code": (
                "# Egress firewall — allowlist approach\n"
                "iptables -P OUTPUT DROP\n"
                "iptables -A OUTPUT -d cdn.company.com -j ACCEPT\n"
                "iptables -A OUTPUT -d api.company.com -j ACCEPT\n"
                "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n"
                "# IDS: Alert on periodic outbound POST to non-whitelisted IP\n"
                "alert http $HOME_NET any -> !$ALLOWED_EGRESS any "
                "(msg:\"Possible C2 Beacon\"; "
                "content:\"POST\"; http_method; "
                "threshold: type both, track by_src, count 3, seconds 60; "
                "sid:9000010;)"
            ),
            "patch_type": "egress_filter",
            "why_it_works": (
                "Egress allowlist blocks all outbound HTTP except to known-good destinations. "
                "IDS rule catches periodic POST pattern even to allowed hosts."
            ),
            "confidence": 0.89,
            "bypass_vectors": ["DNS tunnelling if DNS egress is open", "HTTPS to CDN fronting"],
        },
        {
            "root_cause": "Anomalous User-Agent strings not flagged by proxy",
            "patch_code": (
                "# Proxy User-Agent inspection (Squid / NGINX)\n"
                "# Block non-browser UAs on outbound HTTP\n"
                "if ($http_user_agent !~ \"Mozilla|Chrome|Safari|Firefox|Edge\") {\n"
                "    return 403;\n"
                "}\n\n"
                "# IDS: Flag AttackSim or curl-style UAs\n"
                "alert http any any -> any any "
                "(msg:\"Non-browser UA on egress\"; "
                "content:\"AttackSim\"; http_header; sid:9000011;)"
            ),
            "patch_type": "ids_rule",
            "why_it_works": (
                "Legitimate applications use standard browser UAs through the corporate proxy. "
                "C2 beacons typically use curl, Python-urllib, or custom UA strings."
            ),
            "confidence": 0.82,
            "bypass_vectors": ["Attacker can spoof a valid UA string — combine with beacon interval detection"],
        },
    ],
    "data_exfiltration": [
        {
            "root_cause": "No DLP policy — high-entropy binary egress data not inspected",
            "patch_code": (
                "# DLP egress filter (pseudo-config)\n"
                "dlp_policy:\n"
                "  inspect_outbound: true\n"
                "  entropy_threshold: 7.5   # bits/byte\n"
                "  max_post_body_kb: 10\n"
                "  action_on_violation: block_and_alert\n\n"
                "# iptables: block raw TCP egress on non-standard ports\n"
                "iptables -A OUTPUT -p tcp --dport 1024:65535 \\\n"
                "  ! -d cdn.company.com -m connbytes \\\n"
                "  --connbytes 102400: --connbytes-dir original \\\n"
                "  --connbytes-mode bytes -j DROP"
            ),
            "patch_type": "egress_filter",
            "why_it_works": (
                "Entropy inspection flags random/encrypted payloads that legitimate "
                "traffic (HTML, JSON) does not produce. Byte-count cap limits exfil volume."
            ),
            "confidence": 0.85,
            "bypass_vectors": ["Steganographic encoding to lower entropy", "Slow drip over long period"],
        },
    ],
    "traffic_flood": [
        {
            "root_cause": "No per-IP request rate cap at WAF or load balancer",
            "patch_code": (
                "# NGINX rate limiting\n"
                "http {\n"
                "  limit_req_zone $binary_remote_addr zone=api:10m rate=50r/s;\n"
                "  server {\n"
                "    location / {\n"
                "      limit_req zone=api burst=100 nodelay;\n"
                "      limit_req_status 429;\n"
                "    }\n"
                "  }\n"
                "}\n\n"
                "# Auto-block at firewall if rate exceeded\n"
                "iptables -A INPUT -p tcp --dport 80 -m hashlimit \\\n"
                "  --hashlimit-above 200/sec --hashlimit-burst 50 \\\n"
                "  --hashlimit-mode srcip --hashlimit-name http_flood -j DROP"
            ),
            "patch_type": "rate_limit",
            "why_it_works": (
                "NGINX limits each IP to 50 req/s with burst of 100. iptables hashlimit "
                "drops packets if any single IP exceeds 200 req/s — floors a flood attack."
            ),
            "confidence": 0.94,
            "bypass_vectors": ["Distributed flood across many IPs (botnet)"],
        },
    ],
}


# ── NetworkAgent class ────────────────────────────────────────────────────────

class NetworkAgent:
    """
    Drives network-layer attacks using the attack_sim modules.

    Integrates into DataWatchDawgs in two positions:
      1. Called by BattleEngine alongside RedAgent for full-stack battles.
      2. Used standalone for SOC training, WAF verification, and red-team runs.
    """

    def __init__(self, target: str = "127.0.0.1", port: int = 80):
        self.target = target
        self.port = port
        self._results = []

    # ── Public API ────────────────────────────────────────────────────────

    def attack(
        self,
        attack_type: str,
        round_num: int,
        target_url: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> NetworkExploitResult:
        """
        Fire a network-layer attack simulation and return a result that is
        structurally compatible with RedAgent's ExploitResult.

        Parameters
        ----------
        attack_type : str
            One of: port_scan, brute_force, c2_beacon, data_exfiltration, traffic_flood
        round_num : int
            Current battle round number.
        target_url : str, optional
            Override target (URL or IP).  Falls back to self.target.
        options : dict, optional
            Module-specific kwargs (e.g. {"ports": "22,80", "speed": "stealth"}).
        """
        meta = NETWORK_ATTACK_META.get(attack_type)
        if not meta:
            raise ValueError(f"Unknown network attack type: {attack_type!r}. "
                             f"Choose from: {list(NETWORK_ATTACK_META)}")

        logger.info("[NETWORK] Round %d — firing %s (%s layer)", round_num, attack_type, meta["layer"])

        # Resolve target
        target = target_url or self.target

        # Strip HTTP scheme for modules that expect a hostname (port_scan uses raw TCP)
        host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        # HTTP-based modules must hit the correct endpoint path on the target server
        _ATTACK_PATHS = {
            "brute_force":       f"http://{host}:{self.port}/login",
            "c2_beacon":         f"http://{host}:{self.port}/beacon",
            "data_exfiltration": f"http://{host}:{self.port}/upload",
            "traffic_flood":     f"http://{host}:{self.port}/",
            "port_scan":         host,  # raw TCP — no path needed
        }
        resolved_target = _ATTACK_PATHS.get(attack_type, host)

        # Merge default options with caller overrides
        merged_opts = {**_DEFAULT_OPTIONS.get(attack_type, {}), **(options or {})}

        stats, success, evidence, why_failed = self._run_module(
            attack_type, resolved_target, self.port, merged_opts
        )

        payload_desc = self._payload_description(attack_type, merged_opts, stats)

        result = NetworkExploitResult(
            exploit_id=f"NET-{round_num}-{attack_type.upper()}",
            round_num=round_num,
            vuln_type=attack_type,
            payload_used=payload_desc,
            technique=attack_type.replace("_", " ").title(),
            strategy=f"Network layer — {meta['layer']} — {attack_type}",
            success=success,
            evidence=evidence,
            why_patch_failed=why_failed if success else "",
            payloads_tried=stats.get("packets_sent", 1),
            http_status=0,
            response_snippet="",
            layer=meta["layer"],
            stats=stats,
            detection_rules=meta["detection_rules"],
        )
        self._results.append(result)
        return result

    def propose_detection(
        self,
        attack_type: str,
        round_num: int,
        red_feedback: Optional[str] = None,
    ) -> NetworkDetectionPatch:
        """
        Blue Agent extension: propose a network-layer detection/mitigation patch.
        Returns a NetworkDetectionPatch (structurally similar to Patch).
        """
        fallbacks = FALLBACK_DETECTION_PATCHES.get(attack_type,
                    FALLBACK_DETECTION_PATCHES["port_scan"])
        fb = fallbacks[min(round_num - 1, len(fallbacks) - 1)]

        # Try to get an LLM-enhanced patch (same backends as BlueAgent)
        raw = self._call_groq_detection(attack_type, round_num, red_feedback) or \
              self._call_ollama_detection(attack_type, round_num, red_feedback)

        if raw:
            import json, re
            try:
                clean = re.sub(r"```json|```", "", raw).strip()
                match = re.search(r'\{.*\}', clean, re.DOTALL)
                if match:
                    d = json.loads(match.group())
                    return NetworkDetectionPatch(
                        patch_id=d.get("patch_id", f"NET-BLUE-{round_num}-{attack_type.upper()}"),
                        round_num=round_num,
                        root_cause=d.get("root_cause", fb["root_cause"]),
                        patch_code=d.get("patch_code", fb["patch_code"]),
                        patch_type=d.get("patch_type", fb["patch_type"]),
                        why_it_works=d.get("why_it_works", fb["why_it_works"]),
                        confidence=float(d.get("confidence", fb["confidence"])),
                        bypass_vectors=d.get("bypass_vectors", fb["bypass_vectors"]),
                        layer="network",
                    )
            except Exception as e:
                logger.debug("LLM patch parse error: %s", e)

        return NetworkDetectionPatch(
            patch_id=f"NET-BLUE-{round_num}-{attack_type.upper()}",
            round_num=round_num,
            layer="network",
            **fb,
        )

    def get_results(self):
        return [r.to_dict() for r in self._results]

    # ── Module runner ─────────────────────────────────────────────────────

    def _run_module(
        self,
        attack_type: str,
        host: str,
        port: int,
        options: dict,
    ):
        """
        Instantiate the attack_sim module and run it in a capped thread so it
        doesn't block the battle loop indefinitely.
        Returns (stats, success, evidence, why_failed).
        """
        mod_path, cls_name = _MODULE_MAP[attack_type]
        try:
            # Ensure DWD_3 root is on sys.path so network_sim package is importable
            _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _root not in sys.path:
                sys.path.insert(0, _root)
            mod = importlib.import_module(mod_path)
            ModuleClass = getattr(mod, cls_name)
        except Exception as e:
            logger.error("IMPORT FAILED for %s: %s — NO real traffic sent, using simulation", mod_path, e)
            return self._simulate_stats(attack_type), *self._simulate_outcome(attack_type)

        # Cap duration so battles don't hang
        duration = min(options.get("duration", 15), 20)
        options = {**options, "duration": duration}

        result_holder = {}
        exc_holder = {}

        def _run():
            try:
                instance = ModuleClass(target=host, port=port, **options)
                result_holder["stats"] = instance.run()
            except Exception as ex:
                exc_holder["err"] = ex

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=duration + 5)

        if exc_holder:
            logger.error("Module %s CRASHED: %s — NO real traffic sent, using simulation", attack_type, exc_holder["err"])
            return self._simulate_stats(attack_type), *self._simulate_outcome(attack_type)

        stats = result_holder.get("stats", self._simulate_stats(attack_type))
        success, evidence, why_failed = self._evaluate_result(attack_type, stats)
        return stats, success, evidence, why_failed

    # ── Result evaluation ─────────────────────────────────────────────────

    def _evaluate_result(self, attack_type: str, stats: dict):
        """
        Determine if the network attack 'succeeded' (went undetected / caused impact).
        In a real deployment this hooks into an IDS/SIEM; here we use heuristics
        on the stats to mirror real signal.
        """
        packets = stats.get("packets_sent", 0)
        errors  = stats.get("errors", 0)
        conns   = stats.get("connections", 0)
        bsent   = stats.get("bytes_sent", 0)

        if attack_type == "port_scan":
            # Success = we completed the scan (IDS didn't block the socket calls)
            if packets > 0 and errors / max(packets, 1) < 0.8:
                return (
                    True,
                    f"Port scan completed — {conns} ports probed, {packets - errors} responded",
                    "No IDS rule triggered to block sequential TCP SYN probes",
                )
            return False, f"Scan heavily disrupted — {errors}/{packets} errors", ""

        if attack_type == "brute_force":
            # Success = we sent attempts without being rate-limited (errors < 50 %)
            if packets > 0 and errors / max(packets, 1) < 0.5:
                return (
                    True,
                    f"Brute force sent {packets} login attempts — no rate-limit triggered",
                    "Login endpoint lacks per-IP rate limiting or account lockout",
                )
            return False, f"Most attempts rejected ({errors} errors) — rate limit active", ""

        if attack_type == "c2_beacon":
            # Success = beacons sent without connection errors
            if packets > 0 and errors / max(packets, 1) < 0.5:
                return (
                    True,
                    f"{packets} C2 beacons transmitted — egress not filtered",
                    "No egress firewall or IDS rule blocks periodic outbound HTTP",
                )
            return False, f"Beacons blocked — {errors} connection failures", ""

        if attack_type == "data_exfiltration":
            # Success = data actually moved
            if bsent > 0:
                return (
                    True,
                    f"{bsent:,} bytes exfiltrated in {packets} chunks — no DLP triggered",
                    "No DLP / egress content inspection in place",
                )
            return False, "All data transfer attempts blocked by egress filter", ""

        if attack_type == "traffic_flood":
            # Success = we sent volume (server didn't immediately refuse all connections)
            if packets > 10 and errors / max(packets, 1) < 0.7:
                return (
                    True,
                    f"Flood delivered {packets} requests — server responded to {packets - errors}",
                    "No per-IP rate cap or WAF rule limits inbound request volume",
                )
            return False, f"Flood mostly absorbed — {packets - errors}/{packets} connections refused", ""

        return False, "Attack simulated", ""

    # ── Simulation fallback ───────────────────────────────────────────────

    def _simulate_stats(self, attack_type: str) -> dict:
        defaults = {
            "port_scan":         {"packets_sent": 50, "connections": 50, "errors": 5,  "bytes_sent": 0},
            "brute_force":       {"packets_sent": 20, "connections": 20, "errors": 3,  "bytes_sent": 2048},
            "c2_beacon":         {"packets_sent": 4,  "connections": 4,  "errors": 0,  "bytes_sent": 512},
            "data_exfiltration": {"packets_sent": 10, "connections": 10, "errors": 1,  "bytes_sent": 5120},
            "traffic_flood":     {"packets_sent": 500,"connections": 450,"errors": 50, "bytes_sent": 45000},
        }
        return defaults.get(attack_type, {"packets_sent": 10, "connections": 10, "errors": 1, "bytes_sent": 0})

    def _simulate_outcome(self, attack_type: str):
        """Return (success, evidence, why_failed) for simulation mode."""
        outcomes = {
            "port_scan":         (True,  "Simulated: 8 ports probed, 3 open (22,80,443)", "No IDS rule (simulated)"),
            "brute_force":       (True,  "Simulated: 20 login attempts, no lockout triggered", "No rate-limit (simulated)"),
            "c2_beacon":         (True,  "Simulated: 4 beacons transmitted undetected", "No egress filter (simulated)"),
            "data_exfiltration": (True,  "Simulated: 5 KB exfiltrated with no DLP alert", "No DLP policy (simulated)"),
            "traffic_flood":     (False, "Simulated: flood absorbed — server rate-limited", ""),
        }
        return outcomes.get(attack_type, (False, "Simulation", ""))

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _payload_description(attack_type: str, opts: dict, stats: dict) -> str:
        desc_map = {
            "port_scan":         lambda: f"TCP SYN scan ports={opts.get('ports','1-1024')} speed={opts.get('speed','fast')}",
            "brute_force":       lambda: f"HTTP POST /login username={opts.get('username','admin')} wordlist=passwords.txt",
            "c2_beacon":         lambda: f"HTTP POST beacon interval={opts.get('interval',5)}s jitter=±30%",
            "data_exfiltration": lambda: f"{opts.get('chunk_size',512)}B×{opts.get('chunk_count',10)} chunks via {opts.get('protocol','http').upper()}",
            "traffic_flood":     lambda: f"HTTP GET flood {opts.get('rps',50)} req/s × {opts.get('threads',5)} threads",
        }
        return desc_map.get(attack_type, lambda: attack_type)()

    # ── LLM detection patch generation ───────────────────────────────────

    _DETECTION_SYSTEM = """You are the Blue Agent — Network Security specialist in DataWatchDawgs.
Propose a concrete detection/mitigation rule for a network-layer attack.
Respond with valid JSON only:
{
  "patch_id": "NET-BLUE-<round>-<type>",
  "root_cause": "exact technical root cause",
  "patch_code": "IDS rule / firewall config / rate-limit config",
  "patch_type": "firewall_rule|ids_rule|rate_limit|egress_filter",
  "why_it_works": "technical explanation in 2 sentences",
  "confidence": 0.0-1.0,
  "bypass_vectors": ["remaining attack surface"]
}"""

    def _call_groq_detection(self, attack_type, round_num, red_feedback) -> Optional[str]:
        key = os.getenv("GROQ_API_KEY", "")
        if not key:
            return None
        try:
            from groq import Groq
            meta = NETWORK_ATTACK_META[attack_type]
            prompt = (
                f"Network Attack Type: {attack_type}\n"
                f"Layer: {meta['layer']}\n"
                f"Description: {meta['desc']}\n"
                f"IOC: {meta['ioc']}\n"
                f"Round: {round_num}\n"
            )
            if red_feedback:
                prompt += f"Previous detection failed:\n{red_feedback}\nEvolve the detection rule. JSON only."
            else:
                prompt += "Propose your best detection/mitigation rule. JSON only."
            client = Groq(api_key=key)
            resp = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": self._DETECTION_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=600,
                temperature=0.1,
            )
            return resp.choices[0].message.content
        except Exception as e:
            logger.warning("Groq detection error: %s", e)
            return None

    def _call_ollama_detection(self, attack_type, round_num, red_feedback) -> Optional[str]:
        import requests
        try:
            meta = NETWORK_ATTACK_META[attack_type]
            prompt = (
                f"Network Attack: {attack_type} ({meta['layer']} layer)\n"
                f"IOC: {meta['ioc']}\nRound: {round_num}\n"
            )
            if red_feedback:
                prompt += f"Previous detection failed:\n{red_feedback}\nEvolve the rule. JSON only."
            else:
                prompt += "Best detection rule please. JSON only."
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "gemma3:4b",
                    "prompt": self._DETECTION_SYSTEM + "\n\n" + prompt,
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
                timeout=120,
            )
            return resp.json().get("response", None)
        except Exception as e:
            logger.debug("Ollama detection error: %s", e)
            return None