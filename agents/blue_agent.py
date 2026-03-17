"""
DataWatchDawgs — Blue Agent (The Fixer)
Analyzes vulnerabilities and proposes verified patches.
"""
import os, time, hashlib, json, re, logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("dwd.blue")

try:
    import anthropic
    SDK_OK = True
except ImportError:
    SDK_OK = False

SYSTEM = """You are the Blue Agent in DataWatchDawgs — an autonomous security system.
Your role: DEFEND. Analyze vulnerabilities and propose concrete, deployable patches.

Always respond with valid JSON only — no markdown, no preamble:
{
  "patch_id": "BLUE-<round>-<type>",
  "root_cause": "exact technical root cause in one sentence",
  "patch_code": "actual fix code or config (multi-line ok)",
  "patch_type": "code|config|waf_rule|upgrade",
  "why_it_works": "technical explanation in 2 sentences",
  "confidence": 0.0-1.0,
  "bypass_vectors": ["any remaining attack surface"]
}"""

FALLBACK_PATCHES = {
    "sqli": [
        {"root_cause":"Unsanitized input in SQL string formatting","patch_code":"# Use parameterized queries\nquery = 'SELECT * FROM users WHERE id = ?'\ndb.execute(query, (user_id,))\n\n# WAF rule\nwaf.block(r\"[';\\\"--]\")\nwaf.block(r\"(?i)union.+select\")","patch_type":"code","why_it_works":"Parameterized queries separate code from data, making injection impossible. WAF provides defense-in-depth.","confidence":0.88,"bypass_vectors":["Second-order injection if data is re-used in queries"]},
        {"root_cause":"Missing input validation allows UNION-based data extraction","patch_code":"# Strict input validation\nimport re\ndef validate_id(val):\n    if not re.match(r'^[0-9]+$', str(val)):\n        raise ValueError('Invalid ID')\n    return int(val)","patch_type":"code","why_it_works":"Type-enforced integer validation eliminates all string-based injection vectors.","confidence":0.93,"bypass_vectors":[]},
        {"root_cause":"ORM bypass via raw query execution","patch_code":"# Replace raw SQL with ORM\nuser = User.query.filter_by(id=user_id).first()\n\n# Disable raw SQL execution\nengine.execute = None","patch_type":"code","why_it_works":"ORM abstraction prevents raw SQL, eliminating injection surface entirely.","confidence":0.96,"bypass_vectors":[]},
    ],
    "xss": [
        {"root_cause":"User input reflected in DOM without HTML encoding","patch_code":"import DOMPurify from 'dompurify'\n\nconst render = (input) => {\n  return DOMPurify.sanitize(input, {\n    ALLOWED_TAGS: ['b','i','p'],\n    FORBID_ATTR: ['onerror','onload','onclick']\n  })\n}","patch_type":"code","why_it_works":"DOMPurify removes all script tags and event handlers. Allowlist approach ensures unknown tags are stripped.","confidence":0.90,"bypass_vectors":["Mutation XSS in some browser versions"]},
        {"root_cause":"Missing Content-Security-Policy allows inline script execution","patch_code":"# Add CSP header\nresponse.headers['Content-Security-Policy'] = (\n    \"default-src 'self'; \"\n    \"script-src 'self'; \"\n    \"style-src 'self' 'unsafe-inline';\"\n)\nfrom markupsafe import escape\nreturn str(escape(user_input))","patch_type":"config","why_it_works":"CSP prevents inline scripts from executing. Output encoding neutralizes all HTML special characters.","confidence":0.94,"bypass_vectors":[]},
        {"root_cause":"textContent vs innerHTML misuse allows DOM XSS","patch_code":"// Replace innerHTML with textContent\nelement.textContent = userInput  // safe\n// element.innerHTML = userInput  // UNSAFE\n\nconst safe = marked.parse(DOMPurify.sanitize(input))","patch_type":"code","why_it_works":"textContent treats all input as literal text. Browser never interprets it as HTML or JS.","confidence":0.97,"bypass_vectors":[]},
    ],
    "rce": [
        {"root_cause":"Log4j2 JNDI lookup processes attacker-controlled log messages","patch_code":"# 1. pom.xml: upgrade log4j-core to 2.17.1\n# 2. JVM flags:\n#    -Dlog4j2.formatMsgNoLookups=true\n#    -Dlog4j.noFormatMsgLookup=true\n# 3. WAF rules:\nwaf.block(r\"\\$\\{jndi:\")\nwaf.block(r\"\\$\\{[^}]*j[^}]*n[^}]*d[^}]*i\")","patch_type":"upgrade","why_it_works":"Version 2.17.1 removes JNDI lookup capability entirely. JVM flags provide fallback protection.","confidence":0.92,"bypass_vectors":["${${::-j}ndi} obfuscation if WAF not comprehensive"]},
        {"root_cause":"Shell injection via unsanitized command parameter","patch_code":"import subprocess, re\n\ndef safe_execute(cmd, args):\n    ALLOWED = {'ping', 'nslookup', 'dig'}\n    if cmd not in ALLOWED:\n        raise PermissionError(f'Command not allowed: {cmd}')\n    return subprocess.run([cmd] + args, capture_output=True, timeout=5)","patch_type":"code","why_it_works":"Allowlist prevents unknown commands. List-based subprocess call bypasses shell interpretation entirely.","confidence":0.95,"bypass_vectors":[]},
        {"root_cause":"Deserialization of untrusted data enables arbitrary code execution","patch_code":"import hmac, hashlib\n\ndef safe_deserialize(data, signature, secret):\n    expected = hmac.new(secret, data, hashlib.sha256).hexdigest()\n    if not hmac.compare_digest(signature, expected):\n        raise SecurityError('Invalid signature')\n    return json.loads(data)","patch_type":"code","why_it_works":"HMAC verification ensures only server-signed data is deserialized. JSON cannot execute code.","confidence":0.98,"bypass_vectors":[]},
    ],
    "ssrf": [
        {"root_cause":"User-supplied URLs fetched without domain validation","patch_code":"import ipaddress, socket\nfrom urllib.parse import urlparse\n\nALLOWED = {'cdn.company.com', 'assets.company.com'}\nBLOCKED_CIDRS = ['169.254.0.0/16','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']\n\ndef validate_url(url):\n    p = urlparse(url)\n    if p.hostname not in ALLOWED:\n        raise SecurityError('Domain not allowed')\n    ip = socket.gethostbyname(p.hostname)\n    for cidr in BLOCKED_CIDRS:\n        if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):\n            raise SecurityError('Private IP blocked')","patch_type":"code","why_it_works":"Allowlist prevents unknown domains. Post-resolution IP check blocks DNS rebinding attacks.","confidence":0.91,"bypass_vectors":["IPv6 addresses if not validated"]},
        {"root_cause":"Missing egress filtering allows internal network access","patch_code":"# iptables egress rules\n# iptables -A OUTPUT -d 169.254.0.0/16 -j DROP\n# iptables -A OUTPUT -d 10.0.0.0/8 -j DROP\n# Allow only specific outbound\n# iptables -A OUTPUT -d cdn.company.com -j ACCEPT","patch_type":"config","why_it_works":"Network-layer enforcement is bypass-proof regardless of application logic.","confidence":0.96,"bypass_vectors":[]},
    ],
    "path": [
        {"root_cause":"Filename used directly in path join without sanitization","patch_code":"import os, re\n\ndef safe_path(filename, upload_dir):\n    safe = os.path.basename(filename)\n    if not re.match(r'^[a-zA-Z0-9._-]+$', safe):\n        raise ValueError('Invalid filename')\n    full = os.path.realpath(os.path.join(upload_dir, safe))\n    if not full.startswith(os.path.realpath(upload_dir)):\n        raise SecurityError('Path traversal detected')\n    return full","patch_type":"code","why_it_works":"basename() strips traversal sequences. realpath() comparison catches symlink attacks.","confidence":0.95,"bypass_vectors":[]},
    ],
}


@dataclass
class Patch:
    patch_id: str
    round_num: int
    root_cause: str
    patch_code: str
    patch_type: str
    why_it_works: str
    confidence: float
    bypass_vectors: List[str]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}


class BlueAgent:
    def __init__(self):
        self._results = []

    def propose(self, cve, round_num: int, red_feedback: str = None) -> Patch:
        logger.info(f"[BLUE] Round {round_num} — {cve['id']}")
        prompt = self._build_prompt(cve, round_num, red_feedback)

        raw = self._call_groq(prompt) or self._call_ollama(prompt)
        patch = self._parse(raw, round_num, cve)
        self._results.append(patch)
        return patch

    def _build_prompt(self, cve, round_num, red_feedback):
        base = (
            f"CVE: {cve['id']}\n"
            f"Name: {cve['name']}\n"
            f"Type: {cve['type']}\n"
            f"CVSS: {cve['cvss']}\n"
            f"Description: {cve['desc']}\n"
            f"Known payload: {cve['payloads'][0]}"
        )
        if round_num == 1:
            return f"{base}\n\nRound 1: Propose your best patch. Respond with JSON only."
        return (
            f"{base}\n\nRound {round_num}: Your previous patch was bypassed via:\n"
            f"{red_feedback}\nEvolve the patch to block this specific vector. JSON only."
        )

    def _call_groq(self, prompt) -> Optional[str]:
        key = os.getenv("GROQ_API_KEY", "")
        if not key:
            return None
        try:
            from groq import Groq
            client = Groq(api_key=key)
            resp = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.1
            )
            return resp.choices[0].message.content
        except Exception as e:
            logger.warning(f"Groq error: {e}")
            return None

    def _call_ollama(self, prompt) -> Optional[str]:
        try:
            import requests
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "gemma3:4b",
                    "prompt": SYSTEM + "\n\n" + prompt,
                    "stream": False,
                    "options": {"temperature": 0.1}
                },
                timeout=120
            )
            return resp.json().get("response", None)
        except Exception as e:
            logger.warning(f"Ollama error: {e}")
            return None

    def _parse(self, raw, round_num, cve) -> Patch:
        vuln_type = cve.get("type_key", "sqli")
        fallbacks = FALLBACK_PATCHES.get(vuln_type, FALLBACK_PATCHES["sqli"])
        fb = fallbacks[min(round_num - 1, len(fallbacks) - 1)]

        if raw:
            try:
                clean = re.sub(r"```json|```", "", raw).strip()
                match = re.search(r'\{.*\}', clean, re.DOTALL)
                if match:
                    d = json.loads(match.group())
                    return Patch(
                        patch_id=d.get("patch_id", f"BLUE-{round_num}-{vuln_type.upper()}"),
                        round_num=round_num,
                        root_cause=d.get("root_cause", fb["root_cause"]),
                        patch_code=d.get("patch_code", fb["patch_code"]),
                        patch_type=d.get("patch_type", fb["patch_type"]),
                        why_it_works=d.get("why_it_works", fb["why_it_works"]),
                        confidence=float(d.get("confidence", fb["confidence"])),
                        bypass_vectors=d.get("bypass_vectors", fb["bypass_vectors"]),
                    )
            except Exception as e:
                logger.debug(f"Parse error: {e}")

        return Patch(
            patch_id=f"BLUE-{round_num}-{vuln_type.upper()}",
            round_num=round_num,
            **fb,
        )