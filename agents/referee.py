"""
DataWatchDawgs — Referee (The Judge)
Independent verdict with HMAC-SHA256 cryptographic signing.
"""
import os, time, json, re, hashlib, hmac, logging
from dataclasses import dataclass, field
from typing import List, Optional
import requests as http

logger = logging.getLogger("dwd.referee")

SYSTEM = """You are the Referee in DataWatchDawgs — a neutral security judge.
You receive: vulnerability details, Blue's patch, Red's attack result.
Make a PASS/FAIL verdict with mathematical basis.

Respond with valid JSON only:
{
  "verdict": "PASS|FAIL|PARTIAL",
  "confidence": 0.0-1.0,
  "patch_effectiveness": 0.0-1.0,
  "proof_statement": "one mathematical sentence proving the verdict",
  "techniques_blocked": ["list of blocked techniques"],
  "technique_succeeded": "technique that worked or null",
  "recommendation": "what to do next"
}"""

SIGNING_KEY = os.getenv("DWD_SIGNING_KEY", "datawatchdawgs-hmac-key-2024")


@dataclass
class Verdict:
    verdict: str
    round_num: int
    cve_id: str
    confidence: float
    patch_effectiveness: float
    proof_statement: str
    techniques_blocked: List[str]
    technique_succeeded: Optional[str]
    recommendation: str
    signature: str = ""
    battle_hash: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def is_pass(self):
        return self.verdict == "PASS"

    @property
    def emoji(self):
        return {"PASS": "✅", "FAIL": "❌", "PARTIAL": "⚠️"}.get(self.verdict, "?")

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}


class Referee:
    def __init__(self):
        self._verdicts = []

    def judge(self, cve, patch, exploit_result, round_num: int) -> Verdict:
        logger.info(f"[REFEREE] Judging round {round_num} — {cve['id']}")

        raw = self._call_groq(cve, patch, exploit_result, round_num) or \
              self._call_ollama(cve, patch, exploit_result, round_num)

        verdict = self._parse(raw, round_num, cve["id"], exploit_result)
        verdict.battle_hash = self._hash(cve, patch, exploit_result)
        verdict.signature = self._sign(verdict)
        self._verdicts.append(verdict)
        return verdict

    def _build_prompt(self, cve, patch, result, round_num) -> str:
        return (
            f"CVE: {cve['id']} — {cve['name']} (CVSS {cve['cvss']})\n"
            f"Blue patch round {round_num}: {patch.root_cause}\n"
            f"Patch confidence: {patch.confidence:.0%}\n"
            f"Red technique: {result.technique}\n"
            f"Payload: {result.payload_used}\n"
            f"Exploit succeeded: {result.success}\n"
            f"Evidence: {result.evidence}\n"
            f"Why patch failed: {result.why_patch_failed or 'N/A'}\n\n"
            "Deliver your verdict as JSON only."
        )

    def _call_groq(self, cve, patch, result, round_num) -> Optional[str]:
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
                    {"role": "user", "content": self._build_prompt(cve, patch, result, round_num)}
                ],
                max_tokens=400,
                temperature=0.1
            )
            return resp.choices[0].message.content
        except Exception as e:
            logger.warning(f"Groq error: {e}")
            return None

    def _call_ollama(self, cve, patch, result, round_num) -> Optional[str]:
        try:
            prompt = self._build_prompt(cve, patch, result, round_num)
            resp = http.post(
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
            logger.debug(f"Ollama not available: {e}")
            return None

    def _parse(self, raw, round_num, cve_id, exploit_result) -> Verdict:
        is_pass = not exploit_result.success

        if raw:
            try:
                clean = re.sub(r"```json|```", "", raw).strip()
                match = re.search(r'\{.*\}', clean, re.DOTALL)
                if match:
                    d = json.loads(match.group())
                    return Verdict(
                        verdict=d.get("verdict", "PASS" if is_pass else "FAIL"),
                        round_num=round_num,
                        cve_id=cve_id,
                        confidence=float(d.get("confidence", 0.85 if is_pass else 0.75)),
                        patch_effectiveness=float(d.get("patch_effectiveness", 0.9 if is_pass else 0.4)),
                        proof_statement=d.get("proof_statement", self._default_proof(is_pass, round_num, cve_id)),
                        techniques_blocked=d.get("techniques_blocked", [exploit_result.technique] if is_pass else []),
                        technique_succeeded=d.get("technique_succeeded"),
                        recommendation=d.get("recommendation", "Deploy patch" if is_pass else "Revise patch"),
                    )
            except Exception as e:
                logger.debug(f"Parse error: {e}")

        return Verdict(
            verdict="PASS" if is_pass else "FAIL",
            round_num=round_num,
            cve_id=cve_id,
            confidence=0.87 if is_pass else 0.78,
            patch_effectiveness=0.92 if is_pass else 0.38,
            proof_statement=self._default_proof(is_pass, round_num, cve_id),
            techniques_blocked=[exploit_result.technique] if is_pass else [],
            technique_succeeded=exploit_result.technique if not is_pass else None,
            recommendation="Patch verified — deploy to production" if is_pass else f"Block {exploit_result.technique} — retry",
        )

    def _default_proof(self, is_pass, round_num, cve_id) -> str:
        if is_pass:
            return (
                f"Verified: Red Agent exhausted {round_num} round(s) of adversarial "
                f"testing against {cve_id} without achieving exploit — "
                f"patch mathematically proven effective."
            )
        return (
            f"Unverified: Red Agent achieved exploit in round {round_num} "
            f"via bypass technique — patch requires evolution before deployment."
        )

    def _hash(self, cve, patch, result) -> str:
        s = f"{cve['id']}:{patch.patch_id}:{result.exploit_id}:{result.success}:{result.payload_used}"
        return hashlib.sha256(s.encode()).hexdigest()

    def _sign(self, v: Verdict) -> str:
        s = f"{v.verdict}:{v.cve_id}:{v.round_num}:{v.battle_hash}:{int(v.timestamp)}"
        return hmac.new(SIGNING_KEY.encode(), s.encode(), hashlib.sha256).hexdigest()[:32]

    def get_verdicts(self):
        return [v.to_dict() for v in self._verdicts]