# DataWatchDawgs × attack_sim — Network Layer Integration

attack_sim's network modules have been fully embedded into DataWatchDawgs as a
first-class `NetworkAgent`. Every battle now fires **both** layers simultaneously.

---

## Layer Coverage

```
DataWatchDawgs Red Agent        NetworkAgent  (attack_sim)
─────────────────────────────   ──────────────────────────────
SQLi   (application layer)   +  Port Scan      (network layer)
XSS    (application layer)   +  Brute Force    (auth layer)
RCE    (application layer)   +  C2 Beaconing   (malware layer)
SSRF   (application layer)   +  Data Exfil     (egress layer)
Path   (application layer)   +  Traffic Flood  (volumetric layer)
```

---

## New Files Added

```
DataWatchDawgs/
├── agents/
│   └── network_agent.py          ← NetworkAgent + NetworkDetectionPatch classes
├── core/
│   └── network_battle_engine.py  ← Use 3 / 4 / 5 orchestration engine
├── network_sim/                  ← attack_sim embedded as a package
│   ├── __init__.py
│   ├── config.py
│   ├── logger.py
│   ├── wordlists/
│   │   └── passwords.txt
│   └── modules/
│       ├── __init__.py
│       ├── base.py
│       ├── port_scan.py
│       ├── brute_force.py
│       ├── c2_beacon.py
│       ├── data_exfiltration.py
│       ├── normal_traffic.py
│       └── traffic_flood.py
└── NETWORK_INTEGRATION.md        ← this file
```

### Files Changed
- `core/battle_engine.py`  — network phase injected into every battle round
- `app.py`                 — 4 new API routes + network ticker messages
- `requirements.txt`       — documented zero new dependencies
- `.env`                   — 3 new network config variables

---

## Use 1 — Extended Red Agent (automatic, no action needed)

Every battle round now fires a paired network-layer attack **in addition** to
the app-layer attack. The battle record's `rounds[n].network_exploit` field
contains the full network result, and `network_layer` in the top-level record
shows a per-battle summary.

The pairing is:

| App-layer vuln | Network-layer attack  |
|----------------|-----------------------|
| SQLi           | Port Scan             |
| XSS            | Brute Force           |
| RCE            | C2 Beacon             |
| SSRF           | Data Exfiltration     |
| Path Traversal | Traffic Flood         |

---

## Use 3 — SOC Training Platform

**API:** `POST /api/network/soc-training`

```json
{
  "attack_type": "port_scan",
  "soc_response": {
    "detected": true,
    "rule_proposed": "alert tcp any any -> $HOME_NET any (threshold: type both, track by_src, count 30, seconds 10; sid:9001;)",
    "response_time_s": 45
  }
}
```

DataWatchDawgs:
1. Fires the live attack_sim module
2. Scores the analyst's detection response (0–100%)
3. Returns Blue Agent's reference detection rules
4. Red Agent verifies whether the proposed rule would have caught it

---

## Use 4 — Firewall/WAF Rule Verification

**API:** `POST /api/network/firewall-verify`

```json
{
  "attack_type": "brute_force",
  "proposed_rule": "limit_req zone=login burst=5 nodelay; limit_req_status 429;"
}
```

Workflow:
1. attack_sim fires brute force
2. Blue Agent proposes / incorporates your rule
3. Red Agent attacks again to verify the rule blocks it
4. Referee signs the proof with HMAC-SHA256

---

## Use 5 — Continuous Red Team Automation

**API:** `POST /api/network/red-team`

```json
{
  "target_url": "http://192.168.1.10",
  "options": {
    "brute_force": {"delay": 0.1},
    "traffic_flood": {"rps": 100, "threads": 10}
  }
}
```

Fires all 5 network attack types in sequence and returns a consolidated report:

```json
{
  "campaign_id": "REDTEAM-1748000000",
  "total_attacks": 5,
  "detected": 3,
  "undetected": 2,
  "pass_rate": 0.6,
  "undetected_attacks": ["c2_beacon", "data_exfiltration"]
}
```

Run nightly via cron or as a CI/CD gate:
```bash
# In CI/CD pipeline — fail build if pass_rate < 1.0
curl -s -X POST http://localhost:5000/api/network/red-team \
  | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d['pass_rate']==1.0 else 1)"
```

---

## Available Network Attack Types

| Key                | ID              | Layer      | CVSS |
|--------------------|-----------------|------------|------|
| `port_scan`        | NET-PSCAN-001   | network    | 5.3  |
| `brute_force`      | NET-BRUTE-001   | auth       | 7.5  |
| `c2_beacon`        | NET-C2-001      | malware    | 8.1  |
| `data_exfiltration`| NET-EXFIL-001   | egress     | 8.6  |
| `traffic_flood`    | NET-FLOOD-001   | volumetric | 7.5  |

List via: `GET /api/network/attacks`

---

## Configuration (.env)

```env
NETWORK_LAYER_ENABLED=true   # enable/disable network phase in battles
NETWORK_TARGET=127.0.0.1     # target host for network attacks
NETWORK_PORT=80              # target port
RED_TEAM_ON_STARTUP=false    # fire full red team on app start (CI/CD mode)
```
