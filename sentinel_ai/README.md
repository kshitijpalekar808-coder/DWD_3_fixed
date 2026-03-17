# 🛡️ SentinelAI — Real-Time Intrusion Detection & Response

> **Blue Team counterpart** to the Cyber Attack Simulation Toolkit.
> Built for the **Red Team vs Blue Team live demo**.

---

## Demo Setup (Two Laptops on the Same Network)

### Blue Team Laptop — run SentinelAI

```bash
# Install dependencies (once)
pip install flask rich

# Start SentinelAI (full dashboard)
python sentinel_ai.py --port 5000
```

The dashboard opens immediately.  Note the machine's **local IP** (e.g. `192.168.1.42`).

---

### Red Team Laptop — run the attack sim

Point every attack at Blue Team's IP:

```bash
# 1️⃣  Port Scan — reconnaissance
python attack_simulator.py --mode portscan --target 192.168.1.42

# 2️⃣  Brute Force — credential stuffing
python attack_simulator.py --mode brute --target http://192.168.1.42:5000/login

# 3️⃣  DDoS Flood — volumetric attack
python attack_simulator.py --mode flood --target http://192.168.1.42:5000 --duration 15 --rps 200

# 4️⃣  Data Exfiltration — binary blob upload
python attack_simulator.py --mode exfil --target 192.168.1.42 --port 5000

# 5️⃣  C2 Beaconing — malware check-in
python attack_simulator.py --mode c2 --target http://192.168.1.42:5000/beacon --interval 4
```

---

## What Judges See

| Red Team Action       | SentinelAI Response                                   |
|-----------------------|-------------------------------------------------------|
| Port scan fires       | 🔍 **HIGH** alert within ~1 s, IP auto-blocked        |
| Brute-force login     | 🔑 **HIGH** alert, requests start returning **403**   |
| DDoS flood            | 🌊 **CRITICAL** alert, flood packets dropped          |
| Data exfiltration     | 📤 **HIGH** alert after >20 KB binary POSTs           |
| C2 beaconing          | 📡 **CRITICAL** alert when periodic interval detected |

---

## Detection Logic

| Attack              | Detector Signature                                                     | Threshold              |
|---------------------|------------------------------------------------------------------------|------------------------|
| **Port Scan**       | Same IP hits 5+ honeypot ports in 8 s                                 | 5 ports / 8 s          |
| **Brute Force**     | Same IP sends 5+ POST `/login` in 12 s                                | 5 attempts / 12 s      |
| **DDoS / Flood**    | Same IP exceeds 40 HTTP requests in 5 s                               | 40 req / 5 s           |
| **Data Exfil**      | Same IP sends >20 KB of `application/octet-stream` POSTs in 15 s     | 20 KB or 6 chunks      |
| **C2 Beaconing**    | 5+ timed POSTs with inter-request CV < 0.55 (low jitter = periodic)  | CV ≤ 0.55 / 5 beacons |

---

## Architecture

```
sentinel_ai/
├── sentinel_ai.py        ← main entry point (starts everything)
├── shared_state.py       ← thread-safe event bus & alert store
├── target_server.py      ← Flask "victim" server (the attack target)
├── honeypot.py           ← multi-port TCP listener (catches port scans)
├── detection_engine.py   ← starts all detector threads
├── dashboard.py          ← Rich live terminal UI
└── detectors/
    ├── port_scan.py      ← PortScanDetector
    ├── brute_force.py    ← BruteForceDetector
    ├── traffic_flood.py  ← TrafficFloodDetector
    ├── data_exfil.py     ← DataExfilDetector
    └── c2_beacon.py      ← C2BeaconDetector
```

---

## CLI Options

```
python sentinel_ai.py [--port PORT] [--host HOST] [--no-autoblock]

  --port         Server port  (default: 5000)
  --host         Bind address (default: 0.0.0.0)
  --no-autoblock Alert only — don't ban attacker IPs (good for repeated demos)
```

> **Tip for demos:** Use `--no-autoblock` if you want to run multiple attack waves
> without the Red Team getting banned between rounds.
