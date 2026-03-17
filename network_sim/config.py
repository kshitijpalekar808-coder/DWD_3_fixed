"""
config.py — Shared configuration defaults for the Attack Simulation Toolkit.

All values here act as sensible defaults and can be overridden via CLI flags.
"""

import os

# ─── Network Defaults ────────────────────────────────────────────────────────
DEFAULT_TARGET = "127.0.0.1"
DEFAULT_PORT = 80
DEFAULT_TIMEOUT = 2          # seconds per connection attempt
DEFAULT_DURATION = 30        # seconds for timed attacks

# ─── Port Scan ────────────────────────────────────────────────────────────────
DEFAULT_PORT_RANGE = "1-1024"
STEALTH_DELAY_RANGE = (0.5, 2.0)   # random delay (seconds) for stealth mode
FAST_DELAY = 0.01                   # near-zero delay for fast scan

# ─── Brute Force ──────────────────────────────────────────────────────────────
DEFAULT_USERNAME = "admin"
DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "passwords.txt")
BRUTE_FORCE_DELAY = 0.5     # seconds between login attempts

# ─── Traffic Flood ────────────────────────────────────────────────────────────
DEFAULT_RPS = 100            # requests per second
FLOOD_THREADS = 10           # concurrent threads for flood

# ─── Data Exfiltration ───────────────────────────────────────────────────────
DEFAULT_CHUNK_SIZE = 1024    # bytes per data chunk
DEFAULT_CHUNK_COUNT = 50     # number of chunks to send

# ─── C2 Beaconing ─────────────────────────────────────────────────────────────
DEFAULT_BEACON_INTERVAL = 5  # seconds between beacons
BEACON_JITTER = 0.3          # ±30 % random jitter around the interval

# ─── Normal Traffic ───────────────────────────────────────────────────────────
NORMAL_URLS = [
    "http://example.com",
    "http://example.org",
    "http://httpbin.org/get",
    "http://httpbin.org/html",
    "http://httpbin.org/ip",
]
NORMAL_DELAY_RANGE = (1.0, 5.0)   # mimic human browsing pace

# ─── User-Agent Pool (used by multiple modules) ──────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = "attack_simulation.log"
