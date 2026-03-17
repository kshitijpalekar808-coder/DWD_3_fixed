"""
dashboard.py — SentinelAI Live Terminal Dashboard (powered by Rich).

Refreshes every 0.5 s.  Shows:
  • Header with uptime + global stats
  • Live alert feed (colour-coded by severity)
  • Threat summary counts
  • Blocked IPs list
  • Last-60s traffic sparkline
"""

import time
from collections import defaultdict, deque

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from shared_state import state

console = Console()

# ── Colours ───────────────────────────────────────────────────────────────────
SEV_STYLE = {
    "LOW":      "bright_cyan",
    "MEDIUM":   "yellow",
    "HIGH":     "bold red",
    "CRITICAL": "bold white on red",
}
ATTACK_ICONS = {
    "Port Scan":         "🔍",
    "Brute Force":       "🔑",
    "DDoS / Flood":      "🌊",
    "Data Exfiltration": "📤",
    "C2 Beaconing":      "📡",
}

BANNER = (
    "[bold cyan]███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗[/]\n"
    "[bold cyan]██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║[/]\n"
    "[bold cyan]███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║[/]\n"
    "[cyan]╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║[/]\n"
    "[cyan]███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║[/]\n"
    "[cyan]╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝[/]\n"
    "[dim]              Real-Time AI-Powered Intrusion Detection & Response[/]"
)

# Sparkline characters
SPARK = " ▁▂▃▄▅▆▇█"


# ── Sub-renders ───────────────────────────────────────────────────────────────

def _header() -> Panel:
    s = state.snapshot_stats()
    uptime = time.time() - s["start_time"]
    h, m, sec = int(uptime // 3600), int((uptime % 3600) // 60), int(uptime % 60)
    blocked = len(state.blocked_ips)

    stats_text = (
        f"[bold]Uptime[/]  [green]{h:02d}:{m:02d}:{sec:02d}[/]   "
        f"[bold]Requests[/]  [white]{s['total_requests']:,}[/]   "
        f"[bold]Blocked[/]  [red]{s['blocked_requests']:,}[/]   "
        f"[bold]Alerts[/]  [yellow]{s['total_alerts']}[/]   "
        f"[bold]Banned IPs[/]  [red]{blocked}[/]   "
        f"[bold]Server[/]  [green]http://0.0.0.0:{state.config.get('server_port',5000)}[/]"
    )
    content = Text.from_markup(BANNER + "\n\n" + stats_text)
    return Panel(Align.center(content), border_style="cyan", padding=(0, 1))


def _alert_table() -> Panel:
    alerts = state.recent_alerts(n=18)
    tbl = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.SIMPLE_HEAVY,
        expand=True,
        show_edge=False,
    )
    tbl.add_column("Time",        style="dim",         width=10)
    tbl.add_column("Severity",                         width=10)
    tbl.add_column("Attack Type",                      width=18)
    tbl.add_column("Source IP",   style="cyan",        width=16)
    tbl.add_column("Description", no_wrap=False)
    tbl.add_column("Action",                           width=10)

    for a in reversed(alerts):
        ts    = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
        sev   = Text(a.severity, style=SEV_STYLE.get(a.severity, "white"))
        icon  = ATTACK_ICONS.get(a.attack_type, "⚡")
        atype = f"{icon} {a.attack_type}"
        action = Text("🚫 BLOCKED", style="red") if a.auto_blocked else Text("⚠ ALERT", style="yellow")
        tbl.add_row(ts, sev, atype, a.src_ip, a.description, action)

    if not alerts:
        tbl.add_row("—", "—", "—", "—", "[dim]No threats detected yet — system monitoring…[/]", "—")

    return Panel(tbl, title="[bold yellow]⚡  LIVE THREAT FEED[/]", border_style="yellow", padding=(0, 1))


def _threat_summary() -> Panel:
    s = state.snapshot_stats()
    by_type = s.get("alerts_by_type", {})

    tbl = Table(box=box.SIMPLE, expand=True, show_header=False, show_edge=False)
    tbl.add_column("Icon",  width=4)
    tbl.add_column("Type",  style="bold")
    tbl.add_column("Count", justify="right")

    for atype, icon in ATTACK_ICONS.items():
        count = by_type.get(atype, 0)
        style = "red" if count > 0 else "dim"
        tbl.add_row(icon, Text(atype, style=style), Text(str(count), style=style))

    return Panel(tbl, title="[bold]Threat Summary[/]", border_style="blue", padding=(0, 1))


def _blocked_ips() -> Panel:
    ips = list(state.blocked_ips)[-12:]
    lines = "\n".join(f"[red]🚫  {ip}[/]" for ip in ips) or "[dim]No IPs blocked yet[/]"
    return Panel(Text.from_markup(lines), title="[bold red]Blocked IPs[/]", border_style="red", padding=(0, 1))


def _sparkline() -> Panel:
    """Traffic rate over the last 60 s, bucketed into 60 one-second slots."""
    evts = state.recent_events(60)
    now  = time.time()
    buckets: list[int] = [0] * 60
    for e in evts:
        idx = max(0, min(59, int(now - e.timestamp)))
        buckets[59 - idx] += 1   # oldest on left, newest on right

    peak = max(buckets) or 1
    bar  = "".join(SPARK[min(len(SPARK)-1, int(b / peak * (len(SPARK)-1)))] for b in buckets)
    rps  = buckets[-1] + buckets[-2]

    text = Text()
    text.append(f"  Req/s (last 60s) — current: {rps} req/s\n  ", style="dim")
    for ch in bar:
        style = "red" if ch in "▆▇█" else ("yellow" if ch in "▄▅" else "green")
        text.append(ch, style=style)

    return Panel(text, title="[bold green]Traffic Rate[/]", border_style="green", padding=(0, 0))


# ── Main dashboard loop ───────────────────────────────────────────────────────

def run_dashboard() -> None:
    layout = Layout()
    layout.split_column(
        Layout(name="header",  size=10),
        Layout(name="alerts",  ratio=3),
        Layout(name="bottom",  size=12),
    )
    layout["bottom"].split_row(
        Layout(name="summary", ratio=2),
        Layout(name="blocked", ratio=2),
        Layout(name="spark",   ratio=3),
    )

    with Live(layout, console=console, refresh_per_second=2, screen=True):
        while True:
            layout["header"].update(_header())
            layout["alerts"].update(_alert_table())
            layout["summary"].update(_threat_summary())
            layout["blocked"].update(_blocked_ips())
            layout["spark"].update(_sparkline())
            time.sleep(0.5)
