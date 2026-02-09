import re
import json
import csv
import sys
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# ------------------------------------------------------------
# Allow running as: python3 src/detector.py (without PYTHONPATH)
# ------------------------------------------------------------
if __package__ is None:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from src.responder import block_ip
from src.mitre import mitre_for

LOG_FILE = "/var/log/auth.log"

# === Tuning ===
WINDOW_MINUTES = 2
BRUTE_THRESHOLD = 5          # failures in window
ABUSE_THRESHOLD = 3          # failures in window + success

AUTO_BLOCK = True            # set True after you test
BLOCK_SCORE_THRESHOLD = 80

# Avoid self-blocking
SAFE_IPS = {"127.0.0.1", "::1", "192.168.20.27" }

# Baseline config
BASELINE_FILE = Path("data/baseline.json")

# Output locations
ALERTS_JSONL = Path("alerts/ssh_detector.jsonl")
DASHBOARD_CSV = Path("dashboard/latest.csv")

# auth.log time format: "Feb  1 18:40:02"
TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")

FAIL_RE = re.compile(r"Failed password.*for (\S+).*from (\S+)")
OK_RE   = re.compile(r"Accepted .* for (\S+) from (\S+)")
SUDO_RE = re.compile(r"sudo:.*\bCOMMAND=")

FORWARD_RE = re.compile(r"channel .* open", re.IGNORECASE)


def parse_time(ts: str) -> datetime:
    now = datetime.now()
    return datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S")


def load_baseline():
    if not BASELINE_FILE.exists():
        return {}
    try:
        return json.loads(BASELINE_FILE.read_text())
    except Exception:
        return {}


def ip_allowed(ip: str, prefixes):
    return any(ip.startswith(p) for p in prefixes)


def load_recent_events(window_minutes: int):
    cutoff = datetime.now() - timedelta(minutes=window_minutes)

    failures = defaultdict(int)          # ip -> count
    successes = defaultdict(int)         # ip -> count
    success_users = defaultdict(set)     # ip -> {user}
    timeline = defaultdict(list)         # ip -> list[(time, type, details)]

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m_ts = TS_RE.search(line)
            if not m_ts:
                continue

            t = parse_time(m_ts.group(1))
            if t < cutoff:
                continue

            if "Failed password" in line:
                m = FAIL_RE.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)
                    failures[ip] += 1
                    timeline[ip].append((t, "fail", f"user={user}"))

            elif "Accepted" in line:
                m = OK_RE.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)
                    successes[ip] += 1
                    success_users[ip].add(user)
                    timeline[ip].append((t, "success", f"user={user}"))

            elif "sudo:" in line and SUDO_RE.search(line):
                timeline["_local_sudo_"].append((t, "sudo", line.strip()))

    for ip in timeline:
        timeline[ip].sort(key=lambda x: x[0])

    return failures, successes, success_users, timeline


def clamp_score(score: int) -> int:
    try:
        s = int(score)
    except Exception:
        s = 0
    if s < 0:
        return 0
    if s > 100:
        return 100
    return s


def severity_from_score(score: int) -> str:
    # Standard SOC tiers (easy to explain + no mismatches)
    s = clamp_score(score)
    if s >= 90:
        return "CRITICAL"
    if s >= 70:
        return "HIGH"
    if s >= 40:
        return "MEDIUM"
    return "LOW"


def score_ip(ip: str, fail_count: int, success_count: int, users, baseline):
    score = 0
    events = []
    techniques = set()

    # Brute force
    if fail_count >= BRUTE_THRESHOLD:
        score += 40
        events.append(f"Brute Force ({fail_count} fails/{WINDOW_MINUTES}m)")
        techniques |= mitre_for("bruteforce")
        techniques |= mitre_for("remote_services")

    # Credential abuse
    if success_count > 0 and fail_count >= ABUSE_THRESHOLD:
        score += 50
        events.append(f"Credential Abuse (success after {fail_count} fails)")
        techniques |= mitre_for("valid_accounts")
        techniques |= mitre_for("remote_services")

    # Baseline anomalies
    now_hour = datetime.now().hour
    for user in users:
        b = baseline.get(user, {})
        allowed_hours = set(b.get("login_hours", []))
        allowed_prefixes = b.get("allowed_ip_prefixes", [])

        if allowed_hours and now_hour not in allowed_hours:
            score += 15
            events.append(f"Anomaly: unusual login hour for {user}")
            techniques |= mitre_for("valid_accounts")

        if allowed_prefixes and not ip_allowed(ip, allowed_prefixes):
            score += 25
            events.append(f"Anomaly: new IP range for {user}")
            techniques |= mitre_for("valid_accounts")

    score = clamp_score(score)
    severity = severity_from_score(score)
    return score, severity, events, sorted(techniques)


def render_timeline(ip: str, timeline):
    if ip not in timeline:
        return []

    story = []
    for t, kind, detail in timeline[ip]:
        ts = t.strftime("%H:%M:%S")
        if kind == "fail":
            story.append(f"{ts} – failed login ({detail})")
        elif kind == "success":
            story.append(f"{ts} – successful login ({detail})")
        else:
            story.append(f"{ts} – {kind} ({detail})")
    return story


def detect_ssh_forwarding(window_minutes: int):
    cutoff = datetime.now() - timedelta(minutes=window_minutes)
    forwarding_ips = set()

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m_ts = TS_RE.search(line)
            if not m_ts:
                continue
            t = parse_time(m_ts.group(1))
            if t < cutoff:
                continue

            if "forwarded" in line.lower() or "channel" in line.lower() or FORWARD_RE.search(line):
                ip_match = re.search(r"from (\S+)", line)
                if ip_match:
                    forwarding_ips.add(ip_match.group(1))

    return forwarding_ips


def has_active_ssh_session_from(ip: str) -> bool:
    out = subprocess.run(["ss", "-tnp"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "sshd" in line and ip in line and ":22" in line:
            return True
    return False

def active_ssh_remote_ips() -> set:
    out = subprocess.run(["ss", "-tnp"], capture_output=True, text=True).stdout
    ips = set()
    for line in out.splitlines():
        if "sshd" not in line:
            continue
        # Example ss output contains peer like 192.168.20.18:58112
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}):\d+\b", line)
        if m:
            ips.add(m.group(1))
    return ips


def ensure_parent(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def write_jsonl(alert: dict, path: Path):
    ensure_parent(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def write_dashboard_csv(rows: list[dict], path: Path):
    ensure_parent(path)
    headers = [
        "timestamp", "source_ip", "severity", "score", "events", "mitre"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def run_detection():
    failures, successes, success_users, timeline = load_recent_events(WINDOW_MINUTES)
    baseline = load_baseline()

    forwarding_ips = detect_ssh_forwarding(WINDOW_MINUTES)

    alerts_for_dashboard = []
    any_alert = False
    all_ips = set(failures.keys()) | set(successes.keys())
    all_ips |= active_ssh_remote_ips()
# include IPs with active SSH sessions (tunnels / long-lived)
    for ip in list(all_ips):
        if has_active_ssh_session_from(ip):
            all_ips.add(ip)

    for ip in all_ips:
        if ip in SAFE_IPS:
            continue

        fail_count = failures.get(ip, 0)
        success_count = successes.get(ip, 0)
        users = success_users.get(ip, set())

        score, severity, events, techniques = score_ip(
            ip, fail_count, success_count, users, baseline
        )

        # Tunnel/long-lived session hint
        tunnel_hint = False
        if ip in forwarding_ips:
            tunnel_hint = True
            events.append("Possible SSH Tunnel (forwarding/channel activity)")
            techniques = sorted(set(techniques) | mitre_for("protocol_tunneling"))

        if has_active_ssh_session_from(ip):
            tunnel_hint = True
            events.append("Active SSH session observed (possible long-lived/tunnel)")
            # still remote services technique is relevant
            techniques = sorted(set(techniques) | mitre_for("remote_services") | mitre_for("protocol_tunneling"))

        # Only alert if suspicious criteria met
        suspicious = False
        if fail_count >= BRUTE_THRESHOLD:
            suspicious = True
        if success_count > 0 and fail_count >= ABUSE_THRESHOLD:
            suspicious = True
        if tunnel_hint:
            suspicious = True

        if not suspicious:
            continue

        any_alert = True

        mitre_str = ",".join(techniques) if techniques else ""
        print(f"[{severity}] {ip} | Score={score} | Events={'; '.join(events)} | MITRE={mitre_str}")
        print("  Timeline:")
        for line in render_timeline(ip, timeline):
            print(f"   - {line}")

        alert_obj = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "host": subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip(),
            "source_ip": ip,
            "severity": severity,
            "score": score,
            "events": events,
            "mitre": techniques,
            "window_minutes": WINDOW_MINUTES,
            "failures": fail_count,
            "successes": success_count,
        }

        write_jsonl(alert_obj, ALERTS_JSONL)

        alerts_for_dashboard.append({
            "timestamp": alert_obj["timestamp"],
            "source_ip": ip,
            "severity": severity,
            "score": score,
            "events": " | ".join(events),
            "mitre": mitre_str,
        })

        # Auto response
        if AUTO_BLOCK and score >= BLOCK_SCORE_THRESHOLD and ip not in SAFE_IPS:
            block_ip(ip)

    # Dashboard output
    if alerts_for_dashboard:
        write_dashboard_csv(alerts_for_dashboard, DASHBOARD_CSV)

    if not any_alert:
        print(f"[OK] No suspicious SSH activity in last {WINDOW_MINUTES} minutes.")


if __name__ == "__main__":
    run_detection()
