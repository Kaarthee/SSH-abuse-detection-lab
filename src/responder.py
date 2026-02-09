import subprocess

def block_ip(ip: str) -> None:
    # Insert at top so it takes priority
    cmd = ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd, check=False)
    print(f"[RESPONSE] Blocked IP via iptables: {ip}")

def is_blocked(ip: str) -> bool:
    # Check if rule exists (best-effort)
    cmd = ["sudo", "iptables", "-S", "INPUT"]
    out = subprocess.run(cmd, capture_output=True, text=True)
    return f"-s {ip} -j DROP" in out.stdout

