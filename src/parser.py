import re

LOG_FILE = "/var/log/auth.log"

failed_pattern = re.compile(r"Failed password.*from (\S+)")
success_pattern = re.compile(r"Accepted .* from (\S+)")

def parse_logs():
    failed_ips = []
    success_ips = []

    with open(LOG_FILE, "r") as f:
        for line in f:
            if "Failed password" in line:
                match = failed_pattern.search(line)
                if match:
                    failed_ips.append(match.group(1))
            elif "Accepted" in line:
                match = success_pattern.search(line)
                if match:
                    success_ips.append(match.group(1))

    return failed_ips, success_ips
