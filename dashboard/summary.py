import csv
from datetime import datetime
from pathlib import Path
from src.detector import run_detection

OUT = Path("dashboard/latest.csv")

def main():
    results = run_detection()
    OUT.parent.mkdir(parents=True, exist_ok=True)

    with OUT.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "ip", "score", "severity", "events", "mitre"])
        for ip, score, severity, events, techniques, story in results:
            w.writerow([datetime.now().isoformat(timespec="seconds"), ip, score, severity, " | ".join(events), ",".join(techniques)])

    print(f"[DASHBOARD] Wrote: {OUT}")

if __name__ == "__main__":
    main()
