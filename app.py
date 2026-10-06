from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template

app = Flask(__name__)

LOG_PATH = Path(__file__).parent / "sample_logs" / "sample.log"

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def parse_log(path: Path):
    records = []
    if not path.exists():
        return records

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = LOG_PATTERN.search(line.strip())
            if not match:
                continue

            data = match.groupdict()
            try:
                data["status"] = int(data["status"])
                data["size"] = int(data["size"]) if data["size"] != '-' else 0
            except ValueError:
                continue

            try:
                dt = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
                data["timestamp_dt"] = dt
            except ValueError:
                data["timestamp_dt"] = None

            records.append(data)

    return records


def summarize_logs(records):
    total_requests = len(records)
    unique_ips = len({record["ip"] for record in records})

    status_counts = Counter(str(record["status"]) for record in records)
    top_ips = Counter(record["ip"] for record in records).most_common(5)
    top_paths = Counter(record["path"] for record in records).most_common(5)

    suspicious = []
    by_ip = defaultdict(list)
    for record in records:
        by_ip[record["ip"]].append(record)

    for ip, events in by_ip.items():
        bad_events = [event for event in events if event["status"] >= 400]
        if len(bad_events) >= 2:
            suspicious.append({
                "ip": ip,
                "bad_event_count": len(bad_events),
                "status_codes": sorted({event["status"] for event in bad_events}),
            })

    for record in records:
        if record["status"] >= 400 and record["path"].lower() in {"/admin", "/login", "/wp-admin", "/.env"}:
            suspicious.append({
                "ip": record["ip"],
                "bad_event_count": 1,
                "status_codes": [record["status"]],
                "path": record["path"],
                "method": record["method"],
                "message": "High-risk path access attempt",
            })

    seen = set()
    cleaned_suspicious = []
    for event in suspicious:
        key = (event.get("ip"), event.get("path"), event.get("message"))
        if key not in seen:
            cleaned_suspicious.append(event)
            seen.add(key)

    return {
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "status_counts": dict(sorted(status_counts.items())),
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "top_paths": [{"path": path, "count": count} for path, count in top_paths],
        "suspicious": cleaned_suspicious[:10],
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    records = parse_log(LOG_PATH)
    summary = summarize_logs(records)
    return jsonify(summary)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
