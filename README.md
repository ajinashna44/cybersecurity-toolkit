# Ethical SIEM Dashboard Starter

This project is a small, ethical log analysis / SIEM starter designed for learning and local lab use only. It ingests sample web access log data, summarizes traffic, flags suspicious activity, and presents the results in a browser dashboard.

## Features
- Parses sample access log lines
- Shows total requests, unique IPs, and status-code breakdown
- Lists top IPs and most requested paths
- Flags suspicious events, including repeated 4xx/5xx hits and admin-path access attempts
- Lightweight Flask dashboard

## Safe usage
- Use only on systems you own or are explicitly authorized to test
- Do not run against production or public networks without permission
- This repository is for educational and legitimate security lab scenarios only

## Quick start

1. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the server:
   ```bash
   python app.py
   ```

4. Open the dashboard in your browser:
   ```text
   http://localhost:5000
   ```

## Project structure
- `app.py` — Flask app and log parsing logic
- `templates/index.html` — dashboard frontend
- `static/style.css` — dashboard styling
- `sample_logs/sample.log` — example data for demo purposes

## Notes
This is intentionally a starter project. It can be extended with:
- real log ingestion from files or syslog
- alert rules and thresholds
- SQLite storage for historical trends
- authentication for the web dashboard
- correlation with firewall or IDS events
