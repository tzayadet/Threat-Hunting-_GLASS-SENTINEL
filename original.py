
from pathlib import Path
from datetime import datetime
import csv

DATA = """ts,user,ip,event,bytes,approved
2026-11-06T21:56:00+01:00,ana,198.51.100.24,login_fail,0,no
2026-11-06T21:57:00+01:00,ana,198.51.100.24,login_fail,0,no
2026-11-06T22:00:00+01:00,ana,198.51.100.24,login_success,0,no
2026-11-06T22:05:00+01:00,ana,198.51.100.24,export,74000000,no
2026-11-06T22:06:00+01:00,svc_backup,192.0.2.8,login_success,0,yes
2026-11-06T22:07:00+01:00,svc_backup,192.0.2.8,export,300000000,yes
2026-11-06T22:08:00+01:00,ana,203.0.113.50,export,90000000,no
2026-11-06T22:09:00+01:00,ana,198.51.100.24,login_success,0,no
2026-11-06T22:10:00+01:00,ana,198.51.100.24,export,3000,no
"""

Path("academy_events.csv").write_text(DATA, encoding="utf-8")

with open("academy_events.csv", newline="", encoding="utf-8") as f:
    events = list(csv.DictReader(f))

def when(row):
    return datetime.fromisoformat(row["ts"])

alerts = []

for exp in events:
    if (exp["event"] != "export"
        or int(exp["bytes"]) < 50_000_000
        or exp["approved"] == "yes"):
        continue

    logins = [
        r for r in events
        if r["user"] == exp["user"]
        and r["ip"] == exp["ip"]
        and r["event"] == "login_success"
        and 0 <= (when(exp) - when(r)).total_seconds() <= 600
    ]

    for login in logins:
        fails = [
            r for r in events
            if r["user"] == login["user"]
            and r["ip"] == login["ip"]
            and r["event"] == "login_fail"
            and 0 < (when(login) - when(r)).total_seconds() <= 600
        ]
        if len(fails) >= 2:
            alerts.append((exp["user"], exp["ip"], exp["bytes"]))
            break

print("ALERTAS:", alerts)
