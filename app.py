from flask import Flask, render_template, request, jsonify, session
import sqlite3
import os
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "network.db")

app = Flask(__name__)
app.secret_key = "network-risk-demo-key"

VLAN_INFO = [
    ("10", "HR", "192.168.10.0/24", "192.168.10.1"),
    ("20", "Finance", "192.168.20.0/24", "192.168.20.1"),
    ("30", "IT", "192.168.30.0/24", "192.168.30.1"),
    ("40", "Servers", "192.168.40.0/24", "192.168.40.1"),
    ("50", "Guest", "192.168.50.0/24", "192.168.50.1"),
]

USERS = {
    "guest": "guest123",
    "admin": "admin123",
}


def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = conn()
    c.execute(
        """CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created TEXT NOT NULL,
            source TEXT NOT NULL,
            source_vlan TEXT,
            target TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            protocol TEXT,
            event TEXT,
            risk TEXT,
            status TEXT,
            control TEXT,
            reason TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS controls(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            enabled INTEGER,
            description TEXT
        )"""
    )
    defaults = [
        ("ACL", 1, "Guest access to Finance and Server is blocked."),
        ("Port Security", 1, "Access ports allow one sticky MAC address."),
        ("SSH", 1, "Router management uses SSH with local authentication."),
        ("Unused Ports", 1, "Unused switch access ports are shutdown."),
    ]
    for row in defaults:
        c.execute(
            "INSERT OR IGNORE INTO controls(name,enabled,description) VALUES(?,?,?)",
            row,
        )
    c.commit()
    c.close()


def add_event(source, vlan, target, ip, protocol, event, risk, status, control, reason):
    c = conn()
    c.execute(
        """INSERT INTO events
        (created,source,source_vlan,target,target_ip,protocol,event,risk,status,control,reason)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source,
            vlan,
            target,
            ip,
            protocol,
            event,
            risk,
            status,
            control,
            reason,
        ),
    )
    c.commit()
    c.close()


def require(role=None):
    current = session.get("role")
    if not current:
        return False
    if role and current != role:
        return False
    return True


def serialize_vlans():
    return [
        {"vlan": v, "name": n, "network": net, "gateway": gw}
        for v, n, net, gw in VLAN_INFO
    ]


def get_events(limit=200):
    c = conn()
    rows = [dict(x) for x in c.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    )]
    c.close()
    return rows


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    username = d.get("username", "")
    password = d.get("password", "")
    if username in USERS and USERS[username] == password:
        session["role"] = username
        return jsonify(ok=True, role=username)
    return jsonify(ok=False, error="Invalid username or password"), 401


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    return jsonify(role=session.get("role"))


@app.get("/api/dashboard")
def dashboard():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403

    c = conn()
    total = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    blocked = c.execute("SELECT COUNT(*) FROM events WHERE status='BLOCKED'").fetchone()[0]
    failed = c.execute("SELECT COUNT(*) FROM events WHERE status='FAILED'").fetchone()[0]
    high = c.execute("SELECT COUNT(*) FROM events WHERE risk='HIGH'").fetchone()[0]
    medium = c.execute("SELECT COUNT(*) FROM events WHERE risk='MEDIUM'").fetchone()[0]
    low = c.execute("SELECT COUNT(*) FROM events WHERE risk='LOW'").fetchone()[0]
    allowed = c.execute("SELECT COUNT(*) FROM events WHERE status='ALLOWED'").fetchone()[0]
    controls = [dict(x) for x in c.execute("SELECT * FROM controls ORDER BY id")]
    c.close()

    return jsonify(
        total=total,
        blocked=blocked,
        failed=failed,
        high=high,
        medium=medium,
        low=low,
        allowed=allowed,
        events=get_events(200),
        controls=controls,
        vlans=serialize_vlans(),
    )


@app.get("/api/risk-assessment")
def risk_assessment():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403

    c = conn()
    rows = [dict(x) for x in c.execute(
        """SELECT target, target_ip, COUNT(*) AS attempts,
                  SUM(CASE WHEN status='BLOCKED' THEN 1 ELSE 0 END) AS blocked,
                  SUM(CASE WHEN status='ALLOWED' THEN 1 ELSE 0 END) AS allowed,
                  MAX(risk) AS latest_risk
           FROM events GROUP BY target, target_ip ORDER BY attempts DESC"""
    )]
    c.close()

    return jsonify(vlans=serialize_vlans(), risks=rows, events=get_events(100))


@app.get("/api/controls")
def controls():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403
    c = conn()
    rows = [dict(x) for x in c.execute("SELECT * FROM controls ORDER BY id")]
    c.close()
    return jsonify(controls=rows)


@app.post("/api/controls/<int:control_id>/toggle")
def toggle_control(control_id):
    if not require("admin"):
        return jsonify(error="Admin login required"), 403
    c = conn()
    row = c.execute("SELECT enabled FROM controls WHERE id=?", (control_id,)).fetchone()
    if not row:
        c.close()
        return jsonify(error="Control not found"), 404
    new_value = 0 if row["enabled"] else 1
    c.execute("UPDATE controls SET enabled=? WHERE id=?", (new_value, control_id))
    c.commit()
    c.close()
    return jsonify(ok=True, enabled=bool(new_value))


@app.post("/api/guest/test")
def guest_test():
    if not require("guest"):
        return jsonify(error="Guest login required"), 403

    d = request.get_json(silent=True) or {}
    target = d.get("target")
    targets = {
        "Finance": ("192.168.20.10", "20"),
        "Server": ("192.168.40.10", "40"),
        "HR": ("192.168.10.10", "10"),
        "IT": ("192.168.30.10", "30"),
        "Guest Gateway": ("192.168.50.1", "50"),
    }
    if target not in targets:
        return jsonify(error="Unknown target"), 400

    ip, vlan = targets[target]
    if target in ("Finance", "Server"):
        status, risk, control = "BLOCKED", "HIGH", "ACL"
        reason = f"Guest VLAN 50 is denied access to VLAN {vlan} by GUEST_SECURITY."
    else:
        status, risk, control = "ALLOWED", "LOW", "Network Policy"
        reason = "The requested resource is allowed by the current demonstration policy."

    add_event(
        "192.168.50.10", "50", target, ip, "ICMP", "Guest access attempt",
        risk, status, control, reason
    )
    return jsonify(status=status, risk=risk, control=control, reason=reason, ip=ip)


@app.post("/api/policy-test")
def policy_test():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403

    d = request.get_json(silent=True) or {}
    target = d.get("target")
    source = d.get("source", "192.168.50.10")
    source_vlan = d.get("source_vlan", "50")
    targets = {
        "Finance": ("192.168.20.10", "20"),
        "Server": ("192.168.40.10", "40"),
        "HR": ("192.168.10.10", "10"),
        "IT": ("192.168.30.10", "30"),
        "Guest Gateway": ("192.168.50.1", "50"),
    }
    if target not in targets:
        return jsonify(error="Unknown target"), 400

    ip, vlan = targets[target]
    if source_vlan == "50" and target in ("Finance", "Server"):
        status, risk, control = "BLOCKED", "HIGH", "ACL"
        reason = f"Guest VLAN 50 is denied access to VLAN {vlan} by GUEST_SECURITY."
    else:
        status, risk, control = "ALLOWED", "LOW", "Network Policy"
        reason = "The requested resource is allowed by the current demonstration policy."

    add_event(source, source_vlan, target, ip, "ICMP", "Admin policy test", risk, status, control, reason)
    return jsonify(status=status, risk=risk, control=control, reason=reason, ip=ip)


@app.post("/api/packet-tracer/event")
def packet_tracer_event():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403

    d = request.get_json(silent=True) or {}
    required = ["source", "target", "target_ip", "status"]
    if any(not d.get(x) for x in required):
        return jsonify(error="source, target, target_ip and status are required"), 400

    status = str(d["status"]).upper()
    if status not in ("BLOCKED", "ALLOWED", "FAILED"):
        return jsonify(error="status must be BLOCKED, ALLOWED or FAILED"), 400

    risk = "HIGH" if status in ("BLOCKED", "FAILED") else "LOW"
    add_event(
        d["source"],
        d.get("source_vlan", ""),
        d["target"],
        d["target_ip"],
        d.get("protocol", "ICMP"),
        d.get("event", "Packet Tracer test"),
        risk,
        status,
        d.get("control", "Manual Verification"),
        d.get("reason", "Imported from Packet Tracer test"),
    )
    return jsonify(ok=True, status=status, risk=risk)


@app.get("/api/verification")
def verification():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403

    expected = [
        {"source_vlan": "50", "target": "Finance", "target_vlan": "20", "expected": "BLOCKED"},
        {"source_vlan": "50", "target": "Server", "target_vlan": "40", "expected": "BLOCKED"},
        {"source_vlan": "50", "target": "Gateway", "target_vlan": "50", "expected": "ALLOWED"},
        {"source_vlan": "10", "target": "Finance", "target_vlan": "20", "expected": "ALLOWED"},
    ]

    events = get_events(200)
    results = []
    for item in expected:
        matches = [
            e for e in events
            if str(e.get("source_vlan")) == item["source_vlan"]
            and e.get("target") == item["target"]
        ]
        latest = matches[0] if matches else None
        actual = latest["status"] if latest else "NOT TESTED"
        results.append({**item, "actual": actual, "verified": actual == item["expected"], "event": latest})

    return jsonify(results=results)


@app.get("/api/activity")
def activity():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403
    return jsonify(events=get_events(500))


@app.get("/api/bridge-status")
def bridge_status():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403
    return jsonify(
        backend=True,
        endpoint="/api/packet-tracer/event",
        note="Run packet_tracer_bridge.py on Windows to import OCR-detected Packet Tracer results.",
    )


@app.post("/api/reset")
def reset():
    if not require("admin"):
        return jsonify(error="Admin login required"), 403
    c = conn()
    c.execute("DELETE FROM events")
    c.commit()
    c.close()
    return jsonify(ok=True)


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
