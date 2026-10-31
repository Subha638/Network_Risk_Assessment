import os
import sqlite3
from datetime import datetime

import streamlit as st

# ------------------------------------------------------------
# AI Network Risk Assessment - Streamlit edition
# Based on the supplied Flask project's VLANs, users, policies,
# controls, and event schema.
# ------------------------------------------------------------

st.set_page_config(
    page_title="AI Network Risk Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("NRA_DB_PATH", os.path.join(BASE_DIR, "network.db"))

VLAN_INFO = [
    ("10", "HR", "192.168.10.0/24", "192.168.10.1"),
    ("20", "Finance", "192.168.20.0/24", "192.168.20.1"),
    ("30", "IT", "192.168.30.0/24", "192.168.30.1"),
    ("40", "Servers", "192.168.40.0/24", "192.168.40.1"),
    ("50", "Guest", "192.168.50.0/24", "192.168.50.1"),
]

# Demo credentials from the supplied app.py.
# For a public deployment, move credentials to Streamlit Secrets.
DEFAULT_USERS = {
    "admin": "admin123",
    "guest": "guest123",
}


def get_users():
    """Read optional credentials from Streamlit Secrets; otherwise use demo users."""
    try:
        configured = st.secrets.get("users", {})
        if configured:
            return dict(configured)
    except Exception:
        pass
    return DEFAULT_USERS


def db():
    connection = sqlite3.connect(DB_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db() as con:
        con.execute(
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
        con.execute(
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
            con.execute(
                "INSERT OR IGNORE INTO controls(name,enabled,description) VALUES(?,?,?)",
                row,
            )


def add_event(source, vlan, target, ip, protocol, event, risk, status, control, reason):
    with db() as con:
        con.execute(
            """INSERT INTO events
            (created,source,source_vlan,target,target_ip,protocol,event,risk,status,control,reason)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                source, vlan, target, ip, protocol, event, risk, status, control, reason,
            ),
        )


def get_events(limit=500):
    with db() as con:
        rows = con.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def get_controls():
    with db() as con:
        rows = con.execute("SELECT * FROM controls ORDER BY id").fetchall()
    return [dict(row) for row in rows]


def guest_test(target):
    targets = {
        "Finance": ("192.168.20.10", "20"),
        "Server": ("192.168.40.10", "40"),
        "HR": ("192.168.10.10", "10"),
        "IT": ("192.168.30.10", "30"),
        "Guest Gateway": ("192.168.50.1", "50"),
    }
    ip, vlan = targets[target]
    if target in ("Finance", "Server"):
        status, risk, control = "BLOCKED", "HIGH", "ACL"
        reason = f"Guest VLAN 50 is denied access to VLAN {vlan} by GUEST_SECURITY."
    else:
        status, risk, control = "ALLOWED", "LOW", "Network Policy"
        reason = "The requested resource is allowed by the current demonstration policy."

    add_event(
        "192.168.50.10", "50", target, ip, "ICMP",
        "Guest access attempt", risk, status, control, reason
    )
    return status, risk, control, reason, ip


def admin_policy_test(source, source_vlan, target):
    targets = {
        "Finance": ("192.168.20.10", "20"),
        "Server": ("192.168.40.10", "40"),
        "HR": ("192.168.10.10", "10"),
        "IT": ("192.168.30.10", "30"),
        "Guest Gateway": ("192.168.50.1", "50"),
    }
    ip, vlan = targets[target]
    if str(source_vlan) == "50" and target in ("Finance", "Server"):
        status, risk, control = "BLOCKED", "HIGH", "ACL"
        reason = f"Guest VLAN 50 is denied access to VLAN {vlan} by GUEST_SECURITY."
    else:
        status, risk, control = "ALLOWED", "LOW", "Network Policy"
        reason = "The requested resource is allowed by the current demonstration policy."

    add_event(
        source, str(source_vlan), target, ip, "ICMP",
        "Admin policy test", risk, status, control, reason
    )
    return status, risk, control, reason, ip


def show_login():
    st.title("🛡️ AI Network Risk Assessment")
    st.caption("Secure network monitoring and VLAN access-policy demonstration")
    left, center, right = st.columns([1, 1.2, 1])
    with center:
        with st.container(border=True):
            st.subheader("Login")
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="admin or guest")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Login", use_container_width=True)
            if submitted:
                users = get_users()
                if username in users and str(users[username]) == password:
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.role = username
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
            st.info("Demo Admin: admin / admin123    ·    Guest: guest / guest123")


def metric_row():
    events = get_events(10000)
    total = len(events)
    blocked = sum(e["status"] == "BLOCKED" for e in events)
    allowed = sum(e["status"] == "ALLOWED" for e in events)
    failed = sum(e["status"] == "FAILED" for e in events)
    high = sum(e["risk"] == "HIGH" for e in events)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Events", total)
    c2.metric("Blocked", blocked)
    c3.metric("Allowed", allowed)
    c4.metric("Failed", failed)
    c5.metric("High Risk", high)


def page_dashboard():
    st.title("Dashboard")
    st.write("Overview of network activity and security events.")
    metric_row()
    st.subheader("VLAN Network Overview")
    st.dataframe(
        [
            {"VLAN": v, "Department": n, "Network": net, "Gateway": gw}
            for v, n, net, gw in VLAN_INFO
        ],
        use_container_width=True,
        hide_index=True,
    )
    st.subheader("Recent Activity")
    events = get_events(10)
    if events:
        st.dataframe(events, use_container_width=True, hide_index=True)
    else:
        st.info("No network events have been recorded yet.")


def page_risk():
    st.title("Risk Assessment")
    events = get_events(10000)
    if not events:
        st.info("Run a policy test or guest test to generate risk assessment data.")
        return
    grouped = {}
    for event in events:
        key = (event["target"], event["target_ip"])
        item = grouped.setdefault(key, {"Target": key[0], "Target IP": key[1],
                                        "Attempts": 0, "Blocked": 0, "Allowed": 0,
                                        "Latest Risk": event["risk"]})
        item["Attempts"] += 1
        item["Blocked"] += int(event["status"] == "BLOCKED")
        item["Allowed"] += int(event["status"] == "ALLOWED")
    st.dataframe(list(grouped.values()), use_container_width=True, hide_index=True)
    st.subheader("Risk Events")
    st.dataframe(events, use_container_width=True, hide_index=True)


def page_controls():
    st.title("Security Controls")
    st.caption("Toggle the demonstration controls stored in the local project database.")
    controls = get_controls()
    for control in controls:
        col1, col2, col3 = st.columns([1.2, 1, 3])
        col1.write(f"**{control['name']}**")
        enabled = col2.toggle(
            "Enabled",
            value=bool(control["enabled"]),
            key=f"control_{control['id']}",
            label_visibility="collapsed",
        )
        col3.write(control["description"])
        if int(enabled) != int(control["enabled"]):
            with db() as con:
                con.execute(
                    "UPDATE controls SET enabled=? WHERE id=?",
                    (int(enabled), control["id"]),
                )
            st.toast(f"{control['name']} updated")
            st.rerun()


def page_testing():
    st.title("Network Policy Testing")
    st.write("Simulate an ICMP access attempt using the project's demonstration policy.")
    with st.form("policy_test_form"):
        source = st.text_input("Source IP", value="192.168.50.10")
        source_vlan = st.selectbox("Source VLAN", ["10", "20", "30", "40", "50"], index=4)
        target = st.selectbox("Target", ["Finance", "Server", "HR", "IT", "Guest Gateway"])
        submitted = st.form_submit_button("Run Policy Test", use_container_width=True)
    if submitted:
        status, risk, control, reason, ip = admin_policy_test(source, source_vlan, target)
        if status == "BLOCKED":
            st.error(f"{status} · {risk} risk")
        else:
            st.success(f"{status} · {risk} risk")
        st.write(f"**Target IP:** {ip}")
        st.write(f"**Control:** {control}")
        st.write(f"**Reason:** {reason}")


def page_verification():
    st.title("Verification")
    expected = [
        ("50", "Finance", "BLOCKED"),
        ("50", "Server", "BLOCKED"),
        ("50", "Guest Gateway", "ALLOWED"),
        ("10", "Finance", "ALLOWED"),
    ]
    events = get_events(10000)
    results = []
    for source_vlan, target, expected_status in expected:
        matching = [
            e for e in events
            if str(e.get("source_vlan")) == source_vlan and e.get("target") == target
        ]
        latest = matching[0] if matching else None
        actual = latest["status"] if latest else "NOT TESTED"
        results.append({
            "Source VLAN": source_vlan,
            "Target": target,
            "Expected": expected_status,
            "Actual": actual,
            "Verified": actual == expected_status,
        })
    st.dataframe(results, use_container_width=True, hide_index=True)


def page_activity():
    st.title("Activity Logs")
    events = get_events(500)
    if events:
        st.dataframe(events, use_container_width=True, hide_index=True)
        csv_data = __import__("pandas").DataFrame(events).to_csv(index=False).encode("utf-8")
        st.download_button("Download activity as CSV", csv_data, "network_activity.csv", "text/csv")
    else:
        st.info("No activity has been recorded.")


def page_packet_tracer():
    st.title("Packet Tracer Event Import")
    st.warning(
        "The supplied OCR bridge currently posts to the Flask API at "
        "http://127.0.0.1:5000. It will not automatically post into a hosted "
        "Streamlit app. This form lets you record a Packet Tracer result manually. "
        "For automatic online import, keep a separate authenticated API service."
    )
    with st.form("packet_event_form"):
        source = st.text_input("Source IP", "192.168.50.10")
        source_vlan = st.text_input("Source VLAN", "50")
        target = st.selectbox("Target", ["Finance", "Server", "HR", "IT", "Guest Gateway"])
        target_ips = {
            "Finance": "192.168.20.10",
            "Server": "192.168.40.10",
            "HR": "192.168.10.10",
            "IT": "192.168.30.10",
            "Guest Gateway": "192.168.50.1",
        }
        status = st.selectbox("Observed ping result", ["BLOCKED", "ALLOWED", "FAILED"])
        reason = st.text_area("Reason / Packet Tracer observation")
        submitted = st.form_submit_button("Save Packet Tracer Event")
    if submitted:
        risk = "HIGH" if status in ("BLOCKED", "FAILED") else "LOW"
        add_event(
            source, source_vlan, target, target_ips[target], "ICMP",
            "Packet Tracer ping test", risk, status,
            "GUEST_SECURITY ACL" if status == "BLOCKED" else "Packet Tracer",
            reason or "Imported manually from Cisco Packet Tracer.",
        )
        st.success("Packet Tracer event saved.")
        st.rerun()


def page_guest():
    st.title("Guest Security Test")
    st.write("You can test the access permitted from Guest VLAN 50.")
    target = st.selectbox("Select destination", ["Finance", "Server", "HR", "IT", "Guest Gateway"])
    if st.button("Run Guest Test", type="primary", use_container_width=True):
        status, risk, control, reason, ip = guest_test(target)
        if status == "BLOCKED":
            st.error(f"Access {status} · {risk} risk")
        else:
            st.success(f"Access {status} · {risk} risk")
        st.write(f"**Target IP:** {ip}")
        st.write(f"**Security control:** {control}")
        st.write(f"**Explanation:** {reason}")


def main():
    init_db()
    if not st.session_state.get("authenticated"):
        show_login()
        return

    role = st.session_state.get("role")
    with st.sidebar:
        st.title("🛡️ Network Risk AI")
        st.write(f"Signed in as **{st.session_state.get('username')}**")
        st.caption(f"Role: {role.title()}")
        st.divider()
        if role == "admin":
            page = st.radio(
                "Navigation",
                [
                    "Dashboard", "Risk Assessment", "Controls", "Testing",
                    "Verification", "Activity Logs", "Packet Tracer Import",
                ],
            )
        else:
            page = "Guest Security Test"
        st.divider()
        if st.button("Logout", use_container_width=True):
            for key in ("authenticated", "username", "role"):
                st.session_state.pop(key, None)
            st.rerun()

    if role == "guest":
        page_guest()
    elif page == "Dashboard":
        page_dashboard()
    elif page == "Risk Assessment":
        page_risk()
    elif page == "Controls":
        page_controls()
    elif page == "Testing":
        page_testing()
    elif page == "Verification":
        page_verification()
    elif page == "Activity Logs":
        page_activity()
    elif page == "Packet Tracer Import":
        page_packet_tracer()


if __name__ == "__main__":
    main()
