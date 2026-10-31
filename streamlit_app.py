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
