"""OCR bridge for Cisco Packet Tracer ping results.

Keep Packet Tracer visible with the PC Command Prompt showing a completed ping.
This script OCRs the screen, detects a visible ping summary, and submits a
verified-looking result to the local Flask API. Review the dashboard event.
"""
import os
import re
import time
from datetime import datetime

import pyautogui
import pytesseract
import requests

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

BASE_URL = "http://127.0.0.1:5000"
USERNAME = os.getenv("NRA_ADMIN_USER", "admin")
PASSWORD = os.getenv("NRA_ADMIN_PASSWORD", "admin123")
# If Tesseract is not on PATH, uncomment and set your installed path:
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
POLL_SECONDS = 3
COOLDOWN_SECONDS = 20

TARGETS = {
    "192.168.20.10": ("Finance", "20"),
    "192.168.40.10": ("Server", "40"),
    "192.168.10.10": ("HR", "10"),
    "192.168.30.10": ("IT", "30"),
    "192.168.50.1": ("Guest Gateway", "50"),
}
SOURCE_IP = "192.168.50.10"
SOURCE_VLAN = "50"

session = requests.Session()
last_sent = {}

def connect_admin():
    r = session.post(f"{BASE_URL}/api/login", json={"username": USERNAME, "password": PASSWORD}, timeout=5)
    r.raise_for_status()
    data = r.json()
    if data.get("role") != "admin":
        raise RuntimeError("Flask login did not return admin role.")
    print("Connected to Flask as admin.")

def parse_ping(text):
    # Require a visible ping command/target and a completed Windows ping summary.
    target_ip = None
    for ip in TARGETS:
        if ip in text:
            target_ip = ip
            break
    if not target_ip:
        return None

    lower = text.lower()
    has_summary = ("packets:" in lower or "sent =" in lower) and ("lost =" in lower or "received =" in lower)
    unreachable = "destination host unreachable" in lower or "destination net unreachable" in lower
    # Windows localized/spacing OCR may vary; use summary values when recognized.
    lost_match = re.search(r"lost\s*=\s*(\d+)", lower)
    recv_match = re.search(r"received\s*=\s*(\d+)", lower)
    if not has_summary and not unreachable:
        return None
    if unreachable or (lost_match and int(lost_match.group(1)) == 4):
        status = "BLOCKED" if target_ip in ("192.168.20.10", "192.168.40.10") else "FAILED"
        reason = "OCR detected unreachable/100% packet loss in the visible Packet Tracer ping output. Confirm the ping output before presenting this result."
    elif recv_match and int(recv_match.group(1)) > 0:
        status = "ALLOWED"
        reason = "OCR detected received ping replies in the visible Packet Tracer output."
    else:
        return None
    target, target_vlan = TARGETS[target_ip]
    return {"source": SOURCE_IP, "source_vlan": SOURCE_VLAN, "target": target,
            "target_ip": target_ip, "protocol": "ICMP", "event": "Packet Tracer ping detected by OCR",
            "status": status, "control": "GUEST_SECURITY ACL" if status == "BLOCKED" else "Network Policy",
            "reason": reason, "target_vlan": target_vlan}

def main():
    print("Packet Tracer OCR bridge started. Keep the completed ping output visible on screen.")
    print("Press Ctrl+C in this terminal to stop.")
    connect_admin()
    while True:
        try:
            shot = pyautogui.screenshot()
            text = pytesseract.image_to_string(shot, config="--psm 6")
            event = parse_ping(text)
            if event:
                key = (event["target_ip"], event["status"])
                now = time.time()
                if now - last_sent.get(key, 0) >= COOLDOWN_SECONDS:
                    payload = dict(event)
                    payload.pop("target_vlan", None)
                    r = session.post(f"{BASE_URL}/api/packet-tracer/event", json=payload, timeout=5)
                    if r.ok:
                        last_sent[key] = now
                        print(f"[{datetime.now():%H:%M:%S}] Imported: {event['target']} -> {event['status']}")
                    else:
                        print("API error:", r.status_code, r.text[:200])
            time.sleep(POLL_SECONDS)
        except KeyboardInterrupt:
            print("\nBridge stopped.")
            break
        except Exception as e:
            print("Bridge error:", e)
            time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
