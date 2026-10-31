@echo off
echo This example records a verified Guest-to-Finance Packet Tracer test.
curl -X POST http://127.0.0.1:5000/api/packet-tracer/event -H "Content-Type: application/json" -d "{\"source\":\"192.168.50.10\",\"source_vlan\":\"50\",\"target\":\"Finance\",\"target_ip\":\"192.168.20.10\",\"protocol\":\"ICMP\",\"event\":\"Packet Tracer ping test\",\"status\":\"BLOCKED\",\"control\":\"GUEST_SECURITY ACL\",\"reason\":\"Packet Tracer showed 100 percent packet loss from Guest to Finance.\"}"
pause
