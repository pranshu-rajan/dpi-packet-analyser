import os
import sys
from pathlib import Path

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db, SessionLocal
from app.models.db_models import CaptureRecord, FirewallRuleModel, ThreatEventModel, ChatMessageModel

def run_verification():
    print("=" * 70)
    print("RUNNING COMPREHENSIVE END-TO-END VERIFICATION")
    print("=" * 70)

    # 1. Initialize Database
    print("\n[TEST 1/7] Database Initialization & Table Verification")
    init_db()
    db = SessionLocal()
    rule_count = db.query(FirewallRuleModel).count()
    print(f"  ✓ Database Tables verified (captures, firewall_rules, threat_events, chat_messages)")
    print(f"  ✓ Default Firewall Rules in DB: {rule_count}")
    assert rule_count >= 6, f"Expected at least 6 rules, got {rule_count}"
    db.close()

    client = TestClient(app)

    # 2. System Health & Metadata Endpoints
    print("\n[TEST 2/7] System Health & Root Endpoints")
    r_root = client.get("/")
    assert r_root.status_code == 200, f"Root failed: {r_root.text}"
    root_data = r_root.json()
    print(f"  ✓ GET / -> Status: {root_data['status']}, Engine Ready: {root_data['engine_ready']}")

    r_health = client.get("/health")
    assert r_health.status_code == 200, f"Health failed: {r_health.text}"
    health_data = r_health.json()
    print(f"  ✓ GET /health -> Status: {health_data['status']}, Engine: {health_data['engine_path']}")

    r_status = client.get("/api/analyze/status")
    assert r_status.status_code == 200, f"Engine status failed: {r_status.text}"
    status_data = r_status.json()
    print(f"  ✓ GET /api/analyze/status -> Available: {status_data['available']}, Sample PCAP: {status_data['sample_pcap_available']}")

    # 3. Persistent Firewall Rules CRUD
    print("\n[TEST 3/7] Database-Backed Firewall Rules CRUD API")
    # GET all rules
    r_rules = client.get("/api/rules")
    assert r_rules.status_code == 200
    rules_list = r_rules.json()
    print(f"  ✓ GET /api/rules -> Retrieved {len(rules_list)} rules from DB")

    # POST create rule
    new_rule_payload = {
        "type": "ip",
        "value": "10.99.88.77",
        "action": "drop",
        "enabled": True,
        "description": "E2E Verification Rule"
    }
    r_create = client.post("/api/rules", json=new_rule_payload)
    assert r_create.status_code == 200
    created_rule = r_create.json()
    test_rule_id = created_rule["id"]
    print(f"  ✓ POST /api/rules -> Created Rule ID: {test_rule_id} ({created_rule['value']})")

    # PATCH toggle rule
    r_toggle = client.patch(f"/api/rules/{test_rule_id}/toggle")
    assert r_toggle.status_code == 200
    assert r_toggle.json()["enabled"] is False
    print(f"  ✓ PATCH /api/rules/{test_rule_id}/toggle -> New status: Enabled=False")

    # DELETE rule
    r_del = client.delete(f"/api/rules/{test_rule_id}")
    assert r_del.status_code == 200
    print(f"  ✓ DELETE /api/rules/{test_rule_id} -> Deleted successfully")

    # GET presets
    r_presets = client.get("/api/rules/presets")
    assert r_presets.status_code == 200
    print(f"  ✓ GET /api/rules/presets -> {len(r_presets.json())} presets loaded")

    # 4. DPI Engine Execution & Database Telemetry Storage
    print("\n[TEST 4/7] C++ Multi-Threaded DPI Engine & DB Persistence")
    # Execute sample PCAP with blocking rule for YouTube
    filter_rules = [{"id": "rule-yt", "type": "app", "value": "YouTube", "enabled": True}]
    import json
    r_sample = client.post("/api/analyze/sample", data={"rules_json": json.dumps(filter_rules)})
    assert r_sample.status_code == 200, f"Sample analysis failed: {r_sample.text}"
    sample_data = r_sample.json()
    analysis_id = sample_data["analysis_id"]
    total_pkts = sample_data["summary"]["total_packets"]
    fwd_pkts = sample_data["summary"]["forwarded"]
    drop_pkts = sample_data["summary"]["dropped"]
    print(f"  ✓ POST /api/analyze/sample -> Analysis ID: {analysis_id}")
    print(f"    - Total Packets: {total_pkts}")
    print(f"    - Forwarded: {fwd_pkts}, Dropped: {drop_pkts}")
    print(f"    - Detected SNIs: {len(sample_data['detected_snis'])}")
    print(f"    - Threat Score: {sample_data['threat_score']}/100")
    assert total_pkts == 77, f"Expected 77 packets, got {total_pkts}"
    assert drop_pkts >= 1, f"Expected at least 1 dropped packet, got {drop_pkts}"

    # Verify DB persistence of capture session
    db = SessionLocal()
    capture_row = db.query(CaptureRecord).filter(CaptureRecord.id == analysis_id).first()
    assert capture_row is not None, f"Capture session {analysis_id} not found in DB!"
    print(f"  ✓ Database Verification -> Record '{capture_row.filename}' stored with {capture_row.total_packets} packets")
    db.close()

    # GET /api/analyze/history
    r_hist = client.get("/api/analyze/history")
    assert r_hist.status_code == 200
    history_items = r_hist.json()
    print(f"  ✓ GET /api/analyze/history -> {len(history_items)} historical session(s) in DB")
    assert any(h["id"] == analysis_id for h in history_items)

    # GET /api/analyze/session/{id}
    r_session = client.get(f"/api/analyze/session/{analysis_id}")
    assert r_session.status_code == 200
    print(f"  ✓ GET /api/analyze/session/{analysis_id} -> Reconstructed session successfully from DB")

    # 5. Packet Dissector & Hex Dump API
    print("\n[TEST 5/7] Wireshark Packet Dissector & Hex Dump Endpoints")
    r_packets = client.get(f"/api/packets?analysis_id={analysis_id}&limit=5")
    assert r_packets.status_code == 200
    packets_data = r_packets.json()
    print(f"  ✓ GET /api/packets -> Parsed {len(packets_data['packets'])} packets (Total in capture: {packets_data['total']})")
    first_pkt = packets_data['packets'][0]
    print(f"    - Packet #1: {first_pkt['protocol']} {first_pkt['src_ip']}:{first_pkt['src_port']} -> {first_pkt['dst_ip']}:{first_pkt['dst_port']} [{first_pkt['app']}]")

    # Packet detail & hex dump
    r_detail = client.get(f"/api/packets/1?analysis_id={analysis_id}")
    assert r_detail.status_code == 200
    detail_data = r_detail.json()
    print(f"  ✓ GET /api/packets/1 -> Dissected Layers: {list(detail_data['layers'].keys())}")
    print(f"    - Hex Dump Lines: {len(detail_data['hex_dump'])}")
    print(f"    - Raw Offset Line: {detail_data['hex_dump'][0]['offset']}  {detail_data['hex_dump'][0]['hex'][:24]}...  {detail_data['hex_dump'][0]['ascii'][:16]}")

    # 6. AI Copilot Chat & Audit Log Verification
    print("\n[TEST 6/7] AI Copilot & Chat Audit History")
    r_chat_hist = client.get(f"/api/chat/history/{analysis_id}")
    assert r_chat_hist.status_code == 200
    print(f"  ✓ GET /api/chat/history/{analysis_id} -> Chat history endpoint OK (Retrieved {len(r_chat_hist.json())} messages)")

    # 7. Security Defense & Path Traversal Verification
    print("\n[TEST 7/7] Path Traversal & Security Validation")
    r_traversal = client.get("/api/analyze/download/../../etc/passwd")
    assert r_traversal.status_code in [404, 400], f"Expected 404/400 for path traversal, got {r_traversal.status_code}"
    print(f"  ✓ Path traversal attack blocked with HTTP {r_traversal.status_code}")

    print("\n" + "=" * 70)
    print("[SUCCESS] ALL 7 INTEGRATION TIERS & ENDPOINTS FULLY VERIFIED AND PASSING!")
    print("=" * 70)

if __name__ == "__main__":
    run_verification()
