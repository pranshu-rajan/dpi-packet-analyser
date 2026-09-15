import os
import sys
from pathlib import Path

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.main import app
from app.services.dpi_runner import DPIRunnerService
from app.services.packet_inspector import PacketInspectorService
from app.config import SAMPLE_PCAP_PATH, DPI_ENGINE_PATH
from app.models.schemas import FilterRule

def run_tests():
    print("--- 1. Testing Engine Availability ---")
    status = DPIRunnerService.get_engine_status()
    print("Engine status:", status)
    assert status["available"], f"Engine not found at {DPI_ENGINE_PATH}"
    assert status["sample_pcap_available"], f"Sample PCAP not found at {SAMPLE_PCAP_PATH}"

    print("\n--- 2. Testing DPI Runner on Sample PCAP with Rules ---")
    rules = [
        FilterRule(id="test-yt", type="app", value="YouTube", enabled=True),
        FilterRule(id="test-sp", type="domain", value="spotify", enabled=True)
    ]
    response = DPIRunnerService.run_engine(
        input_pcap=SAMPLE_PCAP_PATH,
        rules=rules,
        custom_id="test_run"
    )
    print(f"Total Packets: {response.summary.total_packets}")
    print(f"Forwarded: {response.summary.forwarded}, Dropped: {response.summary.dropped}")
    print(f"Threat Score: {response.threat_score}/100")
    print(f"Detected SNIs: {len(response.detected_snis)}")
    print(f"Filtered PCAP: {response.output_pcap_name}")
    assert response.summary.total_packets == 77
    assert response.summary.dropped == 2
    assert response.summary.forwarded == 75

    print("\n--- 3. Testing Packet Inspector on PCAP ---")
    packets, total = PacketInspectorService.parse_pcap_packets(
        pcap_path=SAMPLE_PCAP_PATH,
        rules=rules,
        limit=10
    )
    print(f"Parsed {len(packets)} packets (Total in file: {total})")
    assert len(packets) == 10
    first_pkt = packets[0]
    print(f"Packet #1: {first_pkt.protocol} {first_pkt.src_ip}:{first_pkt.src_port} -> {first_pkt.dst_ip}:{first_pkt.dst_port} ({first_pkt.app}) Status: {first_pkt.status}")

    print("\n--- 4. Testing Packet Detail & Hex Dump on Packet #1 ---")
    detail = PacketInspectorService.get_packet_detail(
        pcap_path=SAMPLE_PCAP_PATH,
        packet_id=1,
        rules=rules
    )
    assert detail is not None
    print(f"Packet #1 Hex Dump Lines: {len(detail.hex_dump)}")
    print(f"Sample Hex Line: {detail.hex_dump[0].offset}  {detail.hex_dump[0].hex}  {detail.hex_dump[0].ascii}")

    print("\n--- 5. Testing Database Integration & CRUD ---")
    from app.database import SessionLocal, init_db
    from app.models.db_models import FirewallRuleModel, CaptureRecord
    from app.api.rules import get_all_rules, create_rule, toggle_rule, delete_rule
    from app.api.analyze import persist_analysis_to_db, get_capture_history
    from app.models.schemas import CreateRuleRequest

    init_db()
    db = SessionLocal()
    
    # 5.1 Test Rule CRUD
    rules_in_db = get_all_rules(db=db)
    print(f"Total Rules in Database: {len(rules_in_db)}")
    assert len(rules_in_db) >= 6

    # Create new rule
    new_rule = create_rule(
        CreateRuleRequest(type="ip", value="10.20.30.40", action="drop", enabled=True, description="Test rule"),
        db=db
    )
    print(f"Created rule: {new_rule.id} ({new_rule.value})")
    assert new_rule.value == "10.20.30.40"

    # Toggle rule
    toggled = toggle_rule(new_rule.id, db=db)
    print(f"Toggled rule status: {toggled.enabled}")
    assert toggled.enabled is False

    # Delete rule
    del_res = delete_rule(new_rule.id, db=db)
    print(f"Deleted rule: {del_res}")

    # 5.2 Test Capture Persistence
    persist_analysis_to_db(response, db=db)
    history = get_capture_history(db=db)
    print(f"Capture History in Database: {len(history)} record(s)")
    assert len(history) >= 1
    assert history[0].total_packets == 77
    db.close()

    print("\n[SUCCESS] All Backend Core Services & Database Integration Tested Successfully!")

if __name__ == "__main__":
    run_tests()
