import os
import sys
import json
import time
import re
import uuid
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.config import (
    DPI_ENGINE_PATH,
    UPLOADS_DIR,
    OUTPUTS_DIR,
    SAMPLE_PCAP_PATH,
)
from app.models.schemas import (
    FilterRule,
    SummaryStats,
    ThreadStats,
    ThreadInfo,
    ApplicationBreakdown,
    DetectedSNI,
    ThreatIndicator,
    AnalysisResponse,
)

# In-memory store for recent analyses
ANALYSIS_CACHE: Dict[str, Dict[str, Any]] = {}

def calculate_threat_score(
    summary: SummaryStats,
    apps: List[ApplicationBreakdown],
    snis: List[DetectedSNI]
) -> tuple[int, List[ThreatIndicator]]:
    """
    Computes a 0-100 cyber threat score and generates diagnostic threat indicators
    based on DPI telemetry findings.
    """
    score = 5  # Base baseline
    indicators: List[ThreatIndicator] = []

    # Check for unencrypted HTTP traffic
    http_count = 0
    for app in apps:
        if app.name.upper() == "HTTP":
            http_count = app.count
            break

    if http_count > 0:
        score += min(35, http_count * 5)
        indicators.append(ThreatIndicator(
            severity="medium",
            category="plaintext",
            title="Plaintext HTTP Traffic Detected",
            description=f"Identified {http_count} unencrypted HTTP packet(s). Transmitting data over plaintext exposes sessions to eavesdropping and credential sniffing.",
            affected_count=http_count,
            suggested_action="Enforce HTTPS/TLS encryption or inspect payloads for sensitive leaks."
        ))

    # Check for dropped / blocked packets
    if summary.dropped > 0:
        drop_pct = (summary.dropped / max(1, summary.total_packets)) * 100
        score += min(30, int(drop_pct * 0.8))
        indicators.append(ThreatIndicator(
            severity="high" if drop_pct > 10 else "medium",
            category="blocked_traffic",
            title="Active Firewall Rule Interceptions",
            description=f"DPI Engine actively blocked and dropped {summary.dropped} packet(s) ({drop_pct:.1f}% of total traffic) according to active security policy.",
            affected_count=summary.dropped,
            suggested_action="Review filtered PCAP to verify intercepted endpoints."
        ))

    # Check for unknown / unclassified traffic
    unknown_count = 0
    for app in apps:
        if app.name.lower() == "unknown":
            unknown_count = app.count
            break
            
    if unknown_count > 0:
        unknown_pct = (unknown_count / max(1, summary.total_packets)) * 100
        if unknown_pct > 25:
            score += 15
            indicators.append(ThreatIndicator(
                severity="low",
                category="anomaly",
                title="Elevated Unclassified Flow Volume",
                description=f"{unknown_count} packet(s) ({unknown_pct:.1f}%) could not be classified by SNI or standard protocol signatures. May indicate custom protocols or tunneling.",
                affected_count=unknown_count,
                suggested_action="Inspect raw byte payloads in Packet Explorer."
            ))

    # Check for suspicious / social / video domains in enterprise context
    distracting_apps = {"TIKTOK", "TELEGRAM", "TWITTER/X", "YOUTUBE"}
    found_distracting = []
    for app in apps:
        if app.name.upper() in distracting_apps and app.count > 0:
            found_distracting.append(f"{app.name} ({app.count})")

    if found_distracting:
        indicators.append(ThreatIndicator(
            severity="info",
            category="policy",
            title="High-Bandwidth Application Activity",
            description=f"Detected active external platform traffic: {', '.join(found_distracting)}.",
            affected_count=len(found_distracting),
            suggested_action="Apply application blocking rules if restricted by corporate or compliance policy."
        ))

    # Normalize score between 0 and 100
    score = min(100, max(0, score))
    return score, indicators


class DPIRunnerService:
    @staticmethod
    def get_engine_status() -> Dict[str, Any]:
        exists = DPI_ENGINE_PATH.exists()
        return {
            "engine_path": str(DPI_ENGINE_PATH),
            "available": exists,
            "os": os.name,
            "sample_pcap_available": SAMPLE_PCAP_PATH.exists(),
        }

    @staticmethod
    def run_engine(
        input_pcap: Path,
        rules: Optional[List[FilterRule]] = None,
        custom_id: Optional[str] = None
    ) -> AnalysisResponse:
        if not input_pcap.exists():
            raise FileNotFoundError(f"Input PCAP file not found: {input_pcap}")

        if not DPI_ENGINE_PATH.exists():
            raise RuntimeError(
                f"DPI Engine executable not found at: {DPI_ENGINE_PATH}. "
                "Please compile the C++ engine using: g++ -std=c++17 -O2 -I include -o dpi_engine.exe ..."
            )

        analysis_id = custom_id or str(uuid.uuid4())[:8]
        output_pcap_name = f"filtered_{analysis_id}.pcap"
        output_pcap_path = OUTPUTS_DIR / output_pcap_name
        json_output_path = OUTPUTS_DIR / f"telemetry_{analysis_id}.json"

        # Build CLI arguments
        cmd = [
            str(DPI_ENGINE_PATH),
            str(input_pcap),
            str(output_pcap_path),
            "--json-output",
            str(json_output_path),
        ]

        active_rules = rules or []
        for r in active_rules:
            if not r.enabled or not r.value.strip():
                continue
            t = r.type.lower().strip()
            # Strip shell/control characters and whitespace
            val = re.sub(r'[\r\n\t;|<>&`$\\"]', '', r.value.strip())
            if not val:
                continue
            if t == "ip":
                cmd.extend(["--block-ip", val])
            elif t == "app":
                cmd.extend(["--block-app", val])
            elif t == "domain":
                cmd.extend(["--block-domain", val])

        # Execute C++ DPI engine
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError("DPI Engine execution timed out (exceeded 30 seconds).")
        except Exception as e:
            raise RuntimeError(f"Failed to execute DPI Engine: {str(e)}")

        if res.returncode != 0:
            err_msg = res.stderr.strip() or res.stdout.strip() or f"Exited with code {res.returncode}"
            raise RuntimeError(f"DPI Engine failed: {err_msg}")

        # Read JSON telemetry
        if not json_output_path.exists():
            raise RuntimeError("DPI Engine executed but did not generate telemetry JSON output.")

        with open(json_output_path, "r", encoding="utf-8") as f:
            telemetry_data = json.load(f)

        raw_sum = telemetry_data.get("summary", {})
        summary = SummaryStats(
            total_packets=raw_sum.get("total_packets", 0),
            total_bytes=raw_sum.get("total_bytes", 0),
            tcp_packets=raw_sum.get("tcp_packets", 0),
            udp_packets=raw_sum.get("udp_packets", 0),
            forwarded=raw_sum.get("forwarded", 0),
            dropped=raw_sum.get("dropped", 0),
        )

        raw_threads = telemetry_data.get("thread_stats", {})
        thread_stats = ThreadStats(
            lbs=[ThreadInfo(id=x.get("id", 0), dispatched=x.get("dispatched")) for x in raw_threads.get("lbs", [])],
            fps=[ThreadInfo(id=x.get("id", 0), processed=x.get("processed")) for x in raw_threads.get("fps", [])],
        )

        apps = [
            ApplicationBreakdown(
                name=x.get("name", "Unknown"),
                count=x.get("count", 0),
                percentage=x.get("percentage", 0.0),
            )
            for x in telemetry_data.get("applications", [])
        ]

        snis = [
            DetectedSNI(
                sni=x.get("sni", ""),
                app=x.get("app", "Unknown")
            )
            for x in telemetry_data.get("detected_snis", [])
        ]

        threat_score, indicators = calculate_threat_score(summary, apps, snis)

        response = AnalysisResponse(
            analysis_id=analysis_id,
            filename=input_pcap.name,
            file_size_bytes=input_pcap.stat().st_size if input_pcap.exists() else 0,
            timestamp=datetime.utcnow().isoformat() + "Z",
            summary=summary,
            thread_stats=thread_stats,
            applications=apps,
            detected_snis=snis,
            threat_score=threat_score,
            threat_indicators=indicators,
            active_rules=active_rules,
            output_pcap_name=output_pcap_name,
            output_pcap_download_url=f"/api/analyze/download/{output_pcap_name}",
        )

        # Auto-prune cache if exceeding 50 entries to prevent memory and disk leaks
        if len(ANALYSIS_CACHE) >= 50:
            oldest_id = list(ANALYSIS_CACHE.keys())[0]
            old_entry = ANALYSIS_CACHE.pop(oldest_id, None)
            if old_entry:
                for p_str in [old_entry.get("output_pcap"), old_entry.get("json_output")]:
                    if p_str and Path(p_str).exists() and not str(p_str).endswith("test_dpi.pcap"):
                        try:
                            Path(p_str).unlink(missing_ok=True)
                        except Exception:
                            pass

        # Store in cache
        ANALYSIS_CACHE[analysis_id] = {
            "response": response.model_dump(),
            "input_pcap": str(input_pcap),
            "output_pcap": str(output_pcap_path),
            "json_output": str(json_output_path),
            "rules": [r.model_dump() for r in active_rules],
            "raw_stdout": res.stdout,
        }

        return response
