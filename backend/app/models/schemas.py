from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class FilterRule(BaseModel):
    id: str = Field(..., description="Unique rule ID")
    type: str = Field(..., description="Rule type: 'ip', 'app', or 'domain'")
    value: str = Field(..., description="Target value to block (e.g., 192.168.1.1, YouTube, netflix.com)")
    enabled: bool = Field(default=True, description="Whether this rule is active")
    description: Optional[str] = Field(default=None, description="User note or reason for blocking")

class SummaryStats(BaseModel):
    total_packets: int
    total_bytes: int
    tcp_packets: int
    udp_packets: int
    forwarded: int
    dropped: int

class ThreadInfo(BaseModel):
    id: int
    dispatched: Optional[int] = None
    processed: Optional[int] = None

class ThreadStats(BaseModel):
    lbs: List[ThreadInfo] = []
    fps: List[ThreadInfo] = []

class ApplicationBreakdown(BaseModel):
    name: str
    count: int
    percentage: float

class DetectedSNI(BaseModel):
    sni: str
    app: str

class ThreatIndicator(BaseModel):
    severity: str  # info, low, medium, high, critical
    category: str  # plaintext, anomaly, port_scan, blocked_traffic
    title: str
    description: str
    affected_count: int = 1
    suggested_action: Optional[str] = None

class AnalysisResponse(BaseModel):
    analysis_id: str
    filename: str
    file_size_bytes: int
    timestamp: str
    summary: SummaryStats
    thread_stats: ThreadStats
    applications: List[ApplicationBreakdown]
    detected_snis: List[DetectedSNI]
    threat_score: int  # 0 (safe) to 100 (critical risk)
    threat_indicators: List[ThreatIndicator]
    active_rules: List[FilterRule]
    output_pcap_name: Optional[str] = None
    output_pcap_download_url: Optional[str] = None

class PacketSummary(BaseModel):
    id: int
    timestamp: float
    timestamp_str: str
    length: int
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str  # TCP, UDP, ICMP, etc.
    app: str
    sni: Optional[str] = None
    flags: Optional[str] = None
    status: str = "forwarded"  # "forwarded" or "dropped"
    info: str

class HexDumpLine(BaseModel):
    offset: str
    hex: str
    ascii: str

class PacketDetail(BaseModel):
    summary: PacketSummary
    layers: Dict[str, Any]
    hex_dump: List[HexDumpLine]
    raw_len: int

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    analysis_id: Optional[str] = None

class CaptureHistoryItem(BaseModel):
    id: str
    filename: str
    file_size_bytes: int
    total_packets: int
    processed_packets: int
    dropped_packets: int
    duration_ms: float
    throughput_mbps: float
    status: str
    created_at: str

class CreateRuleRequest(BaseModel):
    type: str = Field(..., description="Rule type: 'ip', 'app', 'domain', or 'port'")
    value: str = Field(..., description="Target pattern to match")
    action: str = Field(default="drop", description="Action: 'drop', 'alert', or 'pass'")
    enabled: bool = Field(default=True)
    description: Optional[str] = Field(default="")
