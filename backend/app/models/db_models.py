import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, BigInteger, Boolean, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class CaptureRecord(Base):
    __tablename__ = "captures"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String(255), nullable=False)
    file_size_bytes = Column(BigInteger, default=0)
    total_packets = Column(Integer, default=0)
    processed_packets = Column(Integer, default=0)
    dropped_packets = Column(Integer, default=0)
    duration_ms = Column(Float, default=0.0)
    throughput_mbps = Column(Float, default=0.0)
    protocol_distribution = Column(JSON, default=dict)
    top_domains = Column(JSON, default=list)
    top_talkers = Column(JSON, default=list)
    summary_metrics = Column(JSON, default=dict)
    status = Column(String(32), default="completed")
    created_at = Column(DateTime, default=datetime.utcnow)

    threat_events = relationship("ThreatEventModel", back_populates="capture", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessageModel", back_populates="capture", cascade="all, delete-orphan")

class FirewallRuleModel(Base):
    __tablename__ = "firewall_rules"

    id = Column(String(64), primary_key=True)
    rule_type = Column(String(32), nullable=False) # app, domain, ip, port
    pattern_value = Column(String(255), nullable=False)
    action = Column(String(32), default="drop") # drop, alert, pass
    is_enabled = Column(Boolean, default=False)
    hit_count = Column(Integer, default=0)
    description = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ThreatEventModel(Base):
    __tablename__ = "threat_events"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    capture_id = Column(String(64), ForeignKey("captures.id", ondelete="CASCADE"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    severity = Column(String(32), default="medium") # critical, high, medium, low
    threat_type = Column(String(64), nullable=False)
    src_ip = Column(String(64), nullable=True)
    dst_ip = Column(String(64), nullable=True)
    domain_or_sni = Column(String(255), nullable=True)
    details = Column(Text, nullable=True)

    capture = relationship("CaptureRecord", back_populates="threat_events")

class ChatMessageModel(Base):
    __tablename__ = "chat_messages"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    capture_id = Column(String(64), ForeignKey("captures.id", ondelete="CASCADE"), nullable=True)
    role = Column(String(32), nullable=False) # user, assistant
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    capture = relationship("CaptureRecord", back_populates="chat_messages")
