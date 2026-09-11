from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query

from app.config import SAMPLE_PCAP_PATH
from app.models.schemas import PacketSummary, PacketDetail, FilterRule
from app.services.dpi_runner import ANALYSIS_CACHE
from app.services.packet_inspector import PacketInspectorService

router = APIRouter(prefix="/api/packets", tags=["Packets"])

def get_pcap_path_and_rules(analysis_id: Optional[str]) -> tuple[Path, List[FilterRule]]:
    if not analysis_id or analysis_id not in ANALYSIS_CACHE:
        if SAMPLE_PCAP_PATH.exists():
            return SAMPLE_PCAP_PATH, []
        raise HTTPException(status_code=404, detail="PCAP capture context not found.")
    
    cached = ANALYSIS_CACHE[analysis_id]
    pcap_path = Path(cached["input_pcap"])
    rules = [FilterRule(**r) for r in cached.get("rules", [])]
    return pcap_path, rules

@router.get("", response_model=dict)
def get_packet_list(
    analysis_id: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    protocol: Optional[str] = None,
    search: Optional[str] = None
):
    """
    Returns paginated packet summary stream with filtering.
    """
    pcap_path, rules = get_pcap_path_and_rules(analysis_id)
    packets, total_count = PacketInspectorService.parse_pcap_packets(
        pcap_path=pcap_path,
        rules=rules,
        limit=limit,
        offset=offset,
        protocol_filter=protocol,
        search_query=search
    )
    return {
        "packets": packets,
        "total": total_count,
        "limit": limit,
        "offset": offset
    }

@router.get("/{packet_id}", response_model=PacketDetail)
def get_packet_details(
    packet_id: int,
    analysis_id: Optional[str] = None
):
    """
    Returns protocol layers breakdown and raw synchronized hex dump for a packet.
    """
    pcap_path, rules = get_pcap_path_and_rules(analysis_id)
    detail = PacketInspectorService.get_packet_detail(pcap_path, packet_id, rules)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Packet #{packet_id} not found in capture.")
    return detail
