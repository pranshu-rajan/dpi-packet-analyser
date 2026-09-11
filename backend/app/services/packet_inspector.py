import struct
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from app.models.schemas import PacketSummary, PacketDetail, HexDumpLine, FilterRule

def format_mac(raw_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw_bytes)

def format_ip(raw_bytes: bytes) -> str:
    return ".".join(str(b) for b in raw_bytes)

def extract_sni_from_payload(payload: bytes) -> Optional[str]:
    """
    Extracts TLS Server Name Indication (SNI) from TLS Client Hello handshake.
    Follows TLS 1.0 - 1.3 RFC specifications.
    """
    try:
        # Check TLS Handshake Record (0x16)
        if len(payload) < 5 or payload[0] != 0x16:
            return None

        # Check Handshake Type: Client Hello (0x01)
        if len(payload) < 9 or payload[5] != 0x01:
            return None

        # Skip record header (5) + handshake header (4) + client version (2) + random (32) = 43
        idx = 43
        if idx >= len(payload):
            return None

        # Session ID length
        sess_id_len = payload[idx]
        idx += 1 + sess_id_len
        if idx + 2 > len(payload):
            return None

        # Cipher Suites length
        cipher_suites_len = struct.unpack(">H", payload[idx:idx+2])[0]
        idx += 2 + cipher_suites_len
        if idx + 1 > len(payload):
            return None

        # Compression methods length
        comp_methods_len = payload[idx]
        idx += 1 + comp_methods_len
        if idx + 2 > len(payload):
            return None

        # Extensions length
        extensions_len = struct.unpack(">H", payload[idx:idx+2])[0]
        idx += 2
        ext_end = idx + extensions_len

        # Walk through TLS Extensions
        while idx + 4 <= ext_end and idx + 4 <= len(payload):
            ext_type, ext_len = struct.unpack(">HH", payload[idx:idx+4])
            idx += 4
            # 0x0000 = Server Name (SNI)
            if ext_type == 0x0000:
                if idx + 2 > len(payload):
                    break
                sni_list_len = struct.unpack(">H", payload[idx:idx+2])[0]
                sni_idx = idx + 2
                if sni_idx + 3 <= len(payload):
                    name_type = payload[sni_idx]
                    name_len = struct.unpack(">H", payload[sni_idx+1:sni_idx+3])[0]
                    sni_idx += 3
                    if name_type == 0 and sni_idx + name_len <= len(payload):
                        return payload[sni_idx:sni_idx+name_len].decode('utf-8', errors='ignore')
            idx += ext_len
    except Exception:
        pass
    return None

def extract_http_host(payload: bytes) -> Optional[str]:
    """Extracts HTTP Host header from plaintext HTTP request."""
    try:
        text = payload[:500].decode('utf-8', errors='ignore')
        for line in text.split('\r\n'):
            if line.lower().startswith('host:'):
                return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return None

def extract_dns_query(payload: bytes) -> Optional[str]:
    """Extracts domain query name from DNS packet (UDP port 53)."""
    try:
        if len(payload) < 13:
            return None
        # DNS header is 12 bytes. Question starts at byte 12.
        idx = 12
        parts = []
        while idx < len(payload):
            length = payload[idx]
            if length == 0:
                break
            idx += 1
            if idx + length > len(payload):
                break
            parts.append(payload[idx:idx+length].decode('utf-8', errors='ignore'))
            idx += length
        if parts:
            return ".".join(parts)
    except Exception:
        pass
    return None

def generate_hex_dump(data: bytes) -> List[HexDumpLine]:
    """Generates standard Wireshark / hexdump formatted lines."""
    lines: List[HexDumpLine] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        offset = f"{i:04x}"
        hex_parts = [f"{b:02x}" for b in chunk]
        # pad hex string to 16 bytes format (e.g. "48 65 6c 6c 6f ...")
        hex_str = " ".join(hex_parts).ljust(48)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(HexDumpLine(offset=offset, hex=hex_str, ascii=ascii_chars))
    return lines

def is_packet_blocked(
    src_ip: str,
    dst_ip: str,
    app: str,
    sni: Optional[str],
    rules: Optional[List[FilterRule]]
) -> bool:
    if not rules:
        return False
    for r in rules:
        if not r.enabled or not r.value.strip():
            continue
        val = r.value.strip().lower()
        t = r.type.lower().strip()
        if t == "ip":
            if src_ip == val or dst_ip == val:
                return True
        elif t == "app":
            if app.lower() == val or val in app.lower():
                return True
        elif t == "domain":
            if sni and (val in sni.lower()):
                return True
    return False


class PacketInspectorService:
    @staticmethod
    def parse_pcap_packets(
        pcap_path: Path,
        rules: Optional[List[FilterRule]] = None,
        limit: int = 500,
        offset: int = 0,
        protocol_filter: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> Tuple[List[PacketSummary], int]:
        """
        Parses PCAP file and returns a list of PacketSummary objects along with total count.
        """
        if not pcap_path.exists():
            return [], 0

        packets: List[PacketSummary] = []
        total_matched = 0

        with open(pcap_path, "rb") as f:
            # Read Global Header (24 bytes)
            ghdr = f.read(24)
            if len(ghdr) < 24:
                return [], 0

            magic = struct.unpack("<I", ghdr[:4])[0]
            endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"

            pkt_id = 0
            while True:
                # Read Packet Header (16 bytes)
                phdr = f.read(16)
                if len(phdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", phdr)
                # Guard against corrupted packet lengths exceeding 1MB
                if incl_len > 1_048_576:
                    break
                raw_data = f.read(incl_len)
                if len(raw_data) < incl_len:
                    break

                pkt_id += 1

                # Parse Ethernet Header (14 bytes)
                if len(raw_data) < 14:
                    continue

                dst_mac = format_mac(raw_data[0:6])
                src_mac = format_mac(raw_data[6:12])
                ethertype = struct.unpack(">H", raw_data[12:14])[0]

                src_ip = "0.0.0.0"
                dst_ip = "0.0.0.0"
                src_port = None
                dst_port = None
                protocol = "Ethernet"
                flags_str = ""
                app_name = "Unknown"
                sni_found = None
                info_desc = ""

                # IPv4 (0x0800)
                if ethertype == 0x0800 and len(raw_data) >= 34:
                    ip_hdr_offset = 14
                    ihl = (raw_data[ip_hdr_offset] & 0x0F) * 4
                    proto_num = raw_data[ip_hdr_offset + 9]
                    src_ip = format_ip(raw_data[ip_hdr_offset + 12: ip_hdr_offset + 16])
                    dst_ip = format_ip(raw_data[ip_hdr_offset + 16: ip_hdr_offset + 20])

                    transport_offset = ip_hdr_offset + ihl

                    if proto_num == 6:  # TCP
                        protocol = "TCP"
                        if len(raw_data) >= transport_offset + 20:
                            src_port, dst_port = struct.unpack(">HH", raw_data[transport_offset:transport_offset+4])
                            tcp_data_offset = ((raw_data[transport_offset + 12] >> 4) & 0x0F) * 4
                            flags_byte = raw_data[transport_offset + 13]
                            
                            flag_names = []
                            if flags_byte & 0x02: flag_names.append("SYN")
                            if flags_byte & 0x10: flag_names.append("ACK")
                            if flags_byte & 0x01: flag_names.append("FIN")
                            if flags_byte & 0x04: flag_names.append("RST")
                            if flags_byte & 0x08: flag_names.append("PSH")
                            flags_str = " ".join(flag_names)

                            payload_offset = transport_offset + tcp_data_offset
                            payload = raw_data[payload_offset:]

                            # Check SNI or HTTP
                            sni_found = extract_sni_from_payload(payload)
                            http_host = extract_http_host(payload)

                            if sni_found:
                                app_name = "TLS / HTTPS"
                                info_desc = f"TLS Client Hello [SNI: {sni_found}]"
                            elif http_host:
                                app_name = "HTTP"
                                info_desc = f"HTTP Request [Host: {http_host}]"
                            elif dst_port == 443 or src_port == 443:
                                app_name = "HTTPS"
                                info_desc = f"HTTPS Data [{src_port} -> {dst_port}] {flags_str}"
                            elif dst_port == 80 or src_port == 80:
                                app_name = "HTTP"
                                info_desc = f"HTTP Traffic [{src_port} -> {dst_port}] {flags_str}"
                            else:
                                app_name = "TCP"
                                info_desc = f"TCP Flow [{src_port} -> {dst_port}] {flags_str}"

                    elif proto_num == 17:  # UDP
                        protocol = "UDP"
                        if len(raw_data) >= transport_offset + 8:
                            src_port, dst_port = struct.unpack(">HH", raw_data[transport_offset:transport_offset+4])
                            payload = raw_data[transport_offset + 8:]
                            if dst_port == 53 or src_port == 53:
                                app_name = "DNS"
                                dns_q = extract_dns_query(payload)
                                if dns_q:
                                    sni_found = dns_q
                                    info_desc = f"Standard DNS Query: {dns_q}"
                                else:
                                    info_desc = "DNS Protocol Message"
                            elif dst_port == 443 or src_port == 443:
                                app_name = "QUIC"
                                info_desc = "QUIC / UDP Payload"
                            else:
                                app_name = "UDP"
                                info_desc = f"UDP Datagram [{src_port} -> {dst_port}]"

                    elif proto_num == 1:
                        protocol = "ICMP"
                        app_name = "ICMP"
                        info_desc = "ICMP Control Message"
                elif ethertype == 0x86DD:
                    protocol = "IPv6"
                    app_name = "IPv6"
                    info_desc = "IPv6 Frame"

                # Apply Filters
                if protocol_filter and protocol.lower() != protocol_filter.lower():
                    continue

                if search_query:
                    q = search_query.lower()
                    matched = (
                        q in src_ip or
                        q in dst_ip or
                        (sni_found and q in sni_found.lower()) or
                        q in app_name.lower() or
                        q in info_desc.lower()
                    )
                    if not matched:
                        continue

                # Determine dropped status
                blocked = is_packet_blocked(src_ip, dst_ip, app_name, sni_found, rules)
                status = "dropped" if blocked else "forwarded"

                total_matched += 1

                # Apply Pagination
                if total_matched > offset and len(packets) < limit:
                    timestamp_flt = ts_sec + (ts_usec / 1_000_000.0)
                    packets.append(PacketSummary(
                        id=pkt_id,
                        timestamp=timestamp_flt,
                        timestamp_str=f"{ts_sec}.{ts_usec:06d}",
                        length=orig_len,
                        src_mac=src_mac,
                        dst_mac=dst_mac,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        app=app_name,
                        sni=sni_found,
                        flags=flags_str,
                        status=status,
                        info=info_desc or f"{protocol} Packet",
                    ))

        return packets, total_matched

    @staticmethod
    def get_packet_detail(pcap_path: Path, packet_id: int, rules: Optional[List[FilterRule]] = None) -> Optional[PacketDetail]:
        """
        Retrieves detailed layer dissection and synchronized hex dump for a specific packet ID.
        """
        if not pcap_path.exists():
            return None

        with open(pcap_path, "rb") as f:
            ghdr = f.read(24)
            if len(ghdr) < 24:
                return None

            magic = struct.unpack("<I", ghdr[:4])[0]
            endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"

            current_id = 0
            while True:
                phdr = f.read(16)
                if len(phdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", phdr)
                if incl_len > 1_048_576:
                    break
                raw_data = f.read(incl_len)
                if len(raw_data) < incl_len:
                    break

                current_id += 1
                if current_id == packet_id:
                    # Found target packet!
                    dst_mac = format_mac(raw_data[0:6])
                    src_mac = format_mac(raw_data[6:12])
                    ethertype = struct.unpack(">H", raw_data[12:14])[0]

                    layers: Dict[str, Any] = {
                        "frame": {
                            "packet_id": packet_id,
                            "captured_len": incl_len,
                            "original_len": orig_len,
                            "timestamp_sec": ts_sec,
                            "timestamp_usec": ts_usec,
                        },
                        "ethernet": {
                            "destination_mac": dst_mac,
                            "source_mac": src_mac,
                            "type_hex": f"0x{ethertype:04x}",
                            "type_name": "IPv4" if ethertype == 0x0800 else ("IPv6" if ethertype == 0x86dd else "Unknown"),
                        }
                    }

                    src_ip = "0.0.0.0"
                    dst_ip = "0.0.0.0"
                    src_port = None
                    dst_port = None
                    protocol = "Ethernet"
                    flags_str = ""
                    app_name = "Unknown"
                    sni = None
                    info = "Packet"

                    if ethertype == 0x0800 and len(raw_data) >= 34:
                        ihl = (raw_data[14] & 0x0F) * 4
                        proto_num = raw_data[23]
                        src_ip = format_ip(raw_data[26:30])
                        dst_ip = format_ip(raw_data[30:34])

                        layers["ipv4"] = {
                            "version": 4,
                            "header_length": ihl,
                            "total_length": struct.unpack(">H", raw_data[16:18])[0],
                            "ttl": raw_data[22],
                            "protocol_num": proto_num,
                            "protocol_name": "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "Other"),
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                        }

                        transport_offset = 14 + ihl
                        if proto_num == 6 and len(raw_data) >= transport_offset + 20:
                            protocol = "TCP"
                            src_port, dst_port = struct.unpack(">HH", raw_data[transport_offset:transport_offset+4])
                            seq, ack = struct.unpack(">II", raw_data[transport_offset+4:transport_offset+12])
                            tcp_offset = ((raw_data[transport_offset + 12] >> 4) & 0x0F) * 4
                            flags_byte = raw_data[transport_offset + 13]
                            window = struct.unpack(">H", raw_data[transport_offset+14:transport_offset+16])[0]

                            layers["tcp"] = {
                                "source_port": src_port,
                                "destination_port": dst_port,
                                "sequence_number": seq,
                                "acknowledgment_number": ack,
                                "header_length": tcp_offset,
                                "flags_byte": f"0x{flags_byte:02x}",
                                "window_size": window,
                            }

                            payload = raw_data[transport_offset + tcp_offset:]
                            sni = extract_sni_from_payload(payload)
                            http_host = extract_http_host(payload)
                            if sni:
                                app_name = "TLS"
                                layers["tls"] = {
                                    "handshake_type": "Client Hello",
                                    "server_name_indication": sni,
                                }
                                info = f"TLS SNI: {sni}"
                            elif http_host:
                                app_name = "HTTP"
                                layers["http"] = {"host": http_host}
                                info = f"HTTP Host: {http_host}"

                        elif proto_num == 17 and len(raw_data) >= transport_offset + 8:
                            protocol = "UDP"
                            src_port, dst_port = struct.unpack(">HH", raw_data[transport_offset:transport_offset+4])
                            udp_len = struct.unpack(">H", raw_data[transport_offset+4:transport_offset+6])[0]
                            layers["udp"] = {
                                "source_port": src_port,
                                "destination_port": dst_port,
                                "length": udp_len,
                            }
                            payload = raw_data[transport_offset + 8:]
                            if dst_port == 53 or src_port == 53:
                                app_name = "DNS"
                                dns_q = extract_dns_query(payload)
                                if dns_q:
                                    sni = dns_q
                                    layers["dns"] = {"query": dns_q}
                                    info = f"DNS Query: {dns_q}"

                    blocked = is_packet_blocked(src_ip, dst_ip, app_name, sni, rules)
                    summary = PacketSummary(
                        id=packet_id,
                        timestamp=ts_sec + (ts_usec / 1_000_000.0),
                        timestamp_str=f"{ts_sec}.{ts_usec:06d}",
                        length=orig_len,
                        src_mac=src_mac,
                        dst_mac=dst_mac,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        app=app_name,
                        sni=sni,
                        status="dropped" if blocked else "forwarded",
                        info=info,
                    )

                    hex_dump = generate_hex_dump(raw_data)
                    return PacketDetail(
                        summary=summary,
                        layers=layers,
                        hex_dump=hex_dump,
                        raw_len=len(raw_data),
                    )
        return None
