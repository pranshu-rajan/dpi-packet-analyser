'use client';

import React, { useState, useEffect } from 'react';
import { Search, Filter, Terminal, ShieldAlert, CheckCircle2, ChevronRight, Copy, Check } from 'lucide-react';
import { PacketSummary, PacketDetail } from '@/types';
import { getPackets, getPacketDetail } from '@/lib/api';

interface PacketDissectorProps {
  analysisId?: string;
}

export const PacketDissector: React.FC<PacketDissectorProps> = ({ analysisId }) => {
  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<PacketDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Filters
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedHex, setCopiedHex] = useState(false);

  // Fetch packet list
  const fetchPacketList = async () => {
    setLoading(true);
    try {
      const data = await getPackets({
        analysisId,
        limit: 200,
        protocol: protocolFilter !== 'ALL' ? protocolFilter : undefined,
        search: searchQuery.trim() || undefined,
      });
      setPackets(data.packets);
      setTotal(data.total);

      // Auto-select first packet if none selected or selected not in list
      if (data.packets.length > 0 && (!selectedId || !data.packets.some(p => p.id === selectedId))) {
        handleSelectPacket(data.packets[0].id);
      }
    } catch (err) {
      console.error('Failed to load packets:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPacketList();
  }, [analysisId, protocolFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchPacketList();
  };

  const handleSelectPacket = async (pktId: number) => {
    setSelectedId(pktId);
    setDetailLoading(true);
    try {
      const data = await getPacketDetail(pktId, analysisId);
      setDetail(data);
    } catch (err) {
      console.error('Failed to load packet detail:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  const copyHexDump = () => {
    if (!detail) return;
    const text = detail.hex_dump.map(l => `${l.offset}  ${l.hex}  ${l.ascii}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 2000);
  };

  // Filter by status on client-side
  const filteredPackets = packets.filter(p => {
    if (statusFilter === 'ALL') return true;
    return p.status.toLowerCase() === statusFilter.toLowerCase();
  });

  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 shadow-sm backdrop-blur-md overflow-hidden">
      
      {/* 1. Header & Filter Bar */}
      <div className="border-b border-slate-800/80 p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold text-white flex items-center space-x-2">
              <Terminal className="h-4 w-4 text-cyan-400" />
              <span>Deep Packet Dissector &amp; Inspector</span>
            </h3>
            <p className="text-xs text-slate-400">
              Wireshark-grade protocol decomposition, 5-tuple tracking, and synchronized byte inspection.
            </p>
          </div>

          {/* Search Bar */}
          <form onSubmit={handleSearchSubmit} className="flex items-center space-x-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="Filter IP, SNI, or app..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-56 rounded-lg border border-slate-800 bg-slate-950/80 py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <button
              type="submit"
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700"
            >
              Filter
            </button>
          </form>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-800/50">
          <div className="flex items-center space-x-1 overflow-x-auto text-xs">
            <span className="text-slate-500 text-[11px] mr-1">Protocol:</span>
            {['ALL', 'TCP', 'UDP', 'DNS', 'HTTPS', 'HTTP'].map((proto) => (
              <button
                key={proto}
                onClick={() => setProtocolFilter(proto)}
                className={`rounded-md px-2 py-0.5 text-xs font-mono transition-colors ${
                  protocolFilter === proto
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                }`}
              >
                {proto}
              </button>
            ))}
          </div>

          <div className="flex items-center space-x-1 text-xs">
            <span className="text-slate-500 text-[11px] mr-1">Status:</span>
            {['ALL', 'FORWARDED', 'DROPPED'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors ${
                  statusFilter === st
                    ? st === 'DROPPED'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
            <span className="text-xs text-slate-500 font-mono ml-2">
              Showing {filteredPackets.length} of {total}
            </span>
          </div>
        </div>
      </div>

      {/* 2. Packet Table */}
      <div className="h-64 overflow-y-auto border-b border-slate-800/80 bg-slate-950/40">
        <table className="w-full text-left text-xs font-mono">
          <thead className="sticky top-0 bg-slate-900 text-slate-400 border-b border-slate-800 z-10 text-[11px]">
            <tr>
              <th className="py-2 px-3 w-14">#</th>
              <th className="py-2 px-3 w-24">Time (s)</th>
              <th className="py-2 px-3">Source</th>
              <th className="py-2 px-3">Destination</th>
              <th className="py-2 px-3 w-16">Proto</th>
              <th className="py-2 px-3 w-28">Application</th>
              <th className="py-2 px-3 w-36">Domain / SNI</th>
              <th className="py-2 px-3 w-20">Status</th>
              <th className="py-2 px-3">Protocol Info</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-850">
            {filteredPackets.map((p) => {
              const isSelected = selectedId === p.id;
              return (
                <tr
                  key={p.id}
                  onClick={() => handleSelectPacket(p.id)}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-cyan-950/40 border-l-2 border-cyan-400 text-cyan-100'
                      : 'hover:bg-slate-900/60 text-slate-300'
                  }`}
                >
                  <td className="py-1.5 px-3 font-semibold text-slate-400">{p.id}</td>
                  <td className="py-1.5 px-3 text-slate-400">{p.timestamp_str}</td>
                  <td className="py-1.5 px-3 truncate" title={`${p.src_ip}:${p.src_port || ''}`}>
                    {p.src_ip}{p.src_port ? `:${p.src_port}` : ''}
                  </td>
                  <td className="py-1.5 px-3 truncate" title={`${p.dst_ip}:${p.dst_port || ''}`}>
                    {p.dst_ip}{p.dst_port ? `:${p.dst_port}` : ''}
                  </td>
                  <td className="py-1.5 px-3">
                    <span className="rounded bg-slate-800 px-1 py-0.2 text-[10px] text-slate-300">
                      {p.protocol}
                    </span>
                  </td>
                  <td className="py-1.5 px-3 font-medium truncate text-cyan-300">
                    {p.app}
                  </td>
                  <td className="py-1.5 px-3 truncate text-slate-300" title={p.sni || '-'}>
                    {p.sni || '-'}
                  </td>
                  <td className="py-1.5 px-3">
                    {p.status === 'dropped' ? (
                      <span className="rounded bg-rose-950/80 border border-rose-800 px-1.5 py-0.2 text-[10px] font-bold text-rose-300">
                        DROP
                      </span>
                    ) : (
                      <span className="rounded bg-emerald-950/60 border border-emerald-800/80 px-1.5 py-0.2 text-[10px] font-bold text-emerald-300">
                        FWD
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 px-3 text-slate-400 truncate" title={p.info}>
                    {p.info}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* 3. Bottom Dual-Pane Inspector (Dissected Layers + Synchronized Hex Dump) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-800/80 bg-slate-950/80">
        
        {/* Left Pane: Protocol Layers Dissection */}
        <div className="p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <h4 className="text-xs font-semibold text-white uppercase tracking-wider font-mono flex items-center space-x-1.5">
              <ChevronRight className="h-3.5 w-3.5 text-cyan-400" />
              <span>Layer Dissection (Packet #{selectedId || '-'})</span>
            </h4>
            {detail && (
              <span className="text-[11px] font-mono text-slate-400">
                Size: {detail.raw_len} bytes
              </span>
            )}
          </div>

          {detailLoading ? (
            <div className="py-12 text-center text-xs text-slate-500">Dissecting packet headers...</div>
          ) : detail ? (
            <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1 text-xs">
              
              {/* Frame Info */}
              <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-2.5 font-mono">
                <div className="font-semibold text-slate-300 mb-1 flex items-center space-x-1 text-cyan-400">
                  <span>Frame #{detail.summary.id}</span>
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-slate-400">
                  <div>Length: <span className="text-slate-200">{detail.layers.frame?.captured_len} bytes</span></div>
                  <div>Epoch: <span className="text-slate-200">{detail.layers.frame?.timestamp_sec}s</span></div>
                </div>
              </div>

              {/* Ethernet Layer */}
              {detail.layers.ethernet && (
                <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-2.5 font-mono">
                  <div className="font-semibold text-slate-300 mb-1 text-cyan-400">
                    Ethernet II
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-slate-400">
                    <div>Src MAC: <span className="text-slate-200">{detail.layers.ethernet.source_mac}</span></div>
                    <div>Dst MAC: <span className="text-slate-200">{detail.layers.ethernet.destination_mac}</span></div>
                    <div>Type: <span className="text-slate-200">{detail.layers.ethernet.type_name} ({detail.layers.ethernet.type_hex})</span></div>
                  </div>
                </div>
              )}

              {/* IPv4 Layer */}
              {detail.layers.ipv4 && (
                <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-2.5 font-mono">
                  <div className="font-semibold text-slate-300 mb-1 text-cyan-400">
                    Internet Protocol Version 4 (IPv4)
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-slate-400">
                    <div>Src IP: <span className="text-slate-200">{detail.layers.ipv4.source_ip}</span></div>
                    <div>Dst IP: <span className="text-slate-200">{detail.layers.ipv4.destination_ip}</span></div>
                    <div>TTL: <span className="text-slate-200">{detail.layers.ipv4.ttl}</span></div>
                    <div>Protocol: <span className="text-slate-200">{detail.layers.ipv4.protocol_name} ({detail.layers.ipv4.protocol_num})</span></div>
                  </div>
                </div>
              )}

              {/* TCP / UDP Layer */}
              {detail.layers.tcp && (
                <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-2.5 font-mono">
                  <div className="font-semibold text-slate-300 mb-1 text-cyan-400">
                    Transmission Control Protocol (TCP)
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-slate-400">
                    <div>Src Port: <span className="text-slate-200">{detail.layers.tcp.source_port}</span></div>
                    <div>Dst Port: <span className="text-slate-200">{detail.layers.tcp.destination_port}</span></div>
                    <div>Seq: <span className="text-slate-200">{detail.layers.tcp.sequence_number}</span></div>
                    <div>Ack: <span className="text-slate-200">{detail.layers.tcp.acknowledgment_number}</span></div>
                    <div>Flags: <span className="text-amber-300">{detail.summary.flags || detail.layers.tcp.flags_byte}</span></div>
                    <div>Window: <span className="text-slate-200">{detail.layers.tcp.window_size}</span></div>
                  </div>
                </div>
              )}

              {detail.layers.udp && (
                <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-2.5 font-mono">
                  <div className="font-semibold text-slate-300 mb-1 text-cyan-400">
                    User Datagram Protocol (UDP)
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-slate-400">
                    <div>Src Port: <span className="text-slate-200">{detail.layers.udp.source_port}</span></div>
                    <div>Dst Port: <span className="text-slate-200">{detail.layers.udp.destination_port}</span></div>
                    <div>Length: <span className="text-slate-200">{detail.layers.udp.length} bytes</span></div>
                  </div>
                </div>
              )}

              {/* Application / TLS SNI / HTTP */}
              {(detail.layers.tls || detail.layers.http || detail.layers.dns) && (
                <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-2.5 font-mono">
                  <div className="font-semibold text-cyan-300 mb-1">
                    Application Payload Inspection (DPI)
                  </div>
                  {detail.layers.tls && (
                    <div className="text-[11px] text-slate-300 space-y-1">
                      <div>Handshake: <span className="text-emerald-300">{detail.layers.tls.handshake_type}</span></div>
                      <div>Server Name Indication (SNI): <span className="text-cyan-300 font-bold">{detail.layers.tls.server_name_indication}</span></div>
                    </div>
                  )}
                  {detail.layers.http && (
                    <div className="text-[11px] text-slate-300 space-y-1">
                      <div>Host Header: <span className="text-amber-300 font-bold">{detail.layers.http.host}</span></div>
                    </div>
                  )}
                  {detail.layers.dns && (
                    <div className="text-[11px] text-slate-300 space-y-1">
                      <div>DNS Query Domain: <span className="text-cyan-300 font-bold">{detail.layers.dns.query}</span></div>
                    </div>
                  )}
                </div>
              )}

            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-500">Select a packet from the table above to dissect layers.</div>
          )}
        </div>

        {/* Right Pane: Synchronized Wireshark Hex Dump */}
        <div className="p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <h4 className="text-xs font-semibold text-white uppercase tracking-wider font-mono flex items-center space-x-1.5">
              <span>Raw Hex Dump &amp; ASCII</span>
            </h4>
            <button
              onClick={copyHexDump}
              disabled={!detail}
              className="flex items-center space-x-1 rounded border border-slate-800 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-300 hover:bg-slate-800 disabled:opacity-50"
            >
              {copiedHex ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              <span>{copiedHex ? 'Copied' : 'Copy Hex'}</span>
            </button>
          </div>

          {detailLoading ? (
            <div className="py-12 text-center text-xs text-slate-500">Rendering hex dump...</div>
          ) : detail ? (
            <div className="rounded-lg border border-slate-800/60 bg-slate-950 p-3 font-mono text-xs overflow-x-auto max-h-72">
              <div className="space-y-1 select-all text-slate-300">
                {detail.hex_dump.map((line, idx) => (
                  <div key={idx} className="flex space-x-4 leading-none">
                    <span className="text-slate-600 select-none w-10 shrink-0">{line.offset}</span>
                    <span className="text-cyan-400/90 whitespace-pre shrink-0">{line.hex}</span>
                    <span className="text-slate-400 whitespace-pre pl-2 border-l border-slate-800">{line.ascii}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-500">Select a packet to view hex byte stream.</div>
          )}
        </div>

      </div>

    </div>
  );
};
