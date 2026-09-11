'use client';

import React from 'react';
import { Layers, HardDrive, ShieldCheck, ShieldAlert, Cpu, AlertTriangle } from 'lucide-react';
import { AnalysisResponse } from '@/types';

interface MetricCardsProps {
  analysis: AnalysisResponse | null;
}

export const MetricCards: React.FC<MetricCardsProps> = ({ analysis }) => {
  if (!analysis) return null;

  const { summary, thread_stats, threat_score, threat_indicators, filename } = analysis;

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const getThreatColor = (score: number) => {
    if (score >= 70) return { text: 'text-red-400', bg: 'bg-red-950/30', border: 'border-red-500/30', label: 'CRITICAL' };
    if (score >= 35) return { text: 'text-amber-400', bg: 'bg-amber-950/30', border: 'border-amber-500/30', label: 'ELEVATED' };
    return { text: 'text-emerald-400', bg: 'bg-emerald-950/30', border: 'border-emerald-500/30', label: 'SECURE' };
  };

  const threatColor = getThreatColor(threat_score);
  const dropPct = summary.total_packets > 0 ? (summary.dropped / summary.total_packets) * 100 : 0;
  const fwdPct = 100 - dropPct;

  const totalDispatched = thread_stats.lbs.reduce((acc, lb) => acc + (lb.dispatched || 0), 0);
  const totalProcessed = thread_stats.fps.reduce((acc, fp) => acc + (fp.processed || 0), 0);

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
      
      {/* Total Packets */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-sm backdrop-blur-md">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Total Packets</span>
          <div className="rounded-lg bg-cyan-500/10 p-1.5 text-cyan-400">
            <Layers className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline space-x-2">
          <span className="text-2xl font-bold font-mono tracking-tight text-white">
            {summary.total_packets.toLocaleString()}
          </span>
          <span className="text-xs text-slate-500">pkts</span>
        </div>
        <div className="mt-2 flex items-center space-x-2 text-xs text-slate-400">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-cyan-400"></span>
          <span>TCP: {summary.tcp_packets}</span>
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-blue-400 ml-1"></span>
          <span>UDP: {summary.udp_packets}</span>
        </div>
      </div>

      {/* Total Data Volume */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-sm backdrop-blur-md">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Traffic Volume</span>
          <div className="rounded-lg bg-blue-500/10 p-1.5 text-blue-400">
            <HardDrive className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline space-x-2">
          <span className="text-2xl font-bold font-mono tracking-tight text-white">
            {formatBytes(summary.total_bytes)}
          </span>
        </div>
        <div className="mt-2 text-xs text-slate-400 truncate" title={filename}>
          Capture: <span className="text-slate-300 font-mono">{filename}</span>
        </div>
      </div>

      {/* Forwarded vs Dropped */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-sm backdrop-blur-md">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Inspection Filtering</span>
          <div className="rounded-lg bg-emerald-500/10 p-1.5 text-emerald-400">
            <ShieldCheck className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline justify-between">
          <div>
            <span className="text-2xl font-bold font-mono tracking-tight text-emerald-400">
              {summary.forwarded.toLocaleString()}
            </span>
            <span className="text-xs text-slate-500 ml-1">fwd</span>
          </div>
          {summary.dropped > 0 && (
            <div className="text-right">
              <span className="text-lg font-bold font-mono tracking-tight text-rose-400">
                {summary.dropped.toLocaleString()}
              </span>
              <span className="text-xs text-slate-500 ml-1">drop</span>
            </div>
          )}
        </div>
        {/* Ratio bar */}
        <div className="mt-2 h-1.5 w-full rounded-full bg-slate-800 overflow-hidden flex">
          <div style={{ width: `${fwdPct}%` }} className="bg-emerald-500 h-full"></div>
          <div style={{ width: `${dropPct}%` }} className="bg-rose-500 h-full"></div>
        </div>
      </div>

      {/* Cyber Threat Index */}
      <div className={`rounded-xl border ${threatColor.border} ${threatColor.bg} p-4 shadow-sm backdrop-blur-md`}>
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Threat Risk Score</span>
          <div className="flex items-center space-x-1">
            <span className={`rounded px-1.5 py-0.2 text-[10px] font-bold border ${threatColor.border} ${threatColor.text}`}>
              {threatColor.label}
            </span>
          </div>
        </div>
        <div className="mt-2 flex items-baseline space-x-2">
          <span className={`text-2xl font-bold font-mono tracking-tight ${threatColor.text}`}>
            {threat_score}
          </span>
          <span className="text-xs text-slate-500">/ 100</span>
        </div>
        <div className="mt-2 flex items-center space-x-1 text-xs text-slate-400">
          <AlertTriangle className="h-3 w-3 text-amber-400" />
          <span>{threat_indicators.length} security diagnostic(s)</span>
        </div>
      </div>

      {/* Multi-thread Engine Stats */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-sm backdrop-blur-md">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Parallel Core Engine</span>
          <div className="rounded-lg bg-purple-500/10 p-1.5 text-purple-400">
            <Cpu className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline space-x-2">
          <span className="text-2xl font-bold font-mono tracking-tight text-white">
            {thread_stats.lbs.length} LB <span className="text-slate-600">/</span> {thread_stats.fps.length} FP
          </span>
        </div>
        <div className="mt-2 text-xs text-slate-400">
          LB Dispatched: <span className="font-mono text-slate-300">{totalDispatched}</span>
        </div>
      </div>

    </div>
  );
};
