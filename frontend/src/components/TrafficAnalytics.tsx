'use client';

import React from 'react';
import { Globe, Radio, AlertOctagon, ShieldX, ExternalLink, CheckCircle } from 'lucide-react';
import { AnalysisResponse, FilterRule } from '@/types';

interface TrafficAnalyticsProps {
  analysis: AnalysisResponse | null;
  onQuickBlockDomain: (domain: string) => void;
  onQuickBlockApp: (app: string) => void;
}

export const TrafficAnalytics: React.FC<TrafficAnalyticsProps> = ({
  analysis,
  onQuickBlockDomain,
  onQuickBlockApp,
}) => {
  if (!analysis) return null;

  const { applications, detected_snis, threat_indicators, threat_score } = analysis;

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'medium':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'low':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  const isDomainBlocked = (domain: string) => {
    return analysis.active_rules.some(
      r => r.enabled && r.type === 'domain' && domain.toLowerCase().includes(r.value.toLowerCase())
    );
  };

  const isAppBlocked = (app: string) => {
    return analysis.active_rules.some(
      r => r.enabled && r.type === 'app' && app.toLowerCase() === r.value.toLowerCase()
    );
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
      
      {/* 1. Application Breakdown */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 shadow-sm backdrop-blur-md">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center space-x-2">
            <Radio className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Application Signatures</h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">{applications.length} detected</span>
        </div>

        <div className="mt-4 space-y-3 max-h-80 overflow-y-auto pr-1">
          {applications.map((app) => {
            const blocked = isAppBlocked(app.name);
            return (
              <div key={app.name} className="group rounded-lg border border-slate-800/60 bg-slate-950/40 p-2.5 transition-colors hover:border-slate-700">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-2">
                    <span className="font-medium text-slate-200">{app.name}</span>
                    {blocked && (
                      <span className="rounded bg-rose-950 border border-rose-800 px-1 py-0.2 text-[9px] font-bold text-rose-300">
                        BLOCKED
                      </span>
                    )}
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-slate-400 font-mono">{app.count} pkts</span>
                    <span className="text-cyan-400 font-mono font-medium">{app.percentage}%</span>
                    {!blocked && !['HTTPS', 'TCP', 'UDP', 'DNS'].includes(app.name) && (
                      <button
                        onClick={() => onQuickBlockApp(app.name)}
                        className="opacity-0 group-hover:opacity-100 rounded px-1.5 py-0.5 text-[10px] font-medium bg-rose-950 border border-rose-700 text-rose-300 hover:bg-rose-900 transition-opacity"
                        title={`Block all ${app.name} traffic`}
                      >
                        Block
                      </button>
                    )}
                  </div>
                </div>
                {/* Progress bar */}
                <div className="mt-2 h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                  <div
                    style={{ width: `${Math.min(100, app.percentage)}%` }}
                    className={`h-full rounded-full ${
                      blocked ? 'bg-rose-500' : 'bg-gradient-to-r from-cyan-500 to-blue-500'
                    }`}
                  ></div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. Detected Domains / SNIs */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 shadow-sm backdrop-blur-md">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center space-x-2">
            <Globe className="h-4 w-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">TLS SNI Domains</h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">{detected_snis.length} extracted</span>
        </div>

        <div className="mt-4 space-y-2 max-h-80 overflow-y-auto pr-1">
          {detected_snis.length === 0 ? (
            <p className="text-xs text-slate-500 text-center py-8">No TLS SNI handshakes detected in capture.</p>
          ) : (
            detected_snis.map((item, idx) => {
              const blocked = isDomainBlocked(item.sni);
              return (
                <div
                  key={`${item.sni}-${idx}`}
                  className="group flex items-center justify-between rounded-lg border border-slate-800/60 bg-slate-950/40 p-2 text-xs transition-colors hover:border-slate-700"
                >
                  <div className="flex flex-col truncate pr-2">
                    <span className="font-mono text-slate-200 truncate" title={item.sni}>
                      {item.sni}
                    </span>
                    <span className="text-[10px] text-slate-400">{item.app}</span>
                  </div>

                  <div className="flex items-center space-x-1.5 shrink-0">
                    {blocked ? (
                      <span className="rounded bg-rose-950/80 border border-rose-800 px-1.5 py-0.5 text-[10px] font-bold text-rose-300">
                        DROPPED
                      </span>
                    ) : (
                      <button
                        onClick={() => onQuickBlockDomain(item.sni)}
                        className="rounded border border-rose-500/30 bg-rose-950/20 px-2 py-1 text-[10px] font-medium text-rose-300 hover:bg-rose-900/50 hover:border-rose-500 transition-colors"
                        title="Add firewall blocking rule for this domain"
                      >
                        Block
                      </button>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* 3. Cybersecurity Threat Diagnostic Findings */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 shadow-sm backdrop-blur-md">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center space-x-2">
            <AlertOctagon className="h-4 w-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-white">Threat Findings &amp; Radar</h3>
          </div>
          <span className="rounded bg-amber-500/10 border border-amber-500/30 px-1.5 py-0.5 text-[10px] font-bold text-amber-400">
            Score: {threat_score}/100
          </span>
        </div>

        <div className="mt-4 space-y-3 max-h-80 overflow-y-auto pr-1">
          {threat_indicators.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-center">
              <CheckCircle className="h-8 w-8 text-emerald-400 mb-2" />
              <p className="text-xs text-slate-300 font-medium">Zero Protocol Anomalies</p>
              <p className="text-[11px] text-slate-500 mt-1">Traffic matches normal compliance parameters.</p>
            </div>
          ) : (
            threat_indicators.map((indicator, idx) => (
              <div
                key={idx}
                className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3 text-xs space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">{indicator.title}</span>
                  <span className={`rounded border px-1.5 py-0.2 text-[9px] font-bold uppercase ${getSeverityBadge(indicator.severity)}`}>
                    {indicator.severity}
                  </span>
                </div>
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  {indicator.description}
                </p>
                {indicator.suggested_action && (
                  <div className="rounded bg-slate-900/80 border border-slate-800 p-1.5 text-[10px] text-cyan-300">
                    <span className="font-semibold text-slate-400">Action: </span>
                    {indicator.suggested_action}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

    </div>
  );
};
