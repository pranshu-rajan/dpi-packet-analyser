'use client';

import React, { useRef } from 'react';
import { Shield, Upload, Download, Sliders, Bot, RefreshCw, Database } from 'lucide-react';
import { AnalysisResponse, FilterRule } from '@/types';
import { ThemeToggle } from './ThemeToggle';

interface NavbarProps {
  analysis: AnalysisResponse | null;
  loading: boolean;
  rules: FilterRule[];
  onLoadSample: () => void;
  onFileUpload: (file: File) => void;
  onOpenRules: () => void;
  onOpenHistory: () => void;
  onToggleCopilot: () => void;
  copilotOpen: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  analysis,
  loading,
  rules,
  onLoadSample,
  onFileUpload,
  onOpenRules,
  onOpenHistory,
  onToggleCopilot,
  copilotOpen,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onFileUpload(e.target.files[0]);
    }
  };

  const activeRulesCount = rules.filter(r => r.enabled).length;

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        
        {/* Logo & Status */}
        <div className="flex items-center space-x-3">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/40 text-cyan-400">
            <Shield className="h-5 w-5" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-tight text-white">DPI Engine</span>
              <span className="rounded-md bg-cyan-950/80 border border-cyan-800 px-1.5 py-0.5 text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                v2.0 MT
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Deep Packet Inspection &amp; Streaming AI Copilot
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-2 sm:space-x-3">
          {/* Sample PCAP Button */}
          <button
            onClick={onLoadSample}
            disabled={loading}
            className="flex items-center space-x-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:border-slate-700 hover:bg-slate-800 disabled:opacity-50"
            title="Analyze built-in test_dpi.pcap capture"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-cyan-400 ${loading ? 'animate-spin' : ''}`} />
            <span className="hidden md:inline">Load Sample</span>
          </button>

          {/* Upload PCAP Button */}
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.cap"
            className="hidden"
            onChange={handleFileChange}
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={loading}
            className="flex items-center space-x-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 px-3 py-1.5 text-xs font-medium text-cyan-300 transition-colors hover:bg-cyan-900/50 hover:border-cyan-500/60 disabled:opacity-50"
          >
            <Upload className="h-3.5 w-3.5" />
            <span>Upload PCAP</span>
          </button>

          {/* Download Filtered PCAP */}
          {analysis?.output_pcap_name && (
            <a
              href={`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/analyze/download/${analysis.output_pcap_name}`}
              download={analysis.output_pcap_name}
              className="flex items-center space-x-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-300 transition-colors hover:bg-emerald-900/50 hover:border-emerald-500/70"
              title="Download sanitized PCAP with blocked packets stripped"
            >
              <Download className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Export Filtered PCAP</span>
            </a>
          )}

          {/* History / Database Button */}
          <button
            onClick={onOpenHistory}
            className="flex items-center space-x-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-1.5 text-xs font-medium text-purple-300 transition-colors hover:border-purple-800/80 hover:bg-purple-950/40"
            title="View historical network captures stored in PostgreSQL"
          >
            <Database className="h-3.5 w-3.5 text-purple-400" />
            <span className="hidden sm:inline">Telemetry History</span>
          </button>

          {/* Firewall Rules Drawer Button */}
          <button
            onClick={onOpenRules}
            className="relative flex items-center space-x-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:border-slate-700 hover:bg-slate-800"
          >
            <Sliders className="h-3.5 w-3.5 text-amber-400" />
            <span className="hidden sm:inline">Firewall Rules</span>
            {activeRulesCount > 0 && (
              <span className="ml-1 rounded-full bg-amber-500/20 border border-amber-500/40 px-1.5 py-0.2 text-[10px] font-bold text-amber-300">
                {activeRulesCount}
              </span>
            )}
          </button>

          {/* AI Copilot Toggle Button */}
          <button
            onClick={onToggleCopilot}
            className={`flex items-center space-x-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-all ${
              copilotOpen
                ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.3)]'
                : 'border-slate-800 bg-slate-900 text-slate-300 hover:border-slate-700 hover:bg-slate-800'
            }`}
          >
            <Bot className="h-3.5 w-3.5 text-cyan-400" />
            <span className="hidden sm:inline">AI Copilot</span>
          </button>

          <ThemeToggle />

        </div>
      </div>
    </header>
  );
};
