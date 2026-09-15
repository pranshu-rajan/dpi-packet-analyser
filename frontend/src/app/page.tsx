'use client';

import React, { useState, useEffect } from 'react';
import { AnalysisResponse, FilterRule } from '@/types';
import {
  analyzeSample,
  uploadAndAnalyze,
  refilterCapture,
  getDatabaseRules,
  bulkSyncDatabaseRules,
  getCaptureSession,
} from '@/lib/api';
import { Navbar } from '@/components/Navbar';
import { MetricCards } from '@/components/MetricCards';
import { TrafficAnalytics } from '@/components/TrafficAnalytics';
import { PacketDissector } from '@/components/PacketDissector';
import { RuleManagerModal } from '@/components/RuleManagerModal';
import { AICopilotDrawer } from '@/components/AICopilotDrawer';
import { CaptureHistoryModal } from '@/components/CaptureHistoryModal';
import { Sparkles, AlertCircle, Clock3, FileArchive, ShieldCheck } from 'lucide-react';

export default function Dashboard() {
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [rules, setRules] = useState<FilterRule[]>([]);
  const [ruleModalOpen, setRuleModalOpen] = useState<boolean>(false);
  const [historyModalOpen, setHistoryModalOpen] = useState<boolean>(false);
  const [copilotOpen, setCopilotOpen] = useState<boolean>(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const getErrorMessage = (error: unknown, fallback: string) =>
    error instanceof Error ? error.message : fallback;

  const showNotification = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 4000);
  };

  const loadSample = async () => {
    setLoading(true);
    setError(null);
    try {
      // Load persistent rules from database first
      let currentRules = rules;
      try {
        const dbRules = await getDatabaseRules();
        if (dbRules && dbRules.length > 0) {
          currentRules = dbRules;
          setRules(dbRules);
        }
      } catch (dbErr) {
        console.warn('Could not fetch DB rules, falling back to local state:', dbErr);
      }

      const data = await analyzeSample(currentRules);
      setAnalysis(data);
      if (data.active_rules && data.active_rules.length > 0) {
        setRules(data.active_rules);
      }
    } catch (err: unknown) {
      console.error(err);
      setError(getErrorMessage(err, 'Failed to analyze sample capture. Ensure FastAPI backend is running on port 8000.'));
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await uploadAndAnalyze(file, rules);
      setAnalysis(data);
      setRules(data.active_rules || rules);
      showNotification(`Uploaded, analyzed, and stored ${file.name} in PostgreSQL!`);
    } catch (err: unknown) {
      console.error(err);
      setError(getErrorMessage(err, 'Failed to upload and analyze PCAP.'));
    } finally {
      setLoading(false);
    }
  };

  const handleSaveAndApplyRules = async (updatedRules: FilterRule[]) => {
    if (!analysis) return;
    setLoading(true);
    try {
      // 1. Persist rules to PostgreSQL
      try {
        await bulkSyncDatabaseRules(updatedRules);
      } catch (dbErr) {
        console.warn('Database rule sync warning:', dbErr);
      }

      // 2. Re-filter the capture with the C++ engine
      const data = await refilterCapture(analysis.analysis_id, updatedRules);
      setAnalysis(data);
      setRules(data.active_rules || updatedRules);
      setRuleModalOpen(false);
      const droppedDelta = data.summary.dropped;
      showNotification(`Firewall rules persisted to database & applied! Dropped ${droppedDelta} packet(s).`);
    } catch (err: unknown) {
      console.error(err);
      setError(getErrorMessage(err, 'Failed to apply rules and refilter.'));
    } finally {
      setLoading(false);
    }
  };

  const handleSelectHistoricalCapture = async (analysisId: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await getCaptureSession(analysisId);
      setAnalysis(data);
      showNotification(`Loaded capture session ${analysisId.substring(0, 8)} from database.`);
    } catch (err) {
      console.error(err);
      setError('Failed to load selected capture from database.');
    } finally {
      setLoading(false);
    }
  };

  // Initial load: run sample capture
  useEffect(() => {
    const timer = window.setTimeout(() => void loadSample(), 0);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleQuickBlockDomain = (domain: string) => {
    const newRule: FilterRule = {
      id: `rule-quick-${Date.now()}`,
      type: 'domain',
      value: domain,
      enabled: true,
      description: `Quick block for domain ${domain}`,
    };
    const updated = [...rules, newRule];
    handleSaveAndApplyRules(updated);
  };

  const handleQuickBlockApp = (app: string) => {
    const newRule: FilterRule = {
      id: `rule-quick-${Date.now()}`,
      type: 'app',
      value: app,
      enabled: true,
      description: `Quick block for app ${app}`,
    };
    const updated = [...rules, newRule];
    handleSaveAndApplyRules(updated);
  };

  const handleApplySuggestedRule = (rule: FilterRule) => {
    const updated = [...rules, rule];
    handleSaveAndApplyRules(updated);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      
      {/* Top Navigation */}
      <Navbar
        analysis={analysis}
        loading={loading}
        rules={rules}
        onLoadSample={loadSample}
        onFileUpload={handleFileUpload}
        onOpenRules={() => setRuleModalOpen(true)}
        onOpenHistory={() => setHistoryModalOpen(true)}
        onToggleCopilot={() => setCopilotOpen(!copilotOpen)}
        copilotOpen={copilotOpen}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* Notification Toast */}
        {actionNotice && (
          <div className="rounded-xl border border-cyan-500/40 bg-cyan-950/80 px-4 py-3 text-xs text-cyan-200 shadow-[0_0_20px_rgba(6,182,212,0.2)] flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Sparkles className="h-4 w-4 text-cyan-400 shrink-0" />
              <span>{actionNotice}</span>
            </div>
            <button onClick={() => setActionNotice(null)} className="text-cyan-400 hover:text-white text-xs">
              Dismiss
            </button>
          </div>
        )}

        {/* Global Error Alert */}
        {error && (
          <div className="rounded-xl border border-rose-800/80 bg-rose-950/60 p-4 text-xs text-rose-200 flex items-start space-x-3">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-semibold">Operation Error:</span>
              <p>{error}</p>
            </div>
          </div>
        )}

        {/* Capture Metadata Header Card */}
        {analysis && (
          <div className="rounded-2xl border border-slate-800/80 bg-slate-900/40 p-4 sm:p-5 backdrop-blur-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center space-x-3.5">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <FileArchive className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h1 className="text-base font-bold text-white tracking-tight">{analysis.filename}</h1>
                  <span className="rounded-full bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
                    Live Session
                  </span>
                </div>
                <div className="flex items-center space-x-3 text-xs text-slate-400 mt-0.5 font-mono">
                  <span>ID: {analysis.analysis_id}</span>
                  <span>•</span>
                  <span>{(analysis.file_size_bytes / 1024).toFixed(1)} KB</span>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-4 self-stretch sm:self-auto justify-between sm:justify-end border-t border-slate-800/80 sm:border-0 pt-3 sm:pt-0">
              <div className="text-right">
                <div className="flex items-center space-x-1.5 text-xs text-slate-400">
                  <Clock3 className="h-3.5 w-3.5 text-slate-400" />
                  <span>{analysis.timestamp}</span>
                </div>
                <span className="text-[11px] text-slate-500">Inspection Finished</span>
              </div>
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400" title="DPI Core Active">
                <ShieldCheck className="h-4 w-4" />
              </div>
            </div>
          </div>
        )}

        {/* 1. Key Telemetry Metrics */}
        <MetricCards analysis={analysis} />

        {/* 2. Applications, SNI Domains, and Threat Radar */}
        <TrafficAnalytics
          analysis={analysis}
          onQuickBlockDomain={handleQuickBlockDomain}
          onQuickBlockApp={handleQuickBlockApp}
        />

        {/* 3. Wireshark-Style Packet Dissector & Hex Dump */}
        <PacketDissector analysisId={analysis?.analysis_id} />

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-950/80 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>DPI Engine Platform v2.0 • Multi-Threaded Packet Dissection &amp; Containment</span>
          <span className="text-slate-400 font-mono">C++ Core • FastAPI • Next.js • PostgreSQL / Supabase • NetCopilot AI</span>
        </div>
      </footer>

      {/* Firewall Rules Modal */}
      <RuleManagerModal
        isOpen={ruleModalOpen}
        onClose={() => setRuleModalOpen(false)}
        rules={rules}
        onSaveAndApply={handleSaveAndApplyRules}
        loading={loading}
      />

      {/* Capture Telemetry & History Modal */}
      <CaptureHistoryModal
        isOpen={historyModalOpen}
        onClose={() => setHistoryModalOpen(false)}
        onSelectCapture={handleSelectHistoricalCapture}
        activeAnalysisId={analysis?.analysis_id}
      />

      {/* AI Copilot Drawer */}
      <AICopilotDrawer
        isOpen={copilotOpen}
        onClose={() => setCopilotOpen(false)}
        analysis={analysis}
        onApplySuggestedRule={handleApplySuggestedRule}
      />

    </div>
  );
}
