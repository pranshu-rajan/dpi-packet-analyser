'use client';

import React, { useState, useEffect } from 'react';
import { AnalysisResponse, FilterRule } from '@/types';
import { analyzeSample, uploadAndAnalyze, refilterCapture } from '@/lib/api';
import { Navbar } from '@/components/Navbar';
import { MetricCards } from '@/components/MetricCards';
import { TrafficAnalytics } from '@/components/TrafficAnalytics';
import { PacketDissector } from '@/components/PacketDissector';
import { RuleManagerModal } from '@/components/RuleManagerModal';
import { AICopilotDrawer } from '@/components/AICopilotDrawer';
import { Shield, Sparkles, RefreshCw, AlertCircle } from 'lucide-react';

export default function Dashboard() {
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [rules, setRules] = useState<FilterRule[]>([]);
  const [ruleModalOpen, setRuleModalOpen] = useState<boolean>(false);
  const [copilotOpen, setCopilotOpen] = useState<boolean>(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Initial load: run sample capture
  useEffect(() => {
    loadSample();
  }, []);

  const showNotification = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 4000);
  };

  const loadSample = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeSample(rules);
      setAnalysis(data);
      setRules(data.active_rules || []);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Failed to analyze sample capture. Ensure FastAPI backend is running on port 8000.');
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
      setRules(data.active_rules || []);
      showNotification(`Uploaded and analyzed ${file.name} successfully!`);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Failed to upload and analyze PCAP.');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveAndApplyRules = async (updatedRules: FilterRule[]) => {
    if (!analysis) return;
    setLoading(true);
    try {
      const data = await refilterCapture(analysis.analysis_id, updatedRules);
      setAnalysis(data);
      setRules(data.active_rules || []);
      setRuleModalOpen(false);
      const droppedDelta = data.summary.dropped;
      showNotification(`Firewall rules applied! Dropped ${droppedDelta} matching packet(s). Filtered PCAP updated.`);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Failed to apply rules and refilter.');
    } finally {
      setLoading(false);
    }
  };

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
      description: `Policy restriction for application ${app}`,
    };
    const updated = [...rules, newRule];
    handleSaveAndApplyRules(updated);
  };

  const handleApplySuggestedRule = (rule: FilterRule) => {
    const updated = [...rules, rule];
    handleSaveAndApplyRules(updated);
    showNotification(`Rule applied from NetCopilot: Block ${rule.type.toUpperCase()} ${rule.value}`);
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans">
      
      {/* Top Navigation */}
      <Navbar
        analysis={analysis}
        loading={loading}
        rules={rules}
        onLoadSample={loadSample}
        onFileUpload={handleFileUpload}
        onOpenRules={() => setRuleModalOpen(true)}
        onToggleCopilot={() => setCopilotOpen(!copilotOpen)}
        copilotOpen={copilotOpen}
      />

      {/* Action Notification Toast */}
      {actionNotice && (
        <div className="fixed top-20 right-6 z-50 rounded-xl border border-cyan-500/40 bg-slate-900/95 px-4 py-3 shadow-2xl backdrop-blur-md text-xs text-cyan-300 flex items-center space-x-2 animate-bounce">
          <Sparkles className="h-4 w-4 text-cyan-400" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Main Dashboard Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        
        {/* Error Alert */}
        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/40 p-4 text-xs text-rose-300 flex items-start space-x-3">
            <AlertCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold">Backend Connection Notice: </span>
              <span>{error}</span>
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
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>DPI Engine Platform v2.0 • Multi-Threaded Packet Dissection &amp; Containment</span>
          <span className="text-slate-400 font-mono">C++ Core • FastAPI • Next.js • NetCopilot AI</span>
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
