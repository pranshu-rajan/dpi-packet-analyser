'use client';

import React, { useState } from 'react';
import { X, Plus, Trash2, Sliders, ShieldCheck, ShieldAlert, Sparkles, Check } from 'lucide-react';
import { FilterRule } from '@/types';
import { getRulePresets } from '@/lib/api';

interface RuleManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
  rules: FilterRule[];
  onSaveAndApply: (updatedRules: FilterRule[]) => void;
  loading: boolean;
}

const COMMON_APPS = [
  'YouTube',
  'TikTok',
  'Netflix',
  'Facebook',
  'Twitter/X',
  'Instagram',
  'Discord',
  'Telegram',
  'Spotify',
  'Zoom',
  'Apple',
  'Amazon',
];

export const RuleManagerModal: React.FC<RuleManagerModalProps> = ({
  isOpen,
  onClose,
  rules: initialRules,
  onSaveAndApply,
  loading,
}) => {
  const [rules, setRules] = useState<FilterRule[]>(initialRules);
  const [ruleType, setRuleType] = useState<'ip' | 'app' | 'domain'>('app');
  const [ruleValue, setRuleValue] = useState<string>('YouTube');
  const [ruleDesc, setRuleDesc] = useState<string>('');

  if (!isOpen) return null;

  const handleAddRule = () => {
    if (!ruleValue.trim()) return;
    const newRule: FilterRule = {
      id: `rule-${Date.now()}`,
      type: ruleType,
      value: ruleValue.trim(),
      enabled: true,
      description: ruleDesc.trim() || `Block ${ruleType.toUpperCase()}: ${ruleValue.trim()}`,
    };
    setRules([...rules, newRule]);
    setRuleDesc('');
    if (ruleType === 'ip') setRuleValue('');
    if (ruleType === 'domain') setRuleValue('');
  };

  const handleToggleRule = (id: string) => {
    setRules(rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const handleDeleteRule = (id: string) => {
    setRules(rules.filter(r => r.id !== id));
  };

  const handleLoadPresets = async () => {
    try {
      const presets = await getRulePresets();
      // Merge presets avoiding duplicates by type and value
      const existingKeys = new Set(rules.map(r => `${r.type}:${r.value.toLowerCase()}`));
      const newItems = presets.filter(p => !existingKeys.has(`${p.type}:${p.value.toLowerCase()}`));
      setRules([...rules, ...newItems]);
    } catch (err) {
      console.error('Failed to load presets:', err);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl rounded-2xl border border-slate-800 bg-slate-950 p-6 shadow-2xl space-y-6">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-2">
            <Sliders className="h-5 w-5 text-amber-400" />
            <div>
              <h2 className="text-base font-bold text-white">Dynamic Firewall &amp; DPI Rule Engine</h2>
              <p className="text-xs text-slate-400">Configure real-time packet dropping rules for the C++ multi-threaded engine.</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Rule Creator Form */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/50 p-4 space-y-3">
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Add New Containment Rule
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Type selector */}
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Target Type</label>
              <select
                value={ruleType}
                onChange={(e) => {
                  const t = e.target.value as 'ip' | 'app' | 'domain';
                  setRuleType(t);
                  if (t === 'app') setRuleValue('YouTube');
                  else setRuleValue('');
                }}
                className="w-full rounded-lg border border-slate-800 bg-slate-950 py-1.5 px-2.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
              >
                <option value="app">Application</option>
                <option value="domain">Domain / SNI Substring</option>
                <option value="ip">Source / Destination IP</option>
              </select>
            </div>

            {/* Target Value */}
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Target Value</label>
              {ruleType === 'app' ? (
                <select
                  value={ruleValue}
                  onChange={(e) => setRuleValue(e.target.value)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 py-1.5 px-2.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
                >
                  {COMMON_APPS.map(app => (
                    <option key={app} value={app}>{app}</option>
                  ))}
                </select>
              ) : (
                <input
                  type="text"
                  placeholder={ruleType === 'ip' ? '192.168.1.50' : 'tiktok.com'}
                  value={ruleValue}
                  onChange={(e) => setRuleValue(e.target.value)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 py-1.5 px-2.5 text-xs text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none font-mono"
                />
              )}
            </div>

            {/* Reason / Note */}
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Reason (Optional)</label>
              <input
                type="text"
                placeholder="Compliance restriction..."
                value={ruleDesc}
                onChange={(e) => setRuleDesc(e.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-slate-950 py-1.5 px-2.5 text-xs text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="flex justify-end pt-1">
            <button
              onClick={handleAddRule}
              className="flex items-center space-x-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/60 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-900/80"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>Add Rule</span>
            </button>
          </div>
        </div>

        {/* Active Rules List */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300">
              Active Policy Rules ({rules.length})
            </span>
            <button
              onClick={handleLoadPresets}
              className="flex items-center space-x-1 text-[11px] text-cyan-400 hover:underline"
            >
              <Sparkles className="h-3 w-3" />
              <span>Load Security Presets</span>
            </button>
          </div>

          <div className="max-h-56 overflow-y-auto space-y-2 pr-1">
            {rules.length === 0 ? (
              <div className="rounded-lg border border-dashed border-slate-800 py-8 text-center text-xs text-slate-500">
                No blocking rules configured. All traffic is currently forwarded without drops.
              </div>
            ) : (
              rules.map((rule) => (
                <div
                  key={rule.id}
                  className={`flex items-center justify-between rounded-lg border p-2.5 text-xs transition-colors ${
                    rule.enabled
                      ? 'border-slate-700 bg-slate-900/60'
                      : 'border-slate-800/40 bg-slate-950/40 opacity-60'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={() => handleToggleRule(rule.id)}
                      className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
                    />
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] font-mono uppercase text-cyan-300">
                          {rule.type}
                        </span>
                        <span className="font-mono font-semibold text-slate-200">{rule.value}</span>
                      </div>
                      {rule.description && (
                        <p className="text-[11px] text-slate-400 mt-0.5">{rule.description}</p>
                      )}
                    </div>
                  </div>

                  <button
                    onClick={() => handleDeleteRule(rule.id)}
                    className="p-1 text-slate-500 hover:text-rose-400 transition-colors"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-slate-800 pt-4">
          <span className="text-xs text-slate-500">
            Applying rules invokes the C++ engine to sanitize the PCAP.
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={onClose}
              className="rounded-lg border border-slate-800 px-4 py-2 text-xs font-medium text-slate-400 hover:bg-slate-900"
            >
              Cancel
            </button>
            <button
              onClick={() => onSaveAndApply(rules)}
              disabled={loading}
              className="flex items-center space-x-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2 text-xs font-semibold text-white shadow-[0_0_15px_rgba(6,182,212,0.4)] hover:brightness-110 disabled:opacity-50"
            >
              <Check className="h-4 w-4" />
              <span>{loading ? 'Re-filtering PCAP...' : 'Apply & Re-filter PCAP'}</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
