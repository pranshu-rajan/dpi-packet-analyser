'use client';

import React, { useState, useEffect } from 'react';
import { X, Database, Clock, FileArchive, Trash2, ArrowRight, RefreshCw, CheckCircle2 } from 'lucide-react';
import { CaptureHistoryItem } from '@/types';
import { getCaptureHistory, deleteCaptureSession } from '@/lib/api';

interface CaptureHistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectCapture: (analysisId: string) => void;
  activeAnalysisId?: string;
}

export const CaptureHistoryModal: React.FC<CaptureHistoryModalProps> = ({
  isOpen,
  onClose,
  onSelectCapture,
  activeAnalysisId,
}) => {
  const [history, setHistory] = useState<CaptureHistoryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getCaptureHistory();
      setHistory(data);
    } catch (err) {
      console.error(err);
      setError('Failed to load capture telemetry from database.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      const timer = window.setTimeout(() => void fetchHistory(), 0);
      return () => window.clearTimeout(timer);
    }
  }, [isOpen]);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await deleteCaptureSession(id);
      setHistory(prev => prev.filter(item => item.id !== id));
    } catch (err) {
      console.error('Failed to delete capture session:', err);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="w-full max-w-3xl rounded-2xl border border-slate-800 bg-slate-950 p-6 shadow-2xl space-y-5">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white">Capture Telemetry &amp; History</h2>
                <span className="rounded-md bg-purple-950/80 border border-purple-800/80 px-2 py-0.5 text-[10px] font-semibold text-purple-300 uppercase tracking-wider">
                  PostgreSQL Store
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Persistent historical PCAP sessions and flow summaries stored in the database.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Action / Refresh Bar */}
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-400">
            {history.length} persistent capture session{history.length === 1 ? '' : 's'} recorded
          </span>
          <button
            onClick={fetchHistory}
            disabled={loading}
            className="flex items-center space-x-1 text-cyan-400 hover:underline disabled:opacity-50"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Telemetry</span>
          </button>
        </div>

        {/* History List */}
        <div className="max-h-80 overflow-y-auto space-y-2.5 pr-1">
          {loading && history.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-500 flex flex-col items-center space-y-2">
              <RefreshCw className="h-5 w-5 animate-spin text-purple-400" />
              <span>Querying database telemetry...</span>
            </div>
          ) : error ? (
            <div className="rounded-lg border border-rose-900/50 bg-rose-950/20 p-4 text-center text-xs text-rose-400">
              {error}
            </div>
          ) : history.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-800 py-12 text-center text-xs text-slate-500">
              No historical captures saved in the database yet. Analyze a sample or upload a PCAP to persist.
            </div>
          ) : (
            history.map((item) => {
              const isActive = activeAnalysisId === item.id;
              const formattedSize = (item.file_size_bytes / (1024 * 1024)).toFixed(2);
              return (
                <div
                  key={item.id}
                  onClick={() => {
                    onSelectCapture(item.id);
                    onClose();
                  }}
                  className={`group flex items-center justify-between rounded-xl border p-3.5 text-xs transition-all cursor-pointer ${
                    isActive
                      ? 'border-purple-500/80 bg-purple-950/20 shadow-[0_0_15px_rgba(168,85,247,0.15)]'
                      : 'border-slate-800/80 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/80'
                  }`}
                >
                  <div className="flex items-center space-x-3.5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-800/60 border border-slate-700/60 text-slate-300">
                      <FileArchive className="h-4 w-4 text-cyan-400" />
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-slate-200">{item.filename}</span>
                        {isActive && (
                          <span className="flex items-center space-x-1 rounded bg-purple-950 border border-purple-700/60 px-1.5 py-0.2 text-[10px] font-medium text-purple-300">
                            <CheckCircle2 className="h-2.5 w-2.5 text-purple-400" />
                            <span>Active</span>
                          </span>
                        )}
                      </div>
                      <div className="flex items-center space-x-3 mt-1 text-[11px] text-slate-400 font-mono">
                        <span>{item.total_packets.toLocaleString()} packets</span>
                        <span>•</span>
                        <span className="text-emerald-400">{item.processed_packets} forwarded</span>
                        {item.dropped_packets > 0 && (
                          <>
                            <span>•</span>
                            <span className="text-rose-400">{item.dropped_packets} dropped</span>
                          </>
                        )}
                        <span>•</span>
                        <span>{formattedSize} MB</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    <div className="text-right hidden sm:block">
                      <div className="flex items-center space-x-1 text-[10px] text-slate-500">
                        <Clock className="h-3 w-3" />
                        <span>{item.created_at ? new Date(item.created_at).toLocaleDateString() : 'Recent'}</span>
                      </div>
                      <span className="text-[10px] font-mono text-purple-400/80">
                        ID: {item.id.substring(0, 12)}
                      </span>
                    </div>

                    <button
                      onClick={(e) => handleDelete(item.id, e)}
                      title="Delete from database"
                      className="p-1.5 text-slate-500 hover:text-rose-400 transition-colors rounded-md hover:bg-rose-950/30"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>

                    <div className="p-1 text-slate-600 group-hover:text-cyan-400 transition-colors">
                      <ArrowRight className="h-4 w-4" />
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-800 pt-4 text-xs">
          <span className="text-slate-500">
            Relational storage tracks network flows, firewall action counts, and threat alerts.
          </span>
          <button
            onClick={onClose}
            className="rounded-lg border border-slate-800 bg-slate-900 px-4 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
