'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Bot, X, Send, Sparkles, Shield, ArrowRight, RefreshCw } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ChatMessage, FilterRule, AnalysisResponse } from '@/types';
import { streamChatResponse } from '@/lib/api';

interface AICopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  analysis: AnalysisResponse | null;
  onApplySuggestedRule: (rule: FilterRule) => void;
}

const DEFAULT_PROMPTS = [
  'Audit this capture for security threats',
  'List all extracted SNI domains and hosts',
  'Recommend firewall rules for policy control',
  'Explain how TLS SNI extraction works without decryption',
];

export const AICopilotDrawer: React.FC<AICopilotDrawerProps> = ({
  isOpen,
  onClose,
  analysis,
  onApplySuggestedRule,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content:
        'Hello! I am **NetCopilot**, your Deep Packet Inspection (DPI) & Network Security AI analyst.\n\n' +
        'I am analyzing your active capture in real-time. Ask me to investigate TLS SNIs, detect protocol anomalies, or configure firewall containment rules.',
    },
  ]);
  const [input, setInput] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isStreaming]);

  if (!isOpen) return null;

  const handleSend = async (customQuery?: string) => {
    const query = (customQuery || input).trim();
    if (!query || isStreaming) return;

    setInput('');
    const userMsg: ChatMessage = { role: 'user', content: query };
    const assistantMsg: ChatMessage = { role: 'assistant', content: '' };

    const updatedMessages = [...messages, userMsg];
    setMessages([...updatedMessages, assistantMsg]);
    setIsStreaming(true);

    let accumulatedContent = '';

    await streamChatResponse(
      updatedMessages,
      analysis?.analysis_id,
      (token: string) => {
        accumulatedContent += token;
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = {
            role: 'assistant',
            content: accumulatedContent,
          };
          return next;
        });
      },
      () => {
        setIsStreaming(false);
      },
      (err: string) => {
        setIsStreaming(false);
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = {
            role: 'assistant',
            content: next[next.length - 1].content + `\n\n*(Error: ${err})*`,
          };
          return next;
        });
      }
    );
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Helper to extract [SUGGEST_RULE:type:value:reason]
  const parseContentWithRules = (content: string) => {
    const ruleRegex = /\[SUGGEST_RULE:([^:]+):([^:]+):([^\]]+)\]/g;
    const parts = [];
    let lastIndex = 0;
    let match;

    while ((match = ruleRegex.exec(content)) !== null) {
      if (match.index > lastIndex) {
        parts.push({ type: 'text', text: content.substring(lastIndex, match.index) });
      }
      const [, rType, rVal, rReason] = match;
      parts.push({
        type: 'rule',
        rule: {
          id: `rule-ai-${match.index}`,
          type: rType as 'ip' | 'app' | 'domain',
          value: rVal,
          enabled: true,
          description: rReason,
        } as FilterRule,
      });
      lastIndex = match.index + match[0].length;
    }

    if (lastIndex < content.length) {
      parts.push({ type: 'text', text: content.substring(lastIndex) });
    }

    return parts;
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-slate-800 bg-slate-950/95 shadow-2xl backdrop-blur-xl transition-all">
      
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 p-4">
        <div className="flex items-center space-x-2.5">
          <div className="relative flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-400">
            <Bot className="h-4 w-4" />
            <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
            </span>
          </div>
          <div>
            <h3 className="text-sm font-bold text-white flex items-center space-x-1.5">
              <span>NetCopilot AI</span>
              <span className="rounded bg-cyan-950 border border-cyan-800 px-1 py-0.2 text-[9px] font-mono text-cyan-400 uppercase">
                Streaming
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">DPI Telemetry Context Aware</p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {messages.map((msg, idx) => {
          const isUser = msg.role === 'user';
          const parts = parseContentWithRules(msg.content);

          return (
            <div
              key={idx}
              className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[88%] rounded-xl p-3.5 leading-relaxed ${
                  isUser
                    ? 'bg-cyan-600 text-white rounded-br-none shadow-[0_0_15px_rgba(6,182,212,0.25)]'
                    : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-bl-none shadow-sm'
                }`}
              >
                {parts.map((part, pIdx) => {
                  if (part.type === 'text') {
                    return (
                      <div key={pIdx} className="space-y-2 text-xs">
                        <ReactMarkdown
                          remarkPlugins={[remarkGfm]}
                          components={{
                            table: ({ children }) => (
                              <div className="overflow-x-auto my-2 rounded-lg border border-slate-800 bg-slate-950/80">
                                <table className="w-full border-collapse text-[11px] font-mono">{children}</table>
                              </div>
                            ),
                            thead: ({ children }) => <thead className="bg-slate-800/80 text-cyan-300 border-b border-slate-700">{children}</thead>,
                            th: ({ children }) => <th className="py-1.5 px-2 text-left font-semibold">{children}</th>,
                            td: ({ children }) => <td className="py-1 px-2 border-t border-slate-800/70 text-slate-300">{children}</td>,
                            h1: ({ children }) => <h1 className="text-sm font-bold text-white mt-2 mb-1 border-b border-slate-800 pb-1">{children}</h1>,
                            h2: ({ children }) => <h2 className="text-sm font-bold text-cyan-300 mt-2 mb-1">{children}</h2>,
                            h3: ({ children }) => <h3 className="text-xs font-bold text-cyan-400 mt-2 mb-0.5">{children}</h3>,
                            h4: ({ children }) => <h4 className="text-xs font-bold text-amber-300 mt-1.5 mb-0.5">{children}</h4>,
                            ul: ({ children }) => <ul className="list-disc pl-4 space-y-1 my-1 text-slate-300">{children}</ul>,
                            ol: ({ children }) => <ol className="list-decimal pl-4 space-y-1 my-1 text-slate-300">{children}</ol>,
                            li: ({ children }) => <li className="text-slate-300 leading-normal">{children}</li>,
                            p: ({ children }) => <p className="leading-relaxed my-1">{children}</p>,
                            code: ({ children }) => (
                              <code className="rounded bg-slate-950 border border-slate-800 px-1 py-0.5 font-mono text-[11px] text-cyan-300">
                                {children}
                              </code>
                            ),
                            hr: () => <hr className="border-slate-800 my-2" />
                          }}
                        >
                          {part.text}
                        </ReactMarkdown>
                      </div>
                    );
                  } else if (part.type === 'rule' && part.rule) {
                    const rule = part.rule;
                    return (
                      <div
                        key={pIdx}
                        className="my-2 rounded-lg border border-cyan-500/40 bg-cyan-950/40 p-2.5 space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-cyan-300 flex items-center space-x-1">
                            <Shield className="h-3.5 w-3.5" />
                            <span>Actionable Containment Rule</span>
                          </span>
                          <span className="rounded bg-slate-800 px-1 py-0.2 text-[9px] font-mono uppercase text-slate-300">
                            {rule.type}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-300">
                          Target: <code className="font-mono text-white font-bold">{rule.value}</code>
                        </p>
                        {rule.description && (
                          <p className="text-[10px] text-slate-400">{rule.description}</p>
                        )}
                        <button
                          onClick={() => onApplySuggestedRule(rule)}
                          className="mt-1 flex items-center justify-center space-x-1 w-full rounded bg-cyan-600 hover:bg-cyan-500 py-1 text-[11px] font-semibold text-white transition-colors"
                        >
                          <span>Apply Rule to Firewall</span>
                          <ArrowRight className="h-3 w-3" />
                        </button>
                      </div>
                    );
                  }
                  return null;
                })}
              </div>
            </div>
          );
        })}

        {isStreaming && (
          <div className="flex items-center space-x-2 text-xs text-cyan-400 font-mono">
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            <span>NetCopilot streaming analysis...</span>
          </div>
        )}

        <div ref={chatBottomRef} />
      </div>

      {/* Suggested Prompt Chips */}
      <div className="border-t border-slate-800/80 p-3 bg-slate-950">
        <div className="flex items-center space-x-1 text-[10px] text-slate-400 mb-2">
          <Sparkles className="h-3 w-3 text-cyan-400" />
          <span>Quick Investigation Queries:</span>
        </div>
        <div className="flex gap-1.5 overflow-x-auto pb-1">
          {DEFAULT_PROMPTS.map((prompt, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(prompt)}
              disabled={isStreaming}
              className="whitespace-nowrap rounded-md border border-slate-800 bg-slate-900 px-2 py-1 text-[10px] text-slate-300 hover:border-cyan-500/50 hover:bg-cyan-950/30 hover:text-cyan-200 transition-colors disabled:opacity-50"
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <div className="border-t border-slate-800 p-3 bg-slate-950">
        <div className="relative">
          <textarea
            rows={2}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about packets, flows, SNIs, or threats (Enter to send)..."
            disabled={isStreaming}
            className="w-full resize-none rounded-xl border border-slate-800 bg-slate-900/80 p-3 pr-10 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
          <button
            onClick={() => handleSend()}
            disabled={!input.trim() || isStreaming}
            className="absolute right-2.5 bottom-3.5 rounded-lg bg-cyan-600 p-1.5 text-white hover:bg-cyan-500 disabled:opacity-40 transition-colors"
          >
            <Send className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

    </div>
  );
};
