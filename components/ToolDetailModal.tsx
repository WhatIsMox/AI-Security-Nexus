import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { 
  Terminal, ExternalLink, Shield, Zap, CheckCircle2, Cpu, 
  X, Copy, Check, Info, Code2, ShieldAlert, ArrowRight
} from 'lucide-react';
import { getEnrichedTool } from '../tool_details_catalog';
import { SecurityTool } from '../types';

export interface ToolDetailModalProps {
  tool: (SecurityTool & { mappedThreats?: string[] }) | null;
  onClose: () => void;
  onNavigateToOwasp?: (threatId: string) => void;
}

export const ToolDetailModal: React.FC<ToolDetailModalProps> = ({ tool, onClose, onNavigateToOwasp }) => {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    const previousOverflow = document.body.style.overflow;
    if (tool) {
      window.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [tool, onClose]);

  if (!tool) return null;

  const enriched = getEnrichedTool(tool);

  const handleCopyCode = () => {
    const textToCopy = enriched.installationOrQuickstart;
    if (!textToCopy) return;
    const fallbackCopy = () => {
      try {
        const textArea = document.createElement("textarea");
        textArea.value = textToCopy;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        textArea.remove();
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (err) {
        // Fallback failed
      }
    };

    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(textToCopy).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }).catch(() => {
        fallbackCopy();
      });
    } else {
      fallbackCopy();
    }
  };

  const handleThreatClick = (threatId: string) => {
    onClose();
    if (onNavigateToOwasp) {
      onNavigateToOwasp(threatId);
    }
  };

  const categoryColor = 
    tool.category === 'Offensive' ? 'text-red-400 border-red-500/30 bg-red-500/10' :
    tool.category === 'Defensive' ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' :
    'text-purple-400 border-purple-500/30 bg-purple-500/10';

  const modalContent = (
    <div 
      className="fixed inset-0 z-[100] flex items-center justify-center pt-[calc(env(safe-area-inset-top,0px)+1rem)] sm:pt-4 pb-[calc(env(safe-area-inset-bottom,0px)+1rem)] sm:pb-4 px-3 sm:px-4 md:p-6 bg-slate-950/85 backdrop-blur-md animate-modal-backdrop"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="tool-modal-title"
    >
      <div 
        className="relative w-full max-w-3xl max-h-[calc(100dvh-env(safe-area-inset-top,0px)-env(safe-area-inset-bottom,0px)-2rem)] sm:max-h-[90vh] rounded-2xl border border-slate-700/80 bg-slate-900 shadow-[0_0_50px_rgba(0,0,0,0.85)] flex flex-col overflow-hidden animate-modal-card my-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Scrollable Container */}
        <div className="overflow-y-auto flex-1 flex flex-col">
          {/* Modal Header (Sticky on Mobile for immediate Close access) */}
          <div className="sticky top-0 z-20 p-4 sm:p-6 border-b border-slate-800 flex items-start justify-between gap-3 bg-slate-950/95 backdrop-blur-md">
            <div className="flex items-start gap-3 min-w-0">
              <div className="p-2 sm:p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400 shrink-0 mt-0.5">
                <Terminal className="w-5 h-5 sm:w-6 sm:h-6" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <h2 id="tool-modal-title" className="text-lg sm:text-2xl font-bold text-white tracking-tight break-words">
                    {tool.name}
                  </h2>
                  {enriched.authorOrMaintainer && (
                    <span className="text-[10px] sm:text-xs font-medium text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded-full border border-slate-700">
                      {enriched.authorOrMaintainer}
                    </span>
                  )}
                </div>
                <p className="text-xs sm:text-sm text-slate-400 leading-snug line-clamp-2 sm:line-clamp-none">
                  {tool.description}
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close tool window"
              className="p-2 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-white hover:border-slate-600 hover:bg-slate-800 transition-all shrink-0 min-w-[36px] min-h-[36px] flex items-center justify-center"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Modal Badges Bar */}
          <div className="px-4 sm:px-6 py-2 bg-slate-950/50 border-b border-slate-800/80 flex items-center gap-1.5 sm:gap-2 flex-wrap text-[11px] sm:text-xs font-mono">
            <span className={`px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-md border font-semibold ${categoryColor}`}>
              {tool.category || 'Dual-Purpose'}
            </span>
            {(() => {
              const displayCost = enriched.cost || tool.cost;
              const isFreeOnly = displayCost.trim().toLowerCase() === 'free';
              const hasFreeTier = displayCost.toLowerCase().includes('free');
              const costStyle = isFreeOnly
                ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                : hasFreeTier
                ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20'
                : 'text-amber-400 bg-amber-500/10 border-amber-500/20';
              return (
                <span className={`px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-md border ${costStyle}`}>
                  Cost: {displayCost}
                </span>
              );
            })()}
            <span className="px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-md border border-slate-800 bg-slate-950 text-slate-300">
              Deploy: {tool.type}
            </span>
            {enriched.license && (
              <span className="px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-md border border-slate-800 bg-slate-950 text-slate-400">
                License: {enriched.license}
              </span>
            )}
          </div>

          {/* Modal Main Content */}
          <div className="p-4 sm:p-6 space-y-5 sm:space-y-6 flex-1 text-slate-300">
          {/* Detailed Overview */}
          <div>
            <h3 className="text-xs uppercase font-bold text-slate-400 tracking-wider mb-2 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-cyan-400" />
              Technical Overview
            </h3>
            <p className="text-sm leading-relaxed text-slate-300 bg-slate-950/40 p-4 rounded-xl border border-slate-800/80">
              {enriched.longDescription}
            </p>
          </div>

          {/* Typical Use Case */}
          {enriched.typicalUseCase && (
            <div>
              <h3 className="text-xs uppercase font-bold text-slate-400 tracking-wider mb-2 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                Typical Security Use Case
              </h3>
              <div className="rounded-xl border border-amber-500/25 bg-amber-500/5 p-4 flex items-start gap-3">
                <div className="p-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 shrink-0 mt-0.5">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <p className="text-sm leading-relaxed text-amber-200/90 font-normal">
                  {enriched.typicalUseCase}
                </p>
              </div>
            </div>
          )}

          {/* Key Capabilities */}
          {enriched.keyFeatures && enriched.keyFeatures.length > 0 && (
            <div>
              <h3 className="text-xs uppercase font-bold text-slate-400 tracking-wider mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                Key Capabilities & Features
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {enriched.keyFeatures.map((feat, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-slate-950/50 border border-slate-800 flex items-start gap-2 text-xs leading-relaxed text-slate-300">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0 mt-1.5" />
                    <span>{feat}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Quickstart / Installation Snippet */}
          {enriched.installationOrQuickstart && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs uppercase font-bold text-slate-400 tracking-wider flex items-center gap-1.5">
                  <Code2 className="w-3.5 h-3.5 text-purple-400" />
                  Quickstart & Installation Command
                </h3>
                <button
                  onClick={handleCopyCode}
                  className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-cyan-300 transition-colors font-mono"
                  title="Copy command to clipboard"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy command</span>
                    </>
                  )}
                </button>
              </div>
              <div className="relative rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs overflow-x-auto text-emerald-300/90 leading-relaxed shadow-inner">
                <pre className="whitespace-pre-wrap break-words">{enriched.installationOrQuickstart}</pre>
              </div>
            </div>
          )}

          {/* Tech Stack & Ecosystem */}
          {enriched.ecosystem && enriched.ecosystem.length > 0 && (
            <div>
              <h3 className="text-xs uppercase font-bold text-slate-400 tracking-wider mb-2 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-blue-400" />
                Supported Tech Stack & Ecosystem
              </h3>
              <div className="flex items-center gap-2 flex-wrap">
                {enriched.ecosystem.map((eco) => (
                  <span key={eco} className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300">
                    {eco}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Mapped Threat Frameworks */}
          {tool.mappedThreats && tool.mappedThreats.length > 0 && (
            <div>
              <h3 className="text-xs uppercase font-bold text-slate-400 tracking-wider mb-2 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-rose-400" />
                Cross-Mapped Threat Categories ({tool.mappedThreats.length})
              </h3>
              <p className="text-xs text-slate-400 mb-2">Click any threat to jump directly into the full framework assessment page:</p>
              <div className="flex items-center gap-1.5 flex-wrap">
                {tool.mappedThreats.map((threatId) => (
                  <button
                    key={threatId}
                    onClick={() => handleThreatClick(threatId)}
                    className="inline-flex items-center gap-1 px-3 py-1 bg-slate-950 hover:bg-cyan-950/40 border border-cyan-500/30 hover:border-cyan-400 rounded-lg text-xs font-mono text-cyan-300 hover:text-white transition-all cursor-pointer"
                  >
                    <span>{threatId}</span>
                    <ArrowRight className="w-3 h-3 text-cyan-400" />
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

          {/* Modal Footer Actions */}
          <div className="p-4 sm:p-5 border-t border-slate-800 bg-slate-950/80 mt-auto flex flex-col sm:flex-row items-center justify-between gap-3">
            <span className="text-xs text-slate-500 hidden sm:inline font-mono">
              Press ESC or click outside to dismiss
            </span>
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <button
                onClick={onClose}
                className="flex-1 sm:flex-none px-4 py-2.5 rounded-xl border border-slate-700 bg-slate-800 text-sm font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-all"
              >
                Close
              </button>
              <a
                href={tool.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex-1 sm:flex-none inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl border border-purple-500/40 bg-purple-500/10 hover:bg-purple-500/20 hover:border-purple-400 text-sm font-bold text-purple-200 hover:text-white transition-all"
              >
                Visit Repository & Docs
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  if (typeof document !== 'undefined') {
    return createPortal(modalContent, document.body);
  }
  return modalContent;
};
export default ToolDetailModal;
