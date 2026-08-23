import React, { useEffect } from 'react';
import { 
  X, Flame, ExternalLink, ShieldAlert, AlertTriangle, 
  Clock, Gavel, ShieldCheck, BookOpen, Layers, Calendar, 
  Building2, Tag, ArrowUpRight, CheckCircle2, Shield
} from 'lucide-react';
import { RealWorldIncident } from '../types';

interface IncidentDetailModalProps {
  incident: RealWorldIncident | null;
  onClose: () => void;
  onNavigateToOwasp?: (threatId: string) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onNavigateToOwasp
}) => {
  // Listen for Escape key to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    if (incident) {
      window.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [incident, onClose]);

  if (!incident) return null;

  const getSeverityBadge = (severity?: string) => {
    switch (severity) {
      case 'Critical':
        return 'border-rose-500/40 bg-rose-500/15 text-rose-300';
      case 'High':
        return 'border-amber-500/40 bg-amber-500/15 text-amber-300';
      case 'Medium':
        return 'border-yellow-500/40 bg-yellow-500/15 text-yellow-300';
      default:
        return 'border-blue-500/40 bg-blue-500/15 text-blue-300';
    }
  };

  return (
    <div 
      className="fixed inset-0 z-50 flex items-start sm:items-center justify-center pt-[calc(env(safe-area-inset-top,0px)+3.5rem)] sm:pt-4 pb-[calc(env(safe-area-inset-bottom,0px)+1rem)] sm:pb-4 px-3 sm:px-4 md:p-6 bg-black/85 backdrop-blur-md animate-in fade-in duration-200"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="incident-modal-title"
    >
      <div 
        className="w-full max-w-4xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.85)] overflow-hidden flex flex-col max-h-[calc(100dvh-env(safe-area-inset-top,0px)-env(safe-area-inset-bottom,0px)-4.5rem)] sm:max-h-[88vh] animate-in zoom-in-95 duration-200"
        onClick={e => e.stopPropagation()}
      >
        {/* Modal Scrollable Container */}
        <div className="overflow-y-auto flex-1 flex flex-col">
          {/* Modal Header (Sticky on Mobile for immediate Close access) */}
          <div className="sticky top-0 z-20 p-3.5 sm:p-5 md:p-6 border-b border-slate-800 bg-slate-950/95 backdrop-blur-md flex items-start justify-between gap-3">
            <div className="space-y-2 min-w-0 flex-1">
              {/* Badges Bar */}
              <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
                <span className="inline-flex items-center gap-1 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-full text-[10px] sm:text-xs font-mono bg-amber-500/10 border border-amber-500/30 text-amber-300">
                  <Flame className="w-3 h-3 text-amber-400" />
                  Case Study
                </span>

                {incident.severity && (
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-full text-[10px] sm:text-xs font-semibold border ${getSeverityBadge(incident.severity)}`}>
                    <AlertTriangle className="w-2.5 h-2.5 sm:w-3 sm:h-3" />
                    {incident.severity.toUpperCase()}
                  </span>
                )}

                {incident.year && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-full text-[10px] sm:text-xs font-mono border border-slate-700 bg-slate-800/80 text-slate-300">
                    <Calendar className="w-2.5 h-2.5 sm:w-3 sm:h-3 text-slate-400" />
                    {incident.year}
                  </span>
                )}

                {incident.targetOrVictim && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-full text-[10px] sm:text-xs font-mono border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
                    <Building2 className="w-2.5 h-2.5 sm:w-3 sm:h-3 text-cyan-400" />
                    {incident.targetOrVictim}
                  </span>
                )}

                {incident.cveOrAdvisoryId && incident.cveOrAdvisoryId !== 'N/A' && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-full text-[10px] sm:text-xs font-mono border border-purple-500/30 bg-purple-500/10 text-purple-300">
                    <Tag className="w-2.5 h-2.5 sm:w-3 sm:h-3 text-purple-400" />
                    {incident.cveOrAdvisoryId}
                  </span>
                )}
              </div>

              {/* Title */}
              <h2 id="incident-modal-title" className="text-base sm:text-xl md:text-2xl font-bold text-white tracking-tight break-words leading-snug">
                {incident.title}
              </h2>
            </div>

            {/* Close & Action Buttons */}
            <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
              {incident.url && (
                <a
                  href={incident.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2 rounded-lg bg-slate-900 hover:bg-cyan-500/20 text-slate-400 hover:text-cyan-300 border border-slate-800 hover:border-cyan-500/30 transition-colors min-w-[36px] min-h-[36px] flex items-center justify-center"
                  title="View authoritative advisory / research paper"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
              )}
              <button
                onClick={onClose}
                className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 hover:border-slate-700 transition-colors min-w-[36px] min-h-[36px] flex items-center justify-center"
                aria-label="Close dialog"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Modal Scrollable Body */}
          <div className="p-3.5 sm:p-5 md:p-6 space-y-4 sm:space-y-6 text-sm">
            {/* Section 1: Technical Attack Vector */}
            <div className="bg-slate-950/60 border border-slate-800/90 rounded-xl p-3.5 sm:p-5 space-y-2">
              <div className="flex items-center gap-2 text-rose-400 font-semibold text-sm sm:text-base">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Attack Vector & Technical Mechanics</span>
              </div>
              <p className="text-slate-300 leading-relaxed text-xs sm:text-sm">
                {incident.attackVector || 'Adversarial execution vector exploiting architectural weaknesses in LLM inputs, weights, or execution pipelines.'}
              </p>
            </div>

            {/* Section 2: Security & Business Impact */}
            <div className="bg-amber-950/20 border border-amber-500/30 rounded-xl p-3.5 sm:p-5 space-y-2">
              <div className="flex items-center gap-2 text-amber-300 font-semibold text-sm sm:text-base">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Security & Operational Impact</span>
              </div>
              <p className="text-amber-100/90 leading-relaxed text-xs sm:text-sm">
                {incident.impact || 'System integrity compromise, confidential data exposure, or unauthorized autonomous actions.'}
              </p>
            </div>

            {/* Section 3: Recovery Timeline & Repercussions */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
              {/* Left: Recovery Time */}
              <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-3.5 sm:p-4 space-y-1.5">
                <div className="flex items-center gap-2 text-cyan-400 font-medium text-xs sm:text-sm">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  <span>Recovery Timeline & Response</span>
                </div>
                <p className="text-slate-300 text-xs sm:text-sm leading-relaxed">
                  {incident.recoveryTime || '48–72 hours (patch deployment & advisory)'}
                </p>
              </div>

              {/* Right: Fallout & Repercussions */}
              <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-3.5 sm:p-4 space-y-1.5">
                <div className="flex items-center gap-2 text-purple-400 font-medium text-xs sm:text-sm">
                  <Gavel className="w-4 h-4 text-purple-400" />
                  <span>Repercussions & Legal Fallout</span>
                </div>
                <p className="text-slate-300 text-xs sm:text-sm leading-relaxed">
                  {incident.repercussions || 'Mandatory security audit, compliance disclosures, and operational policy reform.'}
                </p>
              </div>
            </div>

            {/* Section 4: Technical Remediation */}
            <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-3.5 sm:p-5 space-y-2">
              <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm sm:text-base">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Remediation & Defensive Architecture</span>
              </div>
              <p className="text-emerald-100/90 leading-relaxed text-xs sm:text-sm">
                {incident.remediation || 'Enforce multi-layer guardrails, privilege boundaries, and input/output sanitization.'}
              </p>
            </div>

            {/* Section 5: Lessons Learned */}
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3.5 sm:p-5 space-y-2">
              <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm sm:text-base">
                <BookOpen className="w-4 h-4 text-blue-400" />
                <span>Key Takeaway for AI Security Practitioners</span>
              </div>
              <p className="text-slate-300 leading-relaxed text-xs sm:text-sm">
                {incident.lessonsLearned || 'AI models and autonomous agents must be integrated with defense-in-depth security controls.'}
              </p>
            </div>

            {/* Section 6: Mapped Framework Threats */}
            {incident.mappedThreats && incident.mappedThreats.length > 0 && (
              <div className="pt-3 border-t border-slate-800">
                <div className="flex items-center gap-2 text-slate-400 font-medium text-xs sm:text-sm mb-2.5">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>Mapped Framework Threats & Vulnerabilities</span>
                </div>
                <div className="flex flex-wrap gap-1.5 sm:gap-2">
                  {incident.mappedThreats.map(threatId => (
                    <button
                      key={threatId}
                      onClick={() => {
                        if (onNavigateToOwasp) {
                          onClose();
                          onNavigateToOwasp(threatId);
                        }
                      }}
                      className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-cyan-950/40 border border-slate-800 hover:border-cyan-500/40 text-cyan-400 hover:text-cyan-300 font-mono text-xs transition-colors flex items-center gap-1.5"
                    >
                      <span>{threatId}</span>
                      <ArrowUpRight className="w-3 h-3 opacity-60" />
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Section 7: Primary Advisory Source */}
            {incident.url && (
              <div className="pt-3 border-t border-slate-800 flex items-center justify-between gap-3 flex-wrap bg-slate-950/40 p-3 rounded-lg">
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono truncate max-w-full sm:max-w-md">
                  <Shield className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  <span className="truncate">{incident.url}</span>
                </div>
                <a
                  href={incident.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full sm:w-auto inline-flex items-center justify-center gap-1 px-3 py-2 rounded-md bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-semibold transition-colors shrink-0"
                >
                  <span>Read Full Citation</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </a>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default IncidentDetailModal;
