import React, { useEffect, useState } from 'react';
import { 
  X, Shield, AlertTriangle, ExternalLink, ShieldCheck, Target, 
  BookOpen, Layers3, GitBranch, Flame, Copy, Check, ArrowUpRight, 
  Wrench, Sparkles, Layers, ArrowRight, Lock, Globe
} from 'lucide-react';
import { OwaspTop10Entry, SecurityTool, RealWorldIncident } from '../types';
import { OWASP_TOP_10_DATA } from '../data_llm';
import { OWASP_ML_TOP_10_DATA } from '../data_ml';
import { OWASP_AGENTIC_APPLICATIONS_DATA } from '../data_agentic_applications';
import { OWASP_AGENTIC_THREATS_DATA } from '../data_agentic';
import { OWASP_SAIF_THREATS_DATA } from '../data_saif';
import { OWASP_MCP_TOP_10_DATA } from '../data_mcp';
import { GENAI_DATA_SECURITY_RISKS } from '../data_genai_data_security';
import { TOOLS_BY_THREAT_ID, mergeTools } from '../tools_catalog';
import { INCIDENTS_BY_THREAT_ID } from '../incidents_catalog';
import { getEnrichedIncident } from '../incident_details_catalog';

export interface ThreatDetailModalProps {
  threatId: string | null;
  onClose: () => void;
  onNavigateToOwasp?: (threatId: string) => void;
  onSelectTool?: (tool: SecurityTool) => void;
  onSelectIncident?: (incident: RealWorldIncident) => void;
}

interface ResolvedThreatInfo {
  id: string;
  title: string;
  frameworkName: string;
  frameworkPill: string;
  badgeClass: string;
  description: string;
  whyUnique?: string;
  commonRisks: string[];
  preventionStrategies: string[];
  attackScenarios: { title: string; description: string }[];
  realWorldEvidence?: string[];
  implementationNotes?: { title: string; content: string }[];
  owaspMappings?: string[];
  otherMappings?: string[];
  maestroMappings?: { layer: string; name: string; details: string }[];
  relatedRisks?: { id: string; title: string; relationship: string }[];
  references: { title: string; url: string }[];
  suggestedTools?: SecurityTool[];
}

export function resolveThreatData(threatId: string): ResolvedThreatInfo | null {
  const normId = threatId.trim().toUpperCase();

  // 1. OWASP Top 10 for LLMs (2026)
  const llm = OWASP_TOP_10_DATA.find(e => e.id.toUpperCase() === normId || e.id.toUpperCase().startsWith(normId + ':') || normId.startsWith(e.id.toUpperCase().split(':')[0]));
  if (llm) {
    return {
      ...llm,
      frameworkName: 'OWASP Top 10 for LLM Applications (2026 Edition)',
      frameworkPill: 'OWASP LLM 2026',
      badgeClass: 'border-pink-500/30 bg-pink-500/10 text-pink-400',
    };
  }

  // 2. OWASP Agentic Applications Top 10 (ASI)
  const asi = OWASP_AGENTIC_APPLICATIONS_DATA.find(e => e.id.toUpperCase() === normId);
  if (asi) {
    return {
      ...asi,
      frameworkName: 'OWASP Top 10 for Agentic Applications (2026)',
      frameworkPill: 'Agentic Applications (ASI)',
      badgeClass: 'border-orange-500/30 bg-orange-500/10 text-orange-400',
    };
  }

  // 3. OWASP Agentic Skills Top 10 (AST)
  const ast = OWASP_AGENTIC_THREATS_DATA.find(e => e.id.toUpperCase() === normId);
  if (ast) {
    return {
      ...ast,
      frameworkName: 'OWASP Agentic Skills Top 10',
      frameworkPill: 'Agentic Skills (AST)',
      badgeClass: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400',
    };
  }

  // 4. OWASP ML Security Top 10
  const ml = OWASP_ML_TOP_10_DATA.find(e => e.id.toUpperCase() === normId || e.id.toUpperCase().startsWith(normId + ':') || normId.startsWith(e.id.toUpperCase().split(':')[0]));
  if (ml) {
    return {
      ...ml,
      frameworkName: 'OWASP Machine Learning Security Top 10',
      frameworkPill: 'OWASP ML Top 10',
      badgeClass: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
    };
  }

  // 5. OWASP MCP Top 10
  const mcp = OWASP_MCP_TOP_10_DATA.find(e => e.id.toUpperCase() === normId || e.id.toUpperCase().startsWith(normId + ':') || normId.startsWith(e.id.toUpperCase().split(':')[0]));
  if (mcp) {
    return {
      ...mcp,
      frameworkName: 'OWASP MCP Top 10 (Model Context Protocol)',
      frameworkPill: 'OWASP MCP Top 10',
      badgeClass: 'border-purple-500/30 bg-purple-500/10 text-purple-400',
    };
  }

  // 6. Google SAIF Threat Matrix
  const saif = OWASP_SAIF_THREATS_DATA.find(e => e.id.toUpperCase() === normId);
  if (saif) {
    return {
      ...saif,
      frameworkName: 'Google Secure AI Framework (SAIF)',
      frameworkPill: 'Google SAIF Matrix',
      badgeClass: 'border-blue-500/30 bg-blue-500/10 text-blue-400',
    };
  }

  // 7. OWASP GenAI Data Security Risks (DSGAI)
  const dsgai = GENAI_DATA_SECURITY_RISKS.find(e => e.id.toUpperCase() === normId);
  if (dsgai) {
    const prevention = dsgai.mitigations.flatMap(m => m.items.map(i => `${i.title}: ${i.description}`));
    const attacks = (dsgai.howItUnfolds || []).map((step, idx) => ({
      title: `Attack Step ${idx + 1}`,
      description: step
    }));
    return {
      id: dsgai.id,
      title: dsgai.title,
      description: dsgai.summary,
      frameworkName: 'OWASP GenAI Data Security Risks & Mitigations',
      frameworkPill: 'GenAI Data Security',
      badgeClass: 'border-violet-500/30 bg-violet-500/10 text-violet-400',
      commonRisks: dsgai.impacts || [dsgai.theme],
      preventionStrategies: prevention,
      attackScenarios: attacks,
      references: (dsgai.references || []).map(r => ({ title: r.title, url: r.url })),
    };
  }

  return null;
}

export const ThreatDetailModal: React.FC<ThreatDetailModalProps> = ({
  threatId,
  onClose,
  onNavigateToOwasp,
  onSelectTool,
  onSelectIncident
}) => {
  const [currentThreatId, setCurrentThreatId] = useState<string | null>(threatId);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setCurrentThreatId(threatId);
  }, [threatId]);

  // Listen for Escape key to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    if (currentThreatId) {
      window.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [currentThreatId, onClose]);

  if (!currentThreatId) return null;

  const threat = resolveThreatData(currentThreatId);
  if (!threat) return null;

  const mappedTools = TOOLS_BY_THREAT_ID[threat.id] || [];
  const mergedTools = mergeTools(mappedTools, threat.suggestedTools || []);
  const incidentLinks = INCIDENTS_BY_THREAT_ID[threat.id] || [];

  const handleCopy = () => {
    const text = `${threat.id} - ${threat.title}\nFramework: ${threat.frameworkName}\n\nDescription:\n${threat.description}\n\nKey Prevention Controls:\n${threat.preventionStrategies.slice(0, 4).map(s => `• ${s}`).join('\n')}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div 
      className="fixed inset-0 z-50 flex items-start sm:items-center justify-center pt-[calc(env(safe-area-inset-top,0px)+3.5rem)] sm:pt-4 pb-[calc(env(safe-area-inset-bottom,0px)+1rem)] sm:pb-4 px-3 sm:px-4 md:p-6 bg-black/85 backdrop-blur-md animate-modal-backdrop"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="threat-modal-title"
    >
      <div 
        className="w-full max-w-4xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.85)] overflow-hidden flex flex-col max-h-[calc(100dvh-env(safe-area-inset-top,0px)-env(safe-area-inset-bottom,0px)-4.5rem)] sm:max-h-[88vh] animate-modal-card"
        onClick={e => e.stopPropagation()}
      >
        {/* Modal Scrollable Container */}
        <div className="overflow-y-auto flex-1 flex flex-col">
          {/* Modal Sticky Header */}
          <div className="sticky top-0 z-20 p-3.5 sm:p-5 md:p-6 border-b border-slate-800 bg-slate-950/95 backdrop-blur-md flex items-start justify-between gap-3">
            <div className="space-y-2 min-w-0 flex-1">
              {/* Badges Bar */}
              <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
                <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono font-bold border ${threat.badgeClass}`}>
                  <Shield className="w-3.5 h-3.5" />
                  {threat.id}
                </span>

                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono border border-slate-700 bg-slate-800/80 text-slate-300">
                  <Layers className="w-3 h-3 text-slate-400" />
                  {threat.frameworkPill}
                </span>

                {mergedTools.length > 0 && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                    <Wrench className="w-3 h-3" />
                    {mergedTools.length} Tools
                  </span>
                )}

                {incidentLinks.length > 0 && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border border-amber-500/20 bg-amber-500/10 text-amber-300">
                    <Flame className="w-3 h-3" />
                    {incidentLinks.length} Incidents
                  </span>
                )}
              </div>

              {/* Threat Title */}
              <h2 id="threat-modal-title" className="text-lg sm:text-2xl font-bold text-white tracking-tight leading-snug break-words">
                {threat.title}
              </h2>
            </div>

            {/* Header Action Buttons */}
            <div className="flex items-center gap-1.5 shrink-0 pt-0.5">
              <button
                onClick={handleCopy}
                className="p-2 sm:p-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/80 transition-colors"
                title="Copy threat summary"
                aria-label="Copy threat summary"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>

              <button
                onClick={onClose}
                className="p-2 sm:p-2.5 rounded-xl bg-slate-800/80 hover:bg-rose-500/20 text-slate-400 hover:text-rose-300 border border-slate-700/80 hover:border-rose-500/30 transition-colors"
                title="Close window (Esc)"
                aria-label="Close window"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Modal Content Body */}
          <div className="p-4 sm:p-6 md:p-8 space-y-6">
            {/* Description Card */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80">
              <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
                {threat.description}
              </p>
            </div>

            {/* Why Unique / Distinction */}
            {threat.whyUnique && (
              <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
                <h4 className="text-xs font-bold text-orange-300 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5" />
                  Why this risk is distinct
                </h4>
                <p className="text-sm text-slate-300 leading-relaxed">{threat.whyUnique}</p>
              </div>
            )}

            {/* 2-Column Threat Mechanics & Mitigations */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left Column: Common Risks & Attack Scenarios */}
              <div className="space-y-6">
                {threat.commonRisks.length > 0 && (
                  <div>
                    <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                      <AlertTriangle className="w-4 h-4 text-orange-400" />
                      Risk Mechanics & Impact
                    </h4>
                    <ul className="space-y-2">
                      {threat.commonRisks.map((risk, idx) => (
                        <li key={idx} className="flex items-start gap-2.5 text-slate-300 text-xs sm:text-sm bg-slate-950/60 p-3 rounded-lg border border-slate-800/60 leading-relaxed">
                          <span className="w-1.5 h-1.5 rounded-full bg-orange-400 mt-2 shrink-0" />
                          <span>{risk}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {threat.realWorldEvidence && threat.realWorldEvidence.length > 0 && (
                  <div>
                    <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                      <BookOpen className="w-4 h-4 text-blue-400" />
                      Real-world Evidence
                    </h4>
                    <ul className="space-y-2">
                      {threat.realWorldEvidence.map((evidence, idx) => (
                        <li key={idx} className="flex items-start gap-2.5 text-slate-300 text-xs sm:text-sm bg-blue-500/5 p-3 rounded-lg border border-blue-500/10 leading-relaxed">
                          <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-2 shrink-0" />
                          <span>{evidence}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {threat.attackScenarios.length > 0 && (
                  <div>
                    <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                      <Target className="w-4 h-4 text-red-400" />
                      Attack Scenarios ({threat.attackScenarios.length})
                    </h4>
                    <div className="space-y-2.5 max-h-[320px] overflow-y-auto pr-1">
                      {threat.attackScenarios.map((scenario, idx) => (
                        <div key={idx} className="bg-red-500/5 p-3.5 rounded-lg border border-red-500/10">
                          <div className="font-bold text-red-400 text-xs sm:text-sm mb-1">{scenario.title}</div>
                          <p className="text-slate-400 text-xs leading-relaxed">{scenario.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: Prevention & Mitigations */}
              <div className="space-y-6">
                {threat.preventionStrategies.length > 0 && (
                  <div>
                    <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      Prevention & Mitigation Controls
                    </h4>
                    <ul className="space-y-2">
                      {threat.preventionStrategies.map((strategy, idx) => (
                        <li key={idx} className="flex items-start gap-2.5 text-slate-300 text-xs sm:text-sm bg-emerald-500/5 p-3 rounded-lg border border-emerald-500/10 leading-relaxed">
                          <Shield className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                          <span>{strategy}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {threat.implementationNotes && threat.implementationNotes.length > 0 && (
                  <div>
                    <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                      <Shield className="w-4 h-4 text-cyan-400" />
                      Implementation Guidance
                    </h4>
                    <div className="space-y-2.5">
                      {threat.implementationNotes.map((note) => (
                        <div key={note.title} className="rounded-lg border border-cyan-500/10 bg-cyan-500/5 p-3">
                          <div className="font-bold text-cyan-300 text-xs sm:text-sm mb-1">{note.title}</div>
                          <p className="text-slate-400 text-xs leading-relaxed whitespace-pre-line">{note.content}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Related Risks (Clickable to switch modal view) */}
                {threat.relatedRisks && threat.relatedRisks.length > 0 && (
                  <div>
                    <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                      <GitBranch className="w-4 h-4 text-orange-400" />
                      Related Risks ({threat.relatedRisks.length})
                    </h4>
                    <div className="space-y-2">
                      {threat.relatedRisks.map((risk) => (
                        <button 
                          key={risk.id}
                          type="button"
                          onClick={() => setCurrentThreatId(risk.id)}
                          className="w-full text-left rounded-lg border border-slate-800 bg-slate-950/60 hover:border-orange-500/40 p-3 transition-all hover:bg-slate-900/80 group cursor-pointer"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div>
                              <span className="font-mono text-xs text-orange-300 group-hover:text-orange-200 mr-2 font-bold">{risk.id}</span>
                              <span className="text-xs font-bold text-slate-200 group-hover:text-white">{risk.title}</span>
                            </div>
                            <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-orange-400 transition-colors shrink-0" />
                          </div>
                          <p className="text-xs text-slate-400 leading-relaxed mt-1">{risk.relationship}</p>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Mappings */}
                {(threat.owaspMappings?.length || threat.otherMappings?.length || threat.maestroMappings?.length) ? (
                  <div>
                    <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                      <Layers3 className="w-4 h-4 text-indigo-400" />
                      Framework & Layer Mappings
                    </h4>
                    <div className="space-y-2">
                      {threat.owaspMappings && (
                        <div className="flex flex-wrap gap-1.5">
                          {threat.owaspMappings.map(m => (
                            <span key={m} className="px-2 py-0.5 rounded text-[11px] font-mono border border-purple-500/20 bg-purple-500/5 text-purple-200">{m}</span>
                          ))}
                        </div>
                      )}
                      {threat.maestroMappings && (
                        <div className="space-y-1.5 pt-1">
                          {threat.maestroMappings.map(m => (
                            <div key={`${m.layer}-${m.name}`} className="p-2 rounded border border-slate-800 bg-slate-950 text-xs">
                              <span className="font-mono text-indigo-300 mr-2">{m.layer}</span>
                              <span className="font-semibold text-slate-200">{m.name}</span>
                              <p className="text-[11px] text-slate-400 mt-0.5">{m.details}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>

            {/* Real-World Incidents (Full-Width) */}
            {incidentLinks.length > 0 && (
              <div className="pt-6 border-t border-slate-800">
                <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                  <Flame className="w-4 h-4 text-amber-400" />
                  Real-World Incidents & Case Studies ({incidentLinks.length})
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {incidentLinks.map((incident, idx) => (
                    <div
                      key={idx}
                      onClick={() => onSelectIncident ? onSelectIncident(getEnrichedIncident(incident, threat.id)) : window.open(incident.url, '_blank')}
                      className="flex items-center justify-between gap-3 bg-slate-950/60 p-3.5 rounded-xl border border-slate-800 hover:border-amber-500/40 transition-all group cursor-pointer hover:bg-slate-900/80"
                    >
                      <div className="flex items-start gap-2 min-w-0">
                        <Flame className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                        <span className="text-xs sm:text-sm text-slate-300 group-hover:text-amber-300 line-clamp-2 transition-colors font-medium">
                          {incident.title}
                        </span>
                      </div>
                      <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-amber-400 transition-colors shrink-0" />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommended Security Tools (Full-Width Grid) */}
            {mergedTools.length > 0 && (
              <div className="pt-6 border-t border-slate-800">
                <h4 className="flex items-center gap-2 text-xs font-bold text-cyan-400 uppercase tracking-wider mb-3">
                  <Wrench className="w-4 h-4 text-cyan-400" />
                  Recommended Security Tools ({mergedTools.length})
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {mergedTools.map((tool) => (
                    <div
                      key={tool.name}
                      onClick={() => onSelectTool ? onSelectTool(tool) : window.open(tool.url, '_blank')}
                      className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/60 hover:border-cyan-500/40 hover:bg-slate-900/80 transition-all group cursor-pointer flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <span className="text-white font-bold text-xs sm:text-sm group-hover:text-cyan-300 transition-colors">
                            {tool.name}
                          </span>
                          <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors shrink-0" />
                        </div>
                        <p className="text-xs text-slate-400 leading-relaxed line-clamp-2 mb-3">
                          {tool.description}
                        </p>
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap text-[10px] font-mono">
                        <span className="px-1.5 py-0.5 rounded border border-slate-800 bg-slate-900 text-slate-300">
                          {tool.type}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded border ${
                          tool.cost.toLowerCase() === 'free' 
                            ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' 
                            : tool.cost.toLowerCase().includes('free')
                            ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20'
                            : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                        }`}>
                          {tool.cost}
                        </span>
                        {tool.category && (
                          <span className="px-1.5 py-0.5 rounded border border-purple-500/20 bg-purple-500/10 text-purple-300">
                            {tool.category}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* External Reference Links (Full-Width) */}
            {threat.references.length > 0 && (
              <div className="pt-6 border-t border-slate-800">
                <h4 className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                  <ExternalLink className="w-4 h-4 text-blue-400" />
                  Reference Publications & Standards
                </h4>
                <div className="flex flex-wrap gap-2">
                  {threat.references.map((ref, idx) => (
                    <a
                      key={idx}
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-400 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 rounded-lg transition-colors"
                    >
                      <span>{ref.title}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Modal Footer */}
          <div className="sticky bottom-0 p-3 sm:p-4 border-t border-slate-800 bg-slate-950/95 backdrop-blur-md flex items-center justify-between gap-3">
            <div className="text-[11px] text-slate-500 font-mono hidden sm:block">
              Press <kbd className="px-1.5 py-0.5 bg-slate-900 border border-slate-800 rounded text-slate-400">Esc</kbd> to close
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
              {onNavigateToOwasp && (
                <button
                  onClick={() => {
                    onClose();
                    onNavigateToOwasp(threat.id);
                  }}
                  className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white rounded-xl text-xs font-medium border border-slate-700 transition-all"
                >
                  <span>Jump to Catalog Page</span>
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                </button>
              )}

              <button
                onClick={onClose}
                className="flex-1 sm:flex-none px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl text-xs transition-all shadow-lg shadow-cyan-500/10"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
