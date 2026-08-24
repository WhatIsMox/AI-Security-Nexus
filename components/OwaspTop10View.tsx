
import React, { useState, useEffect } from 'react';
import { FrameworkOverview, OwaspTop10Entry, SecurityTool, RealWorldIncident } from '../types';
import { ChevronDown, Shield, AlertTriangle, ExternalLink, ShieldCheck, Target, Wrench, Globe, Lock, BookOpen, Layers3, GitBranch, Info, ListChecks, Flame, ArrowUpRight } from 'lucide-react';
import { TOOLS_BY_THREAT_ID, mergeTools } from '../tools_catalog';
import { INCIDENTS_BY_THREAT_ID } from '../incidents_catalog';
import { getEnrichedIncident } from '../incident_details_catalog';
import { ToolDetailModal } from './ToolDetailModal';
import { IncidentDetailModal } from './IncidentDetailModal';
import { ThreatDetailModal } from './ThreatDetailModal';

interface OwaspTop10ViewProps {
  initialExpandedId?: string | null;
  data: OwaspTop10Entry[];
  title: string;
  description: string;
  colorTheme?: 'pink' | 'emerald' | 'orange' | 'blue' | 'cyan';
  frameworkOverview?: FrameworkOverview;
}

const OwaspTop10View: React.FC<OwaspTop10ViewProps> = ({ 
  initialExpandedId, 
  data, 
  title, 
  description,
  colorTheme = 'pink',
  frameworkOverview,
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(initialExpandedId || null);
  const [toolFilters, setToolFilters] = useState<Record<string, { category: 'all' | 'defensive' | 'offensive'; pricing: 'all' | 'free' | 'paid' }>>({});
  const [openOverviewSection, setOpenOverviewSection] = useState<'overview' | 'terminology' | 'triage' | null>(null);
  const [selectedTool, setSelectedTool] = useState<SecurityTool | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<RealWorldIncident | null>(null);
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);

  useEffect(() => {
    if (initialExpandedId) {
      setExpandedId(initialExpandedId);
      setTimeout(() => {
        const element = document.getElementById(initialExpandedId);
        if (element) {
          element.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }, 100);
    }
  }, [initialExpandedId]);

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const openRelatedEntry = (id: string) => {
    setExpandedId(id);
    window.setTimeout(() => {
      document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  };

  const getToolFilter = (id: string) => toolFilters[id] || { category: 'all', pricing: 'all' };
  const setToolFilter = (id: string, value: Partial<{ category: 'all' | 'defensive' | 'offensive'; pricing: 'all' | 'free' | 'paid' }>) => {
    setToolFilters(prev => ({ ...prev, [id]: { ...getToolFilter(id), ...value } }));
  };

  const theme = {
    pink: {
      activeBorder: 'border-pink-500/30',
      activeShadow: 'shadow-[0_0_20px_rgba(236,72,153,0.1)]',
      badgeActive: 'bg-pink-500/20 text-pink-400 border border-pink-500/30',
      badgeHover: 'group-hover:text-pink-400 group-hover:border-pink-500/30',
      iconActive: 'text-pink-400',
    },
    emerald: {
      activeBorder: 'border-emerald-500/30',
      activeShadow: 'shadow-[0_0_20px_rgba(16,185,129,0.1)]',
      badgeActive: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
      badgeHover: 'group-hover:text-emerald-400 group-hover:border-emerald-500/30',
      iconActive: 'text-emerald-400',
    },
    orange: {
      activeBorder: 'border-orange-500/30',
      activeShadow: 'shadow-[0_0_20px_rgba(249,115,22,0.1)]',
      badgeActive: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
      badgeHover: 'group-hover:text-orange-400 group-hover:border-orange-500/30',
      iconActive: 'text-orange-400',
    },
    blue: {
      activeBorder: 'border-blue-500/30',
      activeShadow: 'shadow-[0_0_20px_rgba(59,130,246,0.1)]',
      badgeActive: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
      badgeHover: 'group-hover:text-blue-400 group-hover:border-blue-500/30',
      iconActive: 'text-blue-400',
    },
    cyan: {
      activeBorder: 'border-cyan-500/30',
      activeShadow: 'shadow-[0_0_20px_rgba(6,182,212,0.12)]',
      badgeActive: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30',
      badgeHover: 'group-hover:text-cyan-400 group-hover:border-cyan-500/30',
      iconActive: 'text-cyan-400',
    }
  };

  const currentTheme = theme[colorTheme];

  const overviewSections = frameworkOverview ? [
    {
      id: 'overview' as const,
      label: 'Framework overview',
      summary: frameworkOverview.edition,
      icon: BookOpen,
      activeClass: 'border-orange-500/40 bg-orange-500/10 text-orange-200',
      iconClass: 'text-orange-400',
    },
    {
      id: 'terminology' as const,
      label: 'Key terminology',
      summary: `${frameworkOverview.terminology.length} concepts and definitions`,
      icon: Info,
      activeClass: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200',
      iconClass: 'text-cyan-400',
    },
    {
      id: 'triage' as const,
      label: 'Finding triage',
      summary: `${frameworkOverview.triageSteps.length} classification steps`,
      icon: GitBranch,
      activeClass: 'border-purple-500/40 bg-purple-500/10 text-purple-200',
      iconClass: 'text-purple-400',
    },
  ] : [];

  const formatId = (id: string) => {
    if (id.includes(':')) return id.split(':')[0];
    return id;
  };

  return (
    <div className="container-fluid p-3 sm:p-4 md:p-8 max-w-6xl mx-auto animate-in fade-in duration-500">
      {/* Tool Detail Inspection Window */}
      <ToolDetailModal 
        tool={selectedTool} 
        onClose={() => setSelectedTool(null)} 
        onNavigateToOwasp={openRelatedEntry} 
      />

      <div className="mb-10 text-center">
        <h1 className="text-3xl md:text-4xl font-bold text-white mb-4">
          {title}
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto">
          {description}
        </p>
      </div>

      {frameworkOverview && (
        <section className="mb-8" aria-label={`${title} supporting information`}>
          <div className="grid sm:grid-cols-3 gap-3">
            {overviewSections.map((section) => {
              const isOpen = openOverviewSection === section.id;
              return (
                <button
                  key={section.id}
                  type="button"
                  aria-expanded={isOpen}
                  aria-controls={`${section.id}-framework-panel`}
                  onClick={() => setOpenOverviewSection(isOpen ? null : section.id)}
                  className={`group flex items-center gap-3 rounded-xl border p-3.5 text-left transition-all ${isOpen ? section.activeClass : 'border-slate-800 bg-slate-900/55 text-slate-300 hover:border-slate-700 hover:bg-slate-900/80'}`}
                >
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-700/70 bg-slate-950/70">
                    <section.icon className={`w-4 h-4 ${section.iconClass}`} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-bold">{section.label}</span>
                    <span className="block truncate text-[11px] text-slate-500 mt-0.5">{section.summary}</span>
                  </span>
                  <ChevronDown className={`w-4 h-4 shrink-0 text-slate-500 transition-transform ${isOpen ? 'rotate-180' : 'group-hover:text-slate-300'}`} />
                </button>
              );
            })}
          </div>

          {openOverviewSection === 'overview' && (
            <div id="overview-framework-panel" role="region" className="mt-3 rounded-2xl border border-orange-500/20 bg-gradient-to-br from-orange-500/10 via-slate-900/80 to-slate-950 p-5 md:p-7 animate-in fade-in slide-in-from-top-2 duration-200">
              <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 mb-5">
                <div>
                  <div className="inline-flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-orange-300 mb-3">
                    <BookOpen className="w-4 h-4" /> {frameworkOverview.edition}
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed max-w-4xl">{frameworkOverview.scopeNote}</p>
                </div>
                {frameworkOverview.severityNote && (
                  <div className="shrink-0 md:max-w-sm rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs text-amber-100/80 leading-relaxed">
                    <span className="font-bold text-amber-300">Scoring note: </span>{frameworkOverview.severityNote}
                  </div>
                )}
              </div>
              <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-3">
                {frameworkOverview.riskGroups.map((group) => (
                  <div key={group.title} className="rounded-xl border border-slate-700/70 bg-slate-950/60 p-4">
                    <h3 className="flex items-center gap-2 text-sm font-bold text-white mb-2"><Layers3 className="w-4 h-4 text-orange-400" />{group.title}</h3>
                    <p className="font-mono text-[11px] text-orange-300 mb-2">{group.entries.join(' · ')}</p>
                    <p className="text-xs text-slate-400 leading-relaxed">{group.description}</p>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap gap-2 mt-5 pt-5 border-t border-slate-800">
                {frameworkOverview.resources.map((resource) => (
                  <a key={resource.url} href={resource.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 px-3 py-1.5 text-xs text-blue-300 bg-blue-500/10 border border-blue-500/20 rounded-md hover:bg-blue-500/20 transition-colors">
                    {resource.title}<ExternalLink className="w-3 h-3" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {openOverviewSection === 'terminology' && (
            <div id="terminology-framework-panel" role="region" className="mt-3 rounded-2xl border border-cyan-500/20 bg-cyan-500/5 p-5 md:p-7 animate-in fade-in slide-in-from-top-2 duration-200">
              <h2 className="flex items-center gap-2 text-sm font-bold text-slate-200 uppercase tracking-wider mb-5"><Info className="w-4 h-4 text-cyan-400" />Key terminology</h2>
              <dl className="grid md:grid-cols-2 gap-x-8 gap-y-4">
                {frameworkOverview.terminology.map((item) => (
                  <div key={item.term} className="border-l-2 border-cyan-500/30 pl-3">
                    <dt className="text-sm font-bold text-cyan-300">{item.term}</dt>
                    <dd className="text-xs text-slate-400 leading-relaxed mt-1">{item.definition}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}

          {openOverviewSection === 'triage' && (
            <div id="triage-framework-panel" role="region" className="mt-3 rounded-2xl border border-purple-500/20 bg-purple-500/5 p-5 md:p-7 animate-in fade-in slide-in-from-top-2 duration-200">
              <h2 className="flex items-center gap-2 text-sm font-bold text-slate-200 uppercase tracking-wider mb-5"><GitBranch className="w-4 h-4 text-purple-400" />Finding triage</h2>
              <ol className="grid lg:grid-cols-2 gap-4">
                {frameworkOverview.triageSteps.map((step, index) => (
                  <li key={step} className="flex gap-3 text-xs text-slate-400 leading-relaxed rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                    <span className="w-6 h-6 shrink-0 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-300 font-mono flex items-center justify-center">{index + 1}</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </section>
      )}

      <div className="space-y-4">
        {data.map((entry) => (
          <div 
            key={entry.id}
            id={entry.id}
            className={`border rounded-xl transition-all duration-300 overflow-hidden ${
              expandedId === entry.id 
                ? `bg-slate-900 ${currentTheme.activeBorder} ${currentTheme.activeShadow}` 
                : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div 
              onClick={() => toggleExpand(entry.id)}
              className="p-3 sm:p-5 cursor-pointer flex items-start sm:items-center justify-between gap-2 group"
            >
              <div className="flex min-w-0 items-start sm:items-center gap-3 sm:gap-4">
                <div className={`
                  min-w-[72px] sm:min-w-[90px] h-10 px-2 rounded-lg flex items-center justify-center font-mono font-bold text-[9px] sm:text-[10px] md:text-xs shrink-0 transition-colors text-center
                  ${expandedId === entry.id 
                    ? currentTheme.badgeActive
                    : `bg-slate-950 text-slate-500 border border-slate-800 ${currentTheme.badgeHover}`
                  }
                `}>
                  {formatId(entry.id)}
                </div>
                <div className="min-w-0">
                  <h3 className={`break-words text-base sm:text-xl font-bold transition-colors ${expandedId === entry.id ? 'text-white' : 'text-slate-200 group-hover:text-white'}`}>
                    {entry.title}
                  </h3>
                  <div className={`text-sm transition-colors mt-1 ${expandedId === entry.id ? 'text-slate-400' : 'text-slate-500 group-hover:text-slate-400 line-clamp-1'}`}>
                    {entry.description}
                  </div>
                </div>
              </div>
              <ChevronDown className={`mt-2 sm:mt-0 w-5 h-5 sm:w-6 sm:h-6 shrink-0 text-slate-500 transition-transform duration-300 ${expandedId === entry.id ? `rotate-180 ${currentTheme.iconActive}` : 'group-hover:text-slate-300'}`} />
            </div>

            <div className={`
              overflow-hidden transition-[max-height] duration-500 ease-in-out
              ${expandedId === entry.id ? 'max-h-[20000px] opacity-100' : 'max-h-0 opacity-0'}
            `}>
              <div className="p-3 sm:p-6 pt-0 border-t border-slate-800/50">
                {entry.whyUnique && (
                  <div className="mt-6 mb-6 rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
                    <h4 className="text-xs font-bold text-orange-300 uppercase tracking-wider mb-1.5">Why this risk is distinct</h4>
                    <p className="text-sm text-slate-300 leading-relaxed">{entry.whyUnique}</p>
                  </div>
                )}
                <div className="grid lg:grid-cols-2 gap-8 mt-6">
                  <div className="space-y-6">
                    <div>
                      <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                        <AlertTriangle className="w-4 h-4 text-orange-400" />
                        {entry.whyUnique ? 'Risk mechanics & impact' : 'Common risks'}
                      </h4>
                      <ul className="space-y-2">
                        {entry.commonRisks.map((risk, idx) => (
                          <li key={idx} className="flex items-start gap-3 text-slate-300 text-sm bg-slate-950/50 p-3 rounded-lg border border-slate-800/50">
                            <span className="w-1.5 h-1.5 rounded-full bg-orange-500 mt-2 shrink-0"></span>
                            {risk}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {entry.realWorldEvidence && entry.realWorldEvidence.length > 0 && (
                      <div>
                        <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                          <BookOpen className="w-4 h-4 text-blue-400" />
                          Real-world evidence
                        </h4>
                        <ul className="space-y-2 max-h-[520px] overflow-y-auto pr-1" style={{ scrollbarGutter: 'stable' }}>
                          {entry.realWorldEvidence.map((evidence, idx) => (
                            <li key={idx} className="flex items-start gap-3 text-slate-300 text-sm bg-blue-500/5 p-3 rounded-lg border border-blue-500/10">
                              <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-2 shrink-0" />
                              <span className="leading-relaxed">{evidence}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {entry.attackScenarios.length > 0 && (
                      <div>
                        <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                          <Target className="w-4 h-4 text-red-400" />
                          Attack Scenarios
                        </h4>
                        <div
                          className={`space-y-3 ${entry.attackScenarios.length > 4 ? 'max-h-[520px] overflow-y-auto pr-1' : ''}`}
                          style={{ scrollbarGutter: 'stable' }}
                        >
                          {entry.attackScenarios.map((scenario, idx) => (
                            <div key={idx} className="bg-red-500/5 p-4 rounded-lg border border-red-500/10">
                              <div className="font-bold text-red-400 text-sm mb-1">{scenario.title}</div>
                              <p className="text-slate-400 text-sm leading-relaxed">{scenario.description}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {(() => {
                      const incidentLinks = INCIDENTS_BY_THREAT_ID[entry.id] || [];
                      if (incidentLinks.length === 0) return null;
                      return (
                        <div>
                          <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                            <Flame className="w-4 h-4 text-amber-400" />
                            Real-World Incidents & Case Studies
                          </h4>
                          <div
                            className={`space-y-2 ${incidentLinks.length > 4 ? 'max-h-[240px] overflow-y-auto pr-1' : ''}`}
                            style={{ scrollbarGutter: 'stable' }}
                          >
                            {incidentLinks.map((incident, idx) => (
                              <div
                                key={idx}
                                onClick={() => setSelectedIncident(getEnrichedIncident(incident, entry.id))}
                                className="flex items-center justify-between gap-2 bg-slate-950/60 p-3 rounded-lg border border-slate-800/60 hover:border-amber-500/40 transition-all group cursor-pointer hover:bg-slate-900/80"
                              >
                                <div className="flex items-start gap-2 min-w-0">
                                  <Flame className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
                                  <span className="text-sm text-slate-300 group-hover:text-amber-300 line-clamp-2 transition-colors">
                                    {incident.title}
                                  </span>
                                </div>
                                <a
                                  href={incident.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  onClick={(e) => e.stopPropagation()}
                                  className="p-1 text-slate-500 hover:text-amber-400 transition-colors shrink-0"
                                  title="Open direct external citation"
                                >
                                  <ExternalLink className="w-3.5 h-3.5" />
                                </a>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })()}
                  </div>

                  <div className="space-y-6">
                    <div>
                      <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        Prevention & Mitigation
                      </h4>
                      <ul className="space-y-2">
                        {entry.preventionStrategies.map((strategy, idx) => (
                          <li key={idx} className="flex items-start gap-3 text-slate-300 text-sm bg-emerald-500/5 p-3 rounded-lg border border-emerald-500/10">
                            <Shield className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                            {strategy}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {entry.implementationNotes && entry.implementationNotes.length > 0 && (
                      <div>
                        <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                          <ListChecks className="w-4 h-4 text-cyan-400" />
                          Implementation guidance
                        </h4>
                        <div className="space-y-3">
                          {entry.implementationNotes.map((note) => (
                            <div key={note.title} className="rounded-lg border border-cyan-500/10 bg-cyan-500/5 p-4">
                              <div className="font-bold text-cyan-300 text-sm mb-1">{note.title}</div>
                              <p className="text-slate-400 text-sm leading-relaxed whitespace-pre-line">{note.content}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {(entry.owaspMappings?.length || entry.otherMappings?.length) && (
                      <div className="pt-6 border-t border-slate-800">
                        <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3"><Shield className="w-4 h-4 text-purple-400" />Framework mappings</h4>
                        <div className="space-y-4">
                          {entry.owaspMappings && (
                            <div>
                              <div className="text-[10px] uppercase tracking-wider font-bold text-slate-500 mb-2">OWASP / AISVS</div>
                              <div className="flex flex-wrap gap-2">{entry.owaspMappings.map((mapping) => <span key={mapping} className="px-2.5 py-1 rounded-md border border-purple-500/20 bg-purple-500/5 text-[11px] text-purple-200">{mapping}</span>)}</div>
                            </div>
                          )}
                          {entry.otherMappings && entry.otherMappings.length > 0 && (
                            <div>
                              <div className="text-[10px] uppercase tracking-wider font-bold text-slate-500 mb-2">Other mappings</div>
                              <div className="flex flex-wrap gap-2">{entry.otherMappings.map((mapping) => <span key={mapping} className="px-2.5 py-1 rounded-md border border-slate-700 bg-slate-950 text-[11px] text-slate-300">{mapping}</span>)}</div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {entry.maestroMappings && entry.maestroMappings.length > 0 && (
                      <div className="pt-6 border-t border-slate-800">
                        <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3"><Layers3 className="w-4 h-4 text-indigo-400" />CSA MAESTRO layers</h4>
                        <div className="space-y-2">
                          {entry.maestroMappings.map((mapping) => (
                            <div key={`${mapping.layer}-${mapping.name}`} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                              <div className="flex flex-wrap gap-2 items-baseline mb-1"><span className="font-mono text-xs text-indigo-300">{mapping.layer}</span><span className="text-xs font-bold text-slate-200">{mapping.name}</span></div>
                              <p className="text-xs text-slate-400 leading-relaxed">{mapping.details}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {entry.relatedRisks && entry.relatedRisks.length > 0 && (
                      <div className="pt-6 border-t border-slate-800">
                        <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                          <GitBranch className="w-4 h-4 text-orange-400" />
                          Related risks ({entry.relatedRisks.length})
                        </h4>
                        <div className="space-y-2">
                          {entry.relatedRisks.map((risk) => (
                            <button 
                              key={risk.id}
                              type="button"
                              onClick={() => setSelectedThreatId(risk.id)}
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

                  </div>
                </div>

                {/* Full-Width Best Tools Section (Spans 100% of card width across both columns) */}
                {(() => {
                  const mappedTools = TOOLS_BY_THREAT_ID[entry.id] || [];
                  const mergedTools = mergeTools(mappedTools, entry.suggestedTools || []);
                  if (mergedTools.length === 0) return null;
                  const filter = getToolFilter(entry.id);
                  const isCostFree = (cost: string) => cost.toLowerCase().includes('free');
                  const isCostPaid = (cost: string) => !cost.toLowerCase().startsWith('free') || cost.includes('/') || cost.includes('$') || cost.includes('€') || cost.includes('~');
                  const freeCount = mergedTools.filter(t => isCostFree(t.cost)).length;
                  const paidCount = mergedTools.filter(t => isCostPaid(t.cost)).length;
                  const filteredTools = mergedTools.filter(tool => {
                    const categoryValue = tool.category || 'Defensive';
                    const categoryOk = filter.category === 'all'
                      ? true
                      : filter.category === 'defensive'
                        ? categoryValue === 'Defensive' || categoryValue === 'Both'
                        : categoryValue === 'Offensive' || categoryValue === 'Both';
                    const pricingOk = filter.pricing === 'all'
                      ? true
                      : filter.pricing === 'free'
                        ? isCostFree(tool.cost)
                        : isCostPaid(tool.cost);
                    return categoryOk && pricingOk;
                  });
                  return (
                    <div className="pt-6 mt-6 border-t border-slate-800">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                        <h4 className="flex items-center gap-2 text-sm font-bold text-cyan-400 uppercase tracking-wider">
                          <Wrench className="w-4 h-4" />
                          Recommended Security Tools ({mergedTools.length})
                        </h4>

                        <div className="flex flex-wrap items-center gap-2">
                          <div className="inline-flex rounded-lg border border-slate-800 bg-slate-950 p-0.5 text-[10px] font-bold uppercase tracking-wider">
                            <button
                              onClick={() => setToolFilter(entry.id, { category: 'all' })}
                              className={`px-2.5 py-1 rounded-md transition-colors ${
                                filter.category === 'all'
                                  ? 'bg-slate-800 text-white'
                                  : 'text-slate-400 hover:text-white'
                              }`}
                            >
                              All ({mergedTools.length})
                            </button>
                            <button
                              onClick={() => setToolFilter(entry.id, { category: 'defensive' })}
                              className={`px-2.5 py-1 rounded-md transition-colors ${
                                filter.category === 'defensive'
                                  ? 'bg-emerald-500/20 text-emerald-300'
                                  : 'text-slate-400 hover:text-emerald-300'
                              }`}
                            >
                              Defensive
                            </button>
                            <button
                              onClick={() => setToolFilter(entry.id, { category: 'offensive' })}
                              className={`px-2.5 py-1 rounded-md transition-colors ${
                                filter.category === 'offensive'
                                  ? 'bg-rose-500/20 text-rose-300'
                                  : 'text-slate-400 hover:text-rose-300'
                              }`}
                            >
                              Offensive
                            </button>
                          </div>

                          <div className="inline-flex rounded-lg border border-slate-800 bg-slate-950 p-0.5 text-[10px] font-bold uppercase tracking-wider">
                            <button
                              onClick={() => setToolFilter(entry.id, { pricing: 'all' })}
                              className={`px-2.5 py-1 rounded-md transition-colors ${
                                filter.pricing === 'all'
                                  ? 'bg-slate-800 text-white'
                                  : 'text-slate-400 hover:text-white'
                              }`}
                            >
                              All Pricing
                            </button>
                            <button
                              onClick={() => setToolFilter(entry.id, { pricing: 'free' })}
                              className={`px-2.5 py-1 rounded-md transition-colors ${
                                filter.pricing === 'free'
                                  ? 'bg-emerald-500/20 text-emerald-300'
                                  : 'text-slate-400 hover:text-emerald-300'
                              }`}
                            >
                              Free ({freeCount})
                            </button>
                            <button
                              onClick={() => setToolFilter(entry.id, { pricing: 'paid' })}
                              className={`px-2.5 py-1 rounded-md transition-colors ${
                                filter.pricing === 'paid'
                                  ? 'bg-amber-500/20 text-amber-300'
                                  : 'text-slate-400 hover:text-amber-300'
                              }`}
                            >
                              Paid ({paidCount})
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                        {filteredTools.map((tool, idx) => (
                          <div 
                            key={idx} 
                            onClick={() => setSelectedTool(tool)}
                            className="bg-slate-950 border border-slate-800/80 p-4 rounded-xl group/tool hover:border-cyan-500/50 transition-all cursor-pointer hover:bg-slate-900/40 shadow-sm flex flex-col justify-between"
                          >
                            <div>
                              <div className="flex items-start justify-between gap-2 mb-2">
                                <div className="flex items-center gap-2">
                                  <span className="text-white font-bold text-sm group-hover/tool:text-cyan-300 transition-colors">
                                    {tool.name}
                                  </span>
                                  <Info className="w-3.5 h-3.5 text-slate-500 group-hover/tool:text-cyan-400 transition-colors" />
                                </div>
                                <div className="flex gap-1.5 flex-wrap justify-end">
                                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider flex items-center gap-1 ${
                                    tool.type === 'Local' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                                  }`}>
                                    {tool.type === 'Local' ? <Lock className="w-2 h-2" /> : <Globe className="w-2 h-2" />}
                                    {tool.type}
                                  </span>
                                  {(() => {
                                    const isFreeOnly = tool.cost.trim().toLowerCase() === 'free';
                                    const hasFreeTier = tool.cost.toLowerCase().includes('free');
                                    const costStyle = isFreeOnly
                                      ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                                      : hasFreeTier
                                      ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20'
                                      : 'text-amber-400 bg-amber-500/10 border-amber-500/20';
                                    return (
                                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border font-mono ${costStyle}`}>
                                        {tool.cost}
                                      </span>
                                    );
                                  })()}
                                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
                                    (tool.category || 'Defensive') === 'Offensive'
                                      ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                                      : (tool.category || 'Defensive') === 'Both'
                                        ? 'bg-purple-500/15 text-purple-300 border border-purple-500/30'
                                        : 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20'
                                  }`}>
                                    {tool.category || 'Defensive'}
                                  </span>
                                </div>
                              </div>
                              <p className="text-xs text-slate-400 leading-relaxed line-clamp-2">
                                {tool.description}
                              </p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })()}

                {/* Full-Width Reference Links */}
                {entry.references.length > 0 && (
                  <div className="pt-6 mt-6 border-t border-slate-800">
                    <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                      <ExternalLink className="w-4 h-4 text-blue-400" />
                      Reference Links
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {entry.references.map((ref, idx) => (
                        <a 
                          key={idx}
                          href={ref.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-blue-400 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 rounded-md transition-colors"
                        >
                          {ref.title}
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Threat Detail Modal (Opens when clicking related risks or threat references) */}
      <ThreatDetailModal
        threatId={selectedThreatId}
        onClose={() => setSelectedThreatId(null)}
        onNavigateToOwasp={openRelatedEntry}
        onSelectTool={setSelectedTool}
        onSelectIncident={setSelectedIncident}
      />

      {/* Incident Detail Inspection Modal */}
      <IncidentDetailModal 
        incident={selectedIncident} 
        onClose={() => setSelectedIncident(null)} 
        onNavigateToOwasp={openRelatedEntry}
      />
    </div>
  );
};

export default OwaspTop10View;
