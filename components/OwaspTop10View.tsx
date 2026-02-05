
import React, { useState, useEffect } from 'react';
import { OwaspTop10Entry } from '../types';
import { ChevronDown, Shield, AlertTriangle, ExternalLink, ShieldCheck, Target, Wrench, Globe, Lock } from 'lucide-react';
import { TOOLS_BY_THREAT_ID, mergeTools } from '../tools_catalog';

interface OwaspTop10ViewProps {
  initialExpandedId?: string | null;
  data: OwaspTop10Entry[];
  title: string;
  description: string;
  colorTheme?: 'pink' | 'emerald' | 'orange' | 'blue' | 'cyan';
}

const OwaspTop10View: React.FC<OwaspTop10ViewProps> = ({ 
  initialExpandedId, 
  data, 
  title, 
  description,
  colorTheme = 'pink' 
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(initialExpandedId || null);
  const [toolFilters, setToolFilters] = useState<Record<string, { category: 'all' | 'defensive' | 'offensive'; pricing: 'all' | 'free' | 'paid' }>>({});
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({});

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

  const getToolFilter = (id: string) => toolFilters[id] || { category: 'all', pricing: 'all' };
  const toggleTools = (id: string) => {
    setExpandedTools(prev => ({ ...prev, [id]: !prev[id] }));
  };
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

  const formatId = (id: string) => {
    if (id.includes(':')) return id.split(':')[0];
    return id;
  };

  return (
    <div className="p-4 md:p-8 max-w-6xl mx-auto animate-in fade-in duration-500">
      <div className="mb-10 text-center">
        <h1 className="text-3xl md:text-4xl font-bold text-white mb-4">
          {title}
        </h1>
        <p className="text-slate-400 max-w-2xl mx-auto">
          {description}
        </p>
      </div>

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
              className="p-5 cursor-pointer flex items-center justify-between group"
            >
              <div className="flex items-center gap-4">
                <div className={`
                  min-w-[90px] h-10 px-2 rounded-lg flex items-center justify-center font-mono font-bold text-[10px] md:text-xs shrink-0 transition-colors text-center
                  ${expandedId === entry.id 
                    ? currentTheme.badgeActive
                    : `bg-slate-950 text-slate-500 border border-slate-800 ${currentTheme.badgeHover}`
                  }
                `}>
                  {formatId(entry.id)}
                </div>
                <div>
                  <h3 className={`text-xl font-bold transition-colors ${expandedId === entry.id ? 'text-white' : 'text-slate-200 group-hover:text-white'}`}>
                    {entry.title}
                  </h3>
                  <div className={`text-sm transition-colors mt-1 ${expandedId === entry.id ? 'text-slate-400' : 'text-slate-500 group-hover:text-slate-400 line-clamp-1'}`}>
                    {entry.description}
                  </div>
                </div>
              </div>
              <ChevronDown className={`w-6 h-6 text-slate-500 transition-transform duration-300 ${expandedId === entry.id ? `rotate-180 ${currentTheme.iconActive}` : 'group-hover:text-slate-300'}`} />
            </div>

            <div className={`
              overflow-hidden transition-[max-height] duration-500 ease-in-out
              ${expandedId === entry.id ? 'max-h-[3000px] opacity-100' : 'max-h-0 opacity-0'}
            `}>
              <div className="p-6 pt-0 border-t border-slate-800/50">
                <div className="grid lg:grid-cols-2 gap-8 mt-6">
                  <div className="space-y-6">
                    <div>
                      <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                        <AlertTriangle className="w-4 h-4 text-orange-400" />
                        Common Risks
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

                    {entry.attackScenarios.length > 0 && (
                      <div>
                        <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
                          <Target className="w-4 h-4 text-red-400" />
                          Attack Scenarios
                        </h4>
                        <div className="space-y-3">
                          {entry.attackScenarios.map((scenario, idx) => (
                            <div key={idx} className="bg-red-500/5 p-4 rounded-lg border border-red-500/10">
                              <div className="font-bold text-red-400 text-sm mb-1">{scenario.title}</div>
                              <p className="text-slate-400 text-sm">{scenario.description}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
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

                    {/* Best Tools Section - Now above Reference Links */}
                    {(() => {
                      const mappedTools = TOOLS_BY_THREAT_ID[entry.id] || [];
                      const mergedTools = mergeTools(mappedTools, entry.suggestedTools || []);
                      if (mergedTools.length === 0) return null;
                      const filter = getToolFilter(entry.id);
                      const isCostFree = (cost: string) => cost === 'Free' || cost === 'Free+Paid';
                      const isCostPaid = (cost: string) => cost === 'Paid' || cost === 'Free+Paid' || cost.includes('€');
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
                      const isExpanded = !!expandedTools[entry.id];
                      const visibleTools = isExpanded ? filteredTools : filteredTools.slice(0, 4);
                      return (
                      <div className="pt-6 border-t border-slate-800">
                        <h4 className="flex items-center gap-2 text-sm font-bold text-cyan-400 uppercase tracking-wider mb-4">
                          <Wrench className="w-4 h-4" />
                          Recommended Security Tools
                        </h4>
                        <div className="flex flex-wrap gap-2 mb-3">
                          <button
                            onClick={() => setToolFilter(entry.id, { category: 'all' })}
                            className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border transition-colors ${
                              filter.category === 'all'
                                ? 'bg-slate-800 text-white border-slate-700'
                                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white hover:border-slate-700'
                            }`}
                          >
                            All ({mergedTools.length})
                          </button>
                          <button
                            onClick={() => setToolFilter(entry.id, { category: 'defensive' })}
                            className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border transition-colors ${
                              filter.category === 'defensive'
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-emerald-300 hover:border-emerald-500/30'
                            }`}
                          >
                            Defensive
                          </button>
                          <button
                            onClick={() => setToolFilter(entry.id, { category: 'offensive' })}
                            className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border transition-colors ${
                              filter.category === 'offensive'
                                ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-rose-300 hover:border-rose-500/30'
                            }`}
                          >
                            Offensive
                          </button>
                        </div>
                        <div className="flex flex-wrap gap-2 mb-4">
                          <button
                            onClick={() => setToolFilter(entry.id, { pricing: 'all' })}
                            className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border transition-colors ${
                              filter.pricing === 'all'
                                ? 'bg-slate-800 text-white border-slate-700'
                                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white hover:border-slate-700'
                            }`}
                          >
                            All Pricing ({mergedTools.length})
                          </button>
                          <button
                            onClick={() => setToolFilter(entry.id, { pricing: 'free' })}
                            className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border transition-colors ${
                              filter.pricing === 'free'
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-emerald-300 hover:border-emerald-500/30'
                            }`}
                          >
                            Free ({freeCount})
                          </button>
                          <button
                            onClick={() => setToolFilter(entry.id, { pricing: 'paid' })}
                            className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border transition-colors ${
                              filter.pricing === 'paid'
                                ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-amber-300 hover:border-amber-500/30'
                            }`}
                          >
                            Paid ({paidCount})
                          </button>
                        </div>
                        <div
                          className={`grid gap-3 pr-1 ${isExpanded ? 'max-h-[520px] overflow-y-auto' : ''}`}
                          style={{ scrollbarGutter: 'stable' }}
                        >
                          {visibleTools.map((tool, idx) => (
                            <div key={idx} className="bg-slate-950 border border-slate-800 p-4 rounded-xl group/tool hover:border-cyan-500/50 transition-all">
                              <div className="flex justify-between items-start mb-2">
                                <a 
                                  href={tool.url} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  className="text-white font-bold text-sm hover:text-cyan-400 flex items-center gap-2 transition-colors"
                                >
                                  {tool.name}
                                  <ExternalLink className="w-3 h-3 opacity-0 group-hover/tool:opacity-100 transition-opacity" />
                                </a>
                                <div className="flex gap-1.5 flex-wrap justify-end">
                                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider flex items-center gap-1 ${
                                    tool.type === 'Local' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                                  }`}>
                                    {tool.type === 'Local' ? <Lock className="w-2 h-2" /> : <Globe className="w-2 h-2" />}
                                    {tool.type}
                                  </span>
                                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-900 text-slate-400 border border-slate-800 font-mono">
                                    {tool.cost}
                                  </span>
                                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
                                    (tool.category || 'Defensive') === 'Offensive'
                                      ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                                      : (tool.category || 'Defensive') === 'Both'
                                        ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                                        : 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20'
                                  }`}>
                                    {tool.category || 'Defensive'}
                                  </span>
                                </div>
                              </div>
                              <p className="text-xs text-slate-400 leading-relaxed">
                                {tool.description}
                              </p>
                            </div>
                          ))}
                        </div>
                        {filteredTools.length > 4 && (
                          <button
                            onClick={() => toggleTools(entry.id)}
                            className="mt-3 text-[10px] font-bold uppercase tracking-wider text-cyan-400 hover:text-cyan-300"
                          >
                            {isExpanded ? 'Show less' : `Show all (${filteredTools.length})`}
                          </button>
                        )}
                      </div>
                      );
                    })()}

                    {entry.references.length > 0 && (
                      <div className="pt-6 border-t border-slate-800">
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
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default OwaspTop10View;
