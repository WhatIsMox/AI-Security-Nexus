import React, { useState, useMemo } from 'react';
import { 
  Terminal, Search, Filter, ExternalLink, Shield, Wrench, 
  Tag, Layers, ArrowRight, Zap, CheckCircle2, Lock, Cpu, Globe, Info
} from 'lucide-react';
import { TOOLS_BY_THREAT_ID } from '../tools_catalog';
import { getEnrichedTool } from '../tool_details_catalog';
import { ToolDetailModal } from './ToolDetailModal';
import { SecurityTool } from '../types';

export interface ToolDirectoryEntry extends SecurityTool {
  mappedThreats: string[];
}

interface ToolsDirectoryViewProps {
  onNavigateToOwasp: (threatId: string) => void;
}

export const ToolsDirectoryView: React.FC<ToolsDirectoryViewProps> = ({ onNavigateToOwasp }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'All' | 'Defensive' | 'Offensive' | 'Both'>('All');
  const [typeFilter, setTypeFilter] = useState<'All' | 'Local' | 'Third-party'>('All');
  const [costFilter, setCostFilter] = useState<'All' | 'Free' | 'Paid'>('All');
  const [selectedTool, setSelectedTool] = useState<ToolDirectoryEntry | null>(null);

  // Consolidate unique tools with all mapped threats
  const allTools = useMemo<ToolDirectoryEntry[]>(() => {
    const toolMap = new Map<string, ToolDirectoryEntry>();

    for (const [threatId, tools] of Object.entries(TOOLS_BY_THREAT_ID)) {
      for (const rawTool of tools) {
        const tool = getEnrichedTool(rawTool);
        const key = tool.name.toLowerCase().trim();
        if (toolMap.has(key)) {
          const existing = toolMap.get(key)!;
          if (!existing.mappedThreats.includes(threatId)) {
            existing.mappedThreats.push(threatId);
          }
        } else {
          toolMap.set(key, {
            ...tool,
            mappedThreats: [threatId]
          });
        }
      }
    }

    return Array.from(toolMap.values()).sort((a, b) => a.name.localeCompare(b.name));
  }, []);

  // Filtered tools
  const filteredTools = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();

    return allTools.filter(tool => {
      if (categoryFilter !== 'All') {
        if (tool.category !== categoryFilter) return false;
      }

      if (typeFilter !== 'All') {
        if (tool.type !== typeFilter) return false;
      }

      if (costFilter !== 'All') {
        const isFreeOnly = tool.cost.trim().toLowerCase() === 'free';
        const hasFreeOption = tool.cost.toLowerCase().includes('free');
        if (costFilter === 'Free' && !hasFreeOption) return false;
        if (costFilter === 'Paid' && isFreeOnly) return false;
      }

      if (query) {
        const text = `${tool.name} ${tool.description} ${tool.authorOrMaintainer || ''} ${tool.license || ''} ${tool.type} ${tool.cost} ${tool.mappedThreats.join(' ')}`.toLowerCase();
        if (!text.includes(query)) return false;
      }

      return true;
    });
  }, [allTools, searchQuery, categoryFilter, typeFilter, costFilter]);

  return (
    <div className="container-fluid p-3 sm:p-4 md:p-8 max-w-6xl mx-auto animate-in fade-in duration-500">
      {/* Tool Detail Modal Window */}
      <ToolDetailModal 
        tool={selectedTool} 
        onClose={() => setSelectedTool(null)} 
        onNavigateToOwasp={onNavigateToOwasp} 
      />

      {/* Header */}
      <div className="mb-8 border-b border-slate-800 pb-6 flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-purple-500/10 border border-purple-500/30 rounded-full text-purple-300 text-xs font-mono mb-3">
            <Terminal className="w-3.5 h-3.5 text-purple-400" />
            Security Tools Directory
          </div>
          <h2 className="text-2xl md:text-3xl font-bold text-white tracking-tight">AI Security Tooling Matrix</h2>
          <p className="text-slate-400 text-sm md:text-base mt-1">
            Curated catalog of open-source red-team scanners, runtime guardrails, adversarial fuzzers, and DSPM platforms mapped directly to specific threats.
          </p>
        </div>

        <div className="bg-slate-900/90 px-4 py-2 rounded-full border border-slate-800 text-xs md:text-sm text-slate-300 font-mono whitespace-nowrap shrink-0 flex items-center justify-center text-center self-start md:self-auto shadow-sm">
          <span className="font-semibold text-purple-300">{filteredTools.length}</span>
          <span className="text-slate-600 mx-1.5">/</span>
          <span>{allTools.length} TOOLS</span>
        </div>
      </div>

      {/* Search & Filters */}
      <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-4 mb-6 space-y-3">
        {/* Search Input */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search tools by name, author, capability, or threat ID (e.g. 'garak', 'guardrail', 'NVIDIA', 'LLM01', 'SBOM')..."
            className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-3 pt-2 text-xs">
          {/* Posture Category */}
          <div className="flex items-center gap-1">
            <span className="text-slate-500 uppercase font-mono text-[11px] mr-1">Posture:</span>
            {(['All', 'Defensive', 'Offensive', 'Both'] as const).map(cat => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`px-2.5 py-1 rounded transition-all ${
                  categoryFilter === cat
                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Deployment Type */}
          <div className="flex items-center gap-1">
            <span className="text-slate-500 uppercase font-mono text-[11px] mr-1">Type:</span>
            {(['All', 'Local', 'Third-party'] as const).map(t => (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={`px-2.5 py-1 rounded transition-all ${
                  typeFilter === t
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {/* Pricing */}
          <div className="flex items-center gap-1">
            <span className="text-slate-500 uppercase font-mono text-[11px] mr-1">Pricing:</span>
            {(['All', 'Free', 'Paid'] as const).map(c => (
              <button
                key={c}
                onClick={() => setCostFilter(c)}
                className={`px-2.5 py-1 rounded transition-all ${
                  costFilter === c
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {c}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Tools Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredTools.length === 0 ? (
          <div className="col-span-full py-12 text-center text-slate-500 bg-slate-900/30 border border-dashed border-slate-800 rounded-xl">
            <p className="text-sm">No security tools match the active filters.</p>
          </div>
        ) : (
          filteredTools.map(tool => (
            <div 
              key={tool.name}
              onClick={() => setSelectedTool(tool)}
              className="content-auto bg-slate-900/60 border border-slate-800 hover:border-purple-500/50 rounded-xl p-4 transition-all flex flex-col justify-between group hover:bg-slate-900/90 cursor-pointer shadow-sm hover:shadow-[0_0_20px_rgba(168,85,247,0.15)]"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-md bg-purple-500/10 border border-purple-500/20 text-purple-400 group-hover:scale-105 transition-transform">
                      <Terminal className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold text-slate-100 group-hover:text-purple-300 transition-colors text-base leading-tight">
                        {tool.name}
                      </h3>
                      {tool.authorOrMaintainer && (
                        <span className="text-[10px] text-slate-500 font-mono">
                          {tool.authorOrMaintainer}
                        </span>
                      )}
                    </div>
                  </div>

                  <button 
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedTool(tool);
                    }}
                    className="p-1 text-slate-500 hover:text-purple-300 transition-colors"
                    title={`Inspect ${tool.name} details`}
                  >
                    <Info className="w-4 h-4" />
                  </button>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed mb-4 line-clamp-3">
                  {tool.description}
                </p>
              </div>

              <div>
                {/* Meta badges */}
                <div className="flex items-center gap-1.5 flex-wrap mb-3 text-[11px] font-mono">
                  {(() => {
                    const isFreeOnly = tool.cost.trim().toLowerCase() === 'free';
                    const hasFreeTier = tool.cost.toLowerCase().includes('free');
                    const costStyle = isFreeOnly
                      ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                      : hasFreeTier
                      ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20'
                      : 'text-amber-400 bg-amber-500/10 border-amber-500/20';
                    return (
                      <span className={`px-2 py-0.5 rounded border ${costStyle}`}>
                        {tool.cost}
                      </span>
                    );
                  })()}
                  <span className="px-2 py-0.5 rounded border border-slate-800 bg-slate-950 text-slate-400">
                    {tool.type}
                  </span>
                  {tool.category && (
                    <span className="px-2 py-0.5 rounded border border-purple-500/20 bg-purple-500/10 text-purple-300">
                      {tool.category}
                    </span>
                  )}
                </div>

                {/* Threat Mappings */}
                {tool.mappedThreats.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] text-slate-500 uppercase font-mono">Mapped Threats:</span>
                      <span className="text-[10px] text-purple-400/80 font-mono group-hover:text-purple-300 inline-flex items-center gap-0.5">
                        Inspect <ArrowRight className="w-2.5 h-2.5" />
                      </span>
                    </div>
                    <div className="flex items-center gap-1 flex-wrap">
                      {tool.mappedThreats.slice(0, 4).map(tid => (
                        <button
                          key={tid}
                          onClick={(e) => {
                            e.stopPropagation();
                            onNavigateToOwasp(tid);
                          }}
                          className="px-1.5 py-0.5 bg-slate-950 hover:bg-purple-950/40 border border-slate-800 hover:border-purple-500/40 rounded text-[10px] font-mono text-slate-400 hover:text-purple-300 transition-colors"
                        >
                          {tid}
                        </button>
                      ))}
                      {tool.mappedThreats.length > 4 && (
                        <span className="text-[10px] text-slate-500 font-mono">
                          +{tool.mappedThreats.length - 4} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
export default ToolsDirectoryView;

