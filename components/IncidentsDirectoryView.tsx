import React, { useState, useMemo } from 'react';
import { 
  Flame, Search, Filter, ExternalLink, Shield, AlertTriangle, 
  BookOpen, Layers, ArrowRight, Globe, Building2, Calendar
} from 'lucide-react';
import { INCIDENTS_BY_THREAT_ID } from '../incidents_catalog';
import { ExternalResource } from '../types';

interface IncidentDirectoryEntry extends ExternalResource {
  mappedThreats: string[];
}

interface IncidentsDirectoryViewProps {
  onNavigateToOwasp: (threatId: string) => void;
}

export const IncidentsDirectoryView: React.FC<IncidentsDirectoryViewProps> = ({ onNavigateToOwasp }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [frameworkFilter, setFrameworkFilter] = useState<'All' | 'LLM' | 'ML' | 'ASI' | 'AST' | 'SAIF' | 'MCP'>('All');

  // Consolidate unique incidents with all mapped threats
  const allIncidents = useMemo<IncidentDirectoryEntry[]>(() => {
    const incidentMap = new Map<string, IncidentDirectoryEntry>();

    for (const [threatId, incidents] of Object.entries(INCIDENTS_BY_THREAT_ID)) {
      for (const incident of incidents) {
        const key = incident.title.toLowerCase().trim();
        if (incidentMap.has(key)) {
          const existing = incidentMap.get(key)!;
          if (!existing.mappedThreats.includes(threatId)) {
            existing.mappedThreats.push(threatId);
          }
        } else {
          incidentMap.set(key, {
            ...incident,
            mappedThreats: [threatId]
          });
        }
      }
    }

    return Array.from(incidentMap.values()).sort((a, b) => a.title.localeCompare(b.title));
  }, []);

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();

    return allIncidents.filter(incident => {
      if (frameworkFilter !== 'All') {
        const hasMatchingThreat = incident.mappedThreats.some(tid => tid.startsWith(frameworkFilter));
        if (!hasMatchingThreat) return false;
      }

      if (query) {
        const text = `${incident.title} ${incident.url} ${incident.mappedThreats.join(' ')}`.toLowerCase();
        if (!text.includes(query)) return false;
      }

      return true;
    });
  }, [allIncidents, searchQuery, frameworkFilter]);

  return (
    <div className="container-fluid p-3 sm:p-4 md:p-8 max-w-6xl mx-auto animate-in fade-in duration-500">
      {/* Header */}
      <div className="mb-8 border-b border-slate-800 pb-6 flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-amber-500/10 border border-amber-500/30 rounded-full text-amber-300 text-xs font-mono mb-3">
            <Flame className="w-3.5 h-3.5 text-amber-400" />
            AI Threat Intelligence & Case Studies
          </div>
          <h2 className="text-2xl md:text-3xl font-bold text-white tracking-tight">Real-World AI Incidents & Exploits</h2>
          <p className="text-slate-400 text-sm md:text-base mt-1">
            Empirical breach reports, CVE advisories, and peer-reviewed research papers mapped to AI threat categories.
          </p>
        </div>

        <div className="bg-slate-900 px-3 py-2 rounded-full border border-slate-800 text-xs md:text-sm text-slate-400 font-mono">
          {filteredIncidents.length} / {allIncidents.length} CASE STUDIES
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
            placeholder="Search real-world exploits by keyword, company, arXiv ID, CVE, or threat ID (e.g. 'Samsung', 'Bing', 'SolarWinds', 'CVE-2026')..."
            className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        {/* Framework Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-2 text-xs">
          <span className="text-slate-500 uppercase font-mono text-[11px] mr-2">Framework:</span>
          {(['All', 'LLM', 'ML', 'ASI', 'AST', 'SAIF', 'MCP'] as const).map(fw => (
            <button
              key={fw}
              onClick={() => setFrameworkFilter(fw)}
              className={`px-2.5 py-1 rounded transition-all font-mono ${
                frameworkFilter === fw
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {fw}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredIncidents.length === 0 ? (
          <div className="col-span-full py-12 text-center text-slate-500 bg-slate-900/30 border border-dashed border-slate-800 rounded-xl">
            <p className="text-sm">No real-world incidents match the active search or framework filter.</p>
          </div>
        ) : (
          filteredIncidents.map((incident, idx) => (
            <div 
              key={idx}
              className="bg-slate-900/60 border border-slate-800 hover:border-amber-500/40 rounded-xl p-4 transition-all flex flex-col justify-between group hover:bg-slate-900/90"
            >
              <div>
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="flex items-start gap-2.5">
                    <div className="p-1.5 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-400 shrink-0 mt-0.5">
                      <Flame className="w-4 h-4" />
                    </div>
                    <h3 className="font-semibold text-slate-100 group-hover:text-amber-300 transition-colors text-sm leading-snug">
                      {incident.title}
                    </h3>
                  </div>

                  <a 
                    href={incident.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-1 text-slate-500 hover:text-amber-400 transition-colors shrink-0"
                    title="Read full advisory / research paper"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              </div>

              {/* Mapped Threats */}
              <div className="pt-3 border-t border-slate-800/80 mt-3 flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-1 flex-wrap">
                  <span className="text-[10px] text-slate-500 uppercase font-mono mr-1">Threats:</span>
                  {incident.mappedThreats.map(tid => (
                    <button
                      key={tid}
                      onClick={() => onNavigateToOwasp(tid)}
                      className="px-1.5 py-0.5 bg-slate-950 hover:bg-amber-950/40 border border-slate-800 hover:border-amber-500/40 rounded text-[10px] font-mono text-slate-400 hover:text-amber-300 transition-colors"
                    >
                      {tid}
                    </button>
                  ))}
                </div>

                <a 
                  href={incident.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[11px] text-amber-400/80 hover:text-amber-300 flex items-center gap-1 font-mono group-hover:translate-x-0.5 transition-transform"
                >
                  <span>Source</span>
                  <ArrowRight className="w-3 h-3" />
                </a>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
export default IncidentsDirectoryView;
