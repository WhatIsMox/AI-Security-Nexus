
import React from 'react';
import { 
  Box, Database, LayoutGrid, Server, BookOpen, Shield, Book, X, 
  Brain, Cpu, Bot, Gavel, Network, FileText, Search, CheckCircle2, 
  Terminal, Flame, Sparkles, ChevronDown, Globe, SlidersHorizontal 
} from 'lucide-react';
import { Pillar, GlobalDomain } from '../types';
import { TEST_DATA } from '../data';

export type AppView = 
  | 'dashboard' 
  | 'tests' 
  | 'detail' 
  | 'threat-model' 
  | 'mitre-atlas'
  | 'owasp-top10' 
  | 'owasp-ml-top10' 
  | 'owasp-agent-top10' 
  | 'owasp-saif-top10' 
  | 'owasp-mcp-top10' 
  | 'secure-mcp-guide' 
  | 'genai-data-security'
  | 'audit-checklist'
  | 'tools'
  | 'incidents';

export type ActivePillarKey = Pillar | 'ALL' | 'MITREATLAS' | 'TOP10' | 'MLTOP10' | 'AGENTTOP10' | 'SAIFTOP10' | 'MCPTOP10' | 'SECUREMCPGUIDE' | 'GENAIDATASECURITY';

const DOMAIN_OPTIONS: { id: GlobalDomain; label: string; icon: React.ComponentType<{ className?: string }>; color: string; badge: string }[] = [
  { id: 'ALL', label: 'All AI Domains', icon: Globe, color: 'text-cyan-400', badge: 'Global' },
  { id: 'LLM', label: 'Large Language Models', icon: Brain, color: 'text-cyan-400', badge: 'LLM' },
  { id: 'ML', label: 'Machine Learning', icon: Cpu, color: 'text-emerald-400', badge: 'ML' },
  { id: 'AGENT', label: 'Agentic Applications', icon: Bot, color: 'text-pink-400', badge: 'Agents' },
  { id: 'MCP', label: 'Model Context Protocol', icon: Network, color: 'text-indigo-400', badge: 'MCP' },
];

interface SidebarProps {
  activePillar: ActivePillarKey;
  currentView: AppView;
  onSelectPillar: (pillar: ActivePillarKey) => void;
  onSelectDashboard: () => void;
  onSelectThreatModel: () => void;
  onSelectAuditChecklist: () => void;
  onSelectTools: () => void;
  onSelectIncidents: () => void;
  onOpenSearch: () => void;
  isOpen: boolean;
  onClose: () => void;
  globalDomain: GlobalDomain;
  onSelectDomain: (domain: GlobalDomain) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ 
  activePillar, 
  currentView,
  onSelectPillar, 
  onSelectDashboard, 
  onSelectThreatModel, 
  onSelectAuditChecklist,
  onSelectTools,
  onSelectIncidents,
  onOpenSearch,
  isOpen,
  onClose,
  globalDomain,
  onSelectDomain
}) => {
  const currentDomainOption = DOMAIN_OPTIONS.find(opt => opt.id === globalDomain) || DOMAIN_OPTIONS[0];
  const DomainIcon = currentDomainOption.icon;

  const navItems = [
    { id: Pillar.APP, icon: LayoutGrid, label: "Application Testing", color: "text-blue-400" },
    { id: Pillar.MODEL, icon: Box, label: "Model Testing", color: "text-purple-400" },
    { id: Pillar.INFRA, icon: Server, label: "Infrastructure", color: "text-amber-400" },
    { id: Pillar.DATA, icon: Database, label: "Data Testing", color: "text-emerald-400" },
  ];

  return (
    <>
      {/* Mobile Overlay */}
      {isOpen && (
        <div 
          className="mobile-nav-overlay fixed inset-0 bg-black/50 backdrop-blur-sm z-30 md:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Container */}
      <aside id="primary-navigation" aria-label="Primary navigation" className={`app-sidebar
        fixed top-0 left-0 h-full w-64 bg-slate-950 border-r border-slate-800 
        flex flex-col z-40 transition-transform duration-300 ease-in-out
        ${isOpen ? 'translate-x-0' : '-translate-x-full'} 
        md:translate-x-0
      `}>
        {/* Brand Header */}
        <div className="p-5 flex items-center justify-between border-b border-slate-800">
          <button
            type="button"
            className="flex items-center space-x-3 text-left cursor-pointer focus:outline-none focus:ring-1 focus:ring-cyan-500/50 rounded-lg p-1"
            onClick={() => { onSelectDashboard(); onClose(); }}
            aria-label="Return to Dashboard"
          >
            <div className="relative w-9 h-9 rounded-xl overflow-hidden border border-cyan-500/30 bg-slate-900 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.25)] group shrink-0">
              <div className="absolute inset-0 bg-cyan-500/20 blur-md group-hover:bg-cyan-400/30 transition-all pointer-events-none"></div>
              <img src="./favicon.svg" alt="AI Security Nexus" className="w-full h-full object-cover relative z-10" />
            </div>
            <div>
              <h1 className="font-bold text-slate-100 leading-tight tracking-tight uppercase text-sm">AI Security</h1>
              <p className="text-[10px] text-cyan-400 font-mono font-semibold tracking-wide">Nexus Platform</p>
            </div>
          </button>
          <button onClick={onClose} type="button" aria-label="Close navigation menu" className="mobile-menu-button md:hidden text-slate-400 hover:text-white">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Global Search Quick Button */}
        <div className="p-3 border-b border-slate-800/80">
          <button
            type="button"
            onClick={() => { onOpenSearch(); onClose(); }}
            className="w-full flex items-center justify-between px-3 py-2 bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 rounded-xl text-xs text-slate-400 hover:text-slate-200 transition-all group shadow-sm"
          >
            <div className="flex items-center gap-2">
              <Search className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
              <span>Search Nexus...</span>
            </div>
            <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-mono text-slate-500 bg-slate-950 border border-slate-800 rounded">
              ⌘K
            </kbd>
          </button>
        </div>

        {/* Global Domain Scope Selector */}
        <div className="px-3 py-2.5 border-b border-slate-800/80">
          <div className="flex items-center justify-between mb-1.5 px-0.5">
            <label htmlFor="domain-select" className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <SlidersHorizontal className="w-3 h-3 text-cyan-400" />
              <span>Scope Filter</span>
            </label>
            {globalDomain !== 'ALL' ? (
              <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-mono font-semibold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                {currentDomainOption.badge}
              </span>
            ) : (
              <span className="text-[9px] font-mono text-slate-500">
                Global
              </span>
            )}
          </div>
          <div className="relative group">
            <select
              id="domain-select"
              value={globalDomain}
              onChange={(e) => onSelectDomain(e.target.value as GlobalDomain)}
              aria-label="Select AI Domain Focus"
              className="w-full appearance-none bg-slate-900/90 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/40 focus:border-cyan-400 text-slate-200 text-xs font-medium rounded-xl pl-9 pr-8 py-2 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 transition-all cursor-pointer shadow-sm shadow-black/20"
            >
              {DOMAIN_OPTIONS.map((opt) => (
                <option key={opt.id} value={opt.id} className="bg-slate-950 text-slate-200 py-1.5">
                  {opt.label}
                </option>
              ))}
            </select>
            <DomainIcon className={`w-3.5 h-3.5 ${currentDomainOption.color} absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none transition-transform duration-200 group-hover:scale-110`} />
            <ChevronDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyan-400 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none transition-colors" />
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
          {/* Main Navigation */}
          <button
            type="button"
            onClick={() => { onSelectDashboard(); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-sm ${
              currentView === 'dashboard'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-medium'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-4 h-4 shrink-0 text-cyan-400" />
            <span>Overview & Dashboard</span>
          </button>

          <button
            type="button"
            onClick={() => { onSelectThreatModel(); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-sm ${
              currentView === 'threat-model'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-medium'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Shield className="w-4 h-4 shrink-0 text-indigo-400" />
            <span>Threat Modelling</span>
          </button>

          <button
            type="button"
            onClick={() => { onSelectAuditChecklist(); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-sm ${
              currentView === 'audit-checklist'
                ? 'bg-gradient-to-r from-cyan-500/20 to-emerald-500/10 text-cyan-300 border border-cyan-500/30 font-medium'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <CheckCircle2 className="w-4 h-4 shrink-0 text-cyan-400" />
            <span>Audit Checklist & Export</span>
          </button>

          {/* Frameworks & Top 10s */}
          <div className="pt-3 pb-1">
            <p className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
              Frameworks & Standards
            </p>
          </div>

          {(globalDomain === 'ALL' || globalDomain === 'LLM') && (
            <button
              type="button"
              onClick={() => { onSelectPillar('TOP10'); onClose(); }}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
                currentView === 'owasp-top10' || (currentView === 'tests' && activePillar === 'TOP10')
                  ? 'bg-gradient-to-r from-pink-500/20 to-purple-500/10 text-pink-400 border border-pink-500/30'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <Brain className="w-4 h-4 shrink-0 text-pink-400" />
              <span>OWASP Top 10 LLM (2026)</span>
            </button>
          )}

          {(globalDomain === 'ALL' || globalDomain === 'ML') && (
            <button
              type="button"
              onClick={() => { onSelectPillar('MLTOP10'); onClose(); }}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
                currentView === 'owasp-ml-top10' || (currentView === 'tests' && activePillar === 'MLTOP10')
                  ? 'bg-gradient-to-r from-emerald-500/20 to-teal-500/10 text-emerald-400 border border-emerald-500/30'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>OWASP Top 10 ML</span>
            </button>
          )}

          {(globalDomain === 'ALL' || globalDomain === 'AGENT') && (
            <button
              type="button"
              onClick={() => { onSelectPillar('AGENTTOP10'); onClose(); }}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
                currentView === 'owasp-agent-top10' || (currentView === 'tests' && activePillar === 'AGENTTOP10')
                  ? 'bg-gradient-to-r from-orange-500/20 to-amber-500/10 text-orange-400 border border-orange-500/30'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <Bot className="w-4 h-4 shrink-0 text-orange-400" />
              <span>OWASP Agentic Top 10</span>
            </button>
          )}

          {(globalDomain === 'ALL' || globalDomain === 'MCP') && (
            <button
              type="button"
              onClick={() => { onSelectPillar('MCPTOP10'); onClose(); }}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
                currentView === 'owasp-mcp-top10' || (currentView === 'tests' && activePillar === 'MCPTOP10')
                  ? 'bg-gradient-to-r from-cyan-500/20 to-sky-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <Network className="w-4 h-4 shrink-0 text-cyan-400" />
              <span>OWASP MCP Top 10</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => { onSelectPillar('GENAIDATASECURITY'); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
              currentView === 'genai-data-security' || (currentView === 'tests' && activePillar === 'GENAIDATASECURITY')
                ? 'bg-gradient-to-r from-emerald-500/20 to-cyan-500/10 text-emerald-300 border border-emerald-500/30'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Database className="w-4 h-4 shrink-0 text-emerald-400" />
            <span>OWASP GenAI Data Security</span>
          </button>

          {(globalDomain === 'ALL' || globalDomain === 'MCP') && (
            <button
              type="button"
              onClick={() => { onSelectPillar('SECUREMCPGUIDE'); onClose(); }}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
                currentView === 'secure-mcp-guide' || (currentView === 'tests' && activePillar === 'SECUREMCPGUIDE')
                  ? 'bg-gradient-to-r from-cyan-500/20 to-emerald-500/10 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <FileText className="w-4 h-4 shrink-0 text-cyan-300" />
              <span>Secure MCP Server Guide</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => { onSelectPillar('SAIFTOP10'); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
              currentView === 'owasp-saif-top10' || (currentView === 'tests' && activePillar === 'SAIFTOP10')
                ? 'bg-gradient-to-r from-blue-500/20 to-cyan-500/10 text-blue-400 border border-blue-500/30'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Gavel className="w-4 h-4 shrink-0 text-blue-400" />
            <span>Google SAIF Risk Flow</span>
          </button>

          {/* Testing Pillars & Attack Matrix */}
          <div className="pt-3 pb-1">
            <p className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
              Testing Pillars & Matrix
            </p>
          </div>

          <button
            type="button"
            onClick={() => { onSelectPillar('ALL'); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
              (currentView === 'tests' || currentView === 'detail') && activePillar === 'ALL'
                ? 'bg-slate-800 text-white border border-slate-700'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-4 h-4 shrink-0 text-cyan-400" />
            <span>All {TEST_DATA.length} Security Tests</span>
          </button>

          <button
            type="button"
            onClick={() => { onSelectPillar('MITREATLAS'); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
              currentView === 'mitre-atlas' || (currentView === 'tests' && activePillar === 'MITREATLAS')
                ? 'bg-gradient-to-r from-orange-500/20 to-amber-500/10 text-orange-400 border border-orange-500/30 font-semibold'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Flame className="w-4 h-4 shrink-0 text-orange-400" />
            <span>MITRE ATLAS™ Matrix</span>
          </button>

          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => { onSelectPillar(item.id); onClose(); }}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
                (currentView === 'tests' || currentView === 'detail') && activePillar === item.id
                  ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <item.icon className={`w-4 h-4 shrink-0 ${item.color}`} />
              <span>{item.label}</span>
            </button>
          ))}

          {/* Directories & Catalogs */}
          <div className="pt-3 pb-1">
            <p className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
              Intelligence & Catalogs
            </p>
          </div>

          <button
            type="button"
            onClick={() => { onSelectTools(); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
              currentView === 'tools'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4 shrink-0 text-purple-400" />
            <span>Security Tools Matrix</span>
          </button>

          <button
            type="button"
            onClick={() => { onSelectIncidents(); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
              currentView === 'incidents'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Flame className="w-4 h-4 shrink-0 text-amber-400" />
            <span>Real-World Incidents</span>
          </button>
        </nav>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800">
          <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-2.5 text-[10px] text-slate-500 text-center leading-relaxed">
            <span className="font-semibold text-slate-300">AI Security Nexus</span> • v1.3.0<br/>
            Live Framework Navigator
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;

