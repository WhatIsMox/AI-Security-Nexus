
import React from 'react';
import { 
  Box, Database, LayoutGrid, Server, BookOpen, Shield, Book, X, 
  Brain, Cpu, Bot, Gavel, Network, FileText, Search, CheckCircle2, 
  Terminal, Flame, Sparkles 
} from 'lucide-react';
import { Pillar } from '../types';

export type AppView = 
  | 'dashboard' 
  | 'tests' 
  | 'detail' 
  | 'threat-model' 
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

export type ActivePillarKey = Pillar | 'ALL' | 'TOP10' | 'MLTOP10' | 'AGENTTOP10' | 'SAIFTOP10' | 'MCPTOP10' | 'SECUREMCPGUIDE' | 'GENAIDATASECURITY';

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
  onClose
}) => {
  const navItems = [
    { id: Pillar.APP, icon: LayoutGrid, label: "Application Testing" },
    { id: Pillar.MODEL, icon: Box, label: "Model Testing" },
    { id: Pillar.INFRA, icon: Server, label: "Infrastructure" },
    { id: Pillar.DATA, icon: Database, label: "Data Testing" },
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
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => { onSelectDashboard(); onClose(); }}>
            <div className="relative p-1.5 bg-slate-900 rounded-xl border border-cyan-500/30 group overflow-hidden shadow-[0_0_15px_rgba(6,182,212,0.2)]">
              <div className="absolute inset-0 bg-cyan-500/20 blur-md group-hover:bg-cyan-400/30 transition-all"></div>
              <img src="./favicon.svg" alt="AI Security Nexus" className="w-7 h-7 relative z-10 object-contain drop-shadow-[0_0_8px_rgba(34,211,238,0.6)]" />
            </div>
            <div>
              <h1 className="font-bold text-slate-100 leading-tight tracking-tight uppercase text-sm">AI Security</h1>
              <p className="text-[10px] text-cyan-400 font-mono font-semibold tracking-wide">Nexus Platform</p>
            </div>
          </div>
          <button onClick={onClose} type="button" aria-label="Close navigation menu" className="mobile-menu-button md:hidden text-slate-400 hover:text-white">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Global Search Quick Button */}
        <div className="p-3 border-b border-slate-800/80">
          <button
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

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
          {/* Main Navigation */}
          <button
            onClick={() => { onSelectDashboard(); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-sm ${
              currentView === 'dashboard'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-medium'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-4 h-4 shrink-0" />
            <span>Overview & Dashboard</span>
          </button>

          <button
            onClick={() => { onSelectThreatModel(); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-sm ${
              currentView === 'threat-model'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-medium'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Shield className="w-4 h-4 shrink-0" />
            <span>Threat Modelling</span>
          </button>

          <button
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

          {/* Frameworks & Guidelines */}
          <div className="pt-3 pb-1">
            <p className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
              Frameworks & Top 10s
            </p>
          </div>

          <button
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

          <button
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

          <button
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

          <button
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

          <button
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

          <button
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

          <button
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

          {/* Testing Pillars */}
          <div className="pt-3 pb-1">
            <p className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider font-mono">
              Testing Pillars (42 Tests)
            </p>
          </div>

          <button
            onClick={() => { onSelectPillar('ALL'); onClose(); }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
              (currentView === 'tests' || currentView === 'detail') && activePillar === 'ALL'
                ? 'bg-slate-800 text-white border border-slate-700'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-4 h-4 shrink-0 text-cyan-400" />
            <span>All 42 Security Tests</span>
          </button>

          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => { onSelectPillar(item.id); onClose(); }}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 text-left text-xs font-medium ${
                (currentView === 'tests' || currentView === 'detail') && activePillar === item.id
                  ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <item.icon className={`w-4 h-4 shrink-0 ${(currentView === 'tests' || currentView === 'detail') && activePillar === item.id ? 'text-cyan-400' : ''}`} />
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

