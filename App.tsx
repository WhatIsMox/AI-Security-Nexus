
import React, { useEffect, useState, useMemo, useCallback } from 'react';
import Sidebar, { AppView, ActivePillarKey } from './components/Sidebar';
import Dashboard from './components/Dashboard';
import TestList from './components/TestList';
import TestDetail from './components/TestDetail';
import ThreatModelling from './components/ThreatModelling';
import OwaspTop10View from './components/OwaspTop10View';
import AgenticTop10View from './components/AgenticTop10View';
import SecureMcpGuideView from './components/SecureMcpGuideView';
import GenAiDataSecurityView from './components/GenAiDataSecurityView';
import AuditChecklistView from './components/AuditChecklistView';
import ToolsDirectoryView from './components/ToolsDirectoryView';
import IncidentsDirectoryView from './components/IncidentsDirectoryView';
import GlobalSearchModal from './components/GlobalSearchModal';
import ToolDetailModal from './components/ToolDetailModal';
import IncidentDetailModal from './components/IncidentDetailModal';
import { TEST_DATA, OWASP_TOP_10_DATA, OWASP_ML_TOP_10_DATA, OWASP_SAIF_THREATS_DATA, OWASP_MCP_TOP_10_DATA } from './data';
import { Pillar, TestItem, SecurityTool, RealWorldIncident } from './types';
import { Menu, Book, Search } from 'lucide-react';

const parseHashToState = (hash: string): { view: AppView; pillar: ActivePillarKey; id: string | null } => {
  const clean = hash.replace(/^#\/?/, '').trim();
  if (!clean || clean === 'dashboard') {
    return { view: 'dashboard', pillar: 'ALL', id: null };
  }
  if (clean === 'threat-model') {
    return { view: 'threat-model', pillar: 'ALL', id: null };
  }
  if (clean === 'audit-checklist') {
    return { view: 'audit-checklist', pillar: 'ALL', id: null };
  }
  if (clean === 'tools') {
    return { view: 'tools', pillar: 'ALL', id: null };
  }
  if (clean === 'incidents') {
    return { view: 'incidents', pillar: 'ALL', id: null };
  }
  if (clean === 'secure-mcp-guide') {
    return { view: 'secure-mcp-guide', pillar: 'SECUREMCPGUIDE', id: null };
  }
  if (clean.startsWith('genai-data-security')) {
    const parts = clean.split('/');
    return { view: 'genai-data-security', pillar: 'GENAIDATASECURITY', id: parts[1] || null };
  }
  if (clean.startsWith('owasp-top10')) {
    const parts = clean.split('/');
    return { view: 'owasp-top10', pillar: 'TOP10', id: parts[1] || null };
  }
  if (clean.startsWith('owasp-ml-top10')) {
    const parts = clean.split('/');
    return { view: 'owasp-ml-top10', pillar: 'MLTOP10', id: parts[1] || null };
  }
  if (clean.startsWith('owasp-agent-top10')) {
    const parts = clean.split('/');
    return { view: 'owasp-agent-top10', pillar: 'AGENTTOP10', id: parts[1] || null };
  }
  if (clean.startsWith('owasp-saif-top10')) {
    const parts = clean.split('/');
    return { view: 'owasp-saif-top10', pillar: 'SAIFTOP10', id: parts[1] || null };
  }
  if (clean.startsWith('owasp-mcp-top10')) {
    const parts = clean.split('/');
    return { view: 'owasp-mcp-top10', pillar: 'MCPTOP10', id: parts[1] || null };
  }
  if (clean.startsWith('detail/')) {
    const testId = clean.replace('detail/', '').trim();
    return { view: 'detail', pillar: 'ALL', id: testId };
  }
  if (clean.startsWith('tests')) {
    const parts = clean.split('/');
    const pillarSegment = parts[1]?.toLowerCase();
    let pillar: ActivePillarKey = 'ALL';
    if (pillarSegment === 'app') pillar = Pillar.APP;
    else if (pillarSegment === 'model') pillar = Pillar.MODEL;
    else if (pillarSegment === 'infra') pillar = Pillar.INFRA;
    else if (pillarSegment === 'data') pillar = Pillar.DATA;
    return { view: 'tests', pillar, id: null };
  }
  return { view: 'dashboard', pillar: 'ALL', id: null };
};

const stateToHash = (view: AppView, pillar: ActivePillarKey, testId?: string | null, threatId?: string | null): string => {
  if (view === 'dashboard') return '#/dashboard';
  if (view === 'threat-model') return '#/threat-model';
  if (view === 'audit-checklist') return '#/audit-checklist';
  if (view === 'tools') return '#/tools';
  if (view === 'incidents') return '#/incidents';
  if (view === 'secure-mcp-guide') return '#/secure-mcp-guide';
  if (view === 'genai-data-security') return threatId ? `#/genai-data-security/${threatId}` : '#/genai-data-security';
  if (view === 'owasp-top10') return threatId ? `#/owasp-top10/${threatId}` : '#/owasp-top10';
  if (view === 'owasp-ml-top10') return threatId ? `#/owasp-ml-top10/${threatId}` : '#/owasp-ml-top10';
  if (view === 'owasp-agent-top10') return threatId ? `#/owasp-agent-top10/${threatId}` : '#/owasp-agent-top10';
  if (view === 'owasp-saif-top10') return threatId ? `#/owasp-saif-top10/${threatId}` : '#/owasp-saif-top10';
  if (view === 'owasp-mcp-top10') return threatId ? `#/owasp-mcp-top10/${threatId}` : '#/owasp-mcp-top10';
  if (view === 'detail' && testId) return `#/detail/${testId}`;
  if (view === 'tests') {
    if (pillar === Pillar.APP) return '#/tests/app';
    if (pillar === Pillar.MODEL) return '#/tests/model';
    if (pillar === Pillar.INFRA) return '#/tests/infra';
    if (pillar === Pillar.DATA) return '#/tests/data';
    return '#/tests';
  }
  return '#/dashboard';
};

const App: React.FC = () => {
  const initialHashState = useMemo(() => parseHashToState(window.location.hash), []);
  const [currentView, setCurrentView] = useState<AppView>(initialHashState.view);
  const [activePillar, setActivePillar] = useState<ActivePillarKey>(initialHashState.pillar);
  const [selectedTest, setSelectedTest] = useState<TestItem | null>(() => {
    if (initialHashState.view === 'detail' && initialHashState.id) {
      return TEST_DATA.find(t => t.id === initialHashState.id) || null;
    }
    return null;
  });
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [owaspTargetId, setOwaspTargetId] = useState<string | null>(initialHashState.id);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [activeModalTool, setActiveModalTool] = useState<(SecurityTool & { mappedThreats?: string[] }) | null>(null);
  const [activeModalIncident, setActiveModalIncident] = useState<RealWorldIncident | null>(null);

  // Sync state to URL hash
  const syncHash = useCallback((view: AppView, pillar: ActivePillarKey, testId?: string | null, threatId?: string | null) => {
    const targetHash = stateToHash(view, pillar, testId, threatId);
    if (window.location.hash !== targetHash) {
      window.history.pushState(null, '', targetHash);
    }
  }, []);

  // Listen to browser Back/Forward (hashchange/popstate)
  useEffect(() => {
    const handleHashChange = () => {
      const parsed = parseHashToState(window.location.hash);
      setCurrentView(parsed.view);
      setActivePillar(parsed.pillar);
      setOwaspTargetId(parsed.id);
      if (parsed.view === 'detail' && parsed.id) {
        const found = TEST_DATA.find(t => t.id === parsed.id);
        setSelectedTest(found || null);
      } else if (parsed.view !== 'detail') {
        setSelectedTest(null);
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    window.addEventListener('popstate', handleHashChange);

    return () => {
      window.removeEventListener('hashchange', handleHashChange);
      window.removeEventListener('popstate', handleHashChange);
    };
  }, []);

  // Global keyboard shortcut for search (Cmd+K / Ctrl+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsSearchOpen(prev => !prev);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Sidebar escape key handling
  useEffect(() => {
    if (!isSidebarOpen) return;

    const previousOverflow = document.body.style.overflow;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setIsSidebarOpen(false);
    };

    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', closeOnEscape);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', closeOnEscape);
    };
  }, [isSidebarOpen]);

  const filteredTests = useMemo(() => {
    if (activePillar === 'ALL' || activePillar === 'TOP10' || activePillar === 'MLTOP10' || activePillar === 'AGENTTOP10' || activePillar === 'SAIFTOP10' || activePillar === 'MCPTOP10' || activePillar === 'SECUREMCPGUIDE' || activePillar === 'GENAIDATASECURITY') return TEST_DATA;
    return TEST_DATA.filter(t => t.pillar === activePillar);
  }, [activePillar]);

  const handleSelectPillar = (pillar: ActivePillarKey) => {
    setActivePillar(pillar);
    let view: AppView = 'tests';
    if (pillar === 'TOP10') {
      setOwaspTargetId(null); 
      view = 'owasp-top10';
    } else if (pillar === 'MLTOP10') {
      setOwaspTargetId(null);
      view = 'owasp-ml-top10';
    } else if (pillar === 'AGENTTOP10') {
      setOwaspTargetId(null);
      view = 'owasp-agent-top10';
    } else if (pillar === 'SAIFTOP10') {
      setOwaspTargetId(null);
      view = 'owasp-saif-top10';
    } else if (pillar === 'MCPTOP10') {
      setOwaspTargetId(null);
      view = 'owasp-mcp-top10';
    } else if (pillar === 'SECUREMCPGUIDE') {
      setOwaspTargetId(null);
      view = 'secure-mcp-guide';
    } else if (pillar === 'GENAIDATASECURITY') {
      setOwaspTargetId(null);
      view = 'genai-data-security';
    }
    setCurrentView(view);
    syncHash(view, pillar, null, null);
    window.scrollTo(0, 0);
  };

  const handleNavigateToOwasp = (id: string) => {
    setOwaspTargetId(id);
    let view: AppView = 'owasp-top10';
    let pillar: ActivePillarKey = 'TOP10';

    if (id.startsWith("ML")) {
      pillar = 'MLTOP10';
      view = 'owasp-ml-top10';
    } else if (id.startsWith("ASI") || id.startsWith("AST")) {
      pillar = 'AGENTTOP10';
      view = 'owasp-agent-top10';
    } else if (id.startsWith("SAIF")) {
      pillar = 'SAIFTOP10';
      view = 'owasp-saif-top10';
    } else if (id.startsWith("MCP")) {
      pillar = 'MCPTOP10';
      view = 'owasp-mcp-top10';
    } else if (id.startsWith("DSGAI") || id.startsWith("ai-dspm")) {
      pillar = 'GENAIDATASECURITY';
      view = 'genai-data-security';
    }

    setActivePillar(pillar);
    setCurrentView(view);
    syncHash(view, pillar, null, id);
    window.scrollTo(0, 0);
  };

  const handleSelectDashboard = () => {
    setActivePillar('ALL');
    setCurrentView('dashboard');
    syncHash('dashboard', 'ALL');
    window.scrollTo(0, 0);
  };

  const handleSelectThreatModel = () => {
    setCurrentView('threat-model');
    syncHash('threat-model', activePillar);
    window.scrollTo(0, 0);
  };

  const handleSelectAuditChecklist = () => {
    setCurrentView('audit-checklist');
    syncHash('audit-checklist', activePillar);
    window.scrollTo(0, 0);
  };

  const handleSelectTools = () => {
    setCurrentView('tools');
    syncHash('tools', activePillar);
    window.scrollTo(0, 0);
  };

  const handleSelectIncidents = () => {
    setCurrentView('incidents');
    syncHash('incidents', activePillar);
    window.scrollTo(0, 0);
  };

  const handleSelectTest = (test: TestItem) => {
    setSelectedTest(test);
    setCurrentView('detail');
    syncHash('detail', activePillar, test.id);
    window.scrollTo(0, 0);
  };

  const handleBackToTests = () => {
    setSelectedTest(null);
    let view: AppView = 'tests';
    if (activePillar === 'TOP10') {
      view = 'owasp-top10';
    } else if (activePillar === 'MLTOP10') {
      view = 'owasp-ml-top10';
    } else if (activePillar === 'AGENTTOP10') {
      view = 'owasp-agent-top10';
    } else if (activePillar === 'SAIFTOP10') {
      view = 'owasp-saif-top10';
    } else if (activePillar === 'MCPTOP10') {
      view = 'owasp-mcp-top10';
    } else if (activePillar === 'SECUREMCPGUIDE') {
      view = 'secure-mcp-guide';
    } else if (activePillar === 'GENAIDATASECURITY') {
      view = 'genai-data-security';
    }
    setCurrentView(view);
    syncHash(view, activePillar);
  };

  const handleNavigateToTestFromThreatModel = (testId: string) => {
    const test = TEST_DATA.find(t => t.id === testId);
    if (test) {
      setActivePillar(test.pillar);
      setSelectedTest(test);
      setCurrentView('detail'); 
      syncHash('detail', test.pillar, test.id);
      window.scrollTo(0, 0);
    }
  };

  return (
    <div className="app-shell container-fluid min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-cyan-500/30">
      
      {/* Mobile Header */}
      <header className="mobile-header md:hidden fixed top-0 left-0 right-0 h-16 bg-slate-950 border-b border-slate-800 z-30 flex items-center justify-between px-4">
        <div className="flex items-center gap-2.5 cursor-pointer" onClick={handleSelectDashboard}>
          <div className="w-8 h-8 rounded-lg overflow-hidden border border-cyan-500/30 bg-slate-900 flex items-center justify-center shadow-[0_0_10px_rgba(6,182,212,0.2)] shrink-0">
            <img src="./favicon.svg" alt="AI Security Nexus" className="w-full h-full object-cover" />
          </div>
          <span className="font-bold text-slate-100 uppercase text-xs tracking-wider">AI Security Nexus</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsSearchOpen(true)}
            className="p-2 text-slate-400 hover:text-white"
            type="button"
            aria-label="Search"
          >
            <Search className="w-5 h-5" />
          </button>
          <button 
            onClick={() => setIsSidebarOpen(true)}
            className="mobile-menu-button p-2 text-slate-400 hover:text-white"
            type="button"
            aria-label="Open navigation menu"
            aria-controls="primary-navigation"
            aria-expanded={isSidebarOpen}
          >
            <Menu className="w-6 h-6" />
          </button>
        </div>
      </header>

      <Sidebar 
        activePillar={activePillar} 
        currentView={currentView}
        onSelectPillar={handleSelectPillar} 
        onSelectDashboard={handleSelectDashboard}
        onSelectThreatModel={handleSelectThreatModel}
        onSelectAuditChecklist={handleSelectAuditChecklist}
        onSelectTools={handleSelectTools}
        onSelectIncidents={handleSelectIncidents}
        onOpenSearch={() => setIsSearchOpen(true)}
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
      />

      {/* Global Omnisearch Modal */}
      <GlobalSearchModal 
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        onSelectTest={handleSelectTest}
        onNavigateToOwasp={handleNavigateToOwasp}
        onNavigateToView={(view) => {
          if (view === 'tools') handleSelectTools();
          if (view === 'incidents') handleSelectIncidents();
        }}
        onSelectTool={(tool) => setActiveModalTool(tool)}
        onSelectIncident={(incident) => setActiveModalIncident(incident)}
      />

      {/* Global Tool Detail Inspection Modal */}
      <ToolDetailModal 
        tool={activeModalTool} 
        onClose={() => setActiveModalTool(null)} 
        onNavigateToOwasp={handleNavigateToOwasp} 
      />

      {/* Global Incident Detail Inspection Modal */}
      <IncidentDetailModal 
        incident={activeModalIncident} 
        onClose={() => setActiveModalIncident(null)} 
        onNavigateToOwasp={handleNavigateToOwasp} 
      />
      
      <main className={`app-main
        min-h-screen relative transition-all duration-300
        pt-16 md:pt-0
        md:ml-64
      `}>
        <div className="app-backdrop fixed inset-0 pointer-events-none z-0">
          <div className="app-backdrop-orb absolute top-0 right-0 w-[500px] h-[500px] bg-cyan-500/5 rounded-full blur-[100px]" />
          <div className="app-backdrop-orb absolute bottom-0 left-64 w-[500px] h-[500px] bg-purple-500/5 rounded-full blur-[100px]" />
        </div>

        <div className="app-content relative z-10 py-8">
          {currentView === 'dashboard' && (
            <Dashboard 
              onSelectPillar={handleSelectPillar} 
              onSelectThreatModel={handleSelectThreatModel}
              onSelectTest={handleSelectTest}
              onNavigateToOwasp={handleNavigateToOwasp}
              onSelectIncidents={handleSelectIncidents}
              onSelectTools={handleSelectTools}
            />
          )}

          {currentView === 'threat-model' && (
            <ThreatModelling 
              onNavigateToTest={handleNavigateToTestFromThreatModel} 
              onNavigateToOwasp={handleNavigateToOwasp}
            />
          )}

          {currentView === 'audit-checklist' && (
            <AuditChecklistView 
              onSelectTest={handleSelectTest}
              onNavigateToOwasp={handleNavigateToOwasp}
            />
          )}

          {currentView === 'tools' && (
            <ToolsDirectoryView 
              onNavigateToOwasp={handleNavigateToOwasp}
            />
          )}

          {currentView === 'incidents' && (
            <IncidentsDirectoryView 
              onNavigateToOwasp={handleNavigateToOwasp}
            />
          )}

          {currentView === 'owasp-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_TOP_10_DATA}
              title="OWASP Top 10 for LLM Applications (2026 Edition)"
              description="The definitive industry benchmark for Large Language Model security—covering prompt injection, data poisoning, vector store vulnerabilities, over-permissioned tools, and output handling."
              colorTheme="pink"
            />
          )}

          {currentView === 'owasp-ml-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_ML_TOP_10_DATA}
              title="OWASP Machine Learning Security Top 10"
              description="Essential vulnerability catalog for predictive models and deep learning pipelines, covering adversarial evasion, dataset poisoning, model inversion, and supply-chain threats."
              colorTheme="emerald"
            />
          )}

          {currentView === 'owasp-agent-top10' && (
            <AgenticTop10View initialExpandedId={owaspTargetId} />
          )}

          {currentView === 'owasp-saif-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_SAIF_THREATS_DATA}
              title="Google Secure AI Framework (SAIF) Threats"
              description="End-to-end AI security lifecycle model mapping 15 distinct threat vectors across dataset curation, model training, deployment infrastructure, and live operations."
              colorTheme="blue"
            />
          )}

          {currentView === 'owasp-mcp-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_MCP_TOP_10_DATA}
              title="OWASP Model Context Protocol (MCP) Top 10"
              description="Dedicated security standards for Model Context Protocol architectures—focusing on tool integrity, rogue server containment, confused-deputy authorization, and context isolation."
              colorTheme="cyan"
            />
          )}

          {currentView === 'secure-mcp-guide' && (
            <SecureMcpGuideView />
          )}

          {currentView === 'genai-data-security' && (
            <GenAiDataSecurityView initialExpandedId={owaspTargetId} />
          )}

          {currentView === 'tests' && (
            <TestList 
              tests={filteredTests} 
              onSelectTest={handleSelectTest}
              onNavigateToOwasp={handleNavigateToOwasp}
              category={activePillar === 'ALL' ? 'All Security Tests' : activePillar}
            />
          )}

          {currentView === 'detail' && selectedTest && (
            <TestDetail 
              test={selectedTest} 
              onBack={handleBackToTests} 
              onNavigateToOwasp={handleNavigateToOwasp}
            />
          )}
        </div>
      </main>
    </div>
  );
};

export default App;

