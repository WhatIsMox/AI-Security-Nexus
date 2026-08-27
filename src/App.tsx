
import React, { useEffect, useState, useMemo, useCallback, Suspense, lazy } from 'react';
import Sidebar, { AppView, ActivePillarKey } from './components/Sidebar';
import Dashboard from './components/Dashboard';
import GlobalSearchModal from './components/GlobalSearchModal';
import ToolDetailModal from './components/ToolDetailModal';
import IncidentDetailModal from './components/IncidentDetailModal';
import { TEST_DATA, OWASP_TOP_10_DATA, OWASP_ML_TOP_10_DATA, OWASP_SAIF_THREATS_DATA, OWASP_MCP_TOP_10_DATA } from './data';
import { Pillar, TestItem, SecurityTool, RealWorldIncident, GlobalDomain } from './types';
import { Menu, Book, Search, Loader2 } from 'lucide-react';

const TestList = lazy(() => import('./components/TestList'));
const TestDetail = lazy(() => import('./components/TestDetail'));
const ThreatModelling = lazy(() => import('./components/ThreatModelling'));
const OwaspTop10View = lazy(() => import('./components/OwaspTop10View'));
const AgenticTop10View = lazy(() => import('./components/AgenticTop10View'));
const SecureMcpGuideView = lazy(() => import('./components/SecureMcpGuideView'));
const GenAiDataSecurityView = lazy(() => import('./components/GenAiDataSecurityView'));
const AuditChecklistView = lazy(() => import('./components/AuditChecklistView'));
const ToolsDirectoryView = lazy(() => import('./components/ToolsDirectoryView'));
const IncidentsDirectoryView = lazy(() => import('./components/IncidentsDirectoryView'));

const ViewLoadingFallback = () => (
  <div className="flex items-center justify-center min-h-[50vh] text-slate-400">
    <div className="flex flex-col items-center gap-3">
      <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      <span className="text-xs font-mono text-slate-500">Loading view...</span>
    </div>
  </div>
);

const parseHashToState = (hash: string): { view: AppView; pillar: ActivePillarKey; id: string | null } => {
  let clean = hash.replace(/^#\/?/, '').trim();
  try {
    clean = decodeURIComponent(clean);
  } catch (e) {
    // Malformed URI string
  }
  const queryIndex = clean.indexOf('?');
  if (queryIndex !== -1) {
    clean = clean.substring(0, queryIndex);
  }
  if (!clean || clean === 'dashboard') {
    return { view: 'dashboard', pillar: 'ALL', id: null };
  }
  if (clean === 'threat-model') {
    return { view: 'threat-model', pillar: 'ALL', id: null };
  }
  if (clean === 'audit-checklist') {
    return { view: 'audit-checklist', pillar: 'ALL', id: null };
  }
  if (clean === 'tools' || clean.startsWith('tools/')) {
    return { view: 'tools', pillar: 'ALL', id: null };
  }
  if (clean === 'incidents' || clean.startsWith('incidents/')) {
    return { view: 'incidents', pillar: 'ALL', id: null };
  }
  if (clean === 'secure-mcp-guide' || clean.startsWith('secure-mcp-guide/')) {
    const parts = clean.split('/');
    return { view: 'secure-mcp-guide', pillar: 'SECUREMCPGUIDE', id: parts[1] || null };
  }
  if (
    clean === 'minimum-bar' ||
    clean === 'server-architecture' ||
    clean === 'client-transport-security' ||
    clean === 'authorization-boundaries' ||
    clean === 'tool-execution-safety' ||
    clean === 'data-privacy-context-hygiene' ||
    clean === 'audit-logging-monitoring' ||
    clean === 'supply-chain-dependency-security' ||
    clean === 'testing-verification' ||
    clean === 'deployment-infrastructure-hardening' ||
    clean === 'incident-response-preparedness'
  ) {
    return { view: 'secure-mcp-guide', pillar: 'SECUREMCPGUIDE', id: clean };
  }
  if (clean.startsWith('genai-data-security')) {
    const parts = clean.split('/');
    return { view: 'genai-data-security', pillar: 'GENAIDATASECURITY', id: parts[1] || null };
  }
  const upper = clean.toUpperCase();
  if (
    clean.startsWith('DSGAI') ||
    upper.startsWith('DSGAI') ||
    clean.startsWith('ai-dspm') ||
    clean === 'genai-data-security-context' ||
    clean === 'risk-navigator' ||
    clean === 'dspm-framework'
  ) {
    return { view: 'genai-data-security', pillar: 'GENAIDATASECURITY', id: clean };
  }
  if (clean.startsWith('owasp-top10') || clean.startsWith('LLM') || upper.startsWith('LLM')) {
    const parts = clean.split('/');
    const id = (clean.startsWith('LLM') || upper.startsWith('LLM')) ? clean : (parts[1] || null);
    return { view: 'owasp-top10', pillar: 'TOP10', id };
  }
  if (clean.startsWith('owasp-ml-top10') || clean.startsWith('ML') || upper.startsWith('ML')) {
    const parts = clean.split('/');
    const id = (clean.startsWith('ML') || upper.startsWith('ML')) ? clean : (parts[1] || null);
    return { view: 'owasp-ml-top10', pillar: 'MLTOP10', id };
  }
  if (clean.startsWith('owasp-agent-top10') || clean.startsWith('ASI') || clean.startsWith('AST') || upper.startsWith('ASI') || upper.startsWith('AST')) {
    const parts = clean.split('/');
    const id = (clean.startsWith('ASI') || clean.startsWith('AST') || upper.startsWith('ASI') || upper.startsWith('AST')) ? clean : (parts[1] || null);
    return { view: 'owasp-agent-top10', pillar: 'AGENTTOP10', id };
  }
  if (clean.startsWith('owasp-saif-top10') || clean.startsWith('SAIF') || upper.startsWith('SAIF')) {
    const parts = clean.split('/');
    const id = (clean.startsWith('SAIF') || upper.startsWith('SAIF')) ? clean : (parts[1] || null);
    return { view: 'owasp-saif-top10', pillar: 'SAIFTOP10', id };
  }
  if (clean.startsWith('owasp-mcp-top10') || clean.startsWith('MCP') || upper.startsWith('MCP')) {
    const parts = clean.split('/');
    const id = (clean.startsWith('MCP') || upper.startsWith('MCP')) ? clean : (parts[1] || null);
    return { view: 'owasp-mcp-top10', pillar: 'MCPTOP10', id };
  }
  if (clean.startsWith('detail/') || clean.startsWith('AITG-') || clean.startsWith('AGT-') || upper.startsWith('AITG-') || upper.startsWith('AGT-')) {
    const rawId = clean.startsWith('detail/') ? clean.replace(/^detail\//, '').trim() : clean;
    const foundTest = TEST_DATA.find(t => t.id.toUpperCase() === rawId.toUpperCase());
    return { view: 'detail', pillar: 'ALL', id: foundTest ? foundTest.id : rawId };
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
  if (view === 'secure-mcp-guide') return threatId ? `#/secure-mcp-guide/${threatId}` : '#/secure-mcp-guide';
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
  const [globalDomain, setGlobalDomain] = useState<GlobalDomain>('ALL');
  const [currentView, setCurrentView] = useState<AppView>(initialHashState.view);
  const [activePillar, setActivePillar] = useState<ActivePillarKey>(initialHashState.pillar);
  const [selectedTest, setSelectedTest] = useState<TestItem | null>(() => {
    if (initialHashState.view === 'detail' && initialHashState.id) {
      return TEST_DATA.find(t => t.id.toUpperCase() === initialHashState.id!.toUpperCase()) || null;
    }
    return null;
  });
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [owaspTargetId, setOwaspTargetId] = useState<string | null>(() => {
    return initialHashState.view !== 'detail' ? initialHashState.id : null;
  });
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
      setOwaspTargetId(parsed.view !== 'detail' ? parsed.id : null);
      if (parsed.view === 'detail' && parsed.id) {
        const found = TEST_DATA.find(t => t.id.toUpperCase() === parsed.id!.toUpperCase());
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

  // Handle window resize to release mobile scroll lock on desktop
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 768 && isSidebarOpen) {
        setIsSidebarOpen(false);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [isSidebarOpen]);

  const filteredTests = useMemo(() => {
    let tests = TEST_DATA;
    if (globalDomain !== 'ALL') {
      tests = tests.filter(t => {
        if (globalDomain === 'LLM') return !!t.owaspTop10Ref;
        if (globalDomain === 'ML') return !!t.owaspMlTop10Ref;
        if (globalDomain === 'AGENT') return !!t.owaspAgenticRef;
        if (globalDomain === 'MCP') return !!t.owaspMcpTop10Ref;
        return true;
      });
    }
    if (activePillar === 'ALL' || activePillar === 'TOP10' || activePillar === 'MLTOP10' || activePillar === 'AGENTTOP10' || activePillar === 'SAIFTOP10' || activePillar === 'MCPTOP10' || activePillar === 'SECUREMCPGUIDE' || activePillar === 'GENAIDATASECURITY') return tests;
    return tests.filter(t => t.pillar === activePillar);
  }, [activePillar, globalDomain]);

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

    if (id.startsWith("ML") || id.toUpperCase().startsWith("ML")) {
      pillar = 'MLTOP10';
      view = 'owasp-ml-top10';
    } else if (id.startsWith("ASI") || id.startsWith("AST") || id.toUpperCase().startsWith("ASI") || id.toUpperCase().startsWith("AST")) {
      pillar = 'AGENTTOP10';
      view = 'owasp-agent-top10';
    } else if (id.startsWith("SAIF") || id.toUpperCase().startsWith("SAIF")) {
      pillar = 'SAIFTOP10';
      view = 'owasp-saif-top10';
    } else if (id.startsWith("MCP") || id.toUpperCase().startsWith("MCP")) {
      pillar = 'MCPTOP10';
      view = 'owasp-mcp-top10';
    } else if (id.startsWith("DSGAI") || id.startsWith("ai-dspm") || id.toUpperCase().startsWith("DSGAI")) {
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
        globalDomain={globalDomain}
        onSelectDomain={setGlobalDomain}
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
        <div className="app-backdrop fixed inset-0 pointer-events-none z-0 overflow-hidden">
          <div
            className="app-backdrop-orb absolute top-0 right-0 w-[500px] h-[500px] rounded-full"
            style={{
              background: 'radial-gradient(circle, rgba(6, 182, 212, 0.08) 0%, rgba(6, 182, 212, 0.02) 45%, transparent 70%)',
            }}
          />
          <div
            className="app-backdrop-orb absolute bottom-0 left-64 w-[500px] h-[500px] rounded-full"
            style={{
              background: 'radial-gradient(circle, rgba(168, 85, 247, 0.08) 0%, rgba(168, 85, 247, 0.02) 45%, transparent 70%)',
            }}
          />
        </div>

        <div className="app-content relative z-10 py-8">
          <Suspense fallback={<ViewLoadingFallback />}>
            <div 
              key={`${currentView}-${activePillar}-${owaspTargetId || ''}-${selectedTest?.id || ''}`}
              className="page-view-transition animate-page-enter"
            >
              {currentView === 'dashboard' && (
                <Dashboard 
                  globalDomain={globalDomain}
                  onSelectPillar={handleSelectPillar} 
                  onSelectThreatModel={handleSelectThreatModel}
                  onSelectTest={handleSelectTest}
                  onNavigateToOwasp={handleNavigateToOwasp}
                  onSelectIncidents={handleSelectIncidents}
                  onSelectTools={handleSelectTools}
                  onSelectTool={(tool) => setActiveModalTool(tool)}
                  onSelectIncident={(incident) => setActiveModalIncident(incident)}
                />
              )}

              {currentView === 'threat-model' && (
                <ThreatModelling 
                  globalDomain={globalDomain}
                  onNavigateToTest={handleNavigateToTestFromThreatModel} 
                  onNavigateToOwasp={handleNavigateToOwasp}
                />
              )}

              {currentView === 'audit-checklist' && (
                <AuditChecklistView 
                  globalDomain={globalDomain}
                  onSelectTest={handleSelectTest}
                  onNavigateToOwasp={handleNavigateToOwasp}
                />
              )}

              {currentView === 'tools' && (
                <ToolsDirectoryView 
                  globalDomain={globalDomain}
                  onNavigateToOwasp={handleNavigateToOwasp}
                  onSelectTool={(tool) => setActiveModalTool(tool)}
                />
              )}

              {currentView === 'incidents' && (
                <IncidentsDirectoryView 
                  globalDomain={globalDomain}
                  onNavigateToOwasp={handleNavigateToOwasp}
                  onSelectIncident={(incident) => setActiveModalIncident(incident)}
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
                <SecureMcpGuideView initialExpandedId={owaspTargetId} />
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
                  key={selectedTest.id}
                  test={selectedTest} 
                  onBack={handleBackToTests} 
                  onNavigateToOwasp={handleNavigateToOwasp}
                />
              )}

              {currentView === 'detail' && !selectedTest && (
                <div className="container-fluid p-8 max-w-4xl mx-auto text-center">
                  <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-xl">
                    <h2 className="text-xl font-bold text-white mb-2">Test Case Not Found</h2>
                    <p className="text-slate-400 text-sm mb-6">The requested test case ID does not exist in the security catalog.</p>
                    <button
                      onClick={handleBackToTests}
                      className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl text-xs transition-all shadow-lg shadow-cyan-500/20"
                    >
                      Back to All Tests
                    </button>
                  </div>
                </div>
              )}
            </div>
          </Suspense>
        </div>
      </main>
    </div>
  );
};

export default App;

