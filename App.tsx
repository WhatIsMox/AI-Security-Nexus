
import React, { useState, useMemo } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import TestList from './components/TestList';
import TestDetail from './components/TestDetail';
import ThreatModelling from './components/ThreatModelling';
import OwaspTop10View from './components/OwaspTop10View';
import { TEST_DATA, OWASP_TOP_10_DATA, OWASP_ML_TOP_10_DATA, OWASP_AGENTIC_THREATS_DATA, OWASP_SAIF_THREATS_DATA, OWASP_MCP_TOP_10_DATA } from './data';
import { Pillar, TestItem } from './types';
import { Menu, Book } from 'lucide-react';

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<'dashboard' | 'tests' | 'detail' | 'threat-model' | 'owasp-top10' | 'owasp-ml-top10' | 'owasp-agent-top10' | 'owasp-saif-top10' | 'owasp-mcp-top10'>('dashboard');
  const [activePillar, setActivePillar] = useState<Pillar | 'ALL' | 'TOP10' | 'MLTOP10' | 'AGENTTOP10' | 'SAIFTOP10' | 'MCPTOP10'>('ALL');
  const [selectedTest, setSelectedTest] = useState<TestItem | null>(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [owaspTargetId, setOwaspTargetId] = useState<string | null>(null);

  const filteredTests = useMemo(() => {
    if (activePillar === 'ALL' || activePillar === 'TOP10' || activePillar === 'MLTOP10' || activePillar === 'AGENTTOP10' || activePillar === 'SAIFTOP10' || activePillar === 'MCPTOP10') return TEST_DATA;
    return TEST_DATA.filter(t => t.pillar === activePillar);
  }, [activePillar]);

  const handleSelectPillar = (pillar: Pillar | 'ALL' | 'TOP10' | 'MLTOP10' | 'AGENTTOP10' | 'SAIFTOP10' | 'MCPTOP10') => {
    setActivePillar(pillar);
    if (pillar === 'TOP10') {
        setOwaspTargetId(null); 
        setCurrentView('owasp-top10');
    } else if (pillar === 'MLTOP10') {
        setOwaspTargetId(null);
        setCurrentView('owasp-ml-top10');
    } else if (pillar === 'AGENTTOP10') {
        setOwaspTargetId(null);
        setCurrentView('owasp-agent-top10');
    } else if (pillar === 'SAIFTOP10') {
        setOwaspTargetId(null);
        setCurrentView('owasp-saif-top10');
    } else if (pillar === 'MCPTOP10') {
        setOwaspTargetId(null);
        setCurrentView('owasp-mcp-top10');
    } else {
        setCurrentView('tests');
    }
    window.scrollTo(0, 0);
  };

  const handleNavigateToOwasp = (id: string) => {
    setOwaspTargetId(id);
    if (id.startsWith("ML")) {
      setActivePillar('MLTOP10');
      setCurrentView('owasp-ml-top10');
    } else if (id.startsWith("ASI") || (id.startsWith("T") && !id.startsWith("TEST"))) { 
      setActivePillar('AGENTTOP10');
      setCurrentView('owasp-agent-top10');
    } else if (id.startsWith("SAIF")) {
      setActivePillar('SAIFTOP10');
      setCurrentView('owasp-saif-top10');
    } else if (id.startsWith("MCP")) {
      setActivePillar('MCPTOP10');
      setCurrentView('owasp-mcp-top10');
    } else {
      setActivePillar('TOP10');
      setCurrentView('owasp-top10');
    }
    window.scrollTo(0, 0);
  };

  const handleSelectDashboard = () => {
    setActivePillar('ALL');
    setCurrentView('dashboard');
    window.scrollTo(0, 0);
  };

  const handleSelectThreatModel = () => {
    setCurrentView('threat-model');
    window.scrollTo(0, 0);
  };

  const handleSelectTest = (test: TestItem) => {
    setSelectedTest(test);
    setCurrentView('detail');
    window.scrollTo(0, 0);
  };

  const handleBackToTests = () => {
    setSelectedTest(null);
    if (activePillar === 'TOP10') {
      setCurrentView('owasp-top10');
    } else if (activePillar === 'MLTOP10') {
      setCurrentView('owasp-ml-top10');
    } else if (activePillar === 'AGENTTOP10') {
      setCurrentView('owasp-agent-top10');
    } else if (activePillar === 'SAIFTOP10') {
      setCurrentView('owasp-saif-top10');
    } else if (activePillar === 'MCPTOP10') {
      setCurrentView('owasp-mcp-top10');
    } else {
      setCurrentView('tests');
    }
  };

  const handleNavigateToTestFromThreatModel = (testId: string) => {
    const test = TEST_DATA.find(t => t.id === testId);
    if (test) {
      setActivePillar(test.pillar);
      setSelectedTest(test);
      setCurrentView('detail'); 
      window.scrollTo(0, 0);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-cyan-500/30">
      
      {/* Mobile Header */}
      <div className="md:hidden fixed top-0 left-0 right-0 h-16 bg-slate-950 border-b border-slate-800 z-30 flex items-center justify-between px-4">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-cyan-950 rounded border border-cyan-500/30">
            <Book className="w-5 h-5 text-cyan-400" />
          </div>
          <span className="font-bold text-slate-100 uppercase text-xs">AI Security</span>
        </div>
        <button 
          onClick={() => setIsSidebarOpen(true)}
          className="p-2 text-slate-400 hover:text-white"
        >
          <Menu className="w-6 h-6" />
        </button>
      </div>

      <Sidebar 
        activePillar={activePillar} 
        onSelectPillar={handleSelectPillar} 
        onSelectDashboard={handleSelectDashboard}
        onSelectThreatModel={handleSelectThreatModel}
        currentView={
          currentView === 'detail' 
            ? 'tests' 
            : (currentView === 'owasp-top10' || currentView === 'owasp-ml-top10' || currentView === 'owasp-agent-top10' || currentView === 'owasp-saif-top10' || currentView === 'owasp-mcp-top10')
              ? 'tests' 
              : currentView
        }
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
      />
      
      <main className={`
        min-h-screen relative transition-all duration-300
        pt-16 md:pt-0
        md:ml-64
      `}>
        <div className="fixed inset-0 pointer-events-none z-0">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-cyan-500/5 rounded-full blur-[100px]" />
          <div className="absolute bottom-0 left-64 w-[500px] h-[500px] bg-purple-500/5 rounded-full blur-[100px]" />
        </div>

        <div className="relative z-10 py-8">
          {currentView === 'dashboard' && (
            <Dashboard onSelectPillar={handleSelectPillar} />
          )}

          {currentView === 'threat-model' && (
            <ThreatModelling 
              onNavigateToTest={handleNavigateToTestFromThreatModel} 
              onNavigateToOwasp={handleNavigateToOwasp}
            />
          )}

          {currentView === 'owasp-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_TOP_10_DATA}
              title="OWASP Top 10 for LLM Applications 2025"
              description="A definitive guide to the most critical security risks facing Large Language Model applications."
              colorTheme="pink"
            />
          )}

          {currentView === 'owasp-ml-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_ML_TOP_10_DATA}
              title="OWASP Machine Learning Security Top 10"
              description="The comprehensive list of top security issues for Machine Learning systems, covering adversarial attacks, data poisoning, and more."
              colorTheme="emerald"
            />
          )}

          {currentView === 'owasp-agent-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_AGENTIC_THREATS_DATA}
              title="OWASP Agentic AI Threats"
              description="A threat-model-based reference of emerging agentic threats including memory poisoning, tool misuse, and cascading hallucinations."
              colorTheme="orange"
            />
          )}

          {currentView === 'owasp-saif-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_SAIF_THREATS_DATA}
              title="Google SAIF: Secure AI Framework Risks"
              description="A comprehensive mapping of risks across the AI lifecycle, based on Google's Secure AI Framework."
              colorTheme="blue"
            />
          )}

          {currentView === 'owasp-mcp-top10' && (
            <OwaspTop10View 
              initialExpandedId={owaspTargetId} 
              data={OWASP_MCP_TOP_10_DATA}
              title="OWASP MCP Top 10 (v0.1)"
              description="The top risks for Model Context Protocol ecosystems, covering tool integrity, authorization, and context safety."
              colorTheme="cyan"
            />
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
