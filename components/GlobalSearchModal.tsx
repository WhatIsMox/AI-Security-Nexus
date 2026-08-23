import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  Search, X, Brain, Cpu, Bot, Gavel, Network, Database, 
  Terminal, Flame, Shield, ArrowRight, CornerDownLeft, Sparkles, Layers
} from 'lucide-react';
import { 
  TEST_DATA, 
  OWASP_TOP_10_DATA, 
  OWASP_ML_TOP_10_DATA, 
  OWASP_AGENTIC_APPLICATIONS_DATA, 
  OWASP_AGENTIC_THREATS_DATA, 
  OWASP_SAIF_THREATS_DATA, 
  OWASP_MCP_TOP_10_DATA, 
  GENAI_DATA_SECURITY_RISKS,
  GENAI_DSPM_CAPABILITIES
} from '../data';
import { TOOLS_BY_THREAT_ID } from '../tools_catalog';
import { INCIDENTS_BY_THREAT_ID } from '../incidents_catalog';
import { TestItem } from '../types';

export interface SearchResultItem {
  id: string;
  title: string;
  subtitle: string;
  category: 'test' | 'llm' | 'ml' | 'agentic' | 'saif' | 'mcp' | 'dsgai' | 'dspm' | 'tool' | 'incident';
  categoryLabel: string;
  badgeColor: string;
  targetId?: string;
  testItem?: TestItem;
  url?: string;
}

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTest: (test: TestItem) => void;
  onNavigateToOwasp: (id: string) => void;
  onNavigateToView?: (view: string) => void;
}

export const GlobalSearchModal: React.FC<GlobalSearchModalProps> = ({
  isOpen,
  onClose,
  onSelectTest,
  onNavigateToOwasp,
  onNavigateToView
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [activeTab, setActiveTab] = useState<'all' | 'tests' | 'threats' | 'tools' | 'incidents'>('all');
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setSelectedIndex(0);
    } else {
      setQuery('');
    }
  }, [isOpen]);

  // Build searchable index
  const allSearchItems = useMemo<SearchResultItem[]>(() => {
    const items: SearchResultItem[] = [];

    // 1. Security Tests
    for (const test of TEST_DATA) {
      items.push({
        id: `test-${test.id}`,
        title: `${test.id}: ${test.title}`,
        subtitle: test.summary,
        category: 'test',
        categoryLabel: 'Security Test',
        badgeColor: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400',
        testItem: test
      });
    }

    // 2. OWASP LLM Top 10
    for (const entry of OWASP_TOP_10_DATA) {
      items.push({
        id: `llm-${entry.id}`,
        title: `${entry.id}: ${entry.title}`,
        subtitle: entry.description,
        category: 'llm',
        categoryLabel: 'OWASP LLM 2026',
        badgeColor: 'border-pink-500/30 bg-pink-500/10 text-pink-400',
        targetId: entry.id
      });
    }

    // 3. OWASP ML Top 10
    for (const entry of OWASP_ML_TOP_10_DATA) {
      items.push({
        id: `ml-${entry.id}`,
        title: `${entry.id}: ${entry.title}`,
        subtitle: entry.description,
        category: 'ml',
        categoryLabel: 'OWASP ML Top 10',
        badgeColor: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
        targetId: entry.id
      });
    }

    // 4. OWASP Agentic Applications (ASI)
    for (const entry of OWASP_AGENTIC_APPLICATIONS_DATA) {
      items.push({
        id: `asi-${entry.id}`,
        title: `${entry.id}: ${entry.title}`,
        subtitle: entry.description,
        category: 'agentic',
        categoryLabel: 'Agentic App (ASI)',
        badgeColor: 'border-orange-500/30 bg-orange-500/10 text-orange-400',
        targetId: entry.id
      });
    }

    // 5. OWASP Agentic Skills (AST)
    for (const entry of OWASP_AGENTIC_THREATS_DATA) {
      items.push({
        id: `ast-${entry.id}`,
        title: `${entry.id}: ${entry.title}`,
        subtitle: entry.description,
        category: 'agentic',
        categoryLabel: 'Agentic Skill (AST)',
        badgeColor: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
        targetId: entry.id
      });
    }

    // 6. Google SAIF
    for (const entry of OWASP_SAIF_THREATS_DATA) {
      items.push({
        id: `saif-${entry.id}`,
        title: `${entry.id}: ${entry.title}`,
        subtitle: entry.description,
        category: 'saif',
        categoryLabel: 'Google SAIF Risk',
        badgeColor: 'border-blue-500/30 bg-blue-500/10 text-blue-400',
        targetId: entry.id
      });
    }

    // 7. OWASP MCP Top 10
    for (const entry of OWASP_MCP_TOP_10_DATA) {
      items.push({
        id: `mcp-${entry.id}`,
        title: `${entry.id}: ${entry.title}`,
        subtitle: entry.description,
        category: 'mcp',
        categoryLabel: 'OWASP MCP Top 10',
        badgeColor: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400',
        targetId: entry.id
      });
    }

    // 8. GenAI Data Security Risks (DSGAI)
    for (const entry of GENAI_DATA_SECURITY_RISKS) {
      items.push({
        id: `dsgai-${entry.id}`,
        title: `${entry.id}: ${entry.title}`,
        subtitle: entry.summary,
        category: 'dsgai',
        categoryLabel: 'GenAI Data Security',
        badgeColor: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
        targetId: entry.id
      });
    }

    // 9. AI-DSPM Capabilities
    for (const entry of GENAI_DSPM_CAPABILITIES) {
      items.push({
        id: `dspm-${entry.id}`,
        title: `${entry.id}: ${entry.title}`,
        subtitle: entry.objective,
        category: 'dspm',
        categoryLabel: 'AI-DSPM Capability',
        badgeColor: 'border-teal-500/30 bg-teal-500/10 text-teal-300',
        targetId: entry.id
      });
    }

    // 10. Tools Catalog
    const seenToolNames = new Set<string>();
    for (const [threatId, tools] of Object.entries(TOOLS_BY_THREAT_ID)) {
      for (const tool of tools) {
        const key = tool.name.toLowerCase();
        if (!seenToolNames.has(key)) {
          seenToolNames.add(key);
          items.push({
            id: `tool-${tool.name}`,
            title: tool.name,
            subtitle: `${tool.description} (Mapped to ${threatId})`,
            category: 'tool',
            categoryLabel: `Tool (${tool.type})`,
            badgeColor: 'border-purple-500/30 bg-purple-500/10 text-purple-300',
            targetId: threatId,
            url: tool.url
          });
        }
      }
    }

    // 11. Incidents Catalog
    const seenIncidentTitles = new Set<string>();
    for (const [threatId, incidents] of Object.entries(INCIDENTS_BY_THREAT_ID)) {
      for (const inc of incidents) {
        const key = inc.title.toLowerCase();
        if (!seenIncidentTitles.has(key)) {
          seenIncidentTitles.add(key);
          items.push({
            id: `inc-${inc.title}`,
            title: inc.title,
            subtitle: `Real-world exploit/research citation mapped to ${threatId}`,
            category: 'incident',
            categoryLabel: 'Incident / CVE',
            badgeColor: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
            targetId: threatId,
            url: inc.url
          });
        }
      }
    }

    return items;
  }, []);

  // Filtered results
  const filteredResults = useMemo(() => {
    const cleanQuery = query.trim().toLowerCase();
    let list = allSearchItems;

    if (activeTab === 'tests') {
      list = list.filter(i => i.category === 'test');
    } else if (activeTab === 'threats') {
      list = list.filter(i => ['llm', 'ml', 'agentic', 'saif', 'mcp', 'dsgai', 'dspm'].includes(i.category));
    } else if (activeTab === 'tools') {
      list = list.filter(i => i.category === 'tool');
    } else if (activeTab === 'incidents') {
      list = list.filter(i => i.category === 'incident');
    }

    if (!cleanQuery) {
      return list.slice(0, 15);
    }

    return list.filter(item => {
      return (
        item.title.toLowerCase().includes(cleanQuery) ||
        item.subtitle.toLowerCase().includes(cleanQuery) ||
        item.categoryLabel.toLowerCase().includes(cleanQuery)
      );
    }).slice(0, 30);
  }, [allSearchItems, query, activeTab]);

  // Handle keyboard events
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => (prev + 1 < filteredResults.length ? prev + 1 : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => (prev - 1 >= 0 ? prev - 1 : filteredResults.length - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const selected = filteredResults[selectedIndex];
      if (selected) {
        handleSelectItem(selected);
      }
    }
  };

  const handleSelectItem = (item: SearchResultItem) => {
    if (item.testItem) {
      onSelectTest(item.testItem);
    } else if (item.targetId) {
      onNavigateToOwasp(item.targetId);
    } else if (item.category === 'tool' && onNavigateToView) {
      onNavigateToView('tools');
    } else if (item.category === 'incident' && onNavigateToView) {
      onNavigateToView('incidents');
    }
    onClose();
  };

  const getCategoryIcon = (category: SearchResultItem['category']) => {
    switch (category) {
      case 'test': return <Shield className="w-4 h-4 text-cyan-400" />;
      case 'llm': return <Brain className="w-4 h-4 text-pink-400" />;
      case 'ml': return <Cpu className="w-4 h-4 text-emerald-400" />;
      case 'agentic': return <Bot className="w-4 h-4 text-orange-400" />;
      case 'saif': return <Gavel className="w-4 h-4 text-blue-400" />;
      case 'mcp': return <Network className="w-4 h-4 text-cyan-400" />;
      case 'dsgai':
      case 'dspm': return <Database className="w-4 h-4 text-emerald-400" />;
      case 'tool': return <Terminal className="w-4 h-4 text-purple-400" />;
      case 'incident': return <Flame className="w-4 h-4 text-amber-400" />;
    }
  };

  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 z-50 flex items-start justify-center p-3 sm:p-6 md:p-12 bg-black/70 backdrop-blur-md animate-in fade-in duration-200"
      onClick={onClose}
      onKeyDown={handleKeyDown}
    >
      <div 
        className="w-full max-w-3xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh] animate-in zoom-in-95 duration-200"
        onClick={e => e.stopPropagation()}
      >
        {/* Search Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-950/80 flex items-center gap-3">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Search all 42 tests, 89 framework threats, tools, CVEs, or keywords... (e.g. injection, backdoor, AST02, ML07)"
            className="flex-1 bg-transparent border-0 text-slate-100 placeholder:text-slate-500 focus:outline-none text-base"
          />
          {query && (
            <button 
              onClick={() => setQuery('')}
              className="text-slate-500 hover:text-slate-300 p-1"
              type="button"
              aria-label="Clear search"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <kbd className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono text-slate-400 bg-slate-800 border border-slate-700 rounded">
            ESC
          </kbd>
        </div>

        {/* Filter Tabs */}
        <div className="flex items-center gap-1 px-4 py-2 border-b border-slate-800 bg-slate-950/40 text-xs overflow-x-auto">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${activeTab === 'all' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'}`}
          >
            All Results
          </button>
          <button
            onClick={() => setActiveTab('tests')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${activeTab === 'tests' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Tests ({TEST_DATA.length})
          </button>
          <button
            onClick={() => setActiveTab('threats')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${activeTab === 'threats' ? 'bg-pink-500/20 text-pink-300 border border-pink-500/30' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Framework Threats (89)
          </button>
          <button
            onClick={() => setActiveTab('tools')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${activeTab === 'tools' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Tools
          </button>
          <button
            onClick={() => setActiveTab('incidents')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${activeTab === 'incidents' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Incidents
          </button>
        </div>

        {/* Results List */}
        <div ref={listRef} className="flex-1 overflow-y-auto p-2 space-y-1 divide-y divide-slate-800/40">
          {filteredResults.length === 0 ? (
            <div className="py-12 text-center text-slate-500">
              <p className="text-sm">No results found for &ldquo;{query}&rdquo;</p>
              <p className="text-xs text-slate-600 mt-1">Try searching by ID (e.g. LLM01, ASI03, AITG-APP-01) or threat keyword.</p>
            </div>
          ) : (
            filteredResults.map((item, index) => (
              <div
                key={item.id}
                onClick={() => handleSelectItem(item)}
                onMouseEnter={() => setSelectedIndex(index)}
                className={`p-3 rounded-xl cursor-pointer transition-all flex items-start justify-between gap-3 ${
                  selectedIndex === index
                    ? 'bg-slate-800/90 border border-cyan-500/40 text-slate-100 shadow-md'
                    : 'text-slate-300 hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-start gap-3 min-w-0 flex-1">
                  <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 shrink-0 mt-0.5">
                    {getCategoryIcon(item.category)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${item.badgeColor}`}>
                        {item.categoryLabel}
                      </span>
                    </div>
                    <h4 className="font-semibold text-sm text-slate-100 truncate">
                      {item.title}
                    </h4>
                    <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">
                      {item.subtitle}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-center">
                  {selectedIndex === index && (
                    <span className="hidden sm:inline-flex items-center gap-1 text-[11px] text-cyan-400 font-mono">
                      Jump <CornerDownLeft className="w-3 h-3" />
                    </span>
                  )}
                  <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400" />
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/80 text-[11px] text-slate-400 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded font-mono">↑</kbd>
              <kbd className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded font-mono">↓</kbd>
              to navigate
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded font-mono">↵</kbd>
              to select
            </span>
          </div>
          <div>
            <span className="font-mono text-cyan-400">{filteredResults.length}</span> items matching
          </div>
        </div>
      </div>
    </div>
  );
};
export default GlobalSearchModal;
