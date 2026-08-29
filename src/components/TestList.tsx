
import React, { useState, useMemo } from 'react';
import { TestItem } from '../types';
import { 
  ArrowRight, Brain, Filter, ListFilter, Cpu, Bot, Book, Gavel, 
  Network, Database, Search, X, Shield, Flame, ChevronDown, ChevronUp, 
  Layers, ExternalLink, Sparkles 
} from 'lucide-react';
import { MITRE_ATLAS_TECHNIQUES } from '../data';

interface TestListProps {
  tests: TestItem[];
  onSelectTest: (test: TestItem) => void;
  onNavigateToOwasp: (id: string) => void;
  category: string;
}

const TestList: React.FC<TestListProps> = ({ tests, onSelectTest, onNavigateToOwasp, category }) => {
  const [sortMethod, setSortMethod] = useState<'id' | 'severity'>('id');
  const [filterType, setFilterType] = useState<'all' | 'top10' | 'mltop10' | 'agenttop10' | 'saiftop10' | 'mcptop10' | 'aitg' | 'atlas'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isAtlasExpanded, setIsAtlasExpanded] = useState(false);

  const getRiskColor = (level: string) => {
    switch(level) {
      case 'Critical': return 'text-red-400 bg-red-400/10 border-red-400/20';
      case 'High': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
      case 'Medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
      default: return 'text-green-400 bg-green-400/10 border-green-400/20';
    }
  };

  const getRiskValue = (level: string) => {
    switch(level) {
      case 'Critical': return 4;
      case 'High': return 3;
      case 'Medium': return 2;
      default: return 1;
    }
  };

  // Mapped MITRE ATLAS Techniques for the current Pillar / test collection
  const mappedAtlasTechniques = useMemo(() => {
    const atlasIdSet = new Set<string>();
    for (const t of tests) {
      if (t.mitreAtlasRef) atlasIdSet.add(t.mitreAtlasRef);
    }
    const result: { id: string; name: string; tacticName?: string }[] = [];
    for (const id of atlasIdSet) {
      const match = MITRE_ATLAS_TECHNIQUES.find(tech => tech.id === id);
      if (match) {
        result.push({
          id: match.id,
          name: match.name,
          tacticName: match.tactics?.[0]?.name || match.tactics?.[0]?.id || 'MITRE ATLAS'
        });
      } else {
        result.push({ id, name: id, tacticName: 'MITRE ATLAS' });
      }
    }
    return result;
  }, [tests]);

  // 1. Filter the tests based on the selected filterType & free-text searchQuery
  const filteredTests = useMemo(() => {
    const cleanQuery = searchQuery.trim().toLowerCase();

    return tests.filter(test => {
      // Source filter
      if (filterType === 'top10' && !test.owaspTop10Ref) return false;
      if (filterType === 'mltop10' && !test.owaspMlTop10Ref) return false;
      if (filterType === 'agenttop10' && !test.owaspAgenticRef) return false;
      if (filterType === 'saiftop10' && !test.owaspSaifRef) return false;
      if (filterType === 'mcptop10' && !test.owaspMcpTop10Ref) return false;
      if (filterType === 'aitg' && !test.id.startsWith('AITG')) return false;
      if (filterType === 'atlas' && !test.mitreAtlasRef) return false;

      // Free-text keyword search
      if (cleanQuery) {
        const textToSearch = [
          test.id,
          test.title,
          test.summary,
          test.pillar,
          test.riskLevel,
          test.owaspTop10Ref || '',
          test.owaspMlTop10Ref || '',
          test.owaspAgenticRef || '',
          test.owaspSaifRef || '',
          test.owaspMcpTop10Ref || '',
          test.mitreAtlasRef || '',
          ...(test.objectives || []),
          ...(test.payloads || []).map(p => `${p.name} ${p.description} ${p.code || ''}`),
          ...(test.mitigationStrategies || []).map(m => m.content)
        ].join(' ').toLowerCase();

        if (!textToSearch.includes(cleanQuery)) return false;
      }

      return true;
    });
  }, [tests, filterType, searchQuery]);

  // 2. Sort the filtered list
  const sortedTests = useMemo(() => {
    return [...filteredTests].sort((a, b) => {
      if (sortMethod === 'severity') {
        return getRiskValue(b.riskLevel) - getRiskValue(a.riskLevel);
      }
      
      // Default Sort: AITG tests first, then AGT tests
      const isAITG_a = a.id.startsWith('AITG');
      const isAITG_b = b.id.startsWith('AITG');

      if (isAITG_a && !isAITG_b) return -1;
      if (!isAITG_a && isAITG_b) return 1;

      // Secondary sort by ID alpha
      return a.id.localeCompare(b.id);
    });
  }, [filteredTests, sortMethod]);

  return (
    <div className="container-fluid p-3 sm:p-4 md:p-8 max-w-6xl mx-auto animate-in fade-in duration-500">
      {/* Header Section */}
      <div className="mb-8 border-b border-slate-800 pb-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 mb-6">
          <div>
            <h2 className="text-2xl md:text-3xl font-bold text-white mb-2">{category}</h2>
            <p className="text-slate-400 text-sm md:text-base">
              Select a test case to view detailed objectives, payloads, and remediation strategies.
            </p>
          </div>
          
          <div className="bg-slate-900/90 px-4 py-2 rounded-full border border-slate-800 text-xs md:text-sm text-slate-300 font-mono whitespace-nowrap shrink-0 flex items-center justify-center text-center self-start md:self-auto shadow-sm">
            <span className="font-semibold text-cyan-300">{filteredTests.length}</span>
            <span className="text-slate-600 mx-1.5">/</span>
            <span>{tests.length} TEST CASES</span>
          </div>
        </div>

        {/* MITRE ATLAS Mapped Matrix Section for Testing Pillar */}
        {mappedAtlasTechniques.length > 0 && (
          <div className="mb-6 rounded-2xl border border-orange-500/30 bg-gradient-to-br from-orange-500/10 via-slate-900/90 to-slate-950 p-4 shadow-lg shadow-orange-950/20 backdrop-blur-md">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-xl bg-orange-500/20 border border-orange-500/40 flex items-center justify-center text-orange-400 shrink-0">
                  <Flame className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-xs md:text-sm font-bold text-slate-100 uppercase tracking-wide">
                      MITRE ATLAS™ Matrix Mappings
                    </h3>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-orange-500/20 text-orange-300 border border-orange-500/30">
                      {mappedAtlasTechniques.length} Techniques
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Directly mapped adversarial tactics & techniques for this testing pillar
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => onNavigateToOwasp(mappedAtlasTechniques[0]?.id || 'AML.T0051')}
                  className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 bg-orange-500/20 hover:bg-orange-500/30 text-orange-300 border border-orange-500/40 hover:border-orange-400 rounded-lg text-xs font-semibold transition-all"
                >
                  <span>Open Full Matrix</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => setIsAtlasExpanded(prev => !prev)}
                  className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
                  aria-label={isAtlasExpanded ? "Collapse ATLAS matrix section" : "Expand ATLAS matrix section"}
                >
                  {isAtlasExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Collapsed Preview or Expanded Grid */}
            <div className={`mt-3 pt-3 border-t border-slate-800/80 transition-all ${isAtlasExpanded ? 'block' : 'max-h-16 overflow-hidden relative'}`}>
              <div className="flex flex-wrap gap-2">
                {mappedAtlasTechniques.map(tech => (
                  <button
                    key={tech.id}
                    type="button"
                    onClick={() => onNavigateToOwasp(tech.id)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono font-medium bg-slate-900/90 hover:bg-orange-500/20 text-slate-200 hover:text-orange-200 border border-slate-800 hover:border-orange-500/40 transition-all group"
                  >
                    <span className="text-orange-400 font-bold">{tech.id}</span>
                    <span className="text-slate-400 group-hover:text-slate-300 font-sans text-[11px] truncate max-w-[200px]">{tech.name}</span>
                    <ExternalLink className="w-2.5 h-2.5 text-slate-500 group-hover:text-orange-400 shrink-0" />
                  </button>
                ))}
              </div>

              {!isAtlasExpanded && mappedAtlasTechniques.length > 5 && (
                <div className="absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-slate-950 via-slate-950/80 to-transparent flex items-center justify-center">
                  <button
                    type="button"
                    onClick={() => setIsAtlasExpanded(true)}
                    className="text-[10px] font-semibold text-orange-400 hover:text-orange-300 uppercase tracking-wider flex items-center gap-1 bg-slate-900/90 px-2 py-0.5 rounded-full border border-orange-500/30"
                  >
                    <span>+{mappedAtlasTechniques.length - 5} More Techniques</span>
                    <ChevronDown className="w-3 h-3" />
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Search Input Bar */}
        <div className="mb-4 relative">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search test cases by keyword, objective, attack payload, CVE, or ID (e.g., 'jailbreak', 'pickle', 'AITG-APP-01')..."
            className="w-full pl-10 pr-10 py-2.5 bg-slate-900/80 border border-slate-800 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 rounded-xl text-sm text-slate-100 placeholder:text-slate-500 transition-all outline-none"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition-colors"
              type="button"
              aria-label="Clear search"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Controls Toolbar */}
        <div className="flex flex-col sm:flex-row gap-4 justify-between items-center bg-slate-900/50 p-2 rounded-xl border border-slate-800/50">
          
          {/* Filter Controls */}
          <div className="flex items-center gap-1 w-full sm:w-auto overflow-x-auto scrollbar-hide">
            <span className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 hidden sm:block whitespace-nowrap">
              <Filter className="w-3 h-3 inline mr-1" />
              Source:
            </span>
            <div className="flex bg-slate-950 rounded-lg p-1 border border-slate-800 flex-1 sm:flex-none">
              <button 
                type="button"
                onClick={() => setFilterType('all')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all whitespace-nowrap ${filterType === 'all' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
              >
                All
              </button>
              <button 
                type="button"
                onClick={() => setFilterType('atlas')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${filterType === 'atlas' ? 'bg-orange-500/15 text-orange-400 border border-orange-500/30 shadow-sm' : 'text-slate-400 hover:text-orange-300'}`}
              >
                <Flame className="w-3 h-3" />
                ATLAS
              </button>
              <button 
                type="button"
                onClick={() => setFilterType('aitg')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${filterType === 'aitg' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm' : 'text-slate-400 hover:text-cyan-300'}`}
              >
                <Book className="w-3 h-3" />
                AI Testing Guide
              </button>
              <button 
                type="button"
                onClick={() => setFilterType('top10')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${filterType === 'top10' ? 'bg-pink-500/10 text-pink-400 border border-pink-500/20 shadow-sm' : 'text-slate-400 hover:text-pink-300'}`}
              >
                <Brain className="w-3 h-3" />
                LLM
              </button>
              <button 
                type="button"
                onClick={() => setFilterType('mltop10')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${filterType === 'mltop10' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-sm' : 'text-slate-400 hover:text-emerald-300'}`}
              >
                <Cpu className="w-3 h-3" />
                ML
              </button>
              <button 
                type="button"
                onClick={() => setFilterType('agenttop10')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${filterType === 'agenttop10' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20 shadow-sm' : 'text-slate-400 hover:text-orange-300'}`}
              >
                <Bot className="w-3 h-3" />
                Agentic
              </button>
              <button 
                type="button"
                onClick={() => setFilterType('saiftop10')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${filterType === 'saiftop10' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20 shadow-sm' : 'text-slate-400 hover:text-blue-300'}`}
              >
                <Gavel className="w-3 h-3" />
                SAIF
              </button>
              <button 
                type="button"
                onClick={() => setFilterType('mcptop10')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${filterType === 'mcptop10' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm' : 'text-slate-400 hover:text-cyan-300'}`}
              >
                <Network className="w-3 h-3" />
                MCP
              </button>
            </div>
          </div>

          {/* Sort Controls */}
          <div className="flex items-center gap-1 w-full sm:w-auto justify-end">
            <span className="text-xs font-bold text-slate-500 uppercase tracking-wider px-2 hidden sm:block">
              <ListFilter className="w-3 h-3 inline mr-1" />
              Sort:
            </span>
            <div className="flex bg-slate-950 rounded-lg p-1 border border-slate-800 flex-1 sm:flex-none">
              <button 
                type="button"
                onClick={() => setSortMethod('id')}
                className={`flex-1 sm:flex-none px-3 py-1.5 rounded-md text-xs font-medium transition-all ${sortMethod === 'id' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                By ID
              </button>
              <button 
                type="button"
                onClick={() => setSortMethod('severity')}
                className={`flex-1 sm:flex-none px-3 py-1.5 rounded-md text-xs font-medium transition-all ${sortMethod === 'severity' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                Severity
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* List Grid */}
      <div className="grid gap-4">
        {sortedTests.length === 0 ? (
          <div className="text-center py-12 border border-dashed border-slate-800 rounded-xl bg-slate-900/30">
            <p className="text-slate-500">No test cases found matching the current filter.</p>
            <button type="button" onClick={() => setFilterType('all')} className="mt-2 text-cyan-400 text-sm hover:underline">
              Clear filters
            </button>
          </div>
        ) : (
          sortedTests.map((test) => (
            <div 
              key={test.id}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelectTest(test);
                }
              }}
              onClick={() => onSelectTest(test)}
              className="content-auto group bg-slate-900/50 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/30 rounded-xl p-4 sm:p-5 cursor-pointer transition-all duration-200 relative overflow-hidden focus:outline-none focus:ring-1 focus:ring-cyan-500/40"
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 relative z-10">
                
                <div className="space-y-3 flex-1 min-w-0">
                  {/* Identifiers Row (Above Title) */}
                  <div className="flex flex-wrap items-center gap-2">
                    <span 
                      className="font-mono text-xs text-slate-500 bg-slate-950 px-2 py-1 rounded border border-slate-800 min-w-[90px] text-center hover:bg-slate-900 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
                      title="Test ID"
                    >
                      {test.id}
                    </span>
                    {test.owaspTop10Ref && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToOwasp(test.owaspTop10Ref!);
                        }}
                        className="flex items-center gap-1 font-mono text-xs text-pink-400 bg-pink-500/10 px-2 py-1 rounded border border-pink-500/20 whitespace-nowrap hover:bg-pink-500/20 hover:border-pink-500/40 hover:scale-105 active:scale-95 transition-all z-20 cursor-pointer"
                        title="Go to OWASP LLM Top 10 Entry"
                      >
                        <Brain className="w-3 h-3" /> {test.owaspTop10Ref}
                      </button>
                    )}
                    {test.owaspMlTop10Ref && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToOwasp(test.owaspMlTop10Ref!);
                        }}
                        className="flex items-center gap-1 font-mono text-xs text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded border border-emerald-500/20 whitespace-nowrap hover:bg-emerald-500/20 hover:border-emerald-500/40 hover:scale-105 active:scale-95 transition-all z-20 cursor-pointer"
                        title="Go to OWASP ML Top 10 Entry"
                      >
                        <Cpu className="w-3 h-3" /> {test.owaspMlTop10Ref}
                      </button>
                    )}
                    {test.owaspAgenticRef && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToOwasp(test.owaspAgenticRef!);
                        }}
                        className="flex items-center gap-1 font-mono text-xs text-orange-400 bg-orange-500/10 px-2 py-1 rounded border border-orange-500/20 whitespace-nowrap hover:bg-orange-500/20 hover:border-orange-500/40 hover:scale-105 active:scale-95 transition-all z-20 cursor-pointer"
                        title="Go to OWASP Agentic Top 10 entry"
                      >
                        <Bot className="w-3 h-3" /> {test.owaspAgenticRef}
                      </button>
                    )}
                    {test.owaspSaifRef && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToOwasp(test.owaspSaifRef!);
                        }}
                        className="flex items-center gap-1 font-mono text-xs text-blue-400 bg-blue-500/10 px-2 py-1 rounded border border-blue-500/20 whitespace-nowrap hover:bg-blue-500/20 hover:border-blue-500/40 hover:scale-105 active:scale-95 transition-all z-20 cursor-pointer"
                        title="Go to Google SAIF Risk Entry"
                      >
                        <Gavel className="w-3 h-3" /> {test.owaspSaifRef}
                      </button>
                    )}
                    {test.owaspMcpTop10Ref && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToOwasp(test.owaspMcpTop10Ref!);
                        }}
                        className="flex items-center gap-1 font-mono text-xs text-cyan-400 bg-cyan-500/10 px-2 py-1 rounded border border-cyan-500/20 whitespace-nowrap hover:bg-cyan-500/20 hover:border-cyan-500/40 hover:scale-105 active:scale-95 transition-all z-20 cursor-pointer"
                        title="Go to OWASP MCP Top 10 Entry"
                      >
                        <Network className="w-3 h-3" /> {test.owaspMcpTop10Ref}
                      </button>
                    )}
                    {test.owaspDsgaiRef && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToOwasp(test.owaspDsgaiRef!);
                        }}
                        className="flex items-center gap-1 font-mono text-xs text-indigo-400 bg-indigo-500/10 px-2 py-1 rounded border border-indigo-500/20 whitespace-nowrap hover:bg-indigo-500/20 hover:border-indigo-500/40 hover:scale-105 active:scale-95 transition-all z-20 cursor-pointer"
                        title="Go to OWASP GenAI Data Security Entry"
                      >
                        <Database className="w-3 h-3" /> {test.owaspDsgaiRef}
                      </button>
                    )}
                    {test.mitreAtlasRef && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToOwasp(test.mitreAtlasRef!);
                        }}
                        className="flex items-center gap-1 font-mono text-xs text-rose-400 bg-rose-500/10 px-2 py-1 rounded border border-rose-500/20 whitespace-nowrap hover:bg-rose-500/20 hover:border-rose-500/40 hover:scale-105 active:scale-95 transition-all z-20 cursor-pointer"
                        title="Jump to MITRE ATLAS™ Technique Matrix"
                      >
                        <Shield className="w-3 h-3" /> {test.mitreAtlasRef}
                      </button>
                    )}
                  </div>

                  {/* Title Row */}
                  <h3 className="text-base md:text-lg font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors break-words">
                    {test.title}
                  </h3>
                  
                  <p className="text-slate-400 text-sm line-clamp-2">
                    {test.summary}
                  </p>
                </div>
                
                <div className="flex items-center justify-between md:justify-end gap-4 shrink-0 mt-2 md:mt-0 border-t md:border-t-0 border-slate-800/50 pt-3 md:pt-0 self-start">
                  <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getRiskColor(test.riskLevel)}`}>
                    {test.riskLevel} Risk
                  </span>
                  <ArrowRight className="w-5 h-5 text-slate-600 group-hover:text-cyan-400 transform group-hover:translate-x-1 transition-all" />
                </div>

              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default TestList;
