import React, { useState, useMemo, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { 
  Flame, Search, Filter, ExternalLink, Shield, Layers, BookOpen, 
  ChevronRight, ChevronLeft, X, Copy, Check, Info, Sparkles, 
  Eye, Cpu, Crosshair, ArrowUpRight, Terminal, RefreshCw, AlertCircle,
  Radar, FileText, ArrowRight, CornerDownRight, Tag, Compass,
  Grid, ListFilter, SlidersHorizontal, ChevronDown, ChevronUp,
  Bot, BrainCircuit, Network, ShieldCheck, Database, CheckCircle2, Server
} from 'lucide-react';
import { 
  MITRE_ATLAS_META, 
  MITRE_ATLAS_TACTICS, 
  MITRE_ATLAS_TECHNIQUES,
  TEST_DATA 
} from '../data';
import { MitreAtlasTactic, MitreAtlasTechnique, TestItem, Pillar } from '../types';

interface MitreAtlasViewProps {
  initialTechniqueId?: string | null;
  initialPillar?: Pillar | 'ALL';
  onNavigateToTest?: (test: TestItem) => void;
  onNavigateToOwasp?: (id: string) => void;
}

// 4 High-Level Kill Chain Stages for AI Adversaries
interface KillChainPhase {
  id: string;
  name: string;
  shortName: string;
  description: string;
  tacticIds: string[];
  gradient: string;
  borderAccent: string;
  textAccent: string;
  bgBadge: string;
}

const KILL_CHAIN_PHASES: KillChainPhase[] = [
  {
    id: 'phase-recon',
    name: 'Phase 1: Pre-Attack & Resource Preparation',
    shortName: 'Pre-Attack & Recon',
    description: 'Adversaries research target AI architectures, acquire tooling, models, and infrastructure.',
    tacticIds: ['AML.TA0002', 'AML.TA0003'], // Reconnaissance, Resource Development
    gradient: 'from-orange-500/10 to-amber-500/5',
    borderAccent: 'border-orange-500/30',
    textAccent: 'text-orange-400',
    bgBadge: 'bg-orange-500/15',
  },
  {
    id: 'phase-access',
    name: 'Phase 2: Infiltration & Access Execution',
    shortName: 'Access & Infiltration',
    description: 'Breaching boundaries, gaining model access, executing payloads, and establishing footholds.',
    tacticIds: ['AML.TA0004', 'AML.TA0000', 'AML.TA0005', 'AML.TA0006', 'AML.TA0012', 'AML.TA0007', 'AML.TA0013'], // Initial Access, Model Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access
    gradient: 'from-amber-500/10 to-yellow-500/5',
    borderAccent: 'border-amber-500/30',
    textAccent: 'text-amber-400',
    bgBadge: 'bg-amber-500/15',
  },
  {
    id: 'phase-discovery',
    name: 'Phase 3: Discovery & Attack Staging',
    shortName: 'Discovery & Staging',
    description: 'Mapping internal AI pipelines, staging adversarial perturbations, and gathering model artifacts.',
    tacticIds: ['AML.TA0008', 'AML.TA0015', 'AML.TA0009', 'AML.TA0001'], // Discovery, Lateral Movement, Collection, ML Attack Staging
    gradient: 'from-cyan-500/10 to-blue-500/5',
    borderAccent: 'border-cyan-500/30',
    textAccent: 'text-cyan-400',
    bgBadge: 'bg-cyan-500/15',
  },
  {
    id: 'phase-impact',
    name: 'Phase 4: Exfiltration, Evasion & System Impact',
    shortName: 'C2, Exfiltration & Impact',
    description: 'Controlling compromised agentic loops, exfiltrating proprietary IP, and causing catastrophic disruption.',
    tacticIds: ['AML.TA0014', 'AML.TA0010', 'AML.TA0011'], // Command and Control, Exfiltration, Impact
    gradient: 'from-rose-500/10 to-pink-500/5',
    borderAccent: 'border-rose-500/30',
    textAccent: 'text-rose-400',
    bgBadge: 'bg-rose-500/15',
  }
];

// Robust Helper to test if a technique belongs to a tactic
const isTechniqueInTactic = (tech: MitreAtlasTechnique, tacticId: string): boolean => {
  if (tech.tacticId === tacticId) return true;
  if (tech.tactics && tech.tactics.some(t => t.id === tacticId)) return true;
  return false;
};

// Helper to test if a technique belongs to any tactic in a phase
const isTechniqueInPhase = (tech: MitreAtlasTechnique, phaseTacticIds: string[]): boolean => {
  return phaseTacticIds.some(tId => isTechniqueInTactic(tech, tId));
};

// Compute Testing Pillars associated with a MITRE ATLAS technique
export const getTechniquePillars = (tech: MitreAtlasTechnique): Pillar[] => {
  const pillars = new Set<Pillar>();
  
  // 1. Direct cross-references from curated test cases in TEST_DATA
  for (const test of TEST_DATA) {
    if (test.mitreAtlasRef === tech.id) {
      pillars.add(test.pillar);
    }
  }

  // 2. Tactic and Technique mapping heuristics
  const tacticIds = [tech.tacticId, ...(tech.tactics || []).map(t => t.id)].filter(Boolean);
  
  if (
    tacticIds.some(id => ['AML.TA0005', 'AML.TA0006', 'AML.TA0007', 'AML.TA0014', 'AML.TA0010'].includes(id)) ||
    tech.id.startsWith('AML.T005') || tech.id.startsWith('AML.T0036') || tech.id.includes('.002')
  ) {
    pillars.add(Pillar.APP);
  }
  
  if (
    tacticIds.some(id => ['AML.TA0000', 'AML.TA0001', 'AML.TA0011'].includes(id)) ||
    tech.id.startsWith('AML.T0015') || tech.id.startsWith('AML.T0024') || tech.id.startsWith('AML.T0025') ||
    tech.id.startsWith('AML.T0018') || tech.id.startsWith('AML.T0031') || tech.id.includes('.001')
  ) {
    pillars.add(Pillar.MODEL);
  }
  
  if (
    tacticIds.some(id => ['AML.TA0002', 'AML.TA0003', 'AML.TA0004', 'AML.TA0012', 'AML.TA0013', 'AML.TA0015'].includes(id)) ||
    tech.id.startsWith('AML.T0010') || tech.id.startsWith('AML.T0008') || tech.id.startsWith('AML.T0048')
  ) {
    pillars.add(Pillar.INFRA);
  }
  
  if (
    tacticIds.some(id => ['AML.TA0009'].includes(id)) ||
    tech.id.startsWith('AML.T0020') || tech.id.startsWith('AML.T0022') || tech.id.startsWith('AML.T0023') || tech.id.includes('.000')
  ) {
    pillars.add(Pillar.DATA);
  }

  // Fallback: If not mapped, default to APP
  if (pillars.size === 0) {
    pillars.add(Pillar.APP);
  }

  return Array.from(pillars);
};

// Rich Markdown Text Renderer with safe external links & interactive internal technique pills
const MitreDescriptionRenderer: React.FC<{
  text: string;
  onSelectTechniqueById: (id: string) => void;
}> = ({ text, onSelectTechniqueById }) => {
  const lines = text.split('\n');
  const footnoteDefs: { key: string; url: string; title?: string }[] = [];
  const contentLines: string[] = [];

  for (const line of lines) {
    const fnMatch = line.match(/^\[([^\]]+)\]:\s*(https?:\/\/[^\s"]+)(?:\s+"([^"]+)")?/);
    if (fnMatch) {
      footnoteDefs.push({
        key: fnMatch[1],
        url: fnMatch[2],
        title: fnMatch[3]
      });
    } else {
      contentLines.push(line);
    }
  }

  const cleanContent = contentLines.join('\n').trim();
  const paragraphs = cleanContent.split(/\n\s*\n/);

  const renderInline = (str: string) => {
    const tokenRegex = /(\[([^\]]+)\]\((?:\/techniques\/|\/tactics\/)?(AML\.[A-Z0-9.]+)\)|\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)|\[\\?\[([^\]]+)\\?\]\]\[([^\]]+)\]|\*\*([^*]+)\*\*|`([^`]+)`)/g;

    const parts: React.ReactNode[] = [];
    let lastIdx = 0;
    let match: RegExpExecArray | null;

    while ((match = tokenRegex.exec(str)) !== null) {
      if (match.index > lastIdx) {
        parts.push(str.substring(lastIdx, match.index));
      }

      if (match[2] && match[3]) {
        const label = match[2];
        const targetId = match[3];
        parts.push(
          <button
            key={`atlas-link-${match.index}`}
            type="button"
            onClick={() => onSelectTechniqueById(targetId)}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 mx-0.5 rounded bg-orange-500/15 hover:bg-orange-500/25 text-orange-300 hover:text-orange-200 border border-orange-500/30 text-xs font-mono font-medium transition-colors cursor-pointer"
          >
            <Flame className="w-2.5 h-2.5 text-orange-400 shrink-0" />
            <span>{label}</span>
          </button>
        );
      } else if (match[4] && match[5]) {
        const label = match[4];
        const url = match[5];
        parts.push(
          <a
            key={`ext-link-${match.index}`}
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-0.5 text-cyan-400 hover:text-cyan-300 underline underline-offset-2 transition-colors"
          >
            <span>{label}</span>
            <ArrowUpRight className="w-2.5 h-2.5 shrink-0 inline" />
          </a>
        );
      } else if (match[6] && match[7]) {
        const fnKey = match[7];
        const fnDef = footnoteDefs.find(f => f.key === fnKey);
        if (fnDef) {
          parts.push(
            <a
              key={`fn-ref-${match.index}`}
              href={fnDef.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[10px] font-mono font-bold text-amber-400 hover:text-amber-300 ml-0.5 px-1 py-0.5 bg-amber-500/10 rounded border border-amber-500/20"
              title={fnDef.title || fnDef.url}
            >
              [{fnKey}]
            </a>
          );
        } else {
          parts.push(<span key={`fn-${match.index}`} className="text-amber-400 font-mono text-[10px]">[{fnKey}]</span>);
        }
      } else if (match[8]) {
        parts.push(<strong key={`b-${match.index}`} className="font-semibold text-slate-100">{match[8]}</strong>);
      } else if (match[9]) {
        parts.push(
          <code key={`c-${match.index}`} className="px-1.5 py-0.5 rounded bg-slate-800 text-orange-300 font-mono text-xs">
            {match[9]}
          </code>
        );
      }

      lastIdx = match.index + match[0].length;
    }

    if (lastIdx < str.length) {
      parts.push(str.substring(lastIdx));
    }

    return parts;
  };

  return (
    <div className="space-y-3">
      {paragraphs.map((p, idx) => {
        const trimmed = p.trim();
        if (!trimmed) return null;

        if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
          const items = trimmed.split(/\n(?=[- *])/);
          return (
            <ul key={idx} className="list-disc list-inside space-y-1.5 text-sm text-slate-300 pl-2">
              {items.map((item, iIdx) => (
                <li key={iIdx} className="leading-relaxed">
                  {renderInline(item.replace(/^[- *]\s*/, ''))}
                </li>
              ))}
            </ul>
          );
        }

        return (
          <p key={idx} className="text-sm text-slate-300 leading-relaxed">
            {renderInline(trimmed)}
          </p>
        );
      })}

      {footnoteDefs.length > 0 && (
        <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-1.5 text-xs">
          <span className="text-[10px] font-mono uppercase text-slate-500 font-bold block mb-1">Citations & Footnotes</span>
          {footnoteDefs.map((fn) => (
            <div key={fn.key} className="flex items-center gap-2 text-slate-400">
              <span className="font-mono text-amber-400 font-bold">[{fn.key}]</span>
              <a
                href={fn.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:text-cyan-300 truncate underline flex items-center gap-1"
              >
                <span>{fn.title || fn.url}</span>
                <ArrowUpRight className="w-3 h-3 shrink-0" />
              </a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const MitreAtlasView: React.FC<MitreAtlasViewProps> = ({
  initialTechniqueId,
  initialPillar,
  onNavigateToTest,
  onNavigateToOwasp
}) => {
  // Navigation Mode: 'navigator' (Lifecycle Stepper & 2-Pane Workstation) | 'matrix' (Streamlined Matrix) | 'directory' (Searchable List)
  const [viewMode, setViewMode] = useState<'navigator' | 'matrix' | 'directory'>('navigator');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPhaseId, setSelectedPhaseId] = useState<string>('phase-recon');
  const [focusedTacticId, setFocusedTacticId] = useState<string>('AML.TA0002');
  const [selectedDirectoryTacticFilter, setSelectedDirectoryTacticFilter] = useState<string>('ALL');
  const [techniqueTypeFilter, setTechniqueTypeFilter] = useState<'ALL' | 'PARENT' | 'SUB'>('ALL');
  const [hasMitigationsOnly, setHasMitigationsOnly] = useState(false);
  const [hasCaseStudiesOnly, setHasCaseStudiesOnly] = useState(false);
  const [selectedParadigmFilter, setSelectedParadigmFilter] = useState<'ALL' | 'AGENTIC' | 'GENAI' | 'PREDICTIVE' | 'ENTERPRISE'>('ALL');
  const [selectedPillarFilter, setSelectedPillarFilter] = useState<Pillar | 'ALL'>(initialPillar || 'ALL');
  
  // Matrix Subtechnique Collapsing State
  const [expandedParents, setExpandedParents] = useState<Set<string>>(new Set());
  const [allSubtechniquesExpanded, setAllSubtechniquesExpanded] = useState(false);

  // Inspector Modal State
  const [selectedTechnique, setSelectedTechnique] = useState<MitreAtlasTechnique | null>(null);
  const [activeModalTab, setActiveModalTab] = useState<'overview' | 'procedures' | 'mitigations' | 'citations'>('overview');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Sync initialPillar prop
  useEffect(() => {
    if (initialPillar) {
      setSelectedPillarFilter(initialPillar);
    }
  }, [initialPillar]);

  // Handle initial deep-linking by technique or tactic ID
  useEffect(() => {
    if (initialTechniqueId) {
      const upper = initialTechniqueId.toUpperCase();
      const matched = MITRE_ATLAS_TECHNIQUES.find(t => 
        t.id.toUpperCase() === upper || upper.includes(t.id.toUpperCase())
      );
      if (matched) {
        setSelectedTechnique(matched);
        const parentPhase = KILL_CHAIN_PHASES.find(p => p.tacticIds.includes(matched.tacticId));
        if (parentPhase) {
          setSelectedPhaseId(parentPhase.id);
          setFocusedTacticId(matched.tacticId);
        }
      } else {
        const matchedTactic = MITRE_ATLAS_TACTICS.find(tac => 
          tac.id.toUpperCase() === upper || tac.shortname.toUpperCase() === upper
        );
        if (matchedTactic) {
          const parentPhase = KILL_CHAIN_PHASES.find(p => p.tacticIds.includes(matchedTactic.id));
          if (parentPhase) {
            setSelectedPhaseId(parentPhase.id);
            setFocusedTacticId(matchedTactic.id);
          }
        }
      }
    }
  }, [initialTechniqueId]);

  // Handle ESC key to close modal and body scroll locking
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedTechnique) {
        setSelectedTechnique(null);
      }
    };
    if (selectedTechnique) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [selectedTechnique]);

  const handleCopyId = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Toggle individual parent expansion
  const toggleParentExpansion = (parentId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setExpandedParents(prev => {
      const next = new Set(prev);
      if (next.has(parentId)) {
        next.delete(parentId);
      } else {
        next.add(parentId);
      }
      return next;
    });
  };

  // Toggle all subtechniques
  const toggleAllSubtechniques = () => {
    if (allSubtechniquesExpanded) {
      setExpandedParents(new Set());
      setAllSubtechniquesExpanded(false);
    } else {
      const allParentIds = new Set(
        MITRE_ATLAS_TECHNIQUES.filter(t => !t.isSubtechnique && t.subtechniques && t.subtechniques.length > 0).map(t => t.id)
      );
      setExpandedParents(allParentIds);
      setAllSubtechniquesExpanded(true);
    }
  };

  // Helper to categorize techniques by AI paradigm
  const matchesParadigm = (tech: MitreAtlasTechnique, paradigm: string): boolean => {
    if (paradigm === 'ALL') return true;
    const text = `${tech.id} ${tech.name} ${tech.description} ${(tech.platforms || []).join(' ')}`.toLowerCase();
    
    if (paradigm === 'AGENTIC') {
      return text.includes('agent') || text.includes('autonomous') || text.includes('tool') || text.includes('clawdbot') || text.includes('aml.t008') || text.includes('aml.t009');
    }
    if (paradigm === 'GENAI') {
      return text.includes('llm') || text.includes('prompt') || text.includes('generative') || text.includes('gpt') || text.includes('rag') || text.includes('chat') || text.includes('language model');
    }
    if (paradigm === 'PREDICTIVE') {
      return text.includes('evasion') || text.includes('poison') || text.includes('adversarial example') || text.includes('inversion') || text.includes('classifier') || text.includes('surrogate');
    }
    if (paradigm === 'ENTERPRISE') {
      return (tech.platforms || []).includes('Enterprise') || text.includes('cloud') || text.includes('ray') || text.includes('container') || text.includes('infrastructure') || text.includes('registry');
    }
    return true;
  };

  // Global search & facet filtered techniques (independent of selected tactic)
  const baseFilteredTechniques = useMemo(() => {
    return MITRE_ATLAS_TECHNIQUES.filter(tech => {
      // 0. Testing Pillar Filter
      if (selectedPillarFilter !== 'ALL') {
        const pillars = getTechniquePillars(tech);
        if (!pillars.includes(selectedPillarFilter)) {
          return false;
        }
      }
      // 1. Type Filter
      if (techniqueTypeFilter === 'PARENT' && tech.isSubtechnique) return false;
      if (techniqueTypeFilter === 'SUB' && !tech.isSubtechnique) return false;
      // 2. Mitigations Filter
      if (hasMitigationsOnly && (!tech.mitigations || tech.mitigations.length === 0)) {
        return false;
      }
      // 3. Case Studies Filter
      if (hasCaseStudiesOnly && (!tech.caseStudies || tech.caseStudies.length === 0)) {
        return false;
      }
      // 4. Paradigm Filter
      if (!matchesParadigm(tech, selectedParadigmFilter)) {
        return false;
      }
      // 5. Keyword Search
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const matchesId = tech.id.toLowerCase().includes(query);
        const matchesName = tech.name.toLowerCase().includes(query);
        const matchesDesc = tech.description.toLowerCase().includes(query);
        const matchesTactic = tech.tacticName.toLowerCase().includes(query) || (tech.tactics && tech.tactics.some(tac => tac.name.toLowerCase().includes(query)));
        const matchesMitigations = tech.mitigations?.some(m => 
          m.name.toLowerCase().includes(query) || m.id.toLowerCase().includes(query) || m.description.toLowerCase().includes(query) || (m.useDescription && m.useDescription.toLowerCase().includes(query))
        );
        const matchesCaseStudies = tech.caseStudies?.some(c => 
          c.name.toLowerCase().includes(query) || c.id.toLowerCase().includes(query)
        );
        const matchesProcedures = tech.procedureExamples?.some(p => 
          p.caseStudyName.toLowerCase().includes(query) || p.description.toLowerCase().includes(query)
        );

        if (!matchesId && !matchesName && !matchesDesc && !matchesTactic && !matchesMitigations && !matchesCaseStudies && !matchesProcedures) {
          return false;
        }
      }
      return true;
    });
  }, [searchQuery, techniqueTypeFilter, hasMitigationsOnly, hasCaseStudiesOnly, selectedParadigmFilter]);

  // Current active Phase for Navigator mode
  const activePhase = useMemo(() => {
    return KILL_CHAIN_PHASES.find(p => p.id === selectedPhaseId) || KILL_CHAIN_PHASES[0];
  }, [selectedPhaseId]);

  // Tactics in the active phase with accurately computed matching techniques
  const activePhaseTactics = useMemo(() => {
    return MITRE_ATLAS_TACTICS.filter(tac => activePhase.tacticIds.includes(tac.id)).map(tac => {
      const matchingTechs = baseFilteredTechniques.filter(t => isTechniqueInTactic(t, tac.id));
      return {
        ...tac,
        techniques: matchingTechs
      };
    });
  }, [activePhase, baseFilteredTechniques]);

  // Active focused tactic in navigator mode
  const focusedTactic = useMemo(() => {
    const found = MITRE_ATLAS_TACTICS.find(t => t.id === focusedTacticId);
    const targetTactic = (found && activePhase.tacticIds.includes(found.id))
      ? found 
      : (activePhaseTactics[0] || MITRE_ATLAS_TACTICS[0]);
    
    return {
      ...targetTactic,
      techniques: baseFilteredTechniques.filter(t => isTechniqueInTactic(t, targetTactic.id))
    };
  }, [focusedTacticId, activePhase, activePhaseTactics, baseFilteredTechniques]);

  // Build full matrix grouped tactics
  const matrixTactics = useMemo(() => {
    return MITRE_ATLAS_TACTICS.map(tactic => {
      const matchingTechs = baseFilteredTechniques.filter(t => isTechniqueInTactic(t, tactic.id));
      return {
        ...tactic,
        techniques: matchingTechs
      };
    });
  }, [baseFilteredTechniques]);

  // Directory techniques (optionally filtered by tactic selector in directory view)
  const directoryTechniques = useMemo(() => {
    if (selectedDirectoryTacticFilter === 'ALL') {
      return baseFilteredTechniques;
    }
    return baseFilteredTechniques.filter(t => isTechniqueInTactic(t, selectedDirectoryTacticFilter));
  }, [baseFilteredTechniques, selectedDirectoryTacticFilter]);

  // Find related Test Bible items for the selected technique
  const matchingTestItems = useMemo(() => {
    if (!selectedTechnique) return [];
    return TEST_DATA.filter(test => {
      if (test.mitreAtlasRef && test.mitreAtlasRef.includes(selectedTechnique.id)) {
        return true;
      }
      const techName = selectedTechnique.name.toLowerCase();
      const techId = selectedTechnique.id.toLowerCase();
      return (
        test.title.toLowerCase().includes(techName) ||
        test.summary.toLowerCase().includes(techName) ||
        test.summary.toLowerCase().includes(techId)
      );
    });
  }, [selectedTechnique]);

  // Cycle Next/Previous Techniques in modal
  const handleNextTechnique = () => {
    if (!selectedTechnique) return;
    const currentIndex = baseFilteredTechniques.findIndex(t => t.id === selectedTechnique.id);
    if (currentIndex >= 0 && currentIndex < baseFilteredTechniques.length - 1) {
      setSelectedTechnique(baseFilteredTechniques[currentIndex + 1]);
      setActiveModalTab('overview');
    }
  };

  const handlePrevTechnique = () => {
    if (!selectedTechnique) return;
    const currentIndex = baseFilteredTechniques.findIndex(t => t.id === selectedTechnique.id);
    if (currentIndex > 0) {
      setSelectedTechnique(baseFilteredTechniques[currentIndex - 1]);
      setActiveModalTab('overview');
    }
  };

  const currentTechniqueIndex = useMemo(() => {
    if (!selectedTechnique) return -1;
    return baseFilteredTechniques.findIndex(t => t.id === selectedTechnique.id);
  }, [selectedTechnique, baseFilteredTechniques]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-8 animate-page-enter">
      
      {/* 1. Header Banner & Metrics */}
      <div className="relative rounded-2xl overflow-hidden border border-orange-500/30 bg-gradient-to-br from-slate-900/90 via-slate-950 to-slate-900 p-6 md:p-8 shadow-2xl backdrop-blur-xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-orange-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>
        <div className="absolute bottom-0 left-1/3 w-64 h-64 bg-amber-500/10 rounded-full blur-2xl pointer-events-none"></div>

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/30">
              <Flame className="w-3.5 h-3.5 animate-pulse" />
              <span>Adversarial Threat Landscape for AI Systems</span>
            </div>
            
            <h1 className="text-2xl md:text-3xl lg:text-4xl font-extrabold text-slate-100 tracking-tight flex items-center gap-3">
              <span>MITRE ATLAS™ Explorer</span>
              <span className="text-sm md:text-base font-mono font-medium px-2.5 py-0.5 rounded-lg bg-slate-800/80 border border-slate-700 text-orange-400">
                v{MITRE_ATLAS_META.version}
              </span>
            </h1>

            <p className="text-sm md:text-base text-slate-300 max-w-3xl leading-relaxed">
              Actionable threat navigator across all 16 adversary tactics, 178 techniques & sub-techniques, documented real-world procedure examples, and technique-specific mitigations.
            </p>

            {/* Quick Metrics */}
            <div className="pt-2 flex flex-wrap items-center gap-3 text-xs font-mono text-slate-400">
              <div className="flex items-center gap-1.5 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800">
                <Layers className="w-3.5 h-3.5 text-orange-400" />
                <span>16 Tactics</span>
              </div>
              <div className="flex items-center gap-1.5 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800">
                <Crosshair className="w-3.5 h-3.5 text-amber-400" />
                <span>178 Techniques & Subs</span>
              </div>
              <div className="flex items-center gap-1.5 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800">
                <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
                <span>571 Case Procedures</span>
              </div>
              <div className="flex items-center gap-1.5 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800">
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                <span>338 Mitigation Guidance</span>
              </div>
            </div>
          </div>

          {/* Right Nav Mode Controls */}
          <div className="flex flex-col sm:flex-row lg:flex-col items-start sm:items-center lg:items-end gap-3 shrink-0">
            {/* View Mode Switcher */}
            <div className="flex bg-slate-900/90 p-1.5 rounded-xl border border-slate-800 shadow-inner">
              <button
                type="button"
                onClick={() => setViewMode('navigator')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  viewMode === 'navigator'
                    ? 'bg-gradient-to-r from-orange-500 to-amber-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Guided 4-Phase Adversary Lifecycle"
              >
                <Compass className="w-3.5 h-3.5" />
                <span>Lifecycle Flow</span>
              </button>

              <button
                type="button"
                onClick={() => setViewMode('matrix')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  viewMode === 'matrix'
                    ? 'bg-gradient-to-r from-orange-500 to-amber-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Full 16-Column Matrix View"
              >
                <Grid className="w-3.5 h-3.5" />
                <span>Matrix Grid</span>
              </button>

              <button
                type="button"
                onClick={() => setViewMode('directory')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  viewMode === 'directory'
                    ? 'bg-gradient-to-r from-orange-500 to-amber-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Comprehensive Searchable Directory"
              >
                <ListFilter className="w-3.5 h-3.5" />
                <span>Catalog</span>
              </button>
            </div>

            <a
              href="https://atlas.mitre.org/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800/80 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white transition-all shadow-sm group"
            >
              <span>Official ATLAS Portal</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-orange-400 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
            </a>
          </div>
        </div>
      </div>

      {/* 2. Global Search & Intelligent Filter Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 md:p-5 backdrop-blur-md space-y-4">
        
        {/* Main Search Row */}
        <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by ID (AML.T0006), technique name, procedure examples, Ray, Copilot, prompt injection..."
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-10 pr-10 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-orange-500/60 focus:ring-1 focus:ring-orange-500/30 transition-all"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 cursor-pointer"
                aria-label="Clear search query"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Quick Filter Toggles */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setHasCaseStudiesOnly(!hasCaseStudiesOnly)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border transition-all cursor-pointer ${
                hasCaseStudiesOnly
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 font-semibold'
                  : 'bg-slate-950/80 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>Real-World Incidents Only</span>
            </button>

            <button
              type="button"
              onClick={() => setHasMitigationsOnly(!hasMitigationsOnly)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border transition-all cursor-pointer ${
                hasMitigationsOnly
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 font-semibold'
                  : 'bg-slate-950/80 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Mitigated Only</span>
            </button>

            {viewMode === 'matrix' && (
              <button
                type="button"
                onClick={toggleAllSubtechniques}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-slate-950/80 border border-slate-800 hover:border-slate-700 text-purple-300 hover:text-purple-200 transition-all cursor-pointer"
                title={allSubtechniquesExpanded ? 'Collapse Sub-techniques' : 'Expand Sub-techniques'}
              >
                <Layers className="w-3.5 h-3.5 text-purple-400" />
                <span>{allSubtechniquesExpanded ? 'Collapse Sub-techniques' : 'Expand All Sub-techniques'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Testing Pillar Scope Chips */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin scrollbar-thumb-slate-800 text-xs border-b border-slate-800/80 pb-3">
          <span className="text-[11px] font-mono text-slate-400 font-bold uppercase tracking-wider shrink-0 mr-1 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-cyan-400" /> Testing Pillar:
          </span>

          {[
            { id: 'ALL', label: 'All 4 Pillars (178)', icon: BookOpen, color: 'text-slate-300', activeClass: 'bg-slate-800 text-white border-slate-600' },
            { id: Pillar.APP, label: 'Application Testing', icon: Layers, color: 'text-blue-400', activeClass: 'bg-blue-500/20 text-blue-300 border-blue-500/50' },
            { id: Pillar.MODEL, label: 'Model Testing', icon: Cpu, color: 'text-purple-400', activeClass: 'bg-purple-500/20 text-purple-300 border-purple-500/50' },
            { id: Pillar.INFRA, label: 'Infrastructure', icon: Server, color: 'text-amber-400', activeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/50' },
            { id: Pillar.DATA, label: 'Data Testing', icon: Database, color: 'text-emerald-400', activeClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50' },
          ].map(p => {
            const IconComp = p.icon;
            const isSelected = selectedPillarFilter === p.id;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => setSelectedPillarFilter(p.id as any)}
                className={`px-3 py-1.5 rounded-xl shrink-0 transition-all flex items-center gap-1.5 cursor-pointer font-medium border ${
                  isSelected
                    ? `${p.activeClass} font-bold shadow-sm`
                    : 'bg-slate-950/70 text-slate-400 hover:bg-slate-800 hover:text-slate-200 border-slate-800/80'
                }`}
              >
                <IconComp className={`w-3.5 h-3.5 ${p.color}`} />
                <span>{p.label}</span>
              </button>
            );
          })}
        </div>

        {/* AI Paradigm Discovery Chips */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin scrollbar-thumb-slate-800 text-xs">
          <span className="text-[11px] font-mono text-slate-500 font-bold uppercase tracking-wider shrink-0 mr-1 flex items-center gap-1">
            <SlidersHorizontal className="w-3 h-3" /> Paradigm:
          </span>

          {[
            { id: 'ALL', label: 'All Paradigms (178)', icon: Sparkles },
            { id: 'AGENTIC', label: 'Autonomous & Agentic AI', icon: Bot },
            { id: 'GENAI', label: 'Generative AI & LLMs', icon: BrainCircuit },
            { id: 'PREDICTIVE', label: 'Predictive & Classical ML', icon: Network },
            { id: 'ENTERPRISE', label: 'Enterprise Infrastructure', icon: Database },
          ].map(p => {
            const IconComp = p.icon;
            const isSelected = selectedParadigmFilter === p.id;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => setSelectedParadigmFilter(p.id as any)}
                className={`px-3 py-1.5 rounded-xl shrink-0 transition-all flex items-center gap-1.5 cursor-pointer font-medium ${
                  isSelected
                    ? 'bg-orange-500 text-white font-bold shadow-sm'
                    : 'bg-slate-950/70 text-slate-400 hover:bg-slate-800 hover:text-slate-200 border border-slate-800/80'
                }`}
              >
                <IconComp className="w-3.5 h-3.5" />
                <span>{p.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* 3. VIEW MODE 1: LIFECYCLE FLOW NAVIGATOR (2-PANE WORKBENCH) */}
      {viewMode === 'navigator' && (
        <div className="space-y-6">
          {/* Phase Stepper Tabs */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {KILL_CHAIN_PHASES.map((phase, pIdx) => {
              const isSelected = selectedPhaseId === phase.id;
              const phaseTactics = MITRE_ATLAS_TACTICS.filter(t => phase.tacticIds.includes(t.id));
              // Accurate technique count for this phase based on current search & filters
              const techCount = baseFilteredTechniques.filter(t => isTechniqueInPhase(t, phase.tacticIds)).length;

              return (
                <div
                  key={phase.id}
                  onClick={() => {
                    setSelectedPhaseId(phase.id);
                    setFocusedTacticId(phase.tacticIds[0]);
                  }}
                  className={`p-4 rounded-2xl border transition-all cursor-pointer text-left relative overflow-hidden flex flex-col justify-between group ${
                    isSelected
                      ? `bg-slate-900 ${phase.borderAccent} shadow-lg ring-1 ring-orange-500/40`
                      : 'bg-slate-900/40 hover:bg-slate-900/80 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className={`text-[10px] font-mono font-bold uppercase tracking-wider ${phase.textAccent}`}>
                        Stage 0{pIdx + 1}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded-full font-semibold">
                        {techCount} {techCount === 1 ? 'Tech' : 'Techs'}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-slate-100 group-hover:text-white leading-tight">
                      {phase.shortName}
                    </h3>

                    <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                      {phase.description}
                    </p>
                  </div>

                  <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-[11px]">
                    <span className="text-slate-500 font-mono">
                      {phaseTactics.length} Tactics
                    </span>
                    <span className={`flex items-center gap-1 font-semibold ${isSelected ? phase.textAccent : 'text-slate-500 group-hover:text-slate-300'}`}>
                      <span>Explore</span>
                      <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* 2-Pane Workstation: Left (Tactics in active phase) + Right (Techniques Canvas) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            
            {/* Mobile Tactic Selector Strip (< lg) */}
            <div className="lg:hidden space-y-2">
              <div className="flex items-center justify-between px-1">
                <span className="text-xs font-mono text-slate-400 font-bold uppercase tracking-wider">
                  Tactics in {activePhase.shortName}
                </span>
                <span className="text-xs font-mono text-slate-500">
                  {activePhaseTactics.length} Tactics (Swipe to Select)
                </span>
              </div>
              <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-slate-800 -mx-4 px-4 sm:mx-0 sm:px-0">
                {activePhaseTactics.map(tactic => {
                  const isSelected = focusedTactic.id === tactic.id;
                  const techCount = tactic.techniques.length;

                  return (
                    <button
                      key={tactic.id}
                      type="button"
                      onClick={() => setFocusedTacticId(tactic.id)}
                      className={`shrink-0 p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between min-w-[200px] max-w-[240px] min-h-[44px] ${
                        isSelected
                          ? 'bg-slate-900 border-orange-500/60 shadow-md ring-1 ring-orange-500/30'
                          : 'bg-slate-900/60 hover:bg-slate-900 border-slate-800 text-slate-400'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1 w-full">
                        <span className="text-xs font-mono font-bold text-orange-400">
                          {tactic.id}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded font-semibold">
                          {techCount} {techCount === 1 ? 'tech' : 'techs'}
                        </span>
                      </div>
                      <h4 className="text-xs font-bold text-slate-100 truncate w-full">
                        {tactic.name}
                      </h4>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Desktop Left Column: Tactic Selector Sidebar (lg+) */}
            <div className="hidden lg:block lg:col-span-4 space-y-2.5">
              <div className="flex items-center justify-between px-1 mb-1">
                <span className="text-xs font-mono text-slate-400 font-bold uppercase tracking-wider">
                  Tactics in {activePhase.shortName}
                </span>
                <span className="text-xs font-mono text-slate-500">
                  {activePhaseTactics.length} Tactics
                </span>
              </div>

              {activePhaseTactics.map(tactic => {
                const isSelected = focusedTactic.id === tactic.id;
                const techCount = tactic.techniques.length;

                return (
                  <div
                    key={tactic.id}
                    onClick={() => setFocusedTacticId(tactic.id)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer text-left group ${
                      isSelected
                        ? 'bg-slate-900 border-orange-500/50 shadow-md ring-1 ring-orange-500/20'
                        : 'bg-slate-900/50 hover:bg-slate-900 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs font-mono font-bold text-orange-400">
                        {tactic.id}
                      </span>
                      <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded-full font-semibold">
                        {techCount}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-slate-200 group-hover:text-white mb-1 leading-snug">
                      {tactic.name}
                    </h4>

                    <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                      {tactic.description}
                    </p>
                  </div>
                );
              })}
            </div>

            {/* Right Column: Active Tactic Threat Canvas */}
            <div className="lg:col-span-8 space-y-4">
              
              {/* Tactic Hero Header */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 md:p-6 space-y-3 shadow-lg">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold bg-orange-500/15 text-orange-400 border border-orange-500/30">
                      {focusedTactic.id}
                    </span>
                    <h2 className="text-lg md:text-xl font-bold text-slate-100">
                      {focusedTactic.name}
                    </h2>
                  </div>

                  <a
                    href={focusedTactic.url || `https://atlas.mitre.org/tactics/${focusedTactic.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-orange-400 hover:text-orange-300 font-mono inline-flex items-center gap-1"
                  >
                    <span>Official Tactic Page</span>
                    <ArrowUpRight className="w-3 h-3" />
                  </a>
                </div>

                <p className="text-xs md:text-sm text-slate-300 leading-relaxed">
                  {focusedTactic.description}
                </p>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>Showing {focusedTactic.techniques.length} Technique(s) in this Tactic</span>
                  <span className="text-slate-500">Click any card to open full threat dossier</span>
                </div>
              </div>

              {/* Techniques Card Grid (Parent cards with expandable subtechniques) */}
              <div className="space-y-3">
                {focusedTactic.techniques.length === 0 ? (
                  <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-8 text-center text-slate-500 italic">
                    No techniques match the current search or filters for this tactic.
                  </div>
                ) : (
                  // Render parent techniques first, with nested sub-techniques
                  focusedTactic.techniques
                    .filter(t => !t.isSubtechnique)
                    .map(tech => {
                      const isExpanded = expandedParents.has(tech.id) || !!searchQuery.trim();
                      const subtechs = tech.subtechniques || [];

                      return (
                        <div
                          key={tech.id}
                          className="bg-slate-900/70 border border-slate-800 hover:border-slate-700 rounded-2xl p-4 md:p-5 transition-all shadow-md space-y-3"
                        >
                          {/* Parent Card Header */}
                          <div 
                            onClick={() => setSelectedTechnique(tech)}
                            className="cursor-pointer group flex flex-col sm:flex-row sm:items-start justify-between gap-3"
                          >
                            <div className="space-y-1.5 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="px-2.5 py-0.5 rounded-lg text-xs font-mono font-bold bg-orange-500/15 text-orange-400 border border-orange-500/30">
                                  {tech.id}
                                </span>
                                {tech.maturity && (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30">
                                    {tech.maturity}
                                  </span>
                                )}
                                {tech.attackReference && (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-300 border border-blue-500/30">
                                    ATT&CK: {tech.attackReference.id}
                                  </span>
                                )}
                                {getTechniquePillars(tech).map(pill => {
                                  const pillColors: Record<Pillar, string> = {
                                    [Pillar.APP]: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
                                    [Pillar.MODEL]: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
                                    [Pillar.INFRA]: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
                                    [Pillar.DATA]: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                  };
                                  const pillLabels: Record<Pillar, string> = {
                                    [Pillar.APP]: 'App Pillar',
                                    [Pillar.MODEL]: 'Model Pillar',
                                    [Pillar.INFRA]: 'Infra Pillar',
                                    [Pillar.DATA]: 'Data Pillar'
                                  };
                                  return (
                                    <span key={pill} className={`px-2 py-0.5 rounded text-[10px] font-mono border ${pillColors[pill]}`}>
                                      {pillLabels[pill]}
                                    </span>
                                  );
                                })}
                              </div>

                              <h3 className="text-base font-bold text-slate-100 group-hover:text-orange-300 transition-colors">
                                {tech.name}
                              </h3>

                              <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                                {tech.description}
                              </p>
                            </div>

                            {/* Indicators & Inspect CTA */}
                            <div className="flex items-center sm:flex-col items-end gap-2 shrink-0 pt-2 sm:pt-0">
                              <div className="flex items-center gap-2">
                                {tech.procedureExamples && tech.procedureExamples.length > 0 && (
                                  <span className="flex items-center gap-1 text-cyan-400 font-mono text-xs bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20" title="Procedure Examples">
                                    <BookOpen className="w-3 h-3" />
                                    <span>{tech.procedureExamples.length}</span>
                                  </span>
                                )}
                                {tech.mitigations && tech.mitigations.length > 0 && (
                                  <span className="flex items-center gap-1 text-emerald-400 font-mono text-xs bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20" title="Mitigations">
                                    <Shield className="w-3 h-3" />
                                    <span>{tech.mitigations.length}</span>
                                  </span>
                                )}
                              </div>

                              <span className="text-xs text-orange-400 group-hover:translate-x-0.5 transition-transform font-semibold inline-flex items-center gap-1">
                                <span>Inspect</span>
                                <ChevronRight className="w-3.5 h-3.5" />
                              </span>
                            </div>
                          </div>

                          {/* Sub-Techniques Collapsible Tray */}
                          {subtechs.length > 0 && (
                            <div className="pt-2 border-t border-slate-800/80">
                              <div className="flex items-center justify-between mb-2">
                                <button
                                  type="button"
                                  onClick={(e) => toggleParentExpansion(tech.id, e)}
                                  className="text-xs font-mono text-purple-300 hover:text-purple-200 flex items-center gap-1.5 cursor-pointer"
                                >
                                  <Layers className="w-3.5 h-3.5 text-purple-400" />
                                  <span>{subtechs.length} Sub-technique(s)</span>
                                  {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                                </button>
                              </div>

                              {isExpanded && (
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
                                  {subtechs.map(st => {
                                    const subObj = MITRE_ATLAS_TECHNIQUES.find(t => t.id === st.id);
                                    return (
                                      <div
                                        key={st.id}
                                        onClick={() => {
                                          if (subObj) setSelectedTechnique(subObj);
                                        }}
                                        className="p-2.5 rounded-xl bg-slate-950/80 hover:bg-slate-800/90 border border-slate-800 hover:border-purple-500/40 transition-all cursor-pointer group flex items-start justify-between gap-2"
                                      >
                                        <div className="min-w-0">
                                          <span className="text-[11px] font-mono font-bold text-purple-400 block mb-0.5">
                                            {st.id}
                                          </span>
                                          <span className="text-xs font-semibold text-slate-200 group-hover:text-white truncate block">
                                            {st.name}
                                          </span>
                                        </div>
                                        <ChevronRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-purple-400 shrink-0 mt-1" />
                                      </div>
                                    );
                                  })}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 4. VIEW MODE 2: MATRIX GRID (CLEAN & STREAMLINED) */}
      {viewMode === 'matrix' && (
        <div className="space-y-4">
          
          {/* Tactic Jump Ribbon */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-slate-800 text-xs">
            <span className="text-[11px] font-mono text-slate-500 font-bold uppercase tracking-wider shrink-0 mr-1">Jump to:</span>
            {MITRE_ATLAS_TACTICS.map((tac) => {
              const count = baseFilteredTechniques.filter(t => isTechniqueInTactic(t, tac.id)).length;
              return (
                <button
                  key={tac.id}
                  type="button"
                  onClick={() => {
                    const el = document.getElementById(`matrix-col-${tac.id}`);
                    if (el) el.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
                  }}
                  className="px-2.5 py-1 rounded-lg shrink-0 bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 text-xs font-mono transition-all flex items-center gap-1.5 cursor-pointer"
                >
                  <span>{tac.name}</span>
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-400 font-semibold">
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Full Matrix Columns */}
          <div className="overflow-x-auto pb-6 scrollbar-thin scrollbar-thumb-slate-800">
            <div className="inline-flex gap-3 min-w-full items-start">
              {matrixTactics.map(tactic => (
                <div 
                  key={tactic.id}
                  id={`matrix-col-${tactic.id}`}
                  className="w-64 shrink-0 bg-slate-900/60 border border-slate-800 rounded-2xl flex flex-col overflow-hidden shadow-lg"
                >
                  {/* Tactic Header */}
                  <div className="p-3.5 bg-gradient-to-b from-slate-900 to-slate-950 border-b border-slate-800/80">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-mono font-bold text-orange-400 uppercase tracking-wider">
                        {tactic.id}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-800/80 px-1.5 py-0.5 rounded font-semibold">
                        {tactic.techniques.length}
                      </span>
                    </div>
                    <h3 className="text-xs font-bold text-slate-100 leading-tight">
                      {tactic.name}
                    </h3>
                  </div>

                  {/* Technique Cards in Column */}
                  <div className="p-2 space-y-2 max-h-[70vh] overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800/60">
                    {tactic.techniques.length === 0 ? (
                      <div className="py-6 text-center text-[11px] text-slate-500 italic">
                        No matches
                      </div>
                    ) : (
                      // Only show top-level techniques, or show subtechniques if expanded
                      tactic.techniques
                        .filter(t => !t.isSubtechnique || allSubtechniquesExpanded || !!searchQuery.trim())
                        .map(tech => {
                          const isExpanded = expandedParents.has(tech.id) || allSubtechniquesExpanded || !!searchQuery.trim();
                          const subtechs = tech.subtechniques || [];

                          return (
                            <div
                              key={tech.id}
                              className={`p-2.5 rounded-xl border transition-all cursor-pointer group text-left ${
                                tech.isSubtechnique
                                  ? 'bg-slate-950/40 hover:bg-slate-900 border-slate-800/60 hover:border-purple-500/40 ml-2 border-l-2 border-l-purple-500/40'
                                  : 'bg-slate-950/80 hover:bg-slate-900 border-slate-800 hover:border-orange-500/60 hover:shadow-md'
                              }`}
                            >
                              <div 
                                onClick={() => setSelectedTechnique(tech)}
                                className="space-y-1"
                              >
                                <div className="flex items-center justify-between gap-1">
                                  <span className="text-[10px] font-mono font-bold text-orange-400/90 group-hover:text-orange-300">
                                    {tech.id}
                                  </span>
                                  {tech.isSubtechnique && (
                                    <span className="px-1 py-0.2 rounded text-[8px] font-mono bg-purple-500/20 text-purple-300">
                                      Sub
                                    </span>
                                  )}
                                </div>

                                <h4 className="text-[11px] font-medium text-slate-200 group-hover:text-white leading-snug line-clamp-2">
                                  {tech.name}
                                </h4>
                              </div>

                              {/* Indicators & Sub-technique dropdown */}
                              <div className="mt-2 pt-1.5 border-t border-slate-800/50 flex items-center justify-between text-[9px] text-slate-500">
                                <div className="flex items-center gap-1.5">
                                  {tech.mitigations && tech.mitigations.length > 0 && (
                                    <span className="inline-flex items-center gap-0.5 text-emerald-400 font-mono">
                                      <Shield className="w-2.5 h-2.5" />
                                      {tech.mitigations.length}
                                    </span>
                                  )}
                                  {tech.procedureExamples && tech.procedureExamples.length > 0 && (
                                    <span className="inline-flex items-center gap-0.5 text-cyan-400 font-mono">
                                      <BookOpen className="w-2.5 h-2.5" />
                                      {tech.procedureExamples.length}
                                    </span>
                                  )}
                                </div>

                                {subtechs.length > 0 && !allSubtechniquesExpanded && (
                                  <button
                                    type="button"
                                    onClick={(e) => toggleParentExpansion(tech.id, e)}
                                    className="text-[9px] font-mono text-purple-300 hover:text-purple-200 bg-purple-500/10 px-1 py-0.5 rounded cursor-pointer flex items-center gap-0.5"
                                  >
                                    <span>+{subtechs.length}</span>
                                    {isExpanded ? <ChevronUp className="w-2.5 h-2.5" /> : <ChevronDown className="w-2.5 h-2.5" />}
                                  </button>
                                )}
                              </div>

                              {/* Nested Subtechniques when expanded */}
                              {isExpanded && subtechs.length > 0 && !allSubtechniquesExpanded && (
                                <div className="mt-2 pt-1.5 border-t border-slate-800/60 space-y-1">
                                  {subtechs.map(st => {
                                    const subObj = MITRE_ATLAS_TECHNIQUES.find(t => t.id === st.id);
                                    return (
                                      <div
                                        key={st.id}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          if (subObj) setSelectedTechnique(subObj);
                                        }}
                                        className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[10px] flex items-center justify-between text-slate-300 hover:text-white"
                                      >
                                        <span className="font-mono text-purple-400 font-bold mr-1">{st.id}</span>
                                        <span className="truncate flex-1">{st.name}</span>
                                      </div>
                                    );
                                  })}
                                </div>
                              )}
                            </div>
                          );
                        })
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 5. VIEW MODE 3: DIRECTORY / CATALOG LIST */}
      {viewMode === 'directory' && (
        <div className="space-y-4">
          {/* Tactic Selector for Directory */}
          <div className="flex items-center justify-between bg-slate-900/60 border border-slate-800 p-3.5 rounded-xl">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400 uppercase font-bold">Filter by Tactic:</span>
              <select
                value={selectedDirectoryTacticFilter}
                onChange={(e) => setSelectedDirectoryTacticFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-orange-500 cursor-pointer"
              >
                <option value="ALL">All Tactics (16)</option>
                {MITRE_ATLAS_TACTICS.map(tac => (
                  <option key={tac.id} value={tac.id}>
                    {tac.name} ({baseFilteredTechniques.filter(t => isTechniqueInTactic(t, tac.id)).length})
                  </option>
                ))}
              </select>
            </div>

            <span className="text-xs font-mono text-slate-400">
              Showing <strong className="text-slate-200">{directoryTechniques.length}</strong> Techniques
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {directoryTechniques.map(tech => (
              <div
                key={tech.id}
                onClick={() => setSelectedTechnique(tech)}
                className="bg-slate-900/70 hover:bg-slate-900 border border-slate-800 hover:border-orange-500/50 rounded-2xl p-5 cursor-pointer transition-all duration-200 flex flex-col justify-between group shadow-lg"
              >
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold bg-orange-500/10 text-orange-400 border border-orange-500/20 group-hover:border-orange-500/40">
                        {tech.id}
                      </span>
                      {tech.isSubtechnique && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30">
                          Sub
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
                      {tech.tacticName}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-slate-100 group-hover:text-orange-300 transition-colors leading-snug">
                    {tech.name}
                  </h3>

                  <p className="text-xs text-slate-400 line-clamp-3 leading-relaxed">
                    {tech.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                  <div className="flex items-center gap-3">
                    {tech.mitigations && tech.mitigations.length > 0 && (
                      <span className="flex items-center gap-1 text-emerald-400 text-[11px]">
                        <Shield className="w-3 h-3" />
                        <span>{tech.mitigations.length} Mitigations</span>
                      </span>
                    )}
                    {tech.procedureExamples && tech.procedureExamples.length > 0 && (
                      <span className="flex items-center gap-1 text-cyan-400 text-[11px]">
                        <BookOpen className="w-3 h-3" />
                        <span>{tech.procedureExamples.length} Cases</span>
                      </span>
                    )}
                  </div>

                  <span className="text-orange-400 group-hover:translate-x-1 transition-transform flex items-center gap-0.5 text-xs font-semibold">
                    Inspect <ChevronRight className="w-3.5 h-3.5" />
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 6. TABBED TECHNIQUE DETAIL INSPECTION MODAL */}
      {selectedTechnique && typeof document !== 'undefined' && createPortal(
        <div 
          className="fixed inset-0 z-[100] flex items-center justify-center pt-[calc(env(safe-area-inset-top,0px)+1rem)] sm:pt-4 pb-[calc(env(safe-area-inset-bottom,0px)+1rem)] sm:pb-4 px-3 sm:px-4 md:p-6 bg-slate-950/85 backdrop-blur-md animate-modal-backdrop"
          onClick={() => setSelectedTechnique(null)}
          role="dialog"
          aria-modal="true"
          aria-label={selectedTechnique.name}
        >
          <div 
            className="w-full max-w-4xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.85)] overflow-hidden flex flex-col max-h-[calc(100dvh-env(safe-area-inset-top,0px)-env(safe-area-inset-bottom,0px)-2rem)] sm:max-h-[90vh] animate-modal-card relative my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="p-4 sm:p-5 md:p-6 border-b border-slate-800 bg-slate-950/95 backdrop-blur-md z-10 space-y-3 shrink-0">
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-2 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold bg-orange-500/15 text-orange-400 border border-orange-500/30">
                      {selectedTechnique.id}
                    </span>
                    
                    {/* Tactics */}
                    {(selectedTechnique.tactics || [{ id: selectedTechnique.tacticId, name: selectedTechnique.tacticName }]).map(tac => (
                      <span key={tac.id} className="px-2.5 py-1 rounded-lg text-xs font-mono text-slate-300 bg-slate-800 border border-slate-700">
                        {tac.name}
                      </span>
                    ))}

                    {selectedTechnique.maturity && (
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30">
                        Maturity: {selectedTechnique.maturity}
                      </span>
                    )}

                    {selectedTechnique.attackReference && (
                      <a
                        href={selectedTechnique.attackReference.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-2 py-0.5 rounded text-xs font-mono bg-blue-500/10 hover:bg-blue-500/20 text-blue-300 hover:text-blue-200 border border-blue-500/30 inline-flex items-center gap-1 transition-colors"
                        title="View on Enterprise ATT&CK"
                      >
                        <span>ATT&CK: {selectedTechnique.attackReference.id}</span>
                        <ArrowUpRight className="w-2.5 h-2.5" />
                      </a>
                    )}

                    {selectedTechnique.isSubtechnique && selectedTechnique.parentTechniqueId && (
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30">
                        Sub-technique of {selectedTechnique.parentTechniqueId}
                      </span>
                    )}

                    {selectedTechnique.platforms && selectedTechnique.platforms.length > 0 && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                        {selectedTechnique.platforms.join(', ')}
                      </span>
                    )}

                    {getTechniquePillars(selectedTechnique).map(pill => {
                      const pillColors: Record<Pillar, string> = {
                        [Pillar.APP]: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
                        [Pillar.MODEL]: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
                        [Pillar.INFRA]: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
                        [Pillar.DATA]: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                      };
                      const pillLabels: Record<Pillar, string> = {
                        [Pillar.APP]: 'Application Pillar',
                        [Pillar.MODEL]: 'Model Pillar',
                        [Pillar.INFRA]: 'Infrastructure Pillar',
                        [Pillar.DATA]: 'Data Pillar'
                      };
                      return (
                        <span key={pill} className={`px-2.5 py-0.5 rounded-lg text-xs font-mono font-medium border ${pillColors[pill]}`}>
                          {pillLabels[pill]}
                        </span>
                      );
                    })}
                  </div>

                  <h2 className="text-lg sm:text-xl md:text-2xl font-bold text-slate-100 break-words">
                    {selectedTechnique.name}
                  </h2>
                </div>

                {/* Header Action Tools */}
                <div className="flex items-center gap-2 shrink-0">
                  {/* Sequence Prev/Next */}
                  <div className="hidden sm:flex items-center bg-slate-800/80 rounded-xl p-1 border border-slate-700">
                    <button
                      type="button"
                      disabled={currentTechniqueIndex <= 0}
                      onClick={handlePrevTechnique}
                      className="p-1.5 rounded-lg text-slate-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed hover:bg-slate-700 cursor-pointer min-w-[32px] min-h-[32px] flex items-center justify-center"
                      title="Previous Technique"
                      aria-label="Previous Technique"
                    >
                      <ChevronLeft className="w-4 h-4" />
                    </button>
                    <span className="text-[10px] font-mono text-slate-400 px-1.5">
                      {currentTechniqueIndex + 1}/{baseFilteredTechniques.length}
                    </span>
                    <button
                      type="button"
                      disabled={currentTechniqueIndex >= baseFilteredTechniques.length - 1}
                      onClick={handleNextTechnique}
                      className="p-1.5 rounded-lg text-slate-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed hover:bg-slate-700 cursor-pointer min-w-[32px] min-h-[32px] flex items-center justify-center"
                      title="Next Technique"
                      aria-label="Next Technique"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={(e) => handleCopyId(selectedTechnique.id, e)}
                    className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors border border-slate-700 cursor-pointer min-w-[36px] min-h-[36px] flex items-center justify-center"
                    title="Copy Technique ID"
                    aria-label="Copy Technique ID"
                  >
                    {copiedId === selectedTechnique.id ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>

                  <a
                    href={selectedTechnique.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded-xl bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 hover:text-orange-300 transition-colors border border-orange-500/30 min-w-[36px] min-h-[36px] flex items-center justify-center"
                    title="View on MITRE ATLAS"
                    aria-label="View on MITRE ATLAS"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>

                  <button
                    type="button"
                    onClick={() => setSelectedTechnique(null)}
                    className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors border border-slate-700 cursor-pointer min-w-[36px] min-h-[36px] flex items-center justify-center"
                    aria-label="Close modal"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              {/* Modal Navigation Tabs */}
              <div className="flex items-center gap-2 overflow-x-auto scrollbar-thin scrollbar-thumb-slate-800 border-b border-slate-800/80 pb-1 text-xs -mx-1 px-1">
                <button
                  type="button"
                  onClick={() => setActiveModalTab('overview')}
                  className={`shrink-0 px-3 py-2 sm:py-1.5 rounded-lg font-semibold transition-all cursor-pointer flex items-center gap-1.5 min-h-[36px] ${
                    activeModalTab === 'overview'
                      ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Info className="w-3.5 h-3.5" />
                  <span>Overview & Mechanics</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveModalTab('procedures')}
                  className={`shrink-0 px-3 py-2 sm:py-1.5 rounded-lg font-semibold transition-all cursor-pointer flex items-center gap-1.5 min-h-[36px] ${
                    activeModalTab === 'procedures'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <BookOpen className="w-3.5 h-3.5" />
                  <span>Procedure Examples ({selectedTechnique.procedureExamples?.length || 0})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveModalTab('mitigations')}
                  className={`shrink-0 px-3 py-2 sm:py-1.5 rounded-lg font-semibold transition-all cursor-pointer flex items-center gap-1.5 min-h-[36px] ${
                    activeModalTab === 'mitigations'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>Mitigations ({selectedTechnique.mitigations?.length || 0})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveModalTab('citations')}
                  className={`shrink-0 px-3 py-2 sm:py-1.5 rounded-lg font-semibold transition-all cursor-pointer flex items-center gap-1.5 min-h-[36px] ${
                    activeModalTab === 'citations'
                      ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>References & Tests ({((selectedTechnique.references?.length || 0) + matchingTestItems.length)})</span>
                </button>
              </div>
            </div>

            {/* Modal Body - Tabbed Content */}
            <div className="overflow-y-auto flex-1 p-4 sm:p-5 md:p-6 space-y-6">
              
              {/* TAB 1: OVERVIEW & MECHANICS */}
              {activeModalTab === 'overview' && (
                <div className="space-y-6">
                  {/* Parent Jump Banner if sub-technique */}
                  {selectedTechnique.isSubtechnique && selectedTechnique.parentTechniqueId && (
                    <div className="bg-purple-950/30 border border-purple-800/40 rounded-xl p-3.5 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2.5">
                        <CornerDownRight className="w-4 h-4 text-purple-400 shrink-0" />
                        <div>
                          <span className="text-[11px] font-mono text-purple-300 uppercase tracking-wider block">Parent Technique</span>
                          <span className="text-sm font-semibold text-slate-100">
                            {selectedTechnique.parentTechniqueId}: {selectedTechnique.parentTechniqueName || 'Parent Technique'}
                          </span>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          const parent = MITRE_ATLAS_TECHNIQUES.find(t => t.id === selectedTechnique.parentTechniqueId);
                          if (parent) setSelectedTechnique(parent);
                        }}
                        className="px-3 py-1.5 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 text-purple-200 border border-purple-500/40 text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
                      >
                        <span>View Parent</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}

                  {/* Sub-Techniques Section if parent */}
                  {selectedTechnique.subtechniques && selectedTechnique.subtechniques.length > 0 && (
                    <div className="space-y-3">
                      <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-purple-400 flex items-center gap-2">
                        <Layers className="w-3.5 h-3.5" />
                        <span>Sub-Techniques ({selectedTechnique.subtechniques.length})</span>
                      </h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                        {selectedTechnique.subtechniques.map(st => (
                          <button
                            key={st.id}
                            type="button"
                            onClick={() => {
                              const subObj = MITRE_ATLAS_TECHNIQUES.find(t => t.id === st.id);
                              if (subObj) setSelectedTechnique(subObj);
                            }}
                            className="text-left p-3 rounded-xl bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-purple-500/50 transition-all flex items-center justify-between group cursor-pointer"
                          >
                            <div className="min-w-0 pr-2">
                              <span className="text-xs font-mono font-bold text-purple-400 block mb-0.5">{st.id}</span>
                              <span className="text-xs font-semibold text-slate-200 group-hover:text-white truncate block">{st.name}</span>
                            </div>
                            <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-0.5 transition-all shrink-0" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Technical Description */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-orange-400 flex items-center gap-2">
                      <Info className="w-3.5 h-3.5" />
                      <span>Technical Description & Mechanics</span>
                    </h4>
                    <div className="bg-slate-950/60 p-4 md:p-5 rounded-xl border border-slate-800/80">
                      <MitreDescriptionRenderer 
                        text={selectedTechnique.description}
                        onSelectTechniqueById={(id) => {
                          const found = MITRE_ATLAS_TECHNIQUES.find(t => t.id === id || t.id.startsWith(id));
                          if (found) setSelectedTechnique(found);
                        }}
                      />
                    </div>
                  </div>

                  {/* Detection & Telemetry Section */}
                  {selectedTechnique.detection && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400 flex items-center gap-2">
                        <Radar className="w-3.5 h-3.5" />
                        <span>Detection Strategies & Telemetry Guidance</span>
                      </h4>
                      <div className="bg-amber-950/20 border border-amber-800/40 rounded-xl p-4 text-xs text-amber-200 leading-relaxed whitespace-pre-line">
                        {selectedTechnique.detection}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: PROCEDURE EXAMPLES & CASE STUDIES */}
              {activeModalTab === 'procedures' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                      <BookOpen className="w-3.5 h-3.5" />
                      <span>Documented Real-World Case Studies ({selectedTechnique.procedureExamples?.length || 0})</span>
                    </h4>
                    <span className="text-xs font-mono text-slate-500">Official MITRE ATLAS Intelligence</span>
                  </div>

                  {!selectedTechnique.procedureExamples || selectedTechnique.procedureExamples.length === 0 ? (
                    <div className="p-8 text-center bg-slate-950/60 border border-slate-800 rounded-xl text-slate-500 text-xs italic">
                      No specific case study procedure examples currently documented for this technique in MITRE ATLAS.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 gap-3">
                      {selectedTechnique.procedureExamples.map((proc, pIdx) => (
                        <div
                          key={pIdx}
                          className="bg-slate-950/70 border border-slate-800 hover:border-cyan-500/40 rounded-xl p-4 transition-all space-y-2.5"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                                {proc.caseStudyId}
                              </span>
                              {proc.stepId && (
                                <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                                  {proc.stepId}
                                </span>
                              )}
                              <a
                                href={proc.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs font-bold text-slate-200 hover:text-cyan-300 transition-colors inline-flex items-center gap-1 group"
                              >
                                <span>{proc.caseStudyName}</span>
                                <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400" />
                              </a>
                            </div>
                          </div>

                          <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-800/80 font-sans">
                            {proc.description}
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: DEFENSIVE MITIGATIONS */}
              {activeModalTab === 'mitigations' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
                      <Shield className="w-3.5 h-3.5" />
                      <span>Recommended Mitigations & Countermeasures ({selectedTechnique.mitigations?.length || 0})</span>
                    </h4>
                    <span className="text-xs font-mono text-slate-500">Verified Hardening Controls</span>
                  </div>

                  {!selectedTechnique.mitigations || selectedTechnique.mitigations.length === 0 ? (
                    <div className="p-8 text-center bg-slate-950/60 border border-slate-800 rounded-xl text-slate-500 text-xs italic">
                      No direct mitigations mapped for this technique. Apply defense-in-depth model security controls.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 gap-3">
                      {selectedTechnique.mitigations.map(mit => (
                        <div 
                          key={mit.id}
                          className="bg-slate-950/70 border border-slate-800 hover:border-emerald-500/40 rounded-xl p-4 transition-all space-y-2.5"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                                {mit.id}
                              </span>
                              <a
                                href={mit.url || `https://atlas.mitre.org/mitigations/${mit.id}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs font-bold text-slate-200 hover:text-emerald-300 transition-colors inline-flex items-center gap-1 group"
                              >
                                <span>{mit.name}</span>
                                <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-emerald-400" />
                              </a>
                            </div>
                          </div>

                          {mit.useDescription && (
                            <div className="text-xs text-emerald-300 bg-emerald-950/20 p-2.5 rounded-lg border border-emerald-800/40 leading-relaxed">
                              <strong className="text-emerald-400 font-semibold">Specific Technique Guidance: </strong>
                              <span>{mit.useDescription}</span>
                            </div>
                          )}

                          <p className="text-xs text-slate-400 leading-relaxed">
                            {mit.description}
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 4: REFERENCES & SECURITY TESTS */}
              {activeModalTab === 'citations' && (
                <div className="space-y-6">
                  {/* AI Testing Bible Mapped Tests */}
                  {matchingTestItems.length > 0 && (
                    <div className="space-y-3">
                      <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-pink-400 flex items-center gap-2">
                        <Terminal className="w-3.5 h-3.5" />
                        <span>Mapped AI Testing Bible Tests ({matchingTestItems.length})</span>
                      </h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {matchingTestItems.map(testItem => (
                          <div
                            key={testItem.id}
                            onClick={() => {
                              if (onNavigateToTest) {
                                setSelectedTechnique(null);
                                onNavigateToTest(testItem);
                              }
                            }}
                            className="p-3.5 bg-slate-950/80 hover:bg-slate-900 border border-slate-800 hover:border-pink-500/40 rounded-xl cursor-pointer transition-all group"
                          >
                            <div className="flex items-center justify-between gap-2 mb-1">
                              <span className="text-xs font-mono font-bold text-pink-400">
                                {testItem.id}
                              </span>
                              <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                                {testItem.riskLevel}
                              </span>
                            </div>
                            <h5 className="text-xs font-semibold text-slate-200 group-hover:text-white">
                              {testItem.title}
                            </h5>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Scholarly Citations */}
                  <div className="space-y-3">
                    <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-blue-400 flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5" />
                      <span>Official Scholarly Citations & Sources ({selectedTechnique.references?.length || 0})</span>
                    </h4>
                    {!selectedTechnique.references || selectedTechnique.references.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No external citations listed.</p>
                    ) : (
                      <div className="grid grid-cols-1 gap-2.5">
                        {selectedTechnique.references.map((ref, rIdx) => (
                          <div
                            key={rIdx}
                            className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl flex items-start justify-between gap-3 text-xs"
                          >
                            <div className="space-y-1 min-w-0">
                              {ref.sourceName && (
                                <span className="font-mono text-blue-400 font-bold text-[11px] block">{ref.sourceName}</span>
                              )}
                              {ref.description && (
                                <p className="text-slate-300 leading-relaxed">{ref.description}</p>
                              )}
                            </div>
                            {ref.url && (
                              <a
                                href={ref.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-cyan-400 hover:text-cyan-300 shrink-0 p-1 bg-cyan-500/10 rounded-lg border border-cyan-500/20 hover:border-cyan-500/40 transition-colors"
                                title="Open external reference"
                              >
                                <ArrowUpRight className="w-3.5 h-3.5" />
                              </a>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

            </div>

            {/* Modal Footer */}
            <div className="p-3.5 sm:p-4 bg-slate-950/95 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 shrink-0 z-10">
              <div className="flex items-center gap-2">
                <span>MITRE ATLAS™ • v{MITRE_ATLAS_META.version}</span>
                <span className="text-slate-600">•</span>
                <span className="font-mono text-slate-500">{selectedTechnique.id}</span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handlePrevTechnique}
                  disabled={currentTechniqueIndex <= 0}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed font-mono text-xs transition-colors cursor-pointer"
                >
                  ← Prev
                </button>
                <button
                  type="button"
                  onClick={handleNextTechnique}
                  disabled={currentTechniqueIndex >= baseFilteredTechniques.length - 1}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed font-mono text-xs transition-colors cursor-pointer"
                >
                  Next →
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedTechnique(null)}
                  className="px-4 py-1.5 rounded-lg bg-orange-500/20 hover:bg-orange-500/30 text-orange-300 border border-orange-500/40 font-semibold transition-colors cursor-pointer"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

    </div>
  );
};

export default MitreAtlasView;
