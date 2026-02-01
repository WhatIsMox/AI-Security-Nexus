
import React, { useState, useMemo } from 'react';
import { 
  Target, Shield, AlertTriangle, GitBranch, 
  LayoutTemplate, FileText, ArrowRight, ExternalLink,
  Brain, Cpu, Bot, CheckCircle2, ListFilter,
  UserCheck, ShieldAlert, Wrench, Info, AlertOctagon,
  Eye, EyeOff, Lock
} from 'lucide-react';

interface ThreatModellingProps {
  onNavigateToTest: (testId: string) => void;
  onNavigateToOwasp: (threatId: string) => void;
}

// --- Data Structures based on OWASP AI Testing Guide Appendix D & SAIF ---

interface SAIFComponent {
  id: string; 
  name: string;
  layer: 'Application' | 'Model' | 'Infrastructure' | 'Data';
  description: string;
  x: number; 
  y: number;
  width: number;
  height: number;
  style?: 'solid' | 'dotted';
}

interface SAIFControl {
  name: string;
  description: string;
  responsibility: ('Model Creator' | 'Model Consumer')[];
}

interface ThreatDefinition {
  id: string; 
  name: string;
  description: string;
  scenario: string;
  riskOwner: string;
  impact: string;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  relatedTestIds: string[]; 
  affectedComponents: string[]; 
  category: 'Security' | 'Responsible AI' | 'Privacy' | 'Social Engineering';
  // SAIF Lifecycle Mapping
  introducedAt?: string[]; // IDs of components where the risk starts
  exposedAt?: string[];    // IDs of components where the risk is manifested/exploited
  mitigatedAt?: string[]; // IDs of components where controls are applied
  responsibility?: ('Model Creator' | 'Model Consumer')[];
  saifControls?: string[];
}

const SAIF_CONTROLS_LIB: Record<string, SAIFControl> = {
  "input_val": {
    name: "Input Validation and Sanitization",
    description: "Detect malicious queries and react appropriately (blocking/restricting).",
    responsibility: ["Model Creator", "Model Consumer"]
  },
  "output_val": {
    name: "Output Validation and Sanitization",
    description: "Validate/sanitize model output before processing by the application.",
    responsibility: ["Model Creator", "Model Consumer"]
  },
  "adv_train": {
    name: "Adversarial Training and Testing",
    description: "Train model on adversarial inputs to strengthen resilience.",
    responsibility: ["Model Creator", "Model Consumer"]
  }
};

// Redesigned Layout Coordinates to match the reference image
const CENTER_X = 425; // Center of 850px canvas

const SAIF_COMPONENTS: SAIFComponent[] = [
  // --- Application Layer (Top) ---
  { id: "1", name: "User", layer: "Application", description: "Human or system actor interacting with the AI deployment.", x: CENTER_X - 60, y: 10, width: 120, height: 40, style: 'dotted' },
  { id: "4", name: "Application", layer: "Application", description: "The interface interacting with the AI deployment.", x: CENTER_X - 150, y: 70, width: 300, height: 50 },
  { id: "5", name: "Agent / Plugin", layer: "Application", description: "Agents or plugins used by the AI deployment for extended functionality.", x: CENTER_X - 80, y: 140, width: 160, height: 40 },
  { id: "6", name: "External Sources", layer: "Application", description: "Third-party APIs and services providing context or tools.", x: CENTER_X + 175, y: 140, width: 160, height: 40, style: 'dotted' },
  
  // --- Model Layer (Inference Flow) ---
  { id: "7", name: "Input Handling", layer: "Model", description: "Sanitization and validation of prompts before inference.", x: CENTER_X - 170, y: 220, width: 140, height: 40 },
  { id: "8", name: "Output Handling", layer: "Model", description: "Filtering and redaction of generated content.", x: CENTER_X + 30, y: 220, width: 140, height: 40 },
  { id: "9", name: "MODEL", layer: "Model", description: "The central inference engine and weights.", x: CENTER_X - 150, y: 280, width: 300, height: 50 },

  // --- Infrastructure Layer (Support) ---
  { id: "10", name: "Model Storage Infrastructure", layer: "Infrastructure", description: "Artifact registry where model weights and versions are stored.", x: CENTER_X - 190, y: 360, width: 180, height: 40 },
  { id: "11", name: "Model Serving Infrastructure", layer: "Infrastructure", description: "The runtime environment and hardware (GPUs) for inference.", x: CENTER_X + 10, y: 360, width: 180, height: 40 },
  
  { id: "12", name: "Evaluation", layer: "Infrastructure", description: "Safety harness and performance assessment pipelines.", x: CENTER_X - 325, y: 430, width: 120, height: 40 },
  { id: "13", name: "Training and Tuning", layer: "Infrastructure", description: "Processes for fine-tuning and adapting models.", x: CENTER_X - 100, y: 430, width: 200, height: 50 },
  { id: "14", name: "Model Frameworks & Code", layer: "Infrastructure", description: "Code required to run the AI application (PyTorch, TensorFlow, etc.).", x: CENTER_X + 125, y: 430, width: 160, height: 40 },

  { id: "15", name: "Data Storage Infrastructure", layer: "Infrastructure", description: "Vector databases, object stores, and data lakes.", x: CENTER_X - 100, y: 510, width: 200, height: 40 },

  // --- Data Layer (Pipeline Flowing Up) ---
  { id: "16", name: "Training Data", layer: "Data", description: "Curated corpora used for model pre-training or fine-tuning.", x: CENTER_X - 100, y: 580, width: 200, height: 40 },
  { id: "17", name: "Data Filtering & Processing", layer: "Data", description: "ETL, cleaning, and sanitization of raw data.", x: CENTER_X - 100, y: 650, width: 200, height: 40 },
  { id: "18", name: "Data Sources", layer: "Data", description: "Internal databases and repositories providing raw data.", x: CENTER_X - 200, y: 720, width: 400, height: 40 },
  { id: "19", name: "External Sources (Data)", layer: "Data", description: "Public internet, feeds, and third-party data providers.", x: CENTER_X - 80, y: 800, width: 160, height: 40, style: 'dotted' },
];

const THREAT_LIBRARY: ThreatDefinition[] = [
  // --- SAIF-SPECIFIC RISKS (Enriched from PDF) ---
  { 
    id: "SAIF-R01", 
    name: "Unauthorized Training Data", 
    category: "Security", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-DAT-05"], 
    affectedComponents: ["16", "17", "18", "19"], 
    impact: "Legal liabilities, ethical breaches, and potential copyright infringement.", 
    riskOwner: "Model Creator", 
    scenario: "Model is trained on data without proper licensing or user consent, resulting in regulatory fines.", 
    description: "The model is trained on unauthorized data, resulting in legal or ethical issues.",
    responsibility: ["Model Creator"],
    introducedAt: ["19", "18"],
    exposedAt: ["9"],
    mitigatedAt: ["17"]
  },
  { 
    id: "SAIF-R02", 
    name: "Model Source Tampering", 
    category: "Security", 
    riskLevel: "Critical", 
    relatedTestIds: ["AITG-INF-06"], 
    affectedComponents: ["10", "14"], 
    impact: "Complete loss of model integrity, execution of backdoors.", 
    riskOwner: "Model Creator", 
    scenario: "Attackers manipulate the model's source code or weights during the storage phase.", 
    description: "Attackers manipulate the model's source code or weights, compromising performance or creating backdoors.",
    responsibility: ["Model Creator"],
    introducedAt: ["14"],
    exposedAt: ["9", "11"],
    mitigatedAt: ["10"]
  },
  { 
    id: "SAIF-R03", 
    name: "Excessive Data Handling", 
    category: "Privacy", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-DAT-05"], 
    affectedComponents: ["4", "15", "18"], 
    impact: "Privacy violations, GDPR/CCPA compliance failure.", 
    riskOwner: "Model Consumer", 
    scenario: "Data collection exceeds privacy policies, retaining PII beyond allowed duration.", 
    description: "Data collection or retention goes beyond what is allowed in corresponding privacy policies.",
    responsibility: ["Model Consumer"],
    introducedAt: ["4"],
    exposedAt: ["15"],
    mitigatedAt: ["15", "18"]
  },
  { 
    id: "SAIF-R04", 
    name: "Model Deployment Tampering", 
    category: "Security", 
    riskLevel: "Critical", 
    relatedTestIds: ["AITG-INF-01"], 
    affectedComponents: ["11", "9"], 
    impact: "Model behaves maliciously in production despite clean training.", 
    riskOwner: "Model Creator/Consumer", 
    scenario: "Attackers manipulate components used for model deployment (serving infra).", 
    description: "Attackers manipulate components used for model deployment, compromising performance or creating backdoors.",
    responsibility: ["Model Creator", "Model Consumer"],
    introducedAt: ["11"],
    exposedAt: ["4"],
    mitigatedAt: ["11"]
  },
  { 
    id: "SAIF-R05", 
    name: "Inferred Sensitive Data", 
    category: "Privacy", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-APP-03"], 
    affectedComponents: ["9", "8"], 
    impact: "Disclosure of information the user didn't explicitly provide.", 
    riskOwner: "Model Consumer", 
    scenario: "Model provides sensitive information it didn't have access to by inferring it from training data or prompts.", 
    description: "The model provides sensitive information that it did not have access to by inferring it from other data.",
    responsibility: ["Model Creator", "Model Consumer"],
    introducedAt: ["16", "9"],
    exposedAt: ["8", "4"],
    mitigatedAt: ["8", "adv_train"],
    saifControls: ["output_val", "adv_train"]
  },
  { 
    id: "SAIF-R06", 
    name: "Rogue Actions", 
    category: "Security", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-APP-06"], 
    affectedComponents: ["4", "5"], 
    impact: "System destruction, data loss, financial fraud.", 
    riskOwner: "Model Consumer", 
    scenario: "Attackers exploit insufficiently restricted model access to cause harm.", 
    description: "Attackers exploit insufficiently restricted model access to perform harmful actions autonomously.",
    responsibility: ["Model Consumer"],
    introducedAt: ["5"],
    exposedAt: ["4", "6"],
    mitigatedAt: ["4"],
    saifControls: ["output_val"]
  },

  // --- OWASP Top 10 for LLMs 2025 ---
  { 
    id: "LLM01:2025", 
    name: "Prompt Injection", 
    category: "Security", 
    riskLevel: "Critical", 
    relatedTestIds: ["AITG-APP-01", "AITG-APP-02"], 
    affectedComponents: ["4", "5", "6", "7", "9"], 
    impact: "Model hijacking, unauthorized actions, data exfiltration.", 
    riskOwner: "Model User & Creator", 
    scenario: "Direct injection via user input to bypass controls, or indirect injection via retrieval of poisoned external content.", 
    description: "User prompts or external inputs alter the LLM's behavior or output in unintended ways.",
    responsibility: ["Model Creator", "Model Consumer"],
    introducedAt: ["1", "6"],
    exposedAt: ["9", "5"],
    mitigatedAt: ["7"],
    saifControls: ["input_val", "output_val", "adv_train"]
  },
  { 
    id: "LLM02:2025", 
    name: "Sensitive Information Disclosure", 
    category: "Privacy", 
    riskLevel: "Critical", 
    relatedTestIds: ["AITG-APP-03", "AITG-APP-04", "AITG-APP-07"], 
    affectedComponents: ["4", "5", "8", "9", "15"], 
    impact: "Leakage of PII, proprietary secrets, or system prompts.", 
    riskOwner: "Model User", 
    scenario: "Model reveals another user's session data, internal API keys, or memorized training data.", 
    description: "Inadvertent exposure of confidential data in model outputs.",
    responsibility: ["Model Creator", "Model Consumer"],
    introducedAt: ["16", "9"],
    exposedAt: ["8", "4"],
    mitigatedAt: ["8", "adv_train"],
    saifControls: ["output_val", "adv_train"]
  },
  { 
    id: "ASI01", 
    name: "Agent Goal Hijack", 
    category: "Security", 
    riskLevel: "Critical", 
    relatedTestIds: ["AGT-01"], 
    affectedComponents: ["1", "4", "5", "7", "9"], 
    impact: "Redirection of autonomy, data exfiltration, unauthorized actions.", 
    riskOwner: "Model User", 
    scenario: "An attacker emails a crafted message that silently triggers an agent to execute hidden instructions.", 
    description: "Attackers manipulate an agent’s objectives, task selection, or decision pathways.",
    responsibility: ["Model Consumer"],
    introducedAt: ["1", "6"],
    exposedAt: ["5"],
    mitigatedAt: ["4", "7"]
  }
];

// --- Helpers for styling ---

const getThreatTheme = (id: string) => {
  if (id.startsWith('LLM')) return { bg: 'bg-pink-500/10', text: 'text-pink-400', border: 'border-pink-500/20', hoverBg: 'hover:bg-pink-500/20', hoverBorder: 'hover:border-pink-500/40', icon: Brain };
  if (id.startsWith('ML')) return { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20', hoverBg: 'hover:bg-emerald-500/20', hoverBorder: 'hover:border-emerald-500/40', icon: Cpu };
  if (id.startsWith('ASI') || id.startsWith('T')) return { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', hoverBg: 'hover:bg-orange-500/20', hoverBorder: 'hover:border-orange-500/40', icon: Bot };
  if (id.startsWith('SAIF')) return { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', hoverBg: 'hover:bg-blue-500/20', hoverBorder: 'hover:border-blue-500/40', icon: Shield };
  return { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20', hoverBg: 'hover:bg-slate-500/20', hoverBorder: 'hover:border-slate-500/40', icon: Shield };
};

const getSeverityTheme = (level: string) => {
  switch (level) {
    case 'Critical': return 'bg-red-500/10 text-red-400 border-red-500/20';
    case 'High': return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    case 'Medium': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    case 'Low': return 'bg-green-500/10 text-green-400 border-green-500/20';
    default: return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
  }
};

const ThreatModelling: React.FC<ThreatModellingProps> = ({ onNavigateToTest, onNavigateToOwasp }) => {
  const [activeTab, setActiveTab] = useState<'architecture' | 'impact' | 'mapping'>('architecture');
  const [selectedComponentId, setSelectedComponentId] = useState<string | null>(null);
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [sortMethod, setSortMethod] = useState<'default' | 'severity'>('default');

  const selectedThreat = useMemo(() => THREAT_LIBRARY.find(t => t.id === selectedThreatId), [selectedThreatId]);
  const selectedComponent = SAIF_COMPONENTS.find(c => c.id === selectedComponentId);
  
  const threatsForComponent = selectedComponentId 
    ? THREAT_LIBRARY.filter(t => t.affectedComponents.includes(selectedComponentId))
    : [];

  const sortedThreats = useMemo(() => {
    let list = [...THREAT_LIBRARY];
    if (sortMethod === 'severity') {
      const weights = { Critical: 4, High: 3, Medium: 2, Low: 1 };
      list.sort((a, b) => (weights[b.riskLevel] || 0) - (weights[a.riskLevel] || 0));
    }
    return list;
  }, [sortMethod]);

  const handleComponentClick = (id: string) => {
    setSelectedComponentId(id === selectedComponentId ? null : id);
    setSelectedThreatId(null);
  };

  const getLayerColor = (layer: string) => {
    switch (layer) {
      case 'Application': return 'border-blue-500 text-blue-400 bg-blue-500/10 hover:bg-blue-500/20';
      case 'Model': return 'border-purple-500 text-purple-400 bg-purple-500/10 hover:bg-purple-500/20';
      case 'Infrastructure': return 'border-amber-500 text-amber-400 bg-amber-500/10 hover:bg-amber-500/20';
      case 'Data': return 'border-emerald-500 text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20';
      default: return 'border-slate-500 text-slate-400 bg-slate-800';
    }
  };

  return (
    <div className="p-4 md:p-8 max-w-7xl mx-auto animate-in fade-in duration-500">
      
      {/* Header */}
      <div className="mb-8 flex flex-col md:flex-row justify-between items-start gap-6">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">AI Threat Modelling (SAIF)</h2>
          <p className="text-slate-400 max-w-3xl">
            A holistic exploration of AI security risks based on <strong>Google's Secure AI Framework (SAIF)</strong>. 
            Visualize where risks are introduced, exposed, and mitigated across the entire AI pipeline.
          </p>
        </div>
        <div className="flex gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-col items-center">
                <span className="text-[10px] text-slate-500 uppercase font-bold mb-1">Total Risks</span>
                <span className="text-2xl font-bold text-white">{THREAT_LIBRARY.length}</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-col items-center">
                <span className="text-[10px] text-slate-500 uppercase font-bold mb-1">SAIF Coverage</span>
                <span className="text-2xl font-bold text-blue-400">100%</span>
            </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800 mb-6 overflow-x-auto scrollbar-hide">
        <button 
          onClick={() => setActiveTab('architecture')}
          className={`px-4 py-2 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${activeTab === 'architecture' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
        >
          <LayoutTemplate className="w-4 h-4" />
          Risk Flow Map
        </button>
        <button 
          onClick={() => setActiveTab('impact')}
          className={`px-4 py-2 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${activeTab === 'impact' ? 'border-red-500 text-red-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
        >
          <AlertTriangle className="w-4 h-4" />
          Business Impacts
        </button>
        <button 
          onClick={() => setActiveTab('mapping')}
          className={`px-4 py-2 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${activeTab === 'mapping' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
        >
          <GitBranch className="w-4 h-4" />
          Threat Library
        </button>
      </div>

      {/* Architecture View */}
      {activeTab === 'architecture' && (
        <div className="flex flex-col lg:flex-row gap-6 h-[950px]">
          
          {/* Interactive Diagram Area */}
          <div className="flex-1 bg-slate-950 border border-slate-800 rounded-xl relative overflow-hidden flex flex-col">
            {/* Legend Overlay */}
            <div className="absolute top-4 left-4 z-20 flex flex-col gap-2">
                <div className="bg-slate-900/90 backdrop-blur-md border border-slate-800 p-3 rounded-lg text-[10px] font-bold uppercase tracking-wider space-y-2">
                    <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-red-500" /> Risk Introduction</div>
                    <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-orange-500" /> Risk Exposure</div>
                    <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-emerald-500" /> Risk Mitigation</div>
                </div>
                {selectedThreatId && (
                    <button 
                      onClick={() => setSelectedThreatId(null)}
                      className="bg-slate-900/90 text-white px-3 py-1.5 rounded-lg border border-slate-700 text-xs hover:bg-slate-800 transition-colors"
                    >
                        Clear Selection
                    </button>
                )}
            </div>
            
            <div className="flex-1 overflow-auto relative p-2 flex items-center justify-center bg-slate-950">
               <svg width="850" height="880" viewBox="0 0 850 880" className="w-full h-full">
                  <defs>
                    <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                      <path d="M0,0 L0,6 L8,3 z" fill="#475569" />
                    </marker>
                    <filter id="glow">
                        <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
                        <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                  </defs>
                  
                  {/* Flow Lines */}
                  <g stroke="#1e293b" strokeWidth="2" fill="none">
                    <path d="M415 50 L415 70" markerEnd="url(#arrowhead)" />
                    <path d="M435 70 L435 50" markerEnd="url(#arrowhead)" />
                    <path d="M385 120 L385 140" markerEnd="url(#arrowhead)" />
                    <path d="M465 140 L465 120" markerEnd="url(#arrowhead)" />
                    <path d="M505 160 L600 160" strokeDasharray="5,5" markerEnd="url(#arrowhead)" />
                    <path d="M325 120 L325 220" markerEnd="url(#arrowhead)" />
                    <path d="M525 220 L525 120" markerEnd="url(#arrowhead)" />
                    <path d="M325 260 L325 280" markerEnd="url(#arrowhead)" />
                    <path d="M525 280 L525 260" markerEnd="url(#arrowhead)" />
                    <path d="M275 305 L160 305 L160 430" markerEnd="url(#arrowhead)" />
                    <path d="M220 450 L325 450" markerEnd="url(#arrowhead)" />
                    <path d="M550 450 L525 450" markerEnd="url(#arrowhead)" />
                    <path d="M425 430 L425 330" markerEnd="url(#arrowhead)" />
                    <path d="M425 510 L425 480" markerEnd="url(#arrowhead)" />
                    <path d="M425 580 L425 550" markerEnd="url(#arrowhead)" />
                    <path d="M425 650 L425 620" markerEnd="url(#arrowhead)" />
                    <path d="M425 720 L425 690" markerEnd="url(#arrowhead)" />
                    <path d="M425 800 L425 760" strokeDasharray="5,5" />
                  </g>

                  {/* Components */}
                  {SAIF_COMPONENTS.map((comp) => {
                    const isSelected = selectedComponentId === comp.id;
                    const styleClass = getLayerColor(comp.layer);
                    
                    // SAIF Risk Lifecycle Highlighting
                    const isIntroduced = selectedThreat?.introducedAt?.includes(comp.id);
                    const isExposed = selectedThreat?.exposedAt?.includes(comp.id);
                    const isMitigated = selectedThreat?.mitigatedAt?.includes(comp.id);

                    return (
                      <g 
                        key={comp.id} 
                        onClick={(e) => { e.stopPropagation(); handleComponentClick(comp.id); }}
                        className="cursor-pointer transition-all duration-300"
                        style={{ opacity: selectedThreatId && !(isIntroduced || isExposed || isMitigated) ? 0.3 : 1 }}
                      >
                        <rect 
                          x={comp.x} 
                          y={comp.y} 
                          width={comp.width} 
                          height={comp.height} 
                          rx={comp.style === 'dotted' ? 0 : 8}
                          strokeDasharray={comp.style === 'dotted' ? "5,5" : "0"}
                          className={`
                            fill-slate-900 stroke-2 transition-all
                            ${isSelected ? 'stroke-cyan-400 stroke-[3px]' : styleClass.split(' ')[0]}
                            ${isIntroduced ? 'stroke-red-500 stroke-[4px]' : ''}
                            ${isExposed ? 'stroke-orange-500 stroke-[4px]' : ''}
                            ${isMitigated ? 'stroke-emerald-500 stroke-[4px]' : ''}
                          `}
                        />
                        
                        <text 
                          x={comp.x + comp.width/2} 
                          y={comp.y + comp.height/2 + 5} 
                          fill={isSelected ? "#22d3ee" : "#ffffff"}
                          fontWeight="700" 
                          fontSize="11"
                          textAnchor="middle"
                          className="pointer-events-none uppercase tracking-tighter"
                        >
                          {comp.name}
                        </text>

                        {/* Lifecycle Indicators (Floating Icons) */}
                        {isIntroduced && <circle cx={comp.x} cy={comp.y} r="6" fill="#ef4444" filter="url(#glow)" />}
                        {isExposed && <circle cx={comp.x + comp.width} cy={comp.y} r="6" fill="#f97316" filter="url(#glow)" />}
                        {isMitigated && <circle cx={comp.x + comp.width/2} cy={comp.y + comp.height} r="6" fill="#10b981" filter="url(#glow)" />}
                      </g>
                    );
                  })}
               </svg>
            </div>
          </div>

          {/* Details Sidebar */}
          <div className="w-full lg:w-96 bg-slate-950 border-l border-slate-800 flex flex-col shadow-2xl z-20 h-full">
            {selectedThreatId ? (
                // Threat Detail View (When a specific threat is selected from list)
                <div className="flex-1 overflow-y-auto p-6 animate-in slide-in-from-right duration-300">
                    <button onClick={() => setSelectedThreatId(null)} className="text-xs text-slate-500 hover:text-white mb-4 flex items-center gap-1"><ArrowRight className="w-3 h-3 rotate-180" /> Back to components</button>
                    
                    <div className="mb-6">
                        <div className="flex justify-between items-start mb-2">
                             <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityTheme(selectedThreat?.riskLevel || 'Medium')}`}>{selectedThreat?.riskLevel} Risk</span>
                             <span className="font-mono text-xs text-slate-500">{selectedThreat?.id}</span>
                        </div>
                        <h3 className="text-2xl font-bold text-white mb-3">{selectedThreat?.name}</h3>
                        <p className="text-sm text-slate-400 leading-relaxed mb-4">{selectedThreat?.description}</p>
                        
                        <div className="flex flex-wrap gap-2 mb-6">
                            {selectedThreat?.responsibility?.map(r => (
                                <span key={r} className="inline-flex items-center gap-1.5 px-2 py-1 bg-slate-900 border border-slate-800 rounded text-[10px] text-slate-300 font-bold uppercase tracking-wider">
                                    <UserCheck className="w-3 h-3" /> {r}
                                </span>
                            ))}
                        </div>
                    </div>

                    <div className="space-y-6">
                        {/* SAIF Controls Mapping */}
                        {selectedThreat?.saifControls && (
                            <section>
                                <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                                    <Wrench className="w-3.5 h-3.5" /> SAIF Mitigating Controls
                                </h4>
                                <div className="space-y-2">
                                    {selectedThreat.saifControls.map(cId => {
                                        const ctrl = SAIF_CONTROLS_LIB[cId];
                                        return (ctrl ? 
                                            <div key={cId} className="bg-emerald-500/5 border border-emerald-500/20 p-3 rounded-lg">
                                                <div className="text-emerald-400 font-bold text-xs mb-1">{ctrl.name}</div>
                                                <div className="text-[10px] text-slate-400">{ctrl.description}</div>
                                            </div> : null
                                        );
                                    })}
                                </div>
                            </section>
                        )}

                        {/* Lifecycle Path */}
                        <section>
                            <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                                <GitBranch className="w-3.5 h-3.5" /> Lifecycle Propagation
                            </h4>
                            <div className="space-y-3">
                                <div className="flex items-start gap-3">
                                    <div className="w-2 h-2 rounded-full bg-red-500 mt-1.5 shrink-0" />
                                    <div>
                                        <div className="text-[10px] font-bold text-red-400 uppercase">Introduced At</div>
                                        <div className="text-xs text-slate-300">{selectedThreat?.introducedAt?.map(id => SAIF_COMPONENTS.find(c => c.id === id)?.name).join(', ')}</div>
                                    </div>
                                </div>
                                <div className="flex items-start gap-3">
                                    <div className="w-2 h-2 rounded-full bg-orange-500 mt-1.5 shrink-0" />
                                    <div>
                                        <div className="text-[10px] font-bold text-orange-400 uppercase">Exposed At</div>
                                        <div className="text-xs text-slate-300">{selectedThreat?.exposedAt?.map(id => SAIF_COMPONENTS.find(c => c.id === id)?.name).join(', ')}</div>
                                    </div>
                                </div>
                                <div className="flex items-start gap-3">
                                    <div className="w-2 h-2 rounded-full bg-emerald-500 mt-1.5 shrink-0" />
                                    <div>
                                        <div className="text-[10px] font-bold text-emerald-400 uppercase">Mitigated At</div>
                                        <div className="text-xs text-slate-300">{selectedThreat?.mitigatedAt?.map(id => SAIF_COMPONENTS.find(c => c.id === id)?.name).join(', ')}</div>
                                    </div>
                                </div>
                            </div>
                        </section>

                        <section className="pt-4 border-t border-slate-800">
                             <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                                <div className="flex items-center gap-2 text-xs font-bold text-cyan-400 mb-2 uppercase tracking-wider"><ShieldAlert className="w-4 h-4" /> Recommended Tests</div>
                                <div className="flex flex-col gap-2">
                                    {selectedThreat?.relatedTestIds.map(tid => (
                                        <button key={tid} onClick={() => onNavigateToTest(tid)} className="flex justify-between items-center text-[10px] font-mono bg-slate-950 p-2 rounded hover:bg-slate-800 transition-colors border border-slate-800 hover:border-cyan-900 group">
                                            <span>{tid}</span>
                                            <ArrowRight className="w-3 h-3 text-slate-600 group-hover:text-cyan-400" />
                                        </button>
                                    ))}
                                </div>
                             </div>
                        </section>
                    </div>
                </div>
            ) : !selectedComponent ? (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-slate-500">
                <LayoutTemplate className="w-16 h-16 mb-4 opacity-10" />
                <p className="text-sm font-medium">Select a component in the diagram or a threat from the matrix to explore the SAIF security path.</p>
              </div>
            ) : (
              <div className="flex-1 overflow-y-auto p-6 animate-in slide-in-from-right duration-300">
                <div className="mb-6 border-b border-slate-800 pb-4">
                  <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full bg-slate-900 border ${
                    selectedComponent.layer === 'Application' ? 'text-blue-400 border-blue-900' :
                    selectedComponent.layer === 'Model' ? 'text-purple-400 border-purple-900' :
                    selectedComponent.layer === 'Infrastructure' ? 'text-amber-400 border-amber-900' : 'text-emerald-400 border-emerald-900'
                  }`}>
                    {selectedComponent.layer} Layer
                  </span>
                  <h3 className="text-2xl font-bold text-white mt-2 mb-2">{selectedComponent.name}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{selectedComponent.description}</p>
                </div>

                <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Shield className="w-3.5 h-3.5" /> Potential Threats at this Asset
                </h4>

                <div className="space-y-3">
                  {threatsForComponent.map(threat => {
                    const theme = getThreatTheme(threat.id);
                    return (
                      <div 
                        key={threat.id}
                        onClick={() => setSelectedThreatId(threat.id)}
                        className="bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/30 rounded-lg p-4 transition-all group cursor-pointer"
                      >
                        <div className="flex justify-between items-center mb-2">
                            <span className={`flex items-center gap-1.5 font-mono text-[9px] px-1.5 py-0.5 rounded border ${theme.bg} ${theme.text} ${theme.border}`}>{threat.id}</span>
                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${getSeverityTheme(threat.riskLevel)}`}>{threat.riskLevel}</span>
                        </div>
                        <h5 className="font-bold text-slate-200 text-xs mb-1 group-hover:text-cyan-400 transition-colors">{threat.name}</h5>
                        <p className="text-[10px] text-slate-500 line-clamp-2">{threat.description}</p>
                        <div className="mt-2 pt-2 border-t border-slate-800 flex justify-end">
                            <span className="text-[10px] text-cyan-400 font-bold flex items-center gap-1">Analyze Path <ArrowRight className="w-3 h-3" /></span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Impact Analysis Tab */}
      {activeTab === 'impact' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden animate-in fade-in duration-300 shadow-2xl">
          <div className="p-6 border-b border-slate-800 bg-slate-950 flex justify-between items-center">
            <div>
              <h3 className="text-xl font-bold text-white mb-1">Business Impact Matrix</h3>
              <p className="text-xs text-slate-500">Correlation of technical failures to business consequences.</p>
            </div>
            <div className="flex items-center gap-2">
                <ListFilter className="w-4 h-4 text-slate-500" />
                <select 
                    value={sortMethod} 
                    onChange={(e) => setSortMethod(e.target.value as 'default' | 'severity')}
                    className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                    <option value="default">Default (ID)</option>
                    <option value="severity">Risk Level</option>
                </select>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-950/50 text-slate-400 text-[10px] uppercase tracking-widest border-b border-slate-800">
                  <th className="p-4 font-bold">Threat Context</th>
                  <th className="p-4 font-bold">Business Impact</th>
                  <th className="p-4 font-bold">Risk Level</th>
                  <th className="p-4 font-bold">Ownership Responsibility</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-sm">
                {sortedThreats.map((threat) => {
                  const theme = getThreatTheme(threat.id);
                  return (
                    <tr key={threat.id} className="hover:bg-slate-800/50 transition-colors group cursor-pointer" onClick={() => { setSelectedThreatId(threat.id); setActiveTab('architecture'); }}>
                      <td className="p-4 min-w-[200px]">
                        <div className="flex items-center gap-2 mb-1.5">
                           <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${theme.bg} ${theme.text} ${theme.border}`}>
                              {threat.id}
                           </span>
                           <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${getSeverityTheme(threat.riskLevel)}`}>
                             {threat.riskLevel}
                           </span>
                        </div>
                        <div className="font-bold text-slate-200 group-hover:text-cyan-400 transition-colors">{threat.name}</div>
                        <div className="text-[10px] text-slate-500">{threat.category}</div>
                      </td>
                      <td className="p-4 text-slate-400 italic text-xs max-w-xs leading-relaxed">
                        "{threat.impact}"
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                           <div className={`w-2 h-2 rounded-full ${threat.riskLevel === 'Critical' ? 'bg-red-500' : threat.riskLevel === 'High' ? 'bg-orange-500' : 'bg-yellow-500'}`} />
                           <span className="text-xs text-slate-300 font-medium">{threat.riskLevel}</span>
                        </div>
                      </td>
                      <td className="p-4">
                          <div className="flex flex-wrap gap-2">
                            {threat.responsibility?.map(r => {
                                const isCreator = r === 'Model Creator';
                                return (
                                    <span key={r} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-[10px] font-bold uppercase tracking-wider whitespace-nowrap ${
                                      isCreator 
                                        ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' 
                                        : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                    }`}>
                                      {isCreator ? <Cpu className="w-3 h-3" /> : <UserCheck className="w-3 h-3" />}
                                      {r.split(' ')[1]}
                                    </span>
                                );
                            })}
                          </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Threat Mapping Tab */}
      {activeTab === 'mapping' && (
        <div className="animate-in fade-in duration-300">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
              {sortedThreats.map(threat => {
                const theme = getThreatTheme(threat.id);
                return (
                  <div key={threat.id} className="bg-slate-950 rounded-xl border border-slate-800 flex flex-col hover:border-slate-600 transition-all duration-300 group overflow-hidden">
                    <div className="p-5 border-b border-slate-800/50 bg-slate-900/30">
                      <div className="flex justify-between items-start mb-3">
                         <button 
                            onClick={() => onNavigateToOwasp(threat.id)}
                            className={`flex items-center gap-1.5 font-mono text-xs px-2.5 py-1 rounded-md border transition-transform hover:scale-105 ${theme.bg} ${theme.text} ${theme.border}`}
                          >
                            <theme.icon className="w-3.5 h-3.5" /> {threat.id}
                          </button>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityTheme(threat.riskLevel)}`}>
                            {threat.riskLevel}
                          </span>
                      </div>
                      <h4 className="font-bold text-slate-200 text-lg leading-tight group-hover:text-cyan-400 transition-colors cursor-pointer" onClick={() => setSelectedThreatId(threat.id)}>
                        {threat.name}
                      </h4>
                    </div>

                    <div className="p-5 flex-1 flex flex-col gap-4">
                      <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest flex items-center gap-1"><Info className="w-3 h-3" /> Description</div>
                      <p className="text-xs text-slate-400 leading-relaxed italic border-l-2 border-slate-800 pl-3">"{threat.description}"</p>
                      
                      <div className="mt-auto space-y-3">
                        <div className="flex flex-col gap-2">
                           <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" /> Mitigation Testing</span>
                           <div className="flex flex-wrap gap-2">
                             {threat.relatedTestIds.map(testId => (
                                <button 
                                    key={testId}
                                    onClick={() => onNavigateToTest(testId)}
                                    className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-cyan-400 text-[10px] font-mono rounded border border-slate-800 transition-all"
                                >
                                    {testId}
                                </button>
                             ))}
                           </div>
                        </div>
                      </div>
                    </div>

                    <div className="px-5 py-3 bg-slate-900/50 border-t border-slate-800/50 flex justify-between items-center text-[9px] text-slate-500 font-mono">
                      <span className="flex items-center gap-1"><Lock className="w-2.5 h-2.5" /> SAIF Framework</span>
                      <span>{threat.category}</span>
                    </div>
                  </div>
                );
              })}
            </div>
        </div>
      )}

    </div>
  );
};

export default ThreatModelling;
