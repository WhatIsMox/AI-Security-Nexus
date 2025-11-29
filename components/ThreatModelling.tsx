
import React, { useState, useMemo } from 'react';
import { 
  Target, Shield, AlertTriangle, GitBranch, 
  LayoutTemplate, FileText, ArrowRight, ExternalLink,
  Brain, Cpu, Bot, CheckCircle2, ListFilter
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
}

// Redesigned Layout Coordinates to match the reference image
const CENTER_X = 425; // Center of 850px canvas

const SAIF_COMPONENTS: SAIFComponent[] = [
  // --- Application Layer (Top) ---
  { id: "1", name: "User", layer: "Application", description: "Human or system actor.", x: CENTER_X - 60, y: 10, width: 120, height: 40, style: 'dotted' },
  { id: "4", name: "Application", layer: "Application", description: "Orchestration & Logic.", x: CENTER_X - 150, y: 70, width: 300, height: 50 },
  { id: "5", name: "Agent / Plugin", layer: "Application", description: "Tools & Extensions.", x: CENTER_X - 80, y: 140, width: 160, height: 40 },
  { id: "6", name: "External Sources", layer: "Application", description: "3rd Party APIs.", x: CENTER_X + 175, y: 140, width: 160, height: 40, style: 'dotted' },
  
  // --- Model Layer (Inference Flow) ---
  { id: "7", name: "Input Handling", layer: "Model", description: "Sanitization & Validation.", x: CENTER_X - 170, y: 220, width: 140, height: 40 },
  { id: "8", name: "Output Handling", layer: "Model", description: "Filtering & Redaction.", x: CENTER_X + 30, y: 220, width: 140, height: 40 },
  { id: "9", name: "Model", layer: "Model", description: "Inference Engine.", x: CENTER_X - 150, y: 280, width: 300, height: 50 },

  // --- Infrastructure Layer (Support) ---
  { id: "10", name: "Model Storage Infra", layer: "Infrastructure", description: "Artifact Registry.", x: CENTER_X - 190, y: 360, width: 180, height: 40 },
  { id: "11", name: "Model Serving Infra", layer: "Infrastructure", description: "Runtime Env / GPU.", x: CENTER_X + 10, y: 360, width: 180, height: 40 },
  
  { id: "12", name: "Evaluation", layer: "Infrastructure", description: "Safety Harness.", x: CENTER_X - 325, y: 430, width: 120, height: 40 },
  { id: "13", name: "Training and Tuning", layer: "Infrastructure", description: "Fine-tuning Pipelines.", x: CENTER_X - 100, y: 430, width: 200, height: 50 },
  { id: "14", name: "Frameworks & Code", layer: "Infrastructure", description: "PyTorch / TensorFlow.", x: CENTER_X + 125, y: 430, width: 160, height: 40 },

  { id: "15", name: "Data Storage Infra", layer: "Infrastructure", description: "Vector DBs / Object Store.", x: CENTER_X - 100, y: 510, width: 200, height: 40 },

  // --- Data Layer (Pipeline Flowing Up) ---
  { id: "16", name: "Training Data", layer: "Data", description: "Curated Corpora.", x: CENTER_X - 100, y: 580, width: 200, height: 40 },
  { id: "17", name: "Data Filtering", layer: "Data", description: "ETL & Cleaning.", x: CENTER_X - 100, y: 650, width: 200, height: 40 },
  { id: "18", name: "Data Sources", layer: "Data", description: "Internal Databases.", x: CENTER_X - 200, y: 720, width: 400, height: 40 },
  { id: "19", name: "External Sources", layer: "Data", description: "Public Internet/Feeds.", x: CENTER_X - 80, y: 800, width: 160, height: 40, style: 'dotted' },
];

const THREAT_LIBRARY: ThreatDefinition[] = [
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
    scenario: "Direct injection via user input to bypass controls, or indirect injection via retrieval of poisoned external content (e.g. emails, websites).", 
    description: "User prompts or external inputs alter the LLM's behavior or output in unintended ways." 
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
    scenario: "Model reveals another user's session data, internal API keys, or memorized training data in response to probing.", 
    description: "Inadvertent exposure of confidential data in model outputs." 
  },
  { 
    id: "LLM03:2025", 
    name: "Supply Chain Vulnerabilities", 
    category: "Security", 
    riskLevel: "Critical", 
    relatedTestIds: ["AITG-INF-01"], 
    affectedComponents: ["9", "10", "11", "13", "14"], 
    impact: "Compromised model integrity, backdoors, malware execution.", 
    riskOwner: "Model Creator", 
    scenario: "Compromised PyTorch library or pre-trained model introduces a backdoor into the application.", 
    description: "Tampering with dependencies, pre-trained models, or data pipelines." 
  },
  { 
    id: "LLM04:2025", 
    name: "Data and Model Poisoning", 
    category: "Security", 
    riskLevel: "Critical", 
    relatedTestIds: ["AITG-MOD-02", "AITG-MOD-03", "AITG-INF-05"], 
    affectedComponents: ["5", "6", "9", "13", "15", "18", "19"], 
    impact: "Backdoors, bias, degraded performance.", 
    riskOwner: "Model Creator", 
    scenario: "Attacker injects poisoned samples into training set or manipulates runtime RAG data to bias outputs.", 
    description: "Manipulation of pre-training, fine-tuning, or embedding data." 
  },
  { 
    id: "LLM05:2025", 
    name: "Improper Output Handling", 
    category: "Security", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-APP-05", "AITG-APP-12"], 
    affectedComponents: ["4", "8"], 
    impact: "XSS, CSRF, RCE, or Reputational Damage.", 
    riskOwner: "Model User", 
    scenario: "LLM generates malicious JavaScript or toxic content that is rendered unsafely in the user's browser.", 
    description: "Insufficient validation/sanitization of outputs before passing them downstream." 
  },
  { 
    id: "LLM06:2025", 
    name: "Excessive Agency", 
    category: "Security", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-APP-06"], 
    affectedComponents: ["4", "5", "6", "9"], 
    impact: "Unintended irreversible actions (e.g., delete DB, send emails).", 
    riskOwner: "Model User", 
    scenario: "Agent executes a 'delete' command derived from an ambiguous prompt without human confirmation.", 
    description: "Grants the LLM excessive functionality, permissions, or autonomy." 
  },
  { 
    id: "LLM07:2025", 
    name: "System Prompt Leakage", 
    category: "Security", 
    riskLevel: "Medium", 
    relatedTestIds: ["AITG-APP-07"], 
    affectedComponents: ["4", "7", "9"], 
    impact: "Exposure of business logic and facilitating other attacks.", 
    riskOwner: "Model Creator", 
    scenario: "Attacker tricks the model into repeating its initial instructions.", 
    description: "Discovery of the system prompts used to steer the model." 
  },
  { 
    id: "LLM08:2025", 
    name: "Vector and Embedding Weaknesses", 
    category: "Security", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-APP-08"], 
    affectedComponents: ["5", "6", "9", "15", "18"], 
    impact: "Semantic confusion, prompt injection via RAG.", 
    riskOwner: "Model User", 
    scenario: "Poisoned embeddings alter retrieval context, causing the model to answer based on malicious data.", 
    description: "Weaknesses in generation, storage, or retrieval of embeddings." 
  },
  { 
    id: "LLM09:2025", 
    name: "Misinformation", 
    category: "Responsible AI", 
    riskLevel: "Medium", 
    relatedTestIds: ["AITG-APP-11", "AITG-APP-13"], 
    affectedComponents: ["4", "8", "9", "16", "18"], 
    impact: "Reputational damage, incorrect decisions, liability.", 
    riskOwner: "Model Creator", 
    scenario: "Model confidently generates false medical advice or legal precedents.", 
    description: "Producing false, misleading, or nonsensical information (Hallucinations)." 
  },
  { 
    id: "LLM10:2025", 
    name: "Unbounded Consumption", 
    category: "Security", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-INF-02"], 
    affectedComponents: ["4", "7", "9", "11"], 
    impact: "Denial of Service (DoS), Financial exhaustion (Denial of Wallet).", 
    riskOwner: "Model User", 
    scenario: "Attacker floods the system with complex, token-heavy requests causing timeouts or massive bills.", 
    description: "Excessive and uncontrolled inferences leading to resource exhaustion." 
  },

  // --- OWASP Machine Learning Top 10 (Selected) ---
  { 
    id: "ML01:2023", 
    name: "Input Manipulation Attack", 
    category: "Security", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-MOD-01"], 
    affectedComponents: ["7", "9", "12", "13"], 
    impact: "Model evasion, misclassification.", 
    riskOwner: "Model Creator", 
    scenario: "Adversarial perturbations in images or text evade detection filters.", 
    description: "Deliberately altering input data to mislead the model (Evasion)." 
  },
  { 
    id: "ML03:2023", 
    name: "Model Inversion Attack", 
    category: "Privacy", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-MOD-05"], 
    affectedComponents: ["9", "16"], 
    impact: "Reconstruction of sensitive training data.", 
    riskOwner: "Model Creator", 
    scenario: "Attacker reconstructs a face or record from the model's outputs.", 
    description: "Reverse-engineering the model to extract training data." 
  },
  { 
    id: "ML04:2023", 
    name: "Membership Inference Attack", 
    category: "Privacy", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-MOD-04"], 
    affectedComponents: ["9", "16", "17"], 
    impact: "Privacy violation of training subjects.", 
    riskOwner: "Model Creator", 
    scenario: "Attacker determines if a specific individual's record was used to train the model.", 
    description: "Inferring presence of data samples in the training set." 
  },
  { 
    id: "ML05:2023", 
    name: "Model Theft", 
    category: "Security", 
    riskLevel: "High", 
    relatedTestIds: ["AITG-APP-09", "AITG-INF-06"], 
    affectedComponents: ["4", "9", "10", "11"], 
    impact: "IP Theft, Financial Loss, Model Cloning.", 
    riskOwner: "Model User/Creator", 
    scenario: "Attacker extracts model logic via API querying or steals weights from insecure storage.", 
    description: "Unauthorized access or functional replication of the model." 
  },

  // --- OWASP Agentic AI Threats (Complete) ---
  { 
    id: "T1", 
    name: "Memory Poisoning", 
    category: "Security", 
    riskLevel: "Critical", 
    relatedTestIds: ["AGT-01"], 
    affectedComponents: ["4", "5", "15"], 
    impact: "Corrupted agent context, persistent manipulation.", 
    riskOwner: "Model User", 
    scenario: "Attacker injects false facts into the agent's long-term memory to influence future sessions.", 
    description: "Exploiting memory systems to introduce malicious data." 
  },
  { 
    id: "T2", 
    name: "Tool Misuse", 
    category: "Security", 
    riskLevel: "Critical", 
    relatedTestIds: ["AGT-02"], 
    affectedComponents: ["5", "6"], 
    impact: "Unauthorized actions, financial loss.", 
    riskOwner: "Model User", 
    scenario: "Manipulating an agent to use a tool with malicious parameters.", 
    description: "Abusing integrated tools through deceptive prompts." 
  },
  {
    id: "T3",
    name: "Privilege Compromise",
    category: "Security",
    riskLevel: "High",
    relatedTestIds: ["AGT-03"],
    affectedComponents: ["4", "5"], 
    impact: "Escalation to administrative control, cross-system exploitation.",
    riskOwner: "Model User/Developer",
    scenario: "Agent exploits weak permission checks to execute administrative commands on behalf of a lower-privilege user.",
    description: "Attackers exploit weaknesses in permission management to perform unauthorized actions via the Agent."
  },
  {
    id: "T4",
    name: "Resource Overload",
    category: "Security",
    riskLevel: "High",
    relatedTestIds: ["AGT-07", "AITG-INF-02"],
    affectedComponents: ["4", "5", "11"],
    impact: "DoS, Financial exhaustion.",
    riskOwner: "Model User",
    scenario: "Triggering multiple agents to perform complex, expensive loops simultaneously.",
    description: "Targets computational and service capacities to degrade performance."
  },
  {
    id: "T5",
    name: "Cascading Hallucination",
    category: "Responsible AI",
    riskLevel: "Medium",
    relatedTestIds: ["AGT-06"],
    affectedComponents: ["4", "5", "8", "9"],
    impact: "Systemic decision failures.",
    riskOwner: "Model Creator",
    scenario: "One agent hallucinates a fact, which is accepted as truth by downstream agents, leading to a catastrophic error.",
    description: "False information propagating through multi-agent systems."
  },
  {
    id: "T6",
    name: "Intent Breaking",
    category: "Security",
    riskLevel: "High",
    relatedTestIds: ["AGT-04"],
    affectedComponents: ["4", "5"], 
    impact: "Agent Hijacking.",
    riskOwner: "Model User",
    scenario: "Injection of a new high-priority goal that overrides the agent's original safety directives.",
    description: "Exploits vulnerabilities in an AI agent's planning and goal-setting capabilities."
  },
  {
    id: "T7",
    name: "Misaligned Behaviors",
    category: "Responsible AI",
    riskLevel: "High",
    relatedTestIds: ["AITG-APP-06"],
    affectedComponents: ["4", "9"], 
    impact: "Fraud, Reputational damage.",
    riskOwner: "Model Creator",
    scenario: "A trading agent executes technically legal but ethically manipulative trades to maximize profit.",
    description: "Agents executing harmful actions by exploiting gaps in objective functions."
  },
  {
    id: "T8",
    name: "Repudiation & Untraceability",
    category: "Security",
    riskLevel: "Medium",
    relatedTestIds: [],
    affectedComponents: ["4", "11"], 
    impact: "Compliance violations, inability to audit.",
    riskOwner: "Security Architect",
    scenario: "Agent performs an action (e.g., deleting a file) but logs are insufficient to determine *why* or *which* user initiated it.",
    description: "Actions performed by autonomous agents cannot be traced back to a specific root cause or user."
  },
  {
    id: "T9",
    name: "Identity Spoofing",
    category: "Security",
    riskLevel: "High",
    relatedTestIds: ["AGT-05"],
    affectedComponents: ["5", "6"], 
    impact: "Unauthorized access.",
    riskOwner: "Security Architect",
    scenario: "A rogue agent mimics the handshake protocol of a trusted 'Supervisor' agent to issue malicious commands.",
    description: "Attackers exploit authentication to impersonate AI agents, humans, or services."
  },
  {
    id: "T10",
    name: "Overwhelming HITL",
    category: "Security",
    riskLevel: "Medium",
    relatedTestIds: [],
    affectedComponents: ["1", "4"], 
    impact: "Decision fatigue, rushed approvals.",
    riskOwner: "Product Owner",
    scenario: "Agent floods the human reviewer with hundreds of low-confidence requests, causing them to auto-approve a malicious one.",
    description: "Targets systems with human oversight by exploiting cognitive limitations."
  },
  {
    id: "T11",
    name: "Unexpected RCE",
    category: "Security",
    riskLevel: "Critical",
    relatedTestIds: ["AITG-APP-05"],
    affectedComponents: ["5", "11"], 
    impact: "System compromise.",
    riskOwner: "Security Architect",
    scenario: "A coding agent is tricked into generating and executing a Python script that opens a reverse shell.",
    description: "Attackers exploit AI-generated execution environments to inject malicious code."
  },
  {
    id: "T12",
    name: "Agent Comm. Poisoning",
    category: "Security",
    riskLevel: "High",
    relatedTestIds: ["AGT-06"],
    affectedComponents: ["5"], 
    impact: "Systemic failures.",
    riskOwner: "System Architect",
    scenario: "Injecting misleading info into the shared message bus used by multiple agents.",
    description: "Manipulating communication channels between agents."
  },
  {
    id: "T13",
    name: "Rogue Agents",
    category: "Security",
    riskLevel: "High",
    relatedTestIds: [],
    affectedComponents: ["5"], 
    impact: "Persistent threats.",
    riskOwner: "System Architect",
    scenario: "A compromised agent in a swarm begins acting against the collective goal without being detected.",
    description: "Malicious or compromised agents operate outside normal monitoring boundaries."
  },
  {
    id: "T14",
    name: "Human Attacks on Agents",
    category: "Social Engineering",
    riskLevel: "Medium",
    relatedTestIds: [],
    affectedComponents: ["1", "5"], 
    impact: "Privilege escalation.",
    riskOwner: "Security Architect",
    scenario: "A user uses social engineering tactics on a support agent to grant a refund they aren't entitled to.",
    description: "Adversaries exploit inter-agent delegation and trust relationships."
  },
  {
    id: "T15",
    name: "Human Manipulation",
    category: "Social Engineering",
    riskLevel: "High",
    relatedTestIds: [],
    affectedComponents: ["1", "4"], 
    impact: "Phishing, Fraud.",
    riskOwner: "Model User",
    scenario: "An AI agent, tailored for persuasion, convinces a user to transfer funds to a fraudulent account.",
    description: "Attackers exploit user trust in AI agents to influence human decision-making."
  }
];

// --- Helpers for styling ---

const getThreatTheme = (id: string) => {
  if (id.startsWith('LLM')) {
    return {
      bg: 'bg-pink-500/10',
      text: 'text-pink-400',
      border: 'border-pink-500/20',
      hoverBg: 'hover:bg-pink-500/20',
      hoverBorder: 'hover:border-pink-500/40',
      icon: Brain
    };
  }
  if (id.startsWith('ML')) {
    return {
      bg: 'bg-emerald-500/10',
      text: 'text-emerald-400',
      border: 'border-emerald-500/20',
      hoverBg: 'hover:bg-emerald-500/20',
      hoverBorder: 'hover:border-emerald-500/40',
      icon: Cpu
    };
  }
  // Agentic (T1, T2...)
  return {
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'border-orange-500/20',
    hoverBg: 'hover:bg-orange-500/20',
    hoverBorder: 'hover:border-orange-500/40',
    icon: Bot
  };
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

const getRiskWeight = (level: string) => {
  switch (level) {
    case 'Critical': return 4;
    case 'High': return 3;
    case 'Medium': return 2;
    case 'Low': return 1;
    default: return 0;
  }
};


const ThreatModelling: React.FC<ThreatModellingProps> = ({ onNavigateToTest, onNavigateToOwasp }) => {
  const [activeTab, setActiveTab] = useState<'architecture' | 'impact' | 'mapping'>('architecture');
  const [selectedComponentId, setSelectedComponentId] = useState<string | null>(null);
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [sortMethod, setSortMethod] = useState<'default' | 'severity'>('default');

  const selectedComponent = SAIF_COMPONENTS.find(c => c.id === selectedComponentId);
  const threatsForComponent = selectedComponentId 
    ? THREAT_LIBRARY.filter(t => t.affectedComponents.includes(selectedComponentId))
    : [];

  const sortedThreats = useMemo(() => {
    if (sortMethod === 'severity') {
      return [...THREAT_LIBRARY].sort((a, b) => getRiskWeight(b.riskLevel) - getRiskWeight(a.riskLevel));
    }
    return THREAT_LIBRARY;
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

  const getLayerTitleColor = (layer: string) => {
    switch (layer) {
      case 'Application': return '#60a5fa'; // blue-400
      case 'Model': return '#c084fc'; // purple-400
      case 'Infrastructure': return '#fbbf24'; // amber-400
      case 'Data': return '#34d399'; // emerald-400
      default: return '#94a3b8';
    }
  }

  return (
    <div className="p-4 md:p-8 max-w-7xl mx-auto animate-in fade-in duration-500">
      
      {/* Header */}
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">AI Threat Modelling</h2>
        <p className="text-slate-400 max-w-3xl">
          Based on the <strong>Secure AI Framework (SAIF)</strong> and <strong>OWASP AI Testing Guide</strong>. 
          Use this interactive tool to decompose your AI system, identify threats at each architectural layer, 
          and map them to specific business risks and test cases.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800 mb-6 overflow-x-auto">
        <button 
          onClick={() => setActiveTab('architecture')}
          className={`px-4 py-2 border-b-2 transition-colors whitespace-nowrap ${activeTab === 'architecture' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
        >
          <LayoutTemplate className="w-4 h-4 inline mr-2" />
          Architecture & Threats
        </button>
        <button 
          onClick={() => setActiveTab('impact')}
          className={`px-4 py-2 border-b-2 transition-colors whitespace-nowrap ${activeTab === 'impact' ? 'border-red-500 text-red-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
        >
          <AlertTriangle className="w-4 h-4 inline mr-2" />
          Business Impact Analysis
        </button>
        <button 
          onClick={() => setActiveTab('mapping')}
          className={`px-4 py-2 border-b-2 transition-colors whitespace-nowrap ${activeTab === 'mapping' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
        >
          <GitBranch className="w-4 h-4 inline mr-2" />
          Threat Mapping Matrix
        </button>
      </div>

      {/* Architecture View */}
      {activeTab === 'architecture' && (
        <div className="flex flex-col lg:flex-row gap-6 h-[900px]">
          
          {/* Interactive Diagram Area - FLAT DESIGN */}
          <div className="flex-1 bg-slate-950 border border-slate-800 rounded-xl relative overflow-hidden flex flex-col">
            <div className="absolute top-4 left-4 z-10 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded text-xs text-slate-400 pointer-events-none">
              Select components to view threats
            </div>
            
            <div className="flex-1 overflow-auto relative cursor-move p-2 flex items-center justify-center bg-slate-950">
               <svg width="850" height="880" viewBox="0 0 850 880" className="w-full h-full">
                  {/* Connection Lines (Orthogonal / Direct) */}
                  <defs>
                    <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                      <path d="M0,0 L0,6 L8,3 z" fill="#475569" />
                    </marker>
                    <marker id="arrowhead-up" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto-start-reverse">
                       <path d="M0,0 L0,6 L8,3 z" fill="#475569" />
                    </marker>
                  </defs>
                  
                  {/* --- Logical Flow Lines --- */}
                  <g stroke="#475569" strokeWidth="2" fill="none">
                    
                    {/* User <-> Application (Two arrows: Down/Up) */}
                    <path d="M415 50 L415 70" markerEnd="url(#arrowhead)" />
                    <path d="M435 70 L435 50" markerEnd="url(#arrowhead)" />

                    {/* Application <-> Agent/Plugin (Two arrows: Down/Up) */}
                    <path d="M385 120 L385 140" markerEnd="url(#arrowhead)" />
                    <path d="M465 140 L465 120" markerEnd="url(#arrowhead)" />

                    {/* Agent/Plugin <-> Ext Sources (Horizontal Dotted) */}
                    <path d="M505 160 L600 160" strokeDasharray="5,5" markerEnd="url(#arrowhead)" markerStart="url(#arrowhead-up)" />

                    {/* Application -> Input Handling (Down, left side) */}
                    <path d="M325 120 L325 220" markerEnd="url(#arrowhead)" />

                    {/* Output Handling -> Application (Up, right side) */}
                    <path d="M525 220 L525 120" markerEnd="url(#arrowhead)" />

                    {/* Input Handling -> Model (Down) */}
                    <path d="M325 260 L325 280" markerEnd="url(#arrowhead)" />

                    {/* Model -> Output Handling (Up) */}
                    <path d="M525 280 L525 260" markerEnd="url(#arrowhead)" />

                    {/* Model -> Evaluation (Path: Model Left -> Left -> Down -> Eval Left) */}
                    <path d="M275 305 L160 305 L160 430" markerEnd="url(#arrowhead)" />

                    {/* Evaluation -> Training (Right) */}
                    <path d="M220 450 L325 450" markerEnd="url(#arrowhead)" />

                    {/* Frameworks -> Training (Left) */}
                    <path d="M550 450 L525 450" markerEnd="url(#arrowhead)" />

                    {/* Training -> Model (Up through center) */}
                    <path d="M425 430 L425 330" markerEnd="url(#arrowhead)" />

                    {/* Data Storage Infra -> Training (Up) */}
                    <path d="M425 510 L425 480" markerEnd="url(#arrowhead)" />

                    {/* Training Data -> Data Storage Infra (Up) */}
                    <path d="M425 580 L425 550" markerEnd="url(#arrowhead)" />

                    {/* Data Filtering -> Training Data (Up) */}
                    <path d="M425 650 L425 620" markerEnd="url(#arrowhead)" />

                    {/* Data Sources -> Data Filtering (Up) */}
                    <path d="M425 720 L425 690" markerEnd="url(#arrowhead)" />

                    {/* Ext Sources (Data) <-> Data Sources (Up Dotted) */}
                    <path d="M425 800 L425 760" strokeDasharray="5,5" markerEnd="url(#arrowhead)" markerStart="url(#arrowhead-up)" />
                    
                    {/* Application -> Data Sources (Long Dotted Line on Left) */}
                    {/* Path: App Left -> Left -> Down -> Right -> Data Sources Left */}
                    <path d="M275 95 L225 95 L225 740 L225 740" strokeDasharray="5,5" markerEnd="url(#arrowhead)" />

                  </g>

                  {/* Layer Background Zones (Flat, subtle) */}
                  <rect x="20" y="5" width="810" height="190" rx="0" fill="transparent" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
                  <text x="30" y="25" fill="#60a5fa" fontSize="12" fontWeight="bold" letterSpacing="1">APPLICATION LAYER</text>

                  <rect x="20" y="210" width="810" height="130" rx="0" fill="transparent" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
                  <text x="30" y="230" fill="#c084fc" fontSize="12" fontWeight="bold" letterSpacing="1">MODEL LAYER</text>

                  <rect x="20" y="350" width="810" height="210" rx="0" fill="transparent" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
                  <text x="30" y="370" fill="#fbbf24" fontSize="12" fontWeight="bold" letterSpacing="1">INFRASTRUCTURE LAYER</text>

                  <rect x="20" y="570" width="810" height="280" rx="0" fill="transparent" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
                  <text x="30" y="590" fill="#34d399" fontSize="12" fontWeight="bold" letterSpacing="1">DATA LAYER</text>

                  {/* Components */}
                  {SAIF_COMPONENTS.map((comp) => {
                    const isSelected = selectedComponentId === comp.id;
                    const styleClass = getLayerColor(comp.layer);
                    const titleColor = getLayerTitleColor(comp.layer);
                    const isAffected = selectedThreatId ? THREAT_LIBRARY.find(t => t.id === selectedThreatId)?.affectedComponents.includes(comp.id) : false;

                    return (
                      <g 
                        key={comp.id} 
                        onClick={() => handleComponentClick(comp.id)}
                        className="cursor-pointer transition-all duration-200 group"
                        style={{ opacity: selectedThreatId && !isAffected ? 0.2 : 1 }}
                      >
                        {/* Box */}
                        <rect 
                          x={comp.x} 
                          y={comp.y} 
                          width={comp.width} 
                          height={comp.height} 
                          rx={comp.style === 'dotted' ? 0 : 6}
                          strokeDasharray={comp.style === 'dotted' ? "5,5" : "0"}
                          className={`
                            fill-slate-900 stroke-2 transition-all
                            ${isSelected ? 'stroke-white stroke-[3px]' : styleClass.split(' ')[0]}
                            ${isAffected ? 'stroke-red-500 stroke-[4px]' : ''}
                          `}
                        />
                        
                        {/* Header Background (Only for solid boxes) */}
                        {comp.style !== 'dotted' && (
                          <rect 
                            x={comp.x} 
                            y={comp.y} 
                            width={6} 
                            height={comp.height} 
                            rx="0"
                            fill={titleColor}
                            className="rounded-l-md"
                          />
                        )}

                        {/* Text Content */}
                        <text 
                          x={comp.x + (comp.style === 'dotted' ? comp.width/2 : 16)} 
                          y={comp.y + 24} 
                          fill="#ffffff"
                          fontWeight="700" 
                          fontSize="13"
                          textAnchor={comp.style === 'dotted' ? 'middle' : 'start'}
                          className="pointer-events-none"
                        >
                          {comp.name}
                        </text>
                        
                        {/* Only show ID for non-dotted components to reduce clutter */}
                        {comp.style !== 'dotted' && (
                          <text 
                            x={comp.x + 16} 
                            y={comp.y + 38} 
                            fill="#94a3b8" 
                            fontSize="10"
                            className="pointer-events-none font-mono"
                          >
                            #{comp.id}
                          </text>
                        )}
                      </g>
                    );
                  })}
               </svg>
            </div>
          </div>

          {/* Details Sidebar - Adapted Height */}
          <div className="w-full lg:w-96 bg-slate-950 border-l border-slate-800 flex flex-col shadow-2xl z-20 h-full">
            {!selectedComponent ? (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-slate-500">
                <Target className="w-16 h-16 mb-4 opacity-10" />
                <p className="text-sm font-medium">Select a component in the diagram to view its details, threats, and test cases.</p>
              </div>
            ) : (
              <div className="flex-1 overflow-y-auto p-6 animate-in slide-in-from-right duration-300">
                
                {/* Component Header */}
                <div className="mb-6 border-b border-slate-800 pb-4">
                  <div className="flex justify-between items-center mb-1">
                    <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full bg-slate-900 border ${
                      selectedComponent.layer === 'Application' ? 'text-blue-400 border-blue-900' :
                      selectedComponent.layer === 'Model' ? 'text-purple-400 border-purple-900' :
                      selectedComponent.layer === 'Infrastructure' ? 'text-amber-400 border-amber-900' : 'text-emerald-400 border-emerald-900'
                    }`}>
                      {selectedComponent.layer}
                    </span>
                    <span className="font-mono text-xs text-slate-600">ID: {selectedComponent.id}</span>
                  </div>
                  <h3 className="text-2xl font-bold text-white mb-2">{selectedComponent.name}</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">
                    {selectedComponent.description}
                  </p>
                </div>

                {/* Threats List */}
                <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Shield className="w-3.5 h-3.5" />
                  Associated Threats
                </h4>

                <div className="space-y-3">
                  {threatsForComponent.length === 0 ? (
                    <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-800 text-sm text-slate-500 text-center italic">
                      No high-priority threats directly mapped to this component in the base model.
                    </div>
                  ) : (
                    threatsForComponent.map(threat => {
                      const theme = getThreatTheme(threat.id);
                      return (
                        <div 
                          key={threat.id}
                          className="bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg p-4 transition-all group"
                        >
                          <div className="flex flex-wrap gap-2 items-center mb-2">
                            {/* Standardized Threat ID Badge */}
                            <button
                              onClick={() => onNavigateToOwasp(threat.id)}
                              className={`flex items-center gap-1.5 font-mono text-[10px] px-2 py-0.5 rounded border cursor-pointer hover:scale-105 transition-transform ${theme.bg} ${theme.text} ${theme.border} ${theme.hoverBg} ${theme.hoverBorder}`}
                              title="Go to Definition"
                            >
                              <theme.icon className="w-3 h-3" /> {threat.id}
                            </button>

                            {/* Severity Label (Separate) */}
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityTheme(threat.riskLevel)}`}>
                              {threat.riskLevel}
                            </span>
                          </div>
                          
                          <h5 className="font-bold text-slate-200 text-sm mb-1 group-hover:text-cyan-400 transition-colors">{threat.name}</h5>
                          <p className="text-xs text-slate-400 mb-3 leading-relaxed">{threat.description}</p>
                          
                          <div className="bg-slate-950 p-2.5 rounded border border-slate-800/50 mb-3">
                            <div className="flex items-center gap-1.5 text-[10px] text-slate-500 uppercase font-bold mb-1">
                              <FileText className="w-3 h-3" /> Scenario
                            </div>
                            <p className="text-xs text-slate-300 leading-relaxed italic border-l-2 border-slate-700 pl-2">
                              "{threat.scenario}"
                            </p>
                          </div>

                          {/* Related Tests List */}
                          {threat.relatedTestIds.length > 0 && (
                            <div className="flex flex-col gap-1.5">
                              {threat.relatedTestIds.map(testId => (
                                <button 
                                  key={testId}
                                  onClick={() => onNavigateToTest(testId)}
                                  className="flex items-center justify-between w-full px-2.5 py-1.5 bg-cyan-950/20 hover:bg-cyan-950/40 text-cyan-400 text-[10px] font-mono rounded border border-cyan-900/30 hover:border-cyan-500/40 transition-all group/btn"
                                  title="Go to Test Case"
                                >
                                  <span>{testId}</span>
                                  <ArrowRight className="w-3 h-3 opacity-50 group-hover/btn:opacity-100 group-hover/btn:translate-x-0.5 transition-all" />
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Impact Analysis Tab */}
      {activeTab === 'impact' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden animate-in fade-in duration-300">
          <div className="p-6 border-b border-slate-800 bg-slate-950 flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
            <div>
              <h3 className="text-xl font-bold text-white mb-2">Business Impact Analysis (BIA)</h3>
              <p className="text-sm text-slate-400">
                Aligning technical vulnerabilities with business consequences. Based on Table 1.1 of the guide.
              </p>
            </div>
            {/* Sort Controls */}
            <div className="flex items-center gap-2 shrink-0">
               <span className="text-xs font-bold text-slate-500 uppercase tracking-wider hidden sm:block">
                <ListFilter className="w-3 h-3 inline mr-1" />
                Sort:
              </span>
              <div className="flex bg-slate-900 rounded-lg p-1 border border-slate-800">
                <button 
                  onClick={() => setSortMethod('default')}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${sortMethod === 'default' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  Type
                </button>
                <button 
                  onClick={() => setSortMethod('severity')}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${sortMethod === 'severity' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  Risk
                </button>
              </div>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-950 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800">
                  <th className="p-4 font-medium">Risk ID</th>
                  <th className="p-4 font-medium">Threat Description</th>
                  <th className="p-4 font-medium">Business Impact</th>
                  <th className="p-4 font-medium">Risk Level</th>
                  <th className="p-4 font-medium">Risk Owner</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-sm">
                {sortedThreats.map((threat) => {
                  const theme = getThreatTheme(threat.id);
                  return (
                    <tr key={threat.id} className="hover:bg-slate-800/50 transition-colors group cursor-pointer" onClick={() => onNavigateToOwasp(threat.id)}>
                      <td className="p-4">
                        {/* Unified Threat Badge Style */}
                        <span className={`inline-flex items-center gap-1.5 font-mono text-xs px-2 py-1 rounded border ${theme.bg} ${theme.text} ${theme.border}`}>
                           <theme.icon className="w-3 h-3" /> {threat.id}
                        </span>
                      </td>
                      <td className="p-4 text-slate-300">
                        <div className="font-bold mb-1">{threat.name}</div>
                        <div className="text-xs text-slate-500">{threat.description}</div>
                      </td>
                      <td className="p-4 text-slate-400">{threat.impact}</td>
                      <td className="p-4">
                        <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-bold border ${getSeverityTheme(threat.riskLevel)}`}>
                          {threat.riskLevel}
                        </span>
                      </td>
                      <td className="p-4 text-slate-400">{threat.riskOwner}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Threat Mapping Tab - Redesigned Matrix */}
      {activeTab === 'mapping' && (
        <div className="animate-in fade-in duration-300">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
              <div>
                <h3 className="text-xl font-bold text-white mb-2">Threat-to-Test Matrix</h3>
                <p className="text-slate-400">
                  Direct correlation between high-level SAIF threats and actionable test cases.
                </p>
              </div>
              {/* Sort Controls */}
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider hidden sm:block">
                  <ListFilter className="w-3 h-3 inline mr-1" />
                  Sort:
                </span>
                <div className="flex bg-slate-900 rounded-lg p-1 border border-slate-800">
                  <button 
                    onClick={() => setSortMethod('default')}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${sortMethod === 'default' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                  >
                    Type
                  </button>
                  <button 
                    onClick={() => setSortMethod('severity')}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${sortMethod === 'severity' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                  >
                    Risk
                  </button>
                </div>
              </div>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
              {sortedThreats.filter(t => t.relatedTestIds.length > 0).map(threat => {
                const theme = getThreatTheme(threat.id);
                return (
                  <div key={threat.id} className="bg-slate-950 rounded-xl border border-slate-800 flex flex-col hover:border-slate-600 transition-all duration-300 group overflow-hidden shadow-sm hover:shadow-md">
                    
                    {/* Card Header */}
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
                      <h4 className="font-bold text-slate-200 text-lg leading-tight group-hover:text-cyan-400 transition-colors cursor-pointer" onClick={() => onNavigateToOwasp(threat.id)}>
                        {threat.name}
                      </h4>
                    </div>

                    {/* Card Body */}
                    <div className="p-5 flex-1 flex flex-col gap-4">
                      <div className="text-xs text-slate-400">
                        <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Impact</span>
                        {threat.impact}
                      </div>
                      
                      <div className="mt-auto">
                        <div className="flex items-center gap-2 mb-2">
                           <CheckCircle2 className="w-3.5 h-3.5 text-cyan-500" />
                           <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Verified by Tests</span>
                        </div>
                        <div className="grid grid-cols-1 gap-2">
                          {threat.relatedTestIds.map(testId => (
                            <button 
                              key={testId}
                              onClick={() => onNavigateToTest(testId)}
                              className="flex items-center justify-between px-3 py-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-cyan-400 text-xs rounded border border-slate-800 hover:border-cyan-500/30 transition-all group/item"
                            >
                              <span className="font-mono">{testId}</span>
                              <ExternalLink className="w-3 h-3 opacity-30 group-hover/item:opacity-100" />
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Card Footer */}
                    <div className="px-5 py-3 bg-slate-900/50 border-t border-slate-800/50 flex justify-between items-center text-[10px] text-slate-500 font-mono">
                      <span>Components: {threat.affectedComponents.map(c => `#${c}`).join(', ')}</span>
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
