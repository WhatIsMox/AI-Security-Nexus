/**
 * OWASP GenAI Security Project — Securing Agentic Applications V2
 * "A Builder & Defender's Guide" (Version 2.0, October 2026)
 *
 * Structured, lightly edited adaptation of the full guide (chapters 1–9 and
 * acknowledgements) for the interactive Securing Agentic Applications workspace.
 * Wording has been tightened for readability; obvious cross-reference slips in the
 * source are corrected and listed in SAA_EDITORIAL_NOTES.
 *
 * Source: https://genai.owasp.org/resource/securing-agentic-applications-v2/
 * License: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export type SaaTrustLevel = 'System' | 'Vetted' | 'User' | 'Untrusted';

export type SaaWidgetId =
  | 'kc-explorer'
  | 'memory-matrix'
  | 'threat-heatmap'
  | 'architecture-patterns'
  | 'control-plane'
  | 'effective-scope'
  | 'rule-of-two'
  | 'validation-gates'
  | 'guardrail-placement'
  | 'hooks'
  | 'circuit-breaker'
  | 'capability-matrix'
  | 'obo-chain'
  | 'tool-lifecycle'
  | 'assurance-chain';

export interface SaaListItem {
  label?: string;
  text: string;
  children?: SaaListItem[];
}

export type SaaBlock =
  | { type: 'p'; text: string }
  | { type: 'list'; items: SaaListItem[]; ordered?: boolean }
  | { type: 'callout'; tone: 'info' | 'warning' | 'key'; title?: string; text: string }
  | { type: 'table'; headers: string[]; rows: string[][]; caption?: string }
  | { type: 'formula'; text: string; caption?: string }
  | { type: 'links'; items: { label: string; url: string }[] }
  | { type: 'widget'; widget: SaaWidgetId };

export interface SaaSection {
  id: string;
  number: string;
  title: string;
  group?: string;
  summary: string;
  blocks: SaaBlock[];
  threats?: string[];
}

export interface SaaChapter {
  id: string;
  number: string;
  title: string;
  shortTitle: string;
  tagline: string;
  sections: SaaSection[];
}

export interface SaaThreat {
  id: string;
  name: string;
  summary: string;
  relatedAsi?: string;
}

export interface SaaSubcomponent {
  id: string;
  name: string;
  description: string;
  children?: SaaSubcomponent[];
}

export interface SaaKeyComponent {
  id: string;
  name: string;
  shortName: string;
  definition: string;
  subcomponents: SaaSubcomponent[];
  threats: { id: string; text: string }[];
  riskSummary: string;
  breaker: { detect: string; actions: string };
}

export interface SaaMemoryScope {
  id: string;
  name: string;
  sharing: 'In agent' | 'Cross-agent';
  persistence: 'Session' | 'Cross-session' | 'Cross-user';
  compromise: string;
  blastRadius: 1 | 2 | 3 | 4 | 5 | 6;
}

export interface SaaArchitecturePattern {
  id: string;
  name: string;
  summary: string;
  trustModel?: string;
  profile: { brain: string; control: string; reasoning: string; memory: string; tools: string; environment: string };
  comprehensive: { brain: string; control: string; reasoning: string; memory: string; tools: string; environment: string };
  frameworks: string[];
}

export interface SaaHook {
  id: string;
  scope: 'Session' | 'Turn' | 'Inner';
  controls: string;
  dispositions: string[];
  priority?: 'first' | 'next';
}

export interface SaaCapability {
  id: string;
  sectionId: string;
  name: string;
  kc: string;
  capabilityClass: string;
  sensitiveData: string;
  untrustedInput: string;
  externalComms: string;
  requiredControls: string;
  escalationTrigger: string;
  legs: { sensitive: boolean; untrusted: boolean; external: boolean };
}

export interface SaaAssuranceStep {
  id: string;
  label: string;
  detail: string;
}

export interface SaaMeta {
  title: string;
  subtitle: string;
  project: string;
  initiative: string;
  version: string;
  publicationDate: string;
  sourceUrl: string;
  threatsAndMitigationsUrl: string;
  license: { name: string; url: string; summary: string };
  disclaimer: string;
}

// ─── Small content builders (keep the catalog readable) ──────────────────────

const p = (text: string): SaaBlock => ({ type: 'p', text });
const li = (labelOrText: string, text?: string, children?: SaaListItem[]): SaaListItem =>
  text === undefined ? { text: labelOrText, children } : { label: labelOrText, text, children };
const ul = (...items: SaaListItem[]): SaaBlock => ({ type: 'list', items });
const ol = (...items: SaaListItem[]): SaaBlock => ({ type: 'list', items, ordered: true });
const callout = (tone: 'info' | 'warning' | 'key', text: string, title?: string): SaaBlock => ({ type: 'callout', tone, text, title });
const table = (headers: string[], rows: string[][], caption?: string): SaaBlock => ({ type: 'table', headers, rows, caption });
const widget = (w: SaaWidgetId): SaaBlock => ({ type: 'widget', widget: w });

// ─── Metadata ─────────────────────────────────────────────────────────────────

export const SECURING_AGENTIC_APPS_META: SaaMeta = {
  title: 'Securing Agentic Applications V2',
  subtitle: "A Builder & Defender's Guide",
  project: 'OWASP GenAI Security Project',
  initiative: 'Agentic Security Initiative (ASI)',
  version: '2.0',
  publicationDate: 'October 2026',
  sourceUrl: 'https://genai.owasp.org/resource/securing-agentic-applications-v2/',
  threatsAndMitigationsUrl: 'https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/',
  license: {
    name: 'Creative Commons CC BY-SA 4.0',
    url: 'https://creativecommons.org/licenses/by-sa/4.0/legalcode',
    summary:
      'You may share and adapt the material for any purpose, even commercially, provided you give appropriate credit, link to the license, indicate if changes were made, and distribute derivatives under the same license. No additional legal or technological restrictions may be applied.',
  },
  disclaimer:
    'The guide does not constitute legal advice; all information is for general informational purposes only. Links to third-party sites are provided for convenience and are not endorsements by OWASP.',
};

// ─── ASI Threats & Mitigations T-codes referenced throughout the guide ───────
// relatedAsi is an editorial cross-link into the OWASP Top 10 for Agentic
// Applications (2026) navigator in this app; it is not part of the source guide.

export const SAA_THREATS: SaaThreat[] = [
  { id: 'T1', name: 'Memory Poisoning', summary: 'Malicious or false data is planted in short- or long-term memory so it shapes later reasoning.', relatedAsi: 'ASI06' },
  { id: 'T2', name: 'Tool Misuse', summary: 'Legitimate tools are steered into harmful actions; unverified, untrusted, or compromised tools are invoked.', relatedAsi: 'ASI02' },
  { id: 'T3', name: 'Privilege Compromise', summary: 'Excessive or inherited privileges, context collapse, or credential abuse let an agent reach data and actions it should not.', relatedAsi: 'ASI03' },
  { id: 'T4', name: 'Resource Overload', summary: 'Compute, API, or external services are exhausted, causing denial of service or cost overruns.' },
  { id: 'T5', name: 'Cascading Hallucination', summary: 'Incorrect output propagates through planning steps, memory, and other agents, amplifying the error.', relatedAsi: 'ASI08' },
  { id: 'T6', name: 'Intent Breaking & Goal Manipulation', summary: "The agent's goals, plans, or decision process are redirected toward an attacker's objective.", relatedAsi: 'ASI01' },
  { id: 'T7', name: 'Misaligned & Deceptive Behaviors', summary: 'Model alignment failures lead to unintended or deceptive behavior affecting users, organizations, or society.', relatedAsi: 'ASI10' },
  { id: 'T8', name: 'Repudiation & Untraceability', summary: 'Agent actions and decision trails cannot be reliably reconstructed or attributed.' },
  { id: 'T9', name: 'Identity Spoofing & Impersonation', summary: 'An attacker impersonates a user or agent, or manipulates identity parameters, to act with someone else’s authority.', relatedAsi: 'ASI03' },
  { id: 'T10', name: 'Overwhelming Human-in-the-Loop', summary: 'Human reviewers are flooded with approvals until oversight degrades into rubber-stamping.', relatedAsi: 'ASI09' },
  { id: 'T11', name: 'Unexpected RCE & Code Attacks', summary: 'Tools or generated code lead to unintended code execution in the agent environment.', relatedAsi: 'ASI05' },
  { id: 'T12', name: 'Agent Communication Poisoning', summary: 'Inter-agent messages, shared memory, or side channels are corrupted to mislead or persist.', relatedAsi: 'ASI07' },
  { id: 'T13', name: 'Rogue Agents', summary: 'A compromised or misbehaving agent operates outside monitoring limits within a multi-agent system.', relatedAsi: 'ASI10' },
  { id: 'T14', name: 'Human Attacks on Multi-Agent Systems', summary: 'Attackers exploit trust relationships between agents and workflows.' },
  { id: 'T15', name: 'Human Manipulation', summary: 'The agent exploits human trust to manipulate users into harmful decisions.', relatedAsi: 'ASI09' },
];

// ─── Key Components KC1–KC6 (Section 2.1, 2.2, 3.3.8) ────────────────────────

export const SAA_KEY_COMPONENTS: SaaKeyComponent[] = [
  {
    id: 'KC1',
    name: 'Generative Language Models',
    shortName: 'LLM',
    definition:
      'A probabilistic model component that interprets inputs and proposes content, plans, or actions. Its output is untrusted input to deterministic orchestration, policy enforcement, and sink-side authorization. For hosted models, treat the provider as an external trust boundary and document prompt/response retention and secondary use, tenant isolation, processing and storage regions, subprocessors, where tools execute, model/version change notice, and drift monitoring.',
    subcomponents: [
      { id: 'KC1.1', name: 'Large Language Models (LLMs)', description: 'Pre-trained foundation models (e.g., GPT, Claude, Llama, or Gemini families) that propose reasoning artifacts, plans, and content under context-window, latency, and cost constraints. Outputs require deterministic validation and authorization before consequential use.' },
      { id: 'KC1.2', name: 'Multimodal LLMs (MLLMs)', description: 'Models that process and/or generate data beyond text (images, audio), letting agents handle visual or auditory tasks (e.g., GPT-4V, Gemini).' },
      { id: 'KC1.3', name: 'Small Language Models (SLMs)', description: 'Models with fewer parameters trained on smaller, focused datasets for a specific task or use case, with a smaller weight space, parameter count, and context window than an LLM.' },
      { id: 'KC1.4', name: 'Fine-tuned Models', description: 'LLMs/MLLMs further trained on specific datasets to specialize capabilities, adopt personas, or improve reliability. Supervised Fine-Tuning (SFT) and Circuit Breakers (CB) show promising scoping benefits, reducing the propensity to answer out-of-scope topics.' },
    ],
    threats: [
      { id: 'T5', text: 'Foundation models generate incorrect information that propagates.' },
      { id: 'T6', text: 'Attacks target the core decision-making capabilities.' },
      { id: 'T7', text: 'Alignment issues lead to unintended behaviors impacting users, organizations, or the broader population.' },
      { id: 'T15', text: 'Models exploit human trust to manipulate users.' },
    ],
    riskSummary: 'Core vulnerabilities in the "brain" of the agent: hallucinations, goal misalignment, deceptive reasoning, and manipulating humans.',
    breaker: {
      detect: 'Runtime output-guardrail violations (see 3.3.1); latent-space / hidden-activation monitoring; alignment of later messages to the initial task goal.',
      actions: 'Disable inference; quarantine the session (auto-quarantine).',
    },
  },
  {
    id: 'KC2',
    name: 'Orchestration (Control Flow)',
    shortName: 'Orchestration',
    definition:
      "Mechanisms that dictate the agent's overall behavior, information flow, and decision-making. The mechanism — sequential for layered architectures, dynamic for blackboard architectures, or coordinated for multi-agent systems — depends on the architecture and shapes responsiveness and efficiency.",
    subcomponents: [
      { id: 'KC2.1', name: 'Workflows', description: 'A structured, pre-defined sequence of tasks that agents follow to reach a goal. Workflows define the flow of information and actions within and among agents and can be linear, conditional, or iterative.' },
      {
        id: 'KC2.2',
        name: 'Hierarchical Planning',
        description: 'Multiple agents collaborate through a central orchestrator (router) that:',
        children: [
          { id: 'KC2.2-a', name: 'Understands the task', description: 'Receives the initial complex task or request.' },
          { id: 'KC2.2-b', name: 'Decomposes the task', description: 'Breaks it into a series of sub-tasks.' },
          { id: 'KC2.2-c', name: 'Routes to specialized agents', description: 'Assigns each sub-task to the best-suited specialized agent.' },
          { id: 'KC2.2-d', name: 'Optimizes', description: 'Monitors agent performance, identifies inefficiencies, and autonomously adjusts workflows.' },
          { id: 'KC2.2-e', name: 'Interfaces', description: 'Talks to the user directly or to a "master" agent that coordinates the others.' },
        ],
      },
      { id: 'KC2.3', name: 'Multi-agent Collaboration', description: 'Multiple agents communicate and coordinate toward a common goal, sharing information and resources — e.g., one agent collects data, another analyzes it, a third decides.' },
    ],
    threats: [
      { id: 'T6', text: 'Manipulates control flow to achieve unauthorized goals.' },
      { id: 'T8', text: 'Makes agent actions difficult to trace through the workflow.' },
      { id: 'T9', text: 'Especially problematic in multi-agent systems (KC2.2, KC2.3).' },
      { id: 'T10', text: 'Overwhelms human oversight in workflows.' },
      { id: 'T12', text: 'Corrupts inter-agent messaging in multi-agent systems.' },
      { id: 'T13', text: 'Compromises agent orchestration in multi-agent systems.' },
      { id: 'T14', text: 'Exploits trust relationships between agents and workflows.' },
    ],
    riskSummary: 'Vulnerabilities in workflow control: goal manipulation, lack of auditability, identity confusion, overwhelming human oversight, and multi-agent attacks.',
    breaker: {
      detect: 'Sensitive core-agent logs; sub-agents spawned in an unexpected manner.',
      actions: 'Stop or disallow sub-agents; halt the orchestrator (loop detector).',
    },
  },
  {
    id: 'KC3',
    name: 'Reasoning / Planning Paradigm',
    shortName: 'Reasoning',
    definition:
      'Agents use LLMs to solve multi-step problems strategically, breaking high-level tasks into smaller steps, each with its own sub-goal.',
    subcomponents: [
      { id: 'KC3.1', name: 'Structured Planning / Execution', description: 'e.g., ReWOO, LLM Compiler, Plan-and-Execute: decompose tasks into a formal plan, define sequences of actions (often specific tool calls), and execute — sometimes with separate "planner" and "executor" components.' },
      { id: 'KC3.2', name: 'ReAct (Reason + Act)', description: 'Dynamically interleaves reasoning steps with actions (tool use, API queries) and updates reasoning based on feedback.' },
      { id: 'KC3.3', name: 'Chain of Thought (CoT)', description: 'Prompts step-by-step "thinking" so the LLM produces a set of thoughts before a final action or conclusion.' },
      { id: 'KC3.4', name: 'Tree of Thoughts (ToT)', description: 'Generalizes CoT by exploring multiple reasoning paths and plans in parallel, with lookahead, backtracking, and self-evaluation.' },
    ],
    threats: [
      { id: 'T5', text: 'Affects reasoning quality and propagates through planning steps.' },
      { id: 'T6', text: 'Directly attacks the reasoning process to manipulate goals.' },
      { id: 'T7', text: 'Creates subtle reasoning misalignments.' },
      { id: 'T8', text: 'Obscures decision trails in reasoning chains.' },
      { id: 'T15', text: 'Leverages reasoning to craft manipulative responses.' },
    ],
    riskSummary: 'Weaknesses in decision processes: cascading hallucinations, intent manipulation, deceptive reasoning, untraceable decisions, and human manipulation.',
    breaker: {
      detect: 'Chain-of-thought keywords or concepts; plan deviation from the declared intent. (Often monitored at the orchestration layer, where the plan is assembled and executed.)',
      actions: 'Restart the plan; fall back to a safe, read-only mode (scope limiter).',
    },
  },
  {
    id: 'KC4',
    name: 'Memory Modules',
    shortName: 'Memory',
    definition:
      'Let the agent retain short-term (immediate context) and long-term information (past interactions, knowledge) for coherent, personalized interactions. Context "sensitivity" — classification or compartmentalization — reduces the risk of unauthorized exposure. RAG over a vector database is the common long-term memory pattern, retrieving external knowledge through semantic search.',
    subcomponents: [
      { id: 'KC4.1', name: 'In-agent session memory', description: 'Limited to one agent and one session, which limits the ability to compromise other agents or sessions.' },
      { id: 'KC4.2', name: 'Cross-agent session memory', description: 'Shared by multiple agents within one session: other sessions are protected, but one compromised agent can compromise every agent in that session.' },
      { id: 'KC4.3', name: 'In-agent cross-session memory', description: 'One agent, shared across sessions: other agents are protected, but one compromised session can compromise many sessions.' },
      { id: 'KC4.4', name: 'Cross-agent cross-session memory', description: 'Shared across agents and sessions: a compromise in one session may spread to other sessions and/or agents.' },
      { id: 'KC4.5', name: 'In-agent cross-user memory', description: 'One agent, shared across users: a compromised agent may be able to compromise multiple users.' },
      { id: 'KC4.6', name: 'Cross-agent cross-user memory', description: 'Shared across agents and users: a compromised agent may compromise additional agents and users.' },
    ],
    threats: [
      { id: 'T1', text: 'Directly targets all memory types (KC4.1–KC4.6).' },
      { id: 'T3', text: 'Breaks system boundaries through context collapse, causing unauthorized data access or leakage (e.g., across tools).' },
      { id: 'T5', text: 'Stores and amplifies hallucinations across sessions or agents.' },
      { id: 'T6', text: 'Abuses shared context — breaking integrity, leaking or contaminating data, or interfering with records/assets (e.g., within a tool) that should be isolated.' },
      { id: 'T8', text: 'Manipulates or erases evidence from memory.' },
      { id: 'T12', text: 'Affects shared memory in multi-agent systems.' },
    ],
    riskSummary: 'Data integrity issues: memory poisoning, leaking, propagating hallucinations, evidence tampering, and communication poisoning.',
    breaker: {
      detect: 'Any non-authoritative memory read (a taint for task reliability); bloat or unusual memory reads/writes; out-of-context queries (see 9.3).',
      actions: 'Disable memory read/write; restrict read/write to non-sensitive data (circuit breaker).',
    },
  },
  {
    id: 'KC5',
    name: 'Tool Integration Frameworks',
    shortName: 'Tools',
    definition:
      'Extend agents beyond text with external tools (APIs, functions, data stores) that interact with the real world or other systems. The framework manages tool selection and use and offers agent types such as ReAct, Self-Ask, and OpenAI Functions Agent. MCP is treated as a tool-integration profile of KC5; its hardening controls live in Section 6.4.',
    subcomponents: [
      { id: 'KC5.1', name: 'Flexible Libraries / SDK Features', description: 'Code-level building blocks (e.g., LangChain, AG2, Agents, CrewAI, MCP) or API capabilities such as OpenAI Tool Use. High flexibility and control, but more coding effort and expertise to run the full agent loop.' },
      { id: 'KC5.2', name: 'Managed Platforms / Services', description: 'Vendor solutions (e.g., Amazon Bedrock Agents, Microsoft Copilot Platform) that handle infrastructure and much of the orchestration, often low-code, trading flexibility for speed.' },
      { id: 'KC5.3', name: 'Managed APIs', description: "Vendor-hosted services centred on an API (e.g., OpenAI's Assistants API) that manage state and parts of tool orchestration, making stateful agents easier to build than with basic SDK features." },
    ],
    threats: [
      { id: 'T2', text: 'Core vulnerability for all tool integration types (MCP included): unverified, untrusted, or compromised tools.' },
      { id: 'T3', text: 'Tools often run with privileges that can be exploited — excessive agency.' },
      { id: 'T6', text: 'Interferes with data records/assets (e.g., within a tool) that should be isolated from one another.' },
      { id: 'T7', text: 'Creates subtle reasoning misalignments.' },
      { id: 'T8', text: 'Tool use may lack proper logging and auditability.' },
      { id: 'T11', text: 'Tools might enable unexpected code execution.' },
    ],
    riskSummary: 'Tool exploitation vulnerabilities: tool misuse, privilege escalation, unlogged actions, and unexpected code execution.',
    breaker: {
      detect: 'Changes in tool descriptions or schemas; unusual tool-invocation patterns (unexpected fragmentation, combination, or ordering of tools; combinations of domains and data classifications, e.g., in email-tool parameters); cross-agent communication deviations.',
      actions: 'Revoke or suspend tool-call scope, permissions, rate, or allowed tools — especially web access, computer access, and code execution (rate & budget limiter).',
    },
  },
  {
    id: 'KC6',
    name: 'Operational Environment (Agencies)',
    shortName: 'Environment',
    definition:
      'LLMs only know their training data, but agents reach external environments through tools and function calls. Each "agency" lets the agent interact with, gather, and process information from an external environment — and each widens what a compromised agent can do.',
    subcomponents: [
      {
        id: 'KC6.1',
        name: 'API Access',
        description: 'The agent calls APIs on the user’s behalf.',
        children: [
          { id: 'KC6.1.1', name: 'Limited API Access', description: 'The LLM generates some parameters of a predefined REST/GraphQL call. A compromised agent can attack the API through those parameters (see OWASP API Security Top 10), e.g., parameter pollution.' },
          { id: 'KC6.1.2', name: 'Extensive API Access', description: 'The LLM generates the entire call (e.g., traverses a GraphQL API or builds the whole REST URL). A compromised agent can issue unwanted calls with the agent’s excessive authorization and attack the API.' },
        ],
      },
      {
        id: 'KC6.2',
        name: 'Code Execution',
        description: 'The agent runs code.',
        children: [
          { id: 'KC6.2.1', name: 'Limited Code Execution', description: 'The LLM generates parameters for a predefined Python/PHP/JS function. A compromised agent can launch code injection through those parameters.' },
          { id: 'KC6.2.2', name: 'Extensive Code Execution', description: 'The agent runs LLM-generated code. A compromised agent can run arbitrary code.' },
        ],
      },
      {
        id: 'KC6.3',
        name: 'Database Execution',
        description: 'The agent queries or updates data stores.',
        children: [
          { id: 'KC6.3.1', name: 'Limited Database Execution', description: 'Specific queries with a limited permission set (e.g., read-only at table/row level, or writes restricted to certain parameters via parameterized or pre-built queries). A compromised agent could exfiltrate a table or write malformed data to a limited space.' },
          { id: 'KC6.3.2', name: 'Extensive Database Execution', description: 'The LLM generates and runs all CRUD operations on a set of tables or the whole database. A compromised agent could alter any record, delete tables or the database, or leak anything stored.' },
          { id: 'KC6.3.3', name: 'Agent Memory or Context Data Sources (e.g., RAG)', description: 'External data sources supply context or are updated from user input. A compromised agent might disrupt the data or serve malformed retrieved information.' },
        ],
      },
      { id: 'KC6.4', name: 'Web Access (web-use)', description: 'The LLM operates a browser (e.g., OpenAI Operator, browser-use). Compromise usually comes from untrusted web content; the agent may then act with its excessive authorization, e.g., changing sharing or account settings on open sessions.' },
      { id: 'KC6.5', name: 'Controlling PC Operations (PC-use)', description: 'The LLM operates the OS and file system (e.g., Anthropic computer use). A compromised agent may perform unwanted operations, leak personal information, or act maliciously, such as encrypting files.' },
      { id: 'KC6.6', name: 'Operating Critical Systems (e.g., SCADA)', description: 'The LLM operates critical systems. Unauthorized operations can cause catastrophic failure.' },
      { id: 'KC6.7', name: 'Access to IoT Devices', description: 'Unauthorized control of IoT devices can affect the physical environment, e.g., drastically changing room temperature through a connected thermostat.' },
    ],
    threats: [
      { id: 'T2', text: 'All operational environments can be misused, introducing more untrusted content and opportunity for failure, e.g., unauthorized settings changes.' },
      { id: 'T3', text: 'Highest risk in environments with extensive access (KC6.1.2, KC6.2.2, KC6.3.2).' },
      { id: 'T4', text: 'External services can be overwhelmed.' },
      { id: 'T10', text: 'Creates excessive activity requiring human approval.' },
      { id: 'T11', text: 'Direct risk to code-execution environments (KC6.2).' },
      { id: 'T12', text: 'External systems used for side-channel communication and memory persistence.' },
      { id: 'T13', text: 'Compromised agent activity outside monitoring limits.' },
      { id: 'T15', text: 'Leverages operational access to manipulate humans.' },
    ],
    riskSummary: 'Monitoring gaps and external-system risks: misused access, privilege compromise, resource exhaustion, overwhelmed reviewers, code-execution attacks, side-channel storage/communication, and manipulation via the environment.',
    breaker: {
      detect: 'System-level logs; system-level file operations or privilege escalations (see 5.2–5.6).',
      actions: 'Disable the agent identity; treat outputs as compromised across storage, memory, and tools (auto-quarantine).',
    },
  },
];

// ─── Memory scope matrix (Figure 2.2) ────────────────────────────────────────

export const SAA_MEMORY_SCOPES: SaaMemoryScope[] = [
  { id: 'KC4.1', name: 'In-agent session memory', sharing: 'In agent', persistence: 'Session', compromise: 'Limits the ability to compromise additional agents or sessions.', blastRadius: 1 },
  { id: 'KC4.3', name: 'In-agent cross-session memory', sharing: 'In agent', persistence: 'Cross-session', compromise: 'Protects other agents, but one compromised session may compromise multiple sessions.', blastRadius: 3 },
  { id: 'KC4.5', name: 'In-agent cross-user memory', sharing: 'In agent', persistence: 'Cross-user', compromise: 'A compromised agent may compromise multiple users.', blastRadius: 5 },
  { id: 'KC4.2', name: 'Cross-agent session memory', sharing: 'Cross-agent', persistence: 'Session', compromise: 'Protects other sessions, but one compromised agent may compromise every agent in the session.', blastRadius: 2 },
  { id: 'KC4.4', name: 'Cross-agent cross-session memory', sharing: 'Cross-agent', persistence: 'Cross-session', compromise: 'A compromise in one session may spread to other sessions and/or agents.', blastRadius: 4 },
  { id: 'KC4.6', name: 'Cross-agent cross-user memory', sharing: 'Cross-agent', persistence: 'Cross-user', compromise: 'A compromised agent may compromise additional agents and users.', blastRadius: 6 },
];

// ─── Architecture patterns (2.3.2–2.3.4, 2.5) ────────────────────────────────

export const SAA_ARCHITECTURE_PATTERNS: SaaArchitecturePattern[] = [
  {
    id: 'sequential',
    name: 'Sequential Agent Architecture',
    summary: 'A linear workflow in which a single agent processes input through planning, execution, and basic tool use, with a clear chain of thought and limited memory.',
    trustModel: 'Simple trust boundary — focused on single-session memory isolation and basic SDK-level tool integration.',
    profile: { brain: 'Single LLM (KC1.1)', control: 'Simple sequential workflow (KC2.1)', reasoning: 'Chain of Thought (KC3.3)', memory: 'In-agent session memory only (KC4.1)', tools: 'Limited SDK integration (KC5.1)', environment: 'Restricted API access (KC6.1.1)' },
    comprehensive: { brain: 'KC1.1 (Foundation LLMs)', control: 'KC2.1 (Sequential workflows)', reasoning: 'KC3.1, KC3.3 (Structured planning, CoT)', memory: 'KC4.1 (In-agent session)', tools: 'KC5.1 (Basic SDKs)', environment: 'KC6.1.1 (Limited API access)' },
    frameworks: ['BabyAGI', 'ReWOO', 'AgentGPT (basic mode)'],
  },
  {
    id: 'hierarchical',
    name: 'Hierarchical Agent Architecture',
    summary: 'An orchestrator breaks complex tasks down and distributes them to specialized sub-agents, each handling one domain with its own tools; the orchestrator manages the process and integrates results.',
    trustModel: 'Requires On-Behalf-Of (OBO) token exchange to prevent "confused deputy" attacks across sub-agents — task decomposition plus OBO delegation.',
    profile: { brain: 'Multiple specialized LLMs / fine-tuned models (KC1.1 / KC1.2)', control: 'Hierarchical planning with orchestrator (KC2.2)', reasoning: 'Structured planning / execution (KC3.1)', memory: 'Cross-agent session memory (KC4.2)', tools: 'Managed platforms / services (KC5.2)', environment: 'More extensive capabilities (KC6.2, KC6.4)' },
    comprehensive: { brain: 'KC1.1, KC1.2 (Foundation & multimodal)', control: 'KC2.2 (Hierarchical planning)', reasoning: 'KC3.1 (Structured planning/execution)', memory: 'KC4.3, KC4.4 (Cross-session capabilities)', tools: 'KC5.2 (Managed platforms)', environment: 'KC6.1.2, KC6.4 (APIs, web access)' },
    frameworks: ['Amazon Bedrock Agents', 'Microsoft Copilot Platform', 'LangChain (orchestrator mode)'],
  },
  {
    id: 'swarm',
    name: 'Collaborative Agent Swarm',
    summary: 'Multiple peer agents work together without a strict hierarchy.',
    trustModel: 'Requires Decentralized Identifiers (DIDs) and Verifiable Credentials for peer-to-peer authentication — a decentralized mesh with P2P trust.',
    profile: { brain: 'Multiple specialized agents (KC1.1 / KC1.2)', control: 'Multi-agent collaboration (KC2.3)', reasoning: 'Tree of Thoughts to explore multiple solutions (KC3.4)', memory: 'Cross-agent cross-session memory (KC4.4)', tools: 'Flexible libraries with collaboration features (KC5.1)', environment: 'Distributed operational capabilities (various KC6)' },
    comprehensive: { brain: 'KC1.1, KC1.2 (Multiple models)', control: 'KC2.3 (Multi-agent collaboration)', reasoning: 'KC3.1, KC3.4 (Structured planning, ToT)', memory: 'KC4.2, KC4.4 (Cross-agent memory)', tools: 'KC5.1 (Flexible libraries)', environment: 'Various KC6 capabilities' },
    frameworks: ['MetaGPT', 'CrewAI', 'AutoGPT (multi-agent mode)'],
  },
  {
    id: 'reactive',
    name: 'Reactive Agent Architecture',
    summary: 'A responsive agent built on the ReAct paradigm that interleaves reasoning with actions and reacts to feedback (listed in the comprehensive table, 2.5).',
    profile: { brain: 'Multimodal capabilities (KC1.2)', control: 'Responsive workflows (KC2.1)', reasoning: 'ReAct paradigm (KC3.2)', memory: 'Cross-session (KC4.3)', tools: 'Managed APIs (KC5.3)', environment: 'Web access (KC6.4)' },
    comprehensive: { brain: 'KC1.2 (Multimodal capabilities)', control: 'KC2.1 (Responsive workflows)', reasoning: 'KC3.2 (ReAct paradigm)', memory: 'KC4.3 (Cross-session)', tools: 'KC5.3 (Managed APIs)', environment: 'KC6.4 (Web access)' },
    frameworks: ['OpenAI Assistants API', 'AutoGPT', 'Microsoft Semantic Kernel'],
  },
  {
    id: 'knowledge',
    name: 'Knowledge-Intensive Agent',
    summary: 'An agent centred on retrieval and persistent knowledge, typically RAG over data connectors (listed in the comprehensive table, 2.5).',
    profile: { brain: 'Foundation & specialized (KC1.1, KC1.2)', control: 'Knowledge workflows (KC2.1)', reasoning: 'Chain of Thought (KC3.3)', memory: 'Persistent knowledge (KC4.3, KC4.6)', tools: 'Data connectors (KC5.1)', environment: 'RAG & data sources (KC6.3)' },
    comprehensive: { brain: 'KC1.1, KC1.2 (Foundation & specialized)', control: 'KC2.1 (Knowledge workflows)', reasoning: 'KC3.3 (Chain of thought)', memory: 'KC4.3, KC4.6 (Persistent knowledge)', tools: 'KC5.1 (Data connectors)', environment: 'KC6.3 (RAG & data sources)' },
    frameworks: ['LlamaIndex', 'Haystack', 'LangChain (RAG mode)'],
  },
];

// ─── Control-plane inputs (2.7.1, Figure 2.6) ────────────────────────────────

export const SAA_CONTROL_PLANE_INPUTS: { input: string; trust: SaaTrustLevel; path: string }[] = [
  { input: 'System prompts, developer instructions, policies, hook logic', trust: 'System', path: 'Direct to model context; hashes verified at session start and checkpoints.' },
  { input: 'Tool descriptions', trust: 'Vetted', path: 'Admitted after onboarding review; pinned by hash (6.4.3).' },
  { input: 'Retrieved documents, memory summaries', trust: 'Untrusted', path: 'Carry provenance and trust labels; re-checked before influencing actions.' },
  { input: 'User input', trust: 'User', path: 'Direct, labelled as user content — never as system instruction.' },
  { input: 'External content: emails, documents, web pages, tool/API responses, agent messages', trust: 'Untrusted', path: 'Separately mediated, lower-trust ingestion path.' },
];

// ─── Hooks (3.3.7) ───────────────────────────────────────────────────────────

export const SAA_HOOK_DISPOSITIONS: { id: string; description: string }[] = [
  { id: 'Allow', description: 'The action proceeds as-is.' },
  { id: 'Deny', description: 'The action is blocked; the agent receives an error or a policy-defined fallback.' },
  { id: 'Modify', description: 'The action proceeds with altered content (e.g., PII redacted from tool arguments) — redact one field instead of blocking the whole call.' },
  { id: 'Escalate', description: 'Escalate (HITL): the action pauses for human approval before proceeding.' },
  { id: 'Defer', description: 'The action is suspended because the enforcement layer cannot decide confidently, pending more context or validation (e.g., a credential rotation outside a maintenance window).' },
];

export const SAA_HOOKS: SaaHook[] = [
  { id: 'sessionStart', scope: 'Session', controls: 'Component inventory check, session policy binding, intent declaration.', dispositions: ['Allow', 'Deny'] },
  { id: 'agentTrigger / userMessage', scope: 'Session', controls: 'Prompt-injection detection, PII redaction, input policy; trigger-source validation for autonomous agents.', dispositions: ['Allow', 'Deny', 'Modify'] },
  { id: 'turnStart', scope: 'Turn', controls: 'Per-turn state init, cumulative-taint reset, turn-scoped rate limits.', dispositions: ['Allow', 'Deny'] },
  { id: 'memoryContextRetrieval', scope: 'Inner', controls: 'Cross-session taint check, scope enforcement, integrity verification.', dispositions: ['Allow', 'Deny', 'Modify'] },
  { id: 'knowledgeRetrieval', scope: 'Inner', controls: 'Retrieved-content filtering, source-provenance tagging, data classification.', dispositions: ['Allow', 'Deny', 'Modify'] },
  { id: 'toolCallRequest', scope: 'Inner', controls: 'Permission check, argument validation, MCP hash-pin verification (6.4.3), description-poisoning scan (6.4.4), HITL approval, intent-based access control, context-aware action classification, Rule-of-Two enforcement.', dispositions: ['Allow', 'Deny', 'Modify', 'Escalate', 'Defer'], priority: 'first' },
  { id: 'toolCallResult', scope: 'Inner', controls: 'Output sanitization, exfiltration detection, result-provenance tagging.', dispositions: ['Allow', 'Deny', 'Modify'] },
  { id: 'subagentStart', scope: 'Inner', controls: 'Delegation authorization, privilege scoping, intent-inheritance policy.', dispositions: ['Allow', 'Deny'] },
  { id: 'subagentStop', scope: 'Inner', controls: 'Result-provenance binding, trust-level verification.', dispositions: ['Audit only'] },
  { id: 'memoryStore', scope: 'Inner', controls: 'Write authorization, content filtering, scope restriction, TTL.', dispositions: ['Allow', 'Deny', 'Modify'], priority: 'next' },
  { id: 'agentResponse', scope: 'Turn', controls: 'Output filtering, data-leakage prevention, hallucination check, compliance.', dispositions: ['Allow', 'Deny', 'Modify'], priority: 'first' },
  { id: 'preCompact', scope: 'Inner', controls: 'Provenance snapshot before summarization, compaction policy.', dispositions: ['Allow', 'Deny'] },
  { id: 'postCompact', scope: 'Inner', controls: 'Post-compaction lineage binding, summary-trust verification.', dispositions: ['Audit + Modify'] },
  { id: 'turnEnd', scope: 'Turn', controls: 'Turn summary, step-count audit, cumulative-taint capture.', dispositions: ['Audit only'] },
  { id: 'sessionEnd', scope: 'Session', controls: 'Audit-chain finalization, session summary.', dispositions: ['Audit only'] },
  { id: 'skillRegister', scope: 'Inner', controls: 'Whole-definition inspection before a skill is loadable, signature/provenance check, dependency review, least-privilege capability manifest, integrity-digest pinning.', dispositions: ['Allow', 'Deny'] },
  { id: 'skillLoad', scope: 'Inner', controls: 'Bind activation to an approved registration (digest match), inter-skill cascade containment, load-depth limits, capability re-check.', dispositions: ['Allow', 'Deny'] },
  { id: 'skillUnload', scope: 'Inner', controls: 'Active-inventory update, load/unload churn anomaly detection.', dispositions: ['Audit only'] },
];

export const SAA_HOOK_CONTROL_MAP: { control: string; ref: string; hooks: string }[] = [
  { control: 'MCP hardening', ref: '6.4.2–6.4.4', hooks: 'Hash-pin verification, description-poisoning scan, and rug-pull revalidation fire at toolCallRequest.' },
  { control: 'Skill hardening', ref: '6.4 (Agent Skills)', hooks: 'Signing, sandboxing, and permission-manifest controls fire at skillRegister / skillLoad; the digest pinned at skillRegister is what skillLoad verifies.' },
  { control: 'Runtime guardrails', ref: '3.3.2', hooks: 'Input filtering at userMessage, output filtering at agentResponse.' },
  { control: 'HITL', ref: '3.1.5', hooks: 'Approval gates use the Escalate disposition at toolCallRequest.' },
  { control: 'Memory integrity', ref: '3.1.6', hooks: 'Read/write controls fire at memoryContextRetrieval and memoryStore.' },
  { control: 'Circuit breakers', ref: '3.3.8', hooks: 'Emergency halt uses Deny at whichever hook detects the anomaly.' },
  { control: 'Logging & monitoring', ref: '3.3.3', hooks: 'Structured trace data is emitted at every hook regardless of disposition.' },
  { control: 'Turn-scoped policies', ref: '3.3.7', hooks: 'Cumulative-taint tracking and per-turn rate limits enforce at turnStart / turnEnd.' },
];

// ─── Circuit breaker schema (3.3.8) ──────────────────────────────────────────

export const SAA_CIRCUIT_BREAKER_TIERS: { id: string; description: string }[] = [
  { id: 'Warn', description: 'Record and alert; the agent keeps running while the signal is investigated.' },
  { id: 'Limit', description: 'Throttle: reduce rate, budget, or the action space (e.g., revoke web, computer, or code-execution tools).' },
  { id: 'Suspend', description: 'Quarantine: retain observability while blocking all external actions, or fall back to safe read-only mode.' },
  { id: 'Kill', description: 'Halt the agent or orchestrator, disable its identity, and roll back where possible — after capturing an incident snapshot.' },
];

export const SAA_CIRCUIT_BREAKER_SCHEMA: { id: string; text: string }[] = [
  { id: 'Policy', text: 'The governing rule, baselined through behavioral testing / red-teaming before it may enforce (firewall-style), with support for manual exceptions and tuning. It must be hardened against tampering by the agentic system(s).' },
  { id: 'Signal', text: 'What is monitored: output-guardrail violations, drift from the declared task goal, unexpected sub-agent spawning or loops, plan deviation, non-authoritative memory reads, anomalous tool-invocation patterns (fragmentation, ordering, sensitive domain/data combinations), tool schema/signature changes, privilege escalation, or system-file operations.' },
  { id: 'Trigger', text: 'The condition that fires: a file write during an information-gathering phase, agent self-modification (acquiring new tools or changing its own config), reads of system directories when only project files were expected, or any tool schema/signature change.' },
  { id: 'Action', text: 'The response: automatic tool revocation above an anomaly threshold, agent quarantine (observability kept, external actions blocked), halting the orchestrator, falling back to a safe read-only mode, or reducing the agent’s action space rather than only stopping it.' },
  { id: 'Rollback', text: 'Use transaction boundaries, idempotency, and rollback where possible so an interruption can be undone; unsafe outcomes trigger containment plus rollback.' },
  { id: 'Audit / incident snapshot', text: 'Before a kill or rollback, freeze the context window and preserve the tamper-evident provenance chain (principals, decisions, tools, data accessed) so the audit log is a verifiable record, not a trust assertion.' },
];

export const SAA_CIRCUIT_BREAKER_EXAMPLES: string[] = [
  'A protected task is in an information-gathering stage: a file read is expected, a file write should trigger.',
  'An agent write is a self-modification (new tools or a configuration change): it should generally trigger and the trajectory be treated as rogue, not merely blocked. Even where self-modification is accepted, scrutinize the tool-mounting arguments — they may compromise the agent.',
  'A protected task is expected to read business project files: reading files in system directories should trigger.',
  'Recent history for a group of agents (sub-agents, or agents started by the same principal) shows a high rate of data-asset deletions by count or size: the cross-agent pattern should trigger.',
  'A sub-agent increases a principal’s access (e.g., approves an IT ticket granting HR-system access): a second sub-agent then changing that principal’s email to an external domain is a critical behavior to interrupt.',
  'An LLM judge or graph-based anomaly detector finds an action attempting object mutations beyond the intended scope: trigger. A change to tool schema/signature parameters must be blocked or inspected as suspect.',
];

// ─── Capability control matrix (5.0) ─────────────────────────────────────────

export const SAA_CAPABILITIES: SaaCapability[] = [
  { id: 'CAP-API', sectionId: 'SAA-5.1', name: 'API Access', kc: 'KC6.1', capabilityClass: 'read-only → high-impact', sensitiveData: 'Often', untrustedInput: 'Via responses', externalComms: 'Yes', requiredControls: 'Scoped OAuth/keys, allow/deny lists, templates, schema validation, rate limit, logging', escalationTrigger: 'Write/admin scope; new destination domain', legs: { sensitive: true, untrusted: true, external: true } },
  { id: 'CAP-CODE', sectionId: 'SAA-5.2', name: 'Code Execution', kc: 'KC6.2', capabilityClass: 'high-impact', sensitiveData: 'Possibly', untrustedInput: 'Yes (generated code)', externalComms: 'Yes', requiredControls: 'Mandatory sandbox, resource limits, static analysis, command allowlist, HITL for high-risk', escalationTrigger: 'Network/file access from sandbox; arbitrary code', legs: { sensitive: true, untrusted: true, external: true } },
  { id: 'CAP-DB', sectionId: 'SAA-5.3', name: 'Database / RAG', kc: 'KC6.3', capabilityClass: 'bounded-write → high-impact', sensitiveData: 'Yes', untrustedInput: 'Via retrieved content', externalComms: 'Bounded', requiredControls: 'Parameterized queries, least-privilege accounts, post-retrieval PII filter, RBAC vector DB', escalationTrigger: 'CRUD/DDL access; cross-tenant retrieval', legs: { sensitive: true, untrusted: true, external: false } },
  { id: 'CAP-WEB', sectionId: 'SAA-5.4', name: 'Web Use', kc: 'KC6.4', capabilityClass: 'read-only → bounded-write', sensitiveData: 'Via browser data', untrustedInput: 'Yes (web content)', externalComms: 'Yes', requiredControls: 'Sandboxed browser, URL allowlist, SSRF segmentation, content sanitization, logging', escalationTrigger: 'Authenticated session reuse; internal-network reach', legs: { sensitive: true, untrusted: true, external: true } },
  { id: 'CAP-PC', sectionId: 'SAA-5.5', name: 'PC / Computer Use', kc: 'KC6.5', capabilityClass: 'high-impact', sensitiveData: 'Yes', untrustedInput: 'Yes (files, screen)', externalComms: 'Yes', requiredControls: 'OS sandbox, path/command allowlists, dry-run, HITL, screenshot redaction, repo isolation', escalationTrigger: 'OS command exec; destructive git/file ops', legs: { sensitive: true, untrusted: true, external: true } },
  { id: 'CAP-CRIT', sectionId: 'SAA-5.6', name: 'Critical Systems', kc: 'KC6.6', capabilityClass: 'high-impact', sensitiveData: 'Yes', untrustedInput: 'Possibly', externalComms: 'Yes', requiredControls: 'Air-gap/segmentation, MFA, mandatory HITL, read-only default, physical interlocks', escalationTrigger: 'Any control/write action', legs: { sensitive: true, untrusted: true, external: true } },
];

// ─── Assurance chain (7.0, Figure 7.1) ───────────────────────────────────────

export const SAA_ASSURANCE_CHAIN: SaaAssuranceStep[] = [
  { id: 'design scope', label: 'Design scope', detail: 'Intended scope and capability boundaries: what the application is for, what it must not do, and which capability compositions remain out of scope.' },
  { id: 'assumptions', label: 'Assumptions', detail: 'Trust-boundary declarations, operational-environment assumptions, and safe failure states.' },
  { id: 'threat model', label: 'Threat model', detail: 'Which ASI T&M threats are mitigated, accepted as residual risk, or out of scope — the reference for red-team prioritization.' },
  { id: 'controls', label: 'Controls', detail: 'Controls chosen to prevent, reduce, detect, or contain each failure path.' },
  { id: 'validation tests', label: 'Validation tests', detail: 'Red teaming (7.1) tries to falsify the assumptions; behavioral validation (7.2) checks the agent stays useful within scope.' },
  { id: 'runtime monitoring', label: 'Runtime monitoring', detail: 'Continuous, queryable evidence that the controls remain live and correct in production.' },
  { id: 'regression triggers', label: 'Regression triggers', detail: 'A change to a behavior-defining element triggers a partial replay of the affected design checks, red-team scenarios, and behavioral cases — with the scope updated first.' },
];

// ─── Tool lifecycle (6.4, Figure 6.1) ────────────────────────────────────────

export const SAA_TOOL_LIFECYCLE = {
  onboard: [
    { id: 'Vetted registry', detail: 'No direct pulls from public repositories in production.' },
    { id: 'Onboarding checks', detail: 'SAST scan, SBOM, behavioral sandbox, publisher identity verified.' },
    { id: 'Security review admission gate', detail: 'Updates tested in staging; unused tools decommissioned.' },
    { id: 'Signed, version-pinned catalog manifest', detail: 'Signing key held outside the agent runtime.' },
    { id: 'Pin description and schema by hash', detail: 'At first registration.' },
  ],
  run: [
    { id: 'Session start or catalog refresh', detail: 'Also forced by Approval TTL expiry (automatic re-validation, never silent re-approval).' },
    { id: 'Re-hash and compare to the pinned digest', detail: 'Catalog drift (tools added, removed, or renamed) raises an alert and an append-only audit-log entry.' },
  ],
  match: 'Tool may execute.',
  mismatch: 'Blocked pending operator re-approval; the alert includes the diff. Re-approval re-pins the digest.',
};

// ─── Chapters ────────────────────────────────────────────────────────────────

export const SAA_CHAPTERS: SaaChapter[] = [
  // ── Chapter 1 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH1',
    number: '1',
    title: 'Introduction',
    shortTitle: 'Introduction',
    tagline: 'Purpose, scope, audience, and how this guide fits the OWASP Agentic Security Initiative.',
    sections: [
      {
        id: 'SAA-1.1',
        number: '1.1',
        title: 'Purpose and Goals',
        summary: 'Practical, actionable guidance for designing, building, and deploying secure LLM-powered agentic applications.',
        blocks: [
          p('This guide provides practical and actionable guidance for designing, developing, and deploying secure agentic applications powered by large language models (LLMs). It complements the OWASP Agentic AI Threats and Mitigations (ASI T&M) document.'),
          callout('info', 'Frameworks are great for proof of concept, but in production they create more dependencies — a theme the guide returns to in Section 2.4.', 'Recurring caution'),
        ],
      },
      {
        id: 'SAA-1.2',
        number: '1.2',
        title: 'Scope and Audience',
        summary: 'Written for intermediate-to-advanced developers, AI/ML engineers, security architects and engineers, and technical leads.',
        blocks: [
          p('Audience: intermediate to advanced software developers, AI/ML engineers, security architects, security engineers, and technical leads who build, secure, or assess workflow and agentic AI applications.'),
          table(
            ['In scope', 'Out of scope'],
            [
              ['Technical security controls and best practices for agentic systems', 'High-level governance frameworks, organizational policies, or CISO-level strategy (to be covered by a separate "Managing Agentic Risk Guide")'],
              ['Secure architectural patterns specific to agentic AI', 'Detailed implementation guides for specific vendor platforms or frameworks (examples may be illustrative)'],
              ['Mitigation strategies for common agentic threats', 'Ethical considerations beyond their direct security impact (e.g., bias mitigation unrelated to vulnerabilities)'],
              ['Guidance across the lifecycle: design, build, deploy, operate', 'Jurisdiction- or industry-specific legal and compliance requirements (though the principles support compliance)'],
              ['Considerations for LLMs, orchestration, memory, tools, and operational environments', ''],
              ['Examples across single-agent, multi-agent, and other architectures', ''],
            ],
          ),
        ],
      },
      {
        id: 'SAA-1.3',
        number: '1.3',
        title: 'Relationship with other ASI work',
        summary: 'This guide is the "how" companion to the ASI Threats & Mitigations "what", and the defender view of what red teams test.',
        blocks: [
          p('The guide is part of the OWASP Agentic Security Initiative (ASI) and works alongside other ASI resources:'),
          ul(
            li('ASI Threats & Mitigations (T&M)', 'Where the T&M list identifies which threats exist and which mitigations are needed, this guide explains how to implement those mitigations technically and in architectural context. It uses the T-codes (T1–T15) from the T&M list throughout.'),
            li('ASI Red Teaming Guide', 'This guide is the builder and defender perspective: the controls that red teams (following the Red Teaming Guide) will test. Understanding these defenses is essential for designing effective red-team simulations.'),
          ),
          p('In short, it translates the conceptual threats and mitigation principles from other ASI work into actionable architectural patterns and developer guidelines.'),
          { type: 'links', items: [{ label: 'OWASP Agentic AI – Threats and Mitigations', url: 'https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/' }] },
        ],
      },
    ],
  },

  // ── Chapter 2 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH2',
    number: '2',
    title: 'Secure Agentic Architectures',
    shortTitle: 'Architectures',
    tagline: 'The six key components, their attack surfaces, secure patterns, frameworks, and the three cross-cutting concerns.',
    sections: [
      {
        id: 'SAA-2.1',
        number: '2.1',
        title: 'Defining Key Components of Agentic Architectures',
        summary: 'Six key components (KC1–KC6) make up every agentic application; each keeps the same color across this workspace.',
        blocks: [
          p('Every agentic application can be decomposed into six key components: KC1 Generative Language Models, KC2 Orchestration, KC3 Reasoning / Planning Paradigm, KC4 Memory Modules, KC5 Tool Integration Frameworks, and KC6 Operational Environment. Select a component to explore its sub-components, the threats that target it (2.2), and the circuit-breaker signals and actions that protect it (3.3.8).'),
          widget('kc-explorer'),
          p('Memory scope follows two axes — who shares the memory (one agent or several) and how far it persists (session, cross-session, cross-user). The wider the cell, the larger the blast radius of a compromise.'),
          widget('memory-matrix'),
        ],
      },
      {
        id: 'SAA-2.2',
        number: '2.2',
        title: 'Attack Surface Analysis',
        summary: 'Which T-code threats target which key component — most threats cross component lines.',
        threats: ['T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'T8', 'T9', 'T10', 'T11', 'T12', 'T13', 'T14', 'T15'],
        blocks: [
          p('Threat exposure differs by component, and most threats span several components. Click a threat row or a component column to focus it; each filled cell shows how that threat manifests in that component (sections 2.2.1–2.2.6).'),
          widget('threat-heatmap'),
          table(
            ['Key component', 'Associated threats', 'Risk description'],
            [
              ['KC1 – Large Language Models', 'T5, T6, T7, T15', 'Core vulnerabilities in the "brain" of the agent: hallucinations, goal misalignment, deceptive reasoning, and manipulating humans'],
              ['KC2 – Orchestration (Control Flow)', 'T6, T8, T9, T10, T12, T13, T14', 'Workflow control: goal manipulation, lack of auditability, identity confusion, overwhelming human oversight, and multi-agent attacks'],
              ['KC3 – Reasoning / Planning Paradigm', 'T5, T6, T7, T8, T15', 'Decision processes: cascading hallucinations, intent manipulation, deceptive reasoning, untraceable decisions, and human manipulation'],
              ['KC4 – Memory Modules', 'T1, T3, T5, T6, T8, T12', 'Data integrity: memory poisoning, leaking, propagating hallucinations, evidence tampering, and communication poisoning'],
              ['KC5 – Tool Integration Frameworks', 'T2, T3, T6, T8, T11 (and T7 in 2.2.5)', 'Tool exploitation: tool misuse, privilege escalation, unlogged actions, and unexpected code execution'],
              ['KC6 – Operational Environment', 'T2, T3, T4, T10, T11, T12, T13, T15', 'Monitoring gaps and external-system risks: misused access, privilege compromise, resource exhaustion, overwhelmed reviewers, code-execution attacks, side-channel storage/communication, and manipulation via the environment'],
            ],
            'Summary table (2.2)',
          ),
        ],
      },
      {
        id: 'SAA-2.3.1',
        number: '2.3.1',
        title: 'Core patterns used in all frameworks',
        group: '2.3 Secure Architecture Patterns',
        summary: 'Tool use, reflection, RAG, user-privilege assumption, and credential handling — the building blocks every framework reuses.',
        blocks: [
          p('Securing agentic systems takes more than securing individual components: security must be embedded in the architecture itself. The choice of architecture (sequential, hierarchical, swarm) shapes the attack surface and how well isolation, least privilege, and secure communication can be enforced. Core patterns are the building blocks; architectures are the blueprints that organize them.'),
          p('Across frameworks such as LangChain, CrewAI, and AutoGPT, the same patterns recur. Each introduces specific control points — and potential vulnerabilities — regardless of the framework:'),
          ul(
            li('Tool Use pattern', 'Agents call external tools, APIs, or functions for data retrieval, calculations, or actions beyond the LLM’s internal knowledge. Requires tool definitions, a reasoning loop that selects and invokes tools, and integration mechanisms.'),
            li('Reflection pattern', 'Agents introspect, evaluate past actions or outputs against goals or metrics, and use that self-assessment to refine strategies or correct errors. Involves feedback loops, evaluation logic, and mechanisms for the agent to modify its own behavior or knowledge.'),
            li('Retrieval-Augmented Generation (RAG) pattern', 'The agent first retrieves relevant information from a knowledge base (vector store, database) and passes it to the LLM with the query for a better-informed answer. Requires a retriever, a knowledge base, and prompt integration.'),
            li('User privilege / auth assumption pattern for execution', 'When an agent executes against an API, database, or entity with granular user permissions, it should assume the permissions of the invoking user — scoped further by task, resource, context, or action. This stops it returning data the user should not see (other users’ data, or data irrelevant to the action) and supports just-in-time and ephemeral access. If user privileges are not already isolated by a strong "Chinese Wall" model, the agent should also track the boundary of the context it is operating on. Key components: the LLM brain (KC1), an execution system (KC6.1, KC6.3, KC6.4), and an authentication/authorization/IAM system.'),
            li('Credential handling for browser / computer use', 'When a browser or computer-use task needs authentication, route the user through a trusted, user-mediated identity-provider, credential-broker, or password-manager flow. The model and agent context must never receive passwords, reusable session secrets, refresh tokens, or raw access tokens. An out-of-model executor may use an opaque handle or a short-lived, least-privilege, audience- and task-scoped credential — only after explicit user authorization.'),
          ),
        ],
      },
      {
        id: 'SAA-2.3.2',
        number: '2.3.2–2.3.4',
        title: 'Sequential, Hierarchical, and Swarm architectures',
        group: '2.3 Secure Architecture Patterns',
        summary: 'Three reference topologies, each choosing a different set of sub-components and a different trust model.',
        blocks: [
          p('Each architecture picks a different set of sub-components. Compare the profiles, trust models, and example frameworks; the Reactive and Knowledge-Intensive patterns from the comprehensive table (2.5) are included too. Patterns can be mixed and matched — and security matters more as the agent’s operational capabilities expand.'),
          widget('architecture-patterns'),
        ],
      },
      {
        id: 'SAA-2.4',
        number: '2.4',
        title: 'Frameworks',
        summary: 'General-purpose, enterprise, data-oriented, and specialized frameworks — and why framework choice is a security decision.',
        blocks: [
          p('Frameworks provide pre-built components, abstractions, and patterns for state, tools, workflows, and LLM interaction. Their choice affects the default security posture, how easily controls can be implemented, and the attack surface.'),
          callout('warning', 'Customization and abstraction are a trade-off. If you modify a framework to fit your needs and it is later patched for a vulnerability, you may need an urgent update that no longer fits your customized code. Plan for that fragility.', 'Caution'),
          table(
            ['Category', 'Framework', 'Focus'],
            [
              ['General-purpose (2.4.1)', 'LangChain', 'Popular components for LLM apps: memory, tool use, and agent types such as ReAct and Self-Ask.'],
              ['General-purpose (2.4.1)', 'AutoGPT', 'Early autonomous agent that plans and executes with minimal human intervention, using tools and web access.'],
              ['General-purpose (2.4.1)', 'MetaGPT', 'Multi-agent collaboration with specialized roles (product manager, engineer, tester).'],
              ['General-purpose (2.4.1)', 'CrewAI', 'Collaborative agents working through defined roles and workflows.'],
              ['General-purpose (2.4.1)', 'AutoGen', 'Microsoft open-source multi-agent framework; each agent has a role, goal, memory, and toolset.'],
              ['General-purpose (2.4.1)', 'OpenDevin', 'Multimodal agentic framework for DevOps and software engineering; reason + act + observe loop with code editor, browser, CLI, execution environment, and Git.'],
              ['General-purpose (2.4.1)', 'LangGraph', 'Python framework on LangChain defining agents as cyclical, asynchronous, stateful graphs; supports HITL pause/resume checkpoints.'],
              ['General-purpose (2.4.1)', 'Dify', 'Open-source LLM app platform combining agentic workflows, RAG pipelines, agent capabilities, model management, and observability.'],
              ['Enterprise / platform (2.4.2)', 'Amazon Bedrock Agents', 'Managed service to build, test, and deploy agents integrated with AWS services and knowledge bases.'],
              ['Enterprise / platform (2.4.2)', 'Microsoft Semantic Kernel', 'SDK integrating AI with programming languages so agents can use native functions and skills.'],
              ['Enterprise / platform (2.4.2)', 'Microsoft Copilot Platform', 'Managed services for enterprise copilots in the Microsoft ecosystem.'],
              ['Data-oriented (2.4.3)', 'LlamaIndex', 'Connects LLMs to external data with sophisticated RAG and agent capabilities for retrieval and processing.'],
              ['Data-oriented (2.4.3)', 'Haystack', 'Search and question-answering systems with agent capabilities for complex queries.'],
              ['Specialized (2.4.4)', 'OpenAI Assistants API', 'Managed API for stateful assistants with memory, tool use, and retrieval.'],
              ['Specialized (2.4.4)', 'BabyAGI', 'Minimalist framework for autonomous task management and prioritization.'],
              ['Specialized (2.4.4)', 'ReWOO', 'Implements "Reasoning WithOut Observation" for more reliable planning and execution.'],
              ['Specialized (2.4.4)', 'AgentGPT', 'Build and deploy autonomous agents through a web interface.'],
            ],
          ),
        ],
      },
      {
        id: 'SAA-2.5',
        number: '2.5',
        title: 'Comprehensive Table: Components, Patterns, and Frameworks',
        summary: 'How five architectural patterns map onto key components and real frameworks.',
        blocks: [
          table(
            ['Pattern', 'Key components', 'Frameworks'],
            SAA_ARCHITECTURE_PATTERNS.map((ap) => [
              ap.name,
              `Brain: ${ap.comprehensive.brain}. Control: ${ap.comprehensive.control}. Reasoning: ${ap.comprehensive.reasoning}. Memory: ${ap.comprehensive.memory}. Tools: ${ap.comprehensive.tools}. Environment: ${ap.comprehensive.environment}.`,
              ap.frameworks.join('; '),
            ]),
          ),
          ul(
            li('LangChain appears in several patterns because it is flexible enough to implement many architectural approaches.'),
            li('Microsoft Semantic Kernel provides components that can support multiple patterns depending on implementation.'),
            li('AutoGPT can operate in reactive mode or as part of a collaborative system.'),
          ),
          callout('info', 'The source table lists "KC6.3 (Web access)" for the Reactive pattern and "KC6.4 (RAG & data sources)" for the Knowledge-Intensive agent. Per the KC6 definitions, web access is KC6.4 and data sources are KC6.3; the codes are corrected here.', 'Editorial note'),
        ],
      },
      {
        id: 'SAA-2.6',
        number: '2.6',
        title: 'Case Study: Multi-agent co-pilot application',
        summary: 'A hierarchical copilot over calendar, email, Slack, and Drive — and the threats that still apply with limited API access.',
        threats: ['T2', 'T6', 'T9'],
        blocks: [
          p('A typical copilot built as a distributed multi-agent system using KC2.2 Hierarchical Planning to reach enterprise APIs (calendar, email, Drive, Slack). The collaborating agents:'),
          table(
            ['Agent', 'Role', 'Environment / tooling'],
            [
              ['Orchestrator', 'Central controller: receives requests, decomposes them into sub-tasks (KC3.1), routes them to specialized agents, and aggregates responses into one output.', 'KC1.1 LLMs inside its tools; likely KC5.1 SDKs. Tools: Task Decomposition, Agent Routing Mechanism, Response Aggregator (all LLM-based). Memory: KC4.2 cross-agent session memory holding requests, intermediate reasoning, and agent responses — the primary inter-agent channel — compartmentalized by context sensitivity.'],
              ['Calendar agent', 'Scheduling, availability checks, reminders.', 'KC6.1.1 Limited API access to the calendar service (e.g., Google Calendar); requires authN/authZ. Tools: date/time parsing, meeting scheduling logic, reminder system.'],
              ['Email agent', 'Sending, receiving, organizing email.', 'KC6.1.1 to the email service (e.g., Gmail, Outlook). Tools: email API, composition and sending, reading and parsing, filtering and organization.'],
              ['Slack agent', 'Communication and collaboration within Slack.', 'KC6.1.1 to the Slack API. Tools: message sending/retrieval, channel management, notification handling.'],
              ['Drive agent', 'Files and documents in cloud storage (e.g., Google Drive, OneDrive).', 'KC6.1.1 to the storage API. Tools: file retrieval/upload, search and filtering, sharing and permissions.'],
            ],
          ),
          p('Applicable threats, even with predefined (limited) API calls:'),
          ul(
            li('Tool Misuse (T2) via KC6.1.1', 'The agents’ LLMs still generate parameters. Deceptive prompts can make them produce malicious parameters, leading to parameter-pollution attacks or unauthorized operations within the API’s allowed scope.'),
            li('Intent Breaking & Goal Manipulation (T6)', 'Injected prompts steer the underlying LLM toward parameters that achieve a malicious goal, even within the constraints of limited API access.'),
            li('Identity Spoofing & Impersonation (T9)', 'If generated parameters include user identifiers or manipulable tokens, prompt injection can alter them to impersonate another user within the scope of the API interaction.'),
          ),
        ],
      },
      {
        id: 'SAA-2.7.1',
        number: '2.7.1',
        title: 'The Agent Control Plane (instruction & policy inputs)',
        group: '2.7 Cross-Cutting Architectural Concerns',
        summary: 'Control-plane inputs shape behavior but are not equal in authority — keep provenance, and keep policy outside the model.',
        blocks: [
          p('The following concerns are not new key components: they are properties that cut across KC1–KC6 and must be addressed at design time. They are made concrete in the lifecycle (Section 3), capability (Section 5), and deployment (Section 9) chapters.'),
          p('System prompts, developer instructions, tool descriptions, retrieved documents, memory summaries, policies, and hook logic are all control-plane inputs — but they are not equal in authority. Prompt roles, delimiters, and sections are provenance cues, not security boundaries.'),
          widget('control-plane'),
          ul(
            li('Preserve each input’s provenance and trust label.'),
            li('Route external content (emails, documents, web pages, tool/API responses, agent messages) through a separately mediated, lower-trust ingestion path.'),
            li('Keep deterministic policy and authorization outside the model, at the action sinks.'),
            li('Verify active system prompts and tool definitions against approved hashes at session start and at checkpoints to detect unauthorized control-plane changes (see 3.1.2 and Section 6).'),
          ),
        ],
      },
      {
        id: 'SAA-2.7.2',
        number: '2.7.2',
        title: 'Agent Identity & Delegation',
        group: '2.7 Cross-Cutting Architectural Concerns',
        summary: 'Effective Scope is an intersection, not a union: delegation must be explicit, consented, and attenuating.',
        threats: ['T3', 'T9'],
        blocks: [
          p('Identity spans orchestration (KC2), tool integration (KC5), the operational environment (KC6), and deployment. Each agent instance or service should hold a distinct, manageable non-human identity, and authority delegated to or between agents should be explicit and attenuating rather than ambient.'),
          { type: 'formula', text: 'Effective Scope = User Permission ∩ Agent Capability ∩ Bound Intent  [ ∩ Consented Scope, where a user is present ]', caption: 'What an agent may do is bounded by every set at once.' },
          widget('effective-scope'),
          p('Delegation should use On-Behalf-Of (OBO) token exchange — never raw user credentials — with depth limits and monotonically narrowing scope at each hop, and bind authorization to the declared user intent so the agent cannot become a "confused deputy" (detailed in Sections 4 and 9).'),
          p('Agent identity, delegation, and end-user consent. Agent identity must distinguish four layers:'),
          ol(
            li('The logical agent or service role.'),
            li('The runtime workload identity.'),
            li('The ephemeral execution, session, or task identifier.'),
            li('The delegated end-user principal.'),
          ),
          p('Assign a stable, managed non-human identity at an independently deployable workload or service boundary, issue short-lived attested credentials to runtime instances, and create a separately registered principal only where ownership, isolation, policy, or independent revocation requires it. Telemetry and authorization must map every ephemeral run back to its stable owner, deployment, task, and delegation chain.'),
          table(
            ['Situation', 'Recommended mechanism', 'Effective scope'],
            [
              ['User present, agent needs user-owned resources', 'OAuth 2.0 Authorization Code Grant with PKCE: the user authenticates at the authorization server, reviews requested scopes, and the agent receives a short-lived token bound to those scopes — never seeing the user’s credential.', 'User Permission ∩ Agent Capability ∩ Bound Intent ∩ Consented Scope'],
              ['No user present', 'Client Credentials Grant: the agent authenticates under its own identity with administrator-bounded scope.', 'Agent Capability (admin-bounded) ∩ Bound Intent'],
              ['Multi-hop chain with an upstream user context', 'On-Behalf-Of token exchange (RFC 8693) propagates identity downstream with monotonically narrowing scope.', 'Each hop ⊂ previous hop'],
            ],
          ),
          callout('key', 'Delegation presumes consent. Consent must be explicit, recorded, and revocable. Choose among the mechanisms based on data ownership, availability of user interaction, operation timing, and whether permissions should vary per user consent or stay fixed at the agent level.'),
        ],
      },
      {
        id: 'SAA-2.7.3',
        number: '2.7.3',
        title: 'Capability Composition Risk (Lethal Trifecta / Rule of Two)',
        group: '2.7 Cross-Cutting Architectural Concerns',
        summary: 'Private data + untrusted content + external communication in one agent = exfiltration risk. Hold at most two.',
        threats: ['T2', 'T3'],
        blocks: [
          p('An agent’s attack surface is set not only by its components but by the combination of capabilities it holds at runtime. Simon Willison’s "Lethal Trifecta" names the dangerous combination: (1) access to private or sensitive data, (2) exposure to untrusted content, and (3) the ability to communicate externally. An agent holding all three can be manipulated into exfiltrating data.'),
          p('Meta’s "Rule of Two" formalizes the mitigation: expose an agent to at most two of {processes untrustworthy input, accesses sensitive systems/data, communicates externally or changes state}. Try it:'),
          widget('rule-of-two'),
          callout('warning', 'When a design would combine all three, the default is to remove one capability or to separate the legs across independently authorized components with hard information-flow and egress boundaries. Any exception requires layered deterministic enforcement, tested information-flow and egress controls, documented residual-risk ownership and acceptance, and evidence that HITL or monitoring is a supporting control — never the sole one. This gate matters most for dynamically acquired capabilities; Section 5 operationalizes it.', 'Default response'),
        ],
      },
    ],
  },

  // ── Chapter 3 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH3',
    number: '3',
    title: 'Agentic Developer Guidelines',
    shortTitle: 'Developer Lifecycle',
    tagline: 'Security controls across design, build & deploy, and operations — including hooks and behavioral circuit breakers.',
    sections: [
      {
        id: 'SAA-3.0',
        number: '3',
        title: 'A Lifecycle Approach',
        summary: 'Security is a foundational principle across the whole lifecycle, whatever the architecture.',
        blocks: [
          p('Building secure agentic AI means integrating security across the entire lifecycle, from design to operations. It is a foundational principle regardless of architecture (single, multi-agent, swarm), complexity, or function, and it builds resilience against AI-specific threats such as prompt injection, insecure output handling, and data poisoning. Consider frameworks such as the OWASP Top 10 for LLM Applications for common vulnerabilities.'),
          p('Agentic systems introduce new security surfaces. Persistent memory raises the risk of context poisoning, data leakage, and unauthorized state retention. Autonomous planning opens the door to misaligned objectives, recursive decision loops, and unpredictable emergent behavior. These must be handled at design time — beyond traditional threat modeling — by defining "safe failure" states, charting integration boundaries, specifying memory access policies, and adding human-in-the-loop safeguards where applicable.'),
        ],
      },
      {
        id: 'SAA-3.1.1',
        number: '3.1.1',
        title: 'Threat Modeling for Agentic Systems',
        group: '3.1 Secure Design & Development',
        summary: 'Use the latest OWASP Agentic AI Threats and Mitigations as the threat model.',
        blocks: [
          p('For details on threat modeling agentic systems, see the latest version of the OWASP Agentic AI Threats and Mitigations.'),
          { type: 'links', items: [{ label: 'Agentic AI – Threats and Mitigations', url: 'https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/' }] },
        ],
      },
      {
        id: 'SAA-3.1.2',
        number: '3.1.2',
        title: 'System Prompt Engineering & Hardening',
        group: '3.1 Secure Design & Development',
        summary: 'Define instructions, capabilities, and limits securely — and verify at runtime that the approved prompt is the one running.',
        threats: ['T6'],
        blocks: [
          p('Purpose: define the agent’s core instructions, capabilities, and limitations so it resists manipulation and unintended behavior.'),
          ul(
            li('Clear boundaries & safeguards', 'Explicitly state DOs and DON’Ts, forbidden topics, operational scope, and ethical guidelines. Prefer a predetermined allowlist of topics with an implicit deny for everything else; apply the same to languages. In multilingual settings, analyze the expected input’s composition — the balance between structured elements (code, formal queries) and localized natural language.'),
            li('Robustness against injection', '', [
              li('Use clear delimiters (XML tags, triple backticks, or custom ones) to separate instructions from user input.'),
              li('Instruct the model to be wary of attempts to override its core instructions.'),
              li('Insert user input through placeholders or structured formats rather than direct concatenation.'),
              li('Use few-shot examples showing desired behavior and rejection of malicious requests.'),
            ]),
            li('Role definition', 'Clearly define the agent’s persona and purpose to anchor its behavior.'),
            li('Iterative refinement', 'Test prompts against known injection techniques and refine based on results.'),
            li('System prompt provenance', 'Design-time hardening proves nothing about runtime. At session init and defined checkpoints, verify the active system prompt’s hash against the approved version and alert on any change. Apply the same hash-and-verify to tool definitions and permission scopes — this also detects MCP "rug-pull" mutation of a tool after approval (Section 6).'),
          ),
        ],
      },
      {
        id: 'SAA-3.1.3',
        number: '3.1.3',
        title: 'Secure Coding Practices',
        group: '3.1 Secure Design & Development',
        summary: 'Standard secure coding, adapted: validate every input source, handle errors safely, manage secrets, least privilege.',
        blocks: [
          ul(
            li('Input validation', 'Validate all inputs — not just tool arguments, but user prompts, API responses, and data retrieved from memory. Use allowlists where possible.'),
            li('Error handling', 'Handle errors robustly without leaking sensitive information in messages.'),
            li('Secure key management', 'Never hardcode secrets. Use environment variables, dependency injection, or a secrets manager — e.g., dependency injection in AG2, InjectedToolArg in LangChain, AWS Secrets Manager, Google Secret Manager, HashiCorp Vault.'),
            li('Least privilege', 'Run every component with the minimum permissions necessary.'),
          ),
        ],
      },
      {
        id: 'SAA-3.1.4',
        number: '3.1.4',
        title: 'Content Moderation Integration (Design)',
        group: '3.1 Secure Design & Development',
        summary: 'Plan input/output moderation early: which checks, which tools, and what each verdict triggers.',
        blocks: [
          ul(
            li('Identify the checks you need: hate speech, PII, toxicity, specific disallowed topics.'),
            li('Evaluate tools against requirements — rule-based filters, ML classifiers, external APIs (e.g., Meta LlamaGuard, AWS Comprehend, Azure Content Safety, OpenAI Moderation API).'),
            li('Design how moderation results trigger actions: block, flag, sanitize, alert.'),
            li('Test moderation against your policies and for correctness.'),
          ),
        ],
      },
      {
        id: 'SAA-3.1.5',
        number: '3.1.5',
        title: 'Human-in-the-Loop (HITL) Design',
        group: '3.1 Secure Design & Development',
        summary: 'Decide where human approval is mandatory, make review usable, log decisions, and rate-limit to prevent approval floods.',
        threats: ['T10'],
        blocks: [
          ul(
            li('Risk-based identification', 'Identify actions that require approval: sending emails, modifying databases, executing code, spending funds, updating critical memory. Use the EU AI Act’s high-risk list to find further use cases needing human oversight.'),
            li('Clear workflow', 'Design a user-friendly review/approve/reject interface and log every human decision.'),
            li('Framework integration', 'Leverage built-in HITL features (e.g., LangChain interrupts, AutoGen UserProxyAgent, CrewAI human input).'),
            li('Rate limiting', 'Include strong rate limiting so a DoS cannot overwhelm human reviewers.'),
          ),
        ],
      },
      {
        id: 'SAA-3.1.6',
        number: '3.1.6',
        title: 'Memory Security Design',
        group: '3.1 Secure Design & Development',
        summary: 'Treat retrieved memory as untrusted, label provenance, encrypt, and know exactly what integrity checks can and cannot prove.',
        threats: ['T1', 'T3'],
        blocks: [
          ul(
            li('Access control', 'Restrict memory access with IAM roles, API keys, and database permissions on least privilege.'),
            li('Treat retrieved memory as untrusted', 'Preserve provenance and trust labels, authorize memory writes, validate structure and content as defense in depth, and reapply deterministic policy before retrieved data can influence a consequential action. Keyword or regex filtering is only a detection signal — never sanitization.'),
            li('Encryption', 'Encrypt at rest (databases/storage) and in transit (retrieval/updates).'),
            li('Input validation for memory', 'Validate and sanitize data before storing it, so malicious or corrupted data is not persisted (OWASP Input Validation Cheat Sheet).'),
            li('PII handling', 'Detect and redact or anonymize PII before storage (see runtime tooling in 3.3.2).'),
            li('Integrity & provenance — and their limits', 'Use HMACs or integrity hashing on records, tag every entry with provenance (source, author, timestamp, trust level), and scan for instruction-like patterns before persisting.'),
          ),
          callout('warning', 'Integrity checks detect unauthorized modification of a stored record. They do NOT prove the content is semantically safe, and they do not stop legitimately-written-but-poisoned content (e.g., "sleeper agent" instructions) from influencing later reasoning. A cryptographically intact record can still be malicious — pair integrity hashing with semantic validation and provenance/trust labeling.', 'Know the limit'),
          p('Treat poison planted now that triggers later on semantic similarity (temporal decoupling) as part of the threat model, and monitor for memory writes that originate from processed content rather than explicit user commands.'),
        ],
      },
      {
        id: 'SAA-3.1.7',
        number: '3.1.7',
        title: 'Input/Output Validation & Sanitization Design',
        group: '3.1 Secure Design & Development',
        summary: 'Two gates: context admission (before the model) and action execution (before the world). Schema conformance is not authorization.',
        threats: ['T2', 'T6', 'T11'],
        blocks: [
          p('Separate validation into two gates — they protect different things and run at different points in the loop:'),
          widget('validation-gates'),
          ul(
            li('Context admission validation', 'Applied before untrusted content enters the model context: user input, web pages, RAG results, tool/API outputs, MCP tool descriptions, and agent-to-agent messages. Goal: stop instruction-like or malicious content being admitted as if it were trusted instruction (2.7.1). Because fragmented, multi-layer injection payloads can evade content filters, prioritize schema enforcement and runtime isolation over content sanitization alone.'),
            li('Multimodal context admission', 'Apply the same trust and provenance policy to non-text modalities. OCR and speech-to-text turn untrusted media into another untrusted representation — they do not sanitize it, and a multimodal model may perceive content that extraction misses. Keep provenance linking media, metadata, and derived text; treat extraction and pattern scanning only as defense-in-depth signals; and process untrusted media in a no-tools or low-privilege component before modality-aware policy gates any downstream action.'),
            li('Action execution validation', 'Applied before anything affects the outside world: API calls, code execution, database writes, email/send actions, file writes, browser actions, and OS commands. Goal: confirm the action is authorized, in scope, and matches the agent’s declared intent.'),
          ),
          p('Practical approach:'),
          ul(
            li('Input sanitization and escaping', 'Escape or strip special tokens (e.g., ##, <<, {{ }}) before injecting user input into prompts, and avoid templates that concatenate raw user input into instructions.'),
            li('Schema enforcement', 'Define strict schemas for tool arguments and outputs (e.g., Pydantic, JSON Schema, OpenAI Structured Outputs) to constrain output and reduce reinterpretation or hallucinated instructions. Reject duplicate JSON member names and other ambiguous encodings before validation; parse once into a canonical typed structure such as {"actions":[{"type":"tell_joke"}]}; then separately authorize every normalized operation against the authenticated actor, intent, target, resource, and current policy at the execution sink. Schema conformance is not authorization.'),
            li('Allow/deny lists', 'Allowlist known-good values and denylist known-bad patterns in tool arguments or outputs.'),
            li('Output sanitization strategy', 'Neutralize potentially malicious content (scripts, HTML) before rendering or passing it on. Consider the context (browser vs. database), drop suspicious outputs, block payloads that don’t match the expected structure, and stop injected payloads from propagating or being reused by the agent or its environment. Use WAFs where possible and custom filters that enforce allowed fields/types/values without being over-restrictive.'),
            li('Secure rendering', 'Render agent output safely in UIs (e.g., element.textContent instead of element.innerHTML).'),
            li('Facilitate human review', 'In regulated scenarios, support HITL with JSON logs of outputs — easier to audit, automate review, track field-level anomalies, and correlate risk patterns.'),
            li('Multilingual adaptation', 'Minimize low-resource-language input, keep its proportion low by translation, or add English-equivalent content to the system prompt.'),
          ),
        ],
      },
      {
        id: 'SAA-3.1.8',
        number: '3.1.8',
        title: 'Authorization and Authentication',
        group: '3.1 Secure Design & Development',
        summary: 'Use existing identity infrastructure, treat DIDs as optional discovery (not proof), and vault short-lived tokens.',
        threats: ['T3', 'T9'],
        blocks: [
          ul(
            li('Identify permission boundaries', 'Examine agents and tools for expected actions and data reads; make sure they are coded to respect their permissions.'),
            li('Use identity providers and authorization servers', 'Reuse existing identity and authorization frameworks. Decide whether the agent acts as a business system or on behalf of a user and create the right identity type.'),
            li('Use Decentralized Identifiers only where interoperability requires them', 'A DID is an optional identifier and verification-method discovery mechanism; resolving it neither authenticates a caller nor authorizes an action. Require fresh proof of control with an allowed verification method; validate method-specific trust, issuer, audience, freshness, key rotation and recovery, and revocation/status; then apply application authorization to the requested action and resource.'),
            li('Credential providers & token vaults', 'When agents reach services in other trust domains (e.g., GitHub, external calendars), avoid persistent credential storage. Use a Token Vault pattern: agents retrieve short-lived, scoped tokens from a vault (e.g., HashiCorp Vault, AWS Secrets Manager) based on their verified identity and task. This prevents credential sprawl and pivoting across trust domains.'),
          ),
        ],
      },
      {
        id: 'SAA-3.2.0',
        number: '3.2',
        title: 'Secure Build & Deployment — overview',
        group: '3.2 Secure Build & Deployment',
        summary: 'Sandbox agent chains, snapshot capabilities, sign constraints, and support rollback.',
        blocks: [
          p('Productionizing agentic applications needs a robust, adaptive lifecycle. Development environments should sandbox agent chains to isolate failures, constrain tool usage through strict policy checks, and guard against memory corruption or drift. Deployment pipelines must go beyond packaging: snapshot agent capabilities, log audit trails, and embed signed constraints on tool/API usage and memory schema. Release protocols should support rollback, serialization integrity, and runtime enforcement of behavioral boundaries.'),
        ],
      },
      {
        id: 'SAA-3.2.1',
        number: '3.2.1',
        title: 'Static Analysis & Code Scanning (SAST)',
        group: '3.2 Secure Build & Deployment',
        summary: 'Scan every commit for insecure APIs, hardcoded secrets, and unsafe patterns.',
        blocks: [
          ul(
            li('Integrate SAST into CI/CD to scan on commit/merge.'),
            li('Focus on web vulnerabilities (where applicable), insecure API use, hardcoded secrets, and unsafe code patterns.'),
            li('Examples: Bandit (Python), Semgrep (multi-language), ESLint with security plugins (JavaScript), Meta PurpleLlama CodeShield (secure code generation).'),
          ),
        ],
      },
      {
        id: 'SAA-3.2.2',
        number: '3.2.2',
        title: 'Dependency Vulnerability Scanning (SCA)',
        group: '3.2 Secure Build & Deployment',
        summary: 'Find and patch known vulnerabilities in third-party libraries.',
        blocks: [
          ul(
            li('Integrate SCA tools into CI/CD or use package-manager features.'),
            li('Scan regularly and update libraries with known vulnerabilities.'),
            li('Examples: Snyk, GitLab Dependency Scanning, pip-audit, GitHub Dependabot.'),
          ),
        ],
      },
      {
        id: 'SAA-3.2.3',
        number: '3.2.3',
        title: 'Environment Hardening & Sandboxing',
        group: '3.2 Secure Build & Deployment',
        summary: 'Prefer deterministic isolation over probabilistic safety, and guarantee authorized_request == executed_request.',
        threats: ['T11', 'T3'],
        blocks: [
          ul(
            li('Sandboxing', 'Run agent code — especially LLM-generated code or execution tools such as Python interpreters — in isolated environments, balancing isolation against overhead:', [
              li('OS-level containers', 'Docker, Podman — a good balance for many applications.'),
              li('VM / microVM', 'Firecracker, QEMU/KVM — stronger isolation with separate kernels.'),
              li('WebAssembly (Wasm)', 'Memory safety; suitable for client-side or constrained server-side execution (NVIDIA Wasm blog).'),
              li('Sandboxed interpreters', 'e.g., Pyodide.'),
              li('Cloud sandboxing services', 'Managed secure execution environments (e.g., E2B).'),
              li('Research example', 'MITRE’s OCCULT framework uses a simulated CyberLayer to test LLM capabilities safely (arXiv:2502.15797).'),
            ]),
            li('Filesystem / network restrictions', 'Strict sandbox permissions: read-only filesystem where possible, limited egress/ingress.'),
            li('Principle of least privilege', 'Run agent processes with minimal OS-level privileges.'),
            li('Prefer deterministic boundaries over probabilistic safety', 'Prompt engineering is a best-effort layer, not a primary control; relying on the model to self-restrict is insufficient. Enforce isolation deterministically and outside the model: kernel isolation (gVisor, Firecracker, QEMU/KVM microVMs) rather than plain containers where the threat model warrants it; syscall restriction with seccomp / AppArmor / SELinux, plus eBPF for fine-grained syscall monitoring without kernel-module overhead; host-allowlisted egress filtering; and path isolation via mount namespaces, read-only volumes, and ephemeral tmpfs (runtime deployment in Section 9).'),
            li('Execution integrity', 'Passing identity, policy, and validation checks does not guarantee the approved action is still authorized when it executes. Treat authorized_request == executed_request as a semantic invariant (not byte-for-byte equality): bind a signed execution artifact to the authenticated actor and delegated subject, canonical action/tool, verified target and tenant/object, approved parameters, resource or state version, policy version, audience, expiry, and a unique transaction ID or nonce. Immediately before each side effect, the execution sink must authenticate the caller, reauthorize against current state and policy, and reject expired, replayed, revoked, stale, or materially changed artifacts.'),
          ),
        ],
      },
      {
        id: 'SAA-3.2.4',
        number: '3.2.4',
        title: 'Secure Configuration Management',
        group: '3.2 Secure Build & Deployment',
        summary: 'Secrets in dedicated managers with rotation, fine-grained API scopes, and IaC scanning.',
        blocks: [
          ul(
            li('Secrets management', 'Use dedicated systems (AWS Secrets Manager, Google Secret Manager, Vault) rather than config files or environment variables for sensitive data, and rotate credentials (OWASP Secrets Management Cheat Sheet).'),
            li('API access control', 'Use fine-grained access controls for external APIs — OAuth2 scopes, restricted API keys — granting only what is needed.'),
            li('Infrastructure as Code security', 'Scan IaC templates (Terraform, CloudFormation) for misconfigurations before deployment.'),
          ),
          { type: 'links', items: [{ label: 'OAuth 2.0 Scopes', url: 'https://oauth.net/2/scope/' }] },
        ],
      },
      {
        id: 'SAA-3.2.5',
        number: '3.2.5',
        title: 'Pre-deployment Testing (Fuzzing, Pen Testing)',
        group: '3.2 Secure Build & Deployment',
        summary: 'Fuzz the prompt interface and custom APIs, and pen-test the risks from your threat model.',
        blocks: [
          ul(
            li('Prompt interface fuzzing', 'Send malformed, unexpected, or adversarial inputs automatically to uncover injection vulnerabilities or unexpected behavior (e.g., PromptFoo, PyRIT, Garak).'),
            li('API fuzzing', 'Test any custom APIs exposed by the agent system.'),
            li('Targeted penetration testing', 'Manual or automated tests focused on the risks identified during threat modeling.'),
          ),
        ],
      },
      {
        id: 'SAA-3.3.0',
        number: '3.3',
        title: 'Secure Operations & Runtime — overview',
        group: '3.3 Secure Operations & Runtime',
        summary: 'Monitor decisions, plans, memory, and inter-agent communication — not just performance.',
        blocks: [
          p('Live agentic systems need behavioral monitoring far beyond performance metrics: decisions, plan evolution, memory access patterns, and agent–tool interactions. Behavioral drift — deviation from expected plans or tool misuse — must trigger alerts or safeguards. Agents should log timestamped reasoning traces for post-incident analysis, and operators must retain real-time override capabilities.'),
        ],
      },
      {
        id: 'SAA-3.3.1',
        number: '3.3.1',
        title: 'Continuous Monitoring & Anomaly Detection',
        group: '3.3 Secure Operations & Runtime',
        summary: 'Scan I/O, monitor tool calls and plans, watch memory and multi-agent behavior, and feed it all to a SIEM.',
        threats: ['T4', 'T8', 'T13'],
        blocks: [
          ul(
            li('LLM input/output scanning', 'Monitor prompts and responses for:', [
              li('Jailbreak techniques', 'Classifiers, heuristics (repetition, instruction overrides, role-play), or external APIs (LlamaGuard, NeMo Guardrails heuristics, OpenAI Moderation API).'),
              li('Policy violations', 'Against content policies (see 3.1.4).'),
              li('PII detection', 'Flag potential PII in inputs/outputs.'),
            ]),
            li('Tool invocation monitoring', 'Log all tool calls, parameters, and results; watch unusual frequency, suspicious parameters, or calls to sensitive tools. Rate-limit per session/user (LangChain max_iterations) and set timeouts (max_execution_time).'),
            li('Plan & execution monitoring', '', [
              li('Pre-execution checks', 'Validate generated plans for coherence, feasibility, safety, and policy alignment before execution, with rules or "LLM as a judge". Consider sandbox dry runs for high-risk actions.'),
              li('Runtime monitoring', 'Watch code execution inside sandboxes for forbidden actions (network calls, file-system writes).'),
            ]),
            li('Memory anomaly detection', 'Monitor memory updates for unusual frequency, size, or content indicating poisoning or tampering.'),
            li('Behavioral analysis (multi-agent)', 'Monitor communication patterns and actions between agents for collusion, manipulation, or unexpected emergent behavior.'),
            li('SIEM integration', 'Centralize logs and alerts for analysis and correlation.'),
          ),
        ],
      },
      {
        id: 'SAA-3.3.2',
        number: '3.3.2',
        title: 'Runtime Guardrails & Automated Moderation',
        group: '3.3 Secure Operations & Runtime',
        summary: 'Where guardrails sit determines what they can see; plus inter-agent filtering, memory hygiene, safe rendering, and CSP.',
        blocks: [
          ul(
            li('Input/output guardrails', 'Real-time checks that block or sanitize based on rules: prompt-injection and jailbreak detection, keyword blocking, pattern matching, policy enforcement (e.g., NeMo Guardrails, OpenAI Agents SDK custom guardrails, commercial vendors).'),
            li('Locate guardrails', 'Proximity to the application code and LLM changes detection effectiveness. A network-based guardrail (API or AI gateway) may miss multi-turn prompt injection because it lacks session history; guardrails inside the application/agent code have the most visibility and context.'),
          ),
          widget('guardrail-placement'),
          ul(
            li('Content filtering (inter-agent / tool)', 'Sanitize data exchanged between agents or with tools/APIs to stop harmful or covert content or commands propagating; filter at the orchestrator or message handoff points (e.g., redact non-printable characters).'),
            li('Memory TTL / expiration', 'Expire stale memory automatically so sensitive data does not persist needlessly.'),
            li('Memory sanitization & PII redaction', '', [
              li('Safe memory wrappers', 'Encode past actions in markup/JSON so models treat them as data.'),
              li('Read-only buffers', 'Split memory into read/write areas — e.g., system instructions are read-only.'),
              li('Sanitize before storing and before replying', 'Validate with libraries and standard techniques (escaping, allowlisting), and clean memory buffers before replying (e.g., profanity filters).'),
              li('PII removal before storage', 'Regex for structured PII, NER models (spaCy), dedicated services (Microsoft Presidio SDK).'),
              li('Selective deletion', 'Consider memory tools that support it (Mem0, Zep).'),
            ]),
            li('Output sanitization for UI', 'Sanitize before rendering in a web UI to prevent XSS; configure strictly and test bypasses (OWASP XSS Cheat Sheet; e.g., DOMPurify, sanitize-html).'),
            li('Limit data subjects in context', 'Purge memory when the context switches data subjects to avoid leakage, contamination, and bias.'),
            li('Context window', 'Bound how far back a model can recall or query past conversations.'),
            li('Content Security Policy (CSP)', 'Use CSP headers as defense in depth to restrict script sources, styles, and destinations (OWASP CSP Cheat Sheet). Agents that interact directly with websites may introduce new vulnerabilities or unknowingly execute malicious code, so CSP limits the blast radius.'),
          ),
        ],
      },
      {
        id: 'SAA-3.3.3',
        number: '3.3.3',
        title: 'Logging, Auditing & Traceability',
        group: '3.3 Secure Operations & Runtime',
        summary: 'Session-scoped, structured, trace-ID-linked logs of reasoning, plans, tool calls, HITL decisions, and state changes.',
        threats: ['T8'],
        blocks: [
          ul(
            li('Session scoping', 'Tag memory buffers by session ID or user identity (JWT, OAuth, …).'),
            li('Comprehensive logging', 'Reasoning steps, generated plans, validation results, tool calls with parameters/results, HITL interactions and decisions, errors, and state changes.'),
            li('Structured logging', 'JSON or similar for automated parsing.'),
            li('Traceability', 'Trace IDs propagated through agent steps and tool calls to reconstruct execution.'),
            li('Centralized platforms', 'ML/LLM observability such as MLflow, Langfuse, LangSmith, Azure agent monitoring, AWS Bedrock trace events.'),
          ),
        ],
      },
      {
        id: 'SAA-3.3.4',
        number: '3.3.4',
        title: 'Vulnerability Scanning (Runtime)',
        group: '3.3 Secure Operations & Runtime',
        summary: 'Keep scanning the running environment and feed findings into patch management.',
        blocks: [
          ul(
            li('Run periodic infrastructure vulnerability scans.'),
            li('Integrate findings into a patch management process.'),
            li('Use DAST against lower environments for APIs and common interfaces (e.g., OWASP ZAP).'),
            li('Use port and CVE scanners for environment endpoints.'),
          ),
        ],
      },
      {
        id: 'SAA-3.3.5',
        number: '3.3.5',
        title: 'Incident Response Planning',
        group: '3.3 Secure Operations & Runtime',
        summary: 'Define agent incidents, containment steps, roles — and rehearse them.',
        blocks: [
          ul(
            li('Define what constitutes an incident: a successful prompt injection causing harm, a data breach via the agent, unauthorized agent actions.'),
            li('Outline containment (disable the agent, restrict tool access), analysis (logs and monitoring data), remediation, and reporting.'),
            li('Assign roles and responsibilities.'),
            li('Test the plan regularly with tabletop exercises and fire drills.'),
          ),
          p('Embedding these practices across design, development, deployment, and operations yields more robust and trustworthy agentic systems; security is an ongoing process that adapts to new threats.'),
        ],
      },
      {
        id: 'SAA-3.3.6',
        number: '3.3.6',
        title: 'AI Bot Mitigation and Controls',
        group: '3.3 Secure Operations & Runtime',
        summary: 'Verifiable agent identity is the admission ticket to the agentic web: a multi-factor identity bundle and declared intent.',
        threats: ['T9'],
        blocks: [
          p('Why identity matters: bots already buy tickets, snipe prices, and trade. AI agents go further — they reason in real time and chain high-impact actions such as checkouts, fund transfers, cloud provisioning, or spawning other agents. A spoofed agent identity lets attackers siphon data, commit fraud, or inject malicious commands into your pipeline.'),
          p('A tamper-proof agent identity layer lets site owners allow, throttle, or block each request; lets other agents and APIs verify the caller before sharing data; and keeps the builder’s runtime safe from hostile automation and off bot-mitigation blocklists. Verifiable identity is the admission ticket to the agentic web — neglect it and your agent is treated as just another threat.'),
          table(
            ['Layer', 'What to do', 'Why it resists spoofing', 'Readiness & strength'],
            [
              ['Stable network & UA metadata', 'Serve from a documented IP range with a verbose User-Agent, plus optional headers X-AI-Agent, X-AI-Agent-ID / Signature.', 'Helps mitigation systems correlate requests with the cryptographic identity.', 'Good but not enough: proven for good bots for a decade, yet not bulletproof (shared IPs, spoofable UA).'],
              ['Cryptographic request signing', 'Sign every HTTP request with RFC 9421 HTTP Message Signatures; expose the verification key at /.well-known/agent-public-key.json. Web-bot-auth is an emerging IETF protocol supporting it.', 'Keys cannot be forged without compromise.', 'Great against spoofing and MITM, but still early-stage.'],
              ['Agent Name Service (ANS)', 'Publish an ANSName encoding protocol, capability, provider, and version; register the name and public key in an open Agent Registry.', 'Standardized, PKI-backed lookup prevents collisions and impersonation.', 'Spec v1.0 published; pilot registries and tooling emerging. Ideal for a complete handshake.'],
            ],
            'Adopt a multi-factor identity bundle — no single signal is sufficient on its own.',
          ),
          p('Implementing the full bundle establishes a trust-rich handshake between your agent and every online asset it touches, clarifying intent and giving both sides precise control.'),
          p('Industry observations: the HTTP Message Signatures + mTLS pattern is now used for production-grade bot verification; LOKA’s Universal Agent Identity Layer and the open-source Agent Network Protocol (ANP) both point toward a PKI-backed model with capability attestations.'),
          ol(
            li('Identify transparently', 'Ship the identity bundle on every request: a declarative User-Agent, your own IP addresses where possible, and a cryptographic mechanism. Adopt ANS once available.'),
            li('Declare intent, respect policy', 'The more an agent states its intent, the easier it is for mitigation services to allow it. Advertise purpose via X-Agent-Intent (crawl, pay, assist, …).'),
            li('Anticipate the next trust tier', 'Authenticated agents will present a stable agent ID, tag each session uniquely, and build a verifiable reputation downstream systems can query.'),
          ),
          p('Authentication and authorization guidance lives in 3.1.8, 4.1.1, 4.2.2 (OBO delegation & intent binding), and the agent-identity cross-cut in 2.7.2.'),
        ],
      },
      {
        id: 'SAA-3.3.7',
        number: '3.3.7',
        title: 'Security Hooks (Enforcement Points)',
        group: '3.3 Secure Operations & Runtime',
        summary: '18 interception points in the agent loop, five dispositions, fail-closed — wire toolCallRequest and agentResponse first.',
        blocks: [
          p('Guardrails, logging, HITL, memory protection, tool execution control, and circuit breakers only become enforceable if the harness exposes reliable interception points. A hook is a point in the agent’s code-level execution loop where a builder can wire logic that observes an action and returns a disposition before it takes effect. Hooks are a mechanism, not a policy engine: the hook is the interception point; the guardrail/policy is the logic that runs there.'),
          callout('key', 'A guardrail that cannot observe a tool call before it executes is documentation, not a defense.'),
          p('Dispositions — what a hook returns when it can decide: Allow, Deny, Modify, Escalate (HITL), Defer. When it cannot decide (error, timeout, unreachable enforcement service), the action must fail closed — denied or escalated, never allowed by default. A hook that fails open can be bypassed by anyone able to make it fail.'),
          widget('hooks'),
          callout('info', 'Framework coverage is uneven. Input interception, tool-call request/result, and agent response are close to universal across major SDKs. Memory read/write, knowledge retrieval, sub-agent lifecycle, and context-compaction hooks are sparse and inconsistent, and no framework yet exposes a skill-lifecycle hook (a skill load is caught today only because it runs as a tool call). Assess which events your framework can intercept, identify the gaps, and prioritize closing them.'),
          p('Where to start — if you wire only two hooks, wire toolCallRequest and agentResponse:'),
          ul(
            li('toolCallRequest', 'Closes the gap between "agent decides to call a tool" and "tool executes" — the gap exploited by data-exfiltration injection — and is where to inspect model-generated arguments for directory traversal and unvalidated symlinks before a high-privilege write.'),
            li('agentResponse', 'Covers the next most damaging failure: unfiltered sensitive data reaching the user.'),
            li('memoryStore (next)', 'Cross-session poisoning depends on writing tainted content to persistent memory unreviewed. Without a native hook, screen tainted content where it enters (tool results, retrieved content, user input) and at any memory write that runs through a tool call.'),
          ),
          p('Specify per-call vs. per-batch semantics for toolCallRequest, and streaming-disposition semantics for agentResponse.'),
          p('Make hooks a hard boundary. A prompt-layer guardrail ("do not call this tool without approval") is a soft boundary the model can ignore under pressure. A code-layer hook can be hard — but only when two conditions hold:'),
          ol(
            li('Coverage', 'It sits on every path to a consequential action. Coverage fails quietly. Enumerate sensitive leverage points during design and testing and confirm each sits behind a hook. Paths that often escape: direct LLM or tool API calls outside the harness; sub-agents in separate processes; MCP servers calling downstream services; tool-initiated callbacks; browser or code-execution environments; background jobs; external plugins writing to memory; and streaming output released before inspection. For paths entirely outside the harness, fall back to controls that don’t rely on the model: credential scoping, network-egress controls, sandboxing, and server-side authorization (Section 9).'),
            li('Resistance to manipulation', 'The decision cannot be subverted through the channel it polices. A deterministic rule cannot be argued with; a trained classifier scores the input rather than following it; an LLM-as-judge is only as strong as its criteria. Where the decision is manipulable, back the action with a firmer control.'),
          ),
          p('Make the hook surface explicit: a harness that enumerates the hooks it implements (and, by omission, those it does not) turns a silent gap into a declared one. Treat the implemented hook set as part of the harness interface.'),
          callout('warning', 'Observe-only frameworks: where native hooks only observe (e.g., LangChain, LlamaIndex callbacks), you cannot enforce fail-closed through the callback bus. Hard-code enforcement into synchronous wrapper classes around the underlying tool utilities or model clients.'),
          p('Build it in, and log it. Hooks are an architectural decision, not a later bolt-on; even with an allow-all-with-logging policy, the hook points should exist from version one. Map the work: Design — trust boundaries and the hooks each needs; Implementation — wire hooks into the loop; Testing — exercise critical disposition paths; Pre-release review — verify no sensitive path bypasses a hook; Deployment readiness — hook logs carry policy version, hook version, action metadata, and disposition reason codes. Every invocation should emit a structured entry (hook point, action, disposition, timestamp) — the audit trail 3.3.3 requires falls out of the architecture.'),
          p('See Section 9 for hooks as runtime enforcement points.'),
        ],
      },
      {
        id: 'SAA-3.3.8',
        number: '3.3.8',
        title: 'Behavioral Circuit Breakers / Kill Switches',
        group: '3.3 Secure Operations & Runtime',
        summary: 'Detection without automated response at agent speed is "just expensive logging": graduated, schema-driven breakers per component.',
        threats: ['T13', 'T7'],
        blocks: [
          p('A behavioral circuit breaker is a real-time, in-line runtime policy engine that can interrupt a misaligned agent faster than a human. It is not a binary switch: it escalates through graduated tiers (warn → limit → suspend → kill), can act on one sub-agent or the whole system, and notifies external agents, tools, and MCP servers in use. Management can be centralized for coherence while enforcement stays decentralized for speed.'),
          widget('circuit-breaker'),
          callout('warning', 'Common failure modes to design against: high-impact actions misclassified as low-risk; approval logic bypassed through an alternate workflow path; agents retrying failed actions and amplifying harm; irreversible actions with no rollback; and monitoring that only detects issues after the damage is done.'),
        ],
      },
    ],
  },

  // ── Chapter 4 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH4',
    number: '4',
    title: 'Enhanced Security Actions for Agentic AI Systems',
    shortTitle: 'By Architecture',
    tagline: 'What differs for single-agent, orchestrated multi-agent, and swarm systems.',
    sections: [
      {
        id: 'SAA-4.0',
        number: '4',
        title: 'Scope of this chapter',
        summary: 'Generic controls live in Section 3; this chapter covers the architecture-specific deltas.',
        blocks: [
          p('Generic controls that apply to every agentic system — authentication, authorization, data protection, code security, monitoring, logging, and prompt security — are the lifecycle backbone in Section 3. This chapter focuses on what differs by architecture: single-agent, central-orchestrator, and swarm systems (orchestrator trust boundaries, inter-agent authentication, peer-to-peer communication). The single-agent baseline (4.1) is retained from V1 as a reference checklist; where it overlaps with Section 3, Section 3 is authoritative.'),
        ],
      },
      {
        id: 'SAA-4.1.1',
        number: '4.1.1',
        title: 'Authentication & Authorization',
        group: '4.1 Single-Agent Systems',
        summary: 'OAuth 2.0/OIDC with PKCE, managed identities, RBAC, least privilege, read/write separation, just-in-time credentials.',
        blocks: [
          ul(
            li('Implement OAuth 2.0 / OIDC', 'Use the authorization code flow with PKCE when a user interacts through a native app or single-page web interface (preventing client-secret leakage or token extraction), or when the agent is a client to a web server without a client secret. Require explicit consent through a screen listing the specific permissions. Resource: Auth0 OAuth 2.0 implementation guide.'),
            li('Use managed identity services', 'Use cloud identity services instead of embedded credentials — AWS IAM roles or Azure Managed Identities avoid storing secrets. Resource: AWS IAM roles for Amazon EC2.'),
            li('Apply role-based access control (RBAC)', 'Define granular roles per agent function (e.g., only certain roles — user, dev, admin — may read/write system memory) and keep permission matrices. Resource: NIST RBAC standards.'),
            li('Grant only the minimum necessary permissions', 'Give agents only what their tasks need, and audit assignments regularly.'),
            li('Distinguish read and write access', 'Separate them, default to read-only, and grant write explicitly when needed. Resource: AWS IAM policy best practices.'),
            li('Consider just-in-time credential issuance', 'Temporary credentials with limited scope and lifetime, issued only when needed and expiring quickly; for cross-domain authentication apply the Token Vault pattern (3.1.8). Resource: HashiCorp Vault.'),
          ),
        ],
      },
      {
        id: 'SAA-4.1.2',
        number: '4.1.2',
        title: 'Data Protection',
        group: '4.1 Single-Agent Systems',
        summary: 'Encrypt, deploy DLP, label data deterministically by classification, and minimize what the agent touches.',
        blocks: [
          ul(
            li('Encrypt sensitive data', 'TLS 1.2+ in transit and AES-256-GCM at rest. Resource: NIST cryptographic standards.'),
            li('Implement Data Loss Prevention (DLP)', 'Monitor and prevent leakage; scan inputs/outputs for PII, credentials, and other sensitive data. Resource: OpenDLP.'),
            li('Use data classification and sensitivity labels', 'Labels guide how the agent accesses and handles data. Data is accessed deterministically and compared with the agent’s clearance — e.g., HIPAA data cannot be accessed by a non-HIPAA-compliant agent. Use tiers such as public, internal, confidential, restricted. Resource: Microsoft Information Protection.'),
            li('Apply data minimization', 'Collect and process only what the task needs; use data-flow diagrams to find unnecessary collection. Resource: GDPR data minimization principle.'),
          ),
        ],
      },
      {
        id: 'SAA-4.1.3',
        number: '4.1.3',
        title: 'Code Security',
        group: '4.1 Single-Agent Systems',
        summary: 'Security-scanning pipelines, AI-aware code review, and dependency monitoring.',
        blocks: [
          ul(
            li('Establish automated testing pipelines', 'CI/CD with SAST, DAST, and SCA. Resource: OWASP DevSecOps Guideline.'),
            li('Conduct thorough code reviews', 'Automated and manual reviews before deployment, with AI-specific checklists. Resource: OWASP Code Review Guide.'),
            li('Monitor dependencies', 'Continuously check external libraries and alert automatically. Resource: GitHub Dependabot.'),
          ),
        ],
      },
      {
        id: 'SAA-4.1.4',
        number: '4.1.4',
        title: 'Monitoring & Incident Response',
        group: '4.1 Single-Agent Systems',
        summary: 'Baseline behavior, detect anomalies in real time, alert, plan responses, and build off-switches.',
        blocks: [
          ul(
            li('Log all actions and establish baselines', 'Comprehensive activity logs and behavioral baselines. For sensitive operations, keep a chain-of-thought log classified at the highest data level involved in generating it. Resource: Cloud Security Alliance logging guidelines.'),
            li('Implement real-time anomaly detection', 'ML-enabled SIEM and systems that identify deviations from normal operation. Resource: Awesome Anomaly Detection.'),
            li('Set up alerts for suspicious events', 'Alert on access attempts to sensitive endpoints, request spikes, and unusual IP origins. Resource: PagerDuty incident response documentation.'),
            li('Develop incident response plans', 'Containment, investigation, remediation, and recovery steps. Resource: NIST Computer Security Incident Handling Guide.'),
            li('Build emergency off-switches', 'Kill switches that immediately revoke access, with automated and manual mechanisms to stop agent operations. Resource: Anthropic AI safety research.'),
          ),
        ],
      },
      {
        id: 'SAA-4.1.5',
        number: '4.1.5',
        title: 'Prompt Security',
        group: '4.1 Single-Agent Systems',
        summary: 'Validate inputs, filter outputs, harden system prompts, and sanitize everything.',
        blocks: [
          ul(
            li('Implement input validation', 'Rule-based patterns, NLP techniques, or multimodal filtering; check for malicious patterns before processing (WAF rules). Resource: guide to LLM prompt-injection defenses.'),
            li('Apply content filtering on AI outputs', 'Screen generated responses with pattern matching and ML classifiers. Resource: Perspective API.'),
            li('Harden system prompts', 'Embed security policies in the foundational instructions and structure prompts to reject harmful requests. Resource: OpenAI system message guidelines.'),
            li('Sanitize all inputs', 'Clean and normalize inputs; remove or escape special characters and formatting that could alter behavior. Resource: OWASP Input Validation Cheat Sheet.'),
          ),
        ],
      },
      {
        id: 'SAA-4.2.1',
        number: '4.2.1',
        title: 'Authentication & Authorization (orchestrated)',
        group: '4.2 Multi-Agent Systems with Central Orchestrator',
        summary: 'Separate control planes, apply the user-privilege pattern, authenticate every interaction, restrict discovery.',
        threats: ['T9', 'T3'],
        blocks: [
          p('A multi-agent system has several intelligent agents interacting with each other and a shared environment; they act independently, perceive, decide, and act. The central orchestrator coordinates interactions, assigns tasks, and maintains the overall workflow or state.'),
          ul(
            li('Apply the authentication and authorization controls from 4.1.1.'),
            li('Establish separation of control planes', 'Clearly separate agent functionalities; use the user-privilege assumption pattern (2.3.1) to enforce user permissions on an agent; keep a distinct least-privilege permission set per agent. Resource: AWS separation of control and data planes.'),
            li('Authenticate and verify all agent interactions (see 4.2.3).'),
            li('Restrict discovery to known and trusted servers', 'Hard-code discovery servers in agent instructions and block communication with other discovery servers through network and logical controls.'),
          ),
        ],
      },
      {
        id: 'SAA-4.2.2',
        number: '4.2.2',
        title: 'Orchestrator Security',
        group: '4.2 Multi-Agent Systems with Central Orchestrator',
        summary: 'Harden the orchestrator API, prevent control-flow hijacking and confused deputies, and formalize OBO delegation with intent binding.',
        threats: ['T6', 'T9', 'T3'],
        blocks: [
          ul(
            li('Harden the central orchestrator’s API', 'Robust authentication and authorization, rate limiting, input validation, detailed logging. Resource: OWASP API Security Top 10.'),
            li('Protect against control-flow hijacking', 'Validate agent responses so they cannot manipulate the orchestrator’s decisions; integrity-check operational metadata and outputs. Resource: MITRE ATLAS.'),
            li('Mitigate the "confused deputy" problem', 'Prevent trusted components being tricked into unauthorized actions with additional context validation and cross-checks.'),
            li('Formalize On-Behalf-Of (OBO) delegation and intent binding', '', [
              li('Delegate user authority via OAuth 2.0 Token Exchange (RFC 8693), never raw user credentials. Issue short-lived, task-bound, audience-bound tokens; each sub-agent or intermediary performs its own exchange.'),
              li('Enforce delegation depth limits and monotonic scope attenuation: each hop’s token is a proper subset of its parent’s, with decaying TTL and cascade revocation.'),
              li('Bind authorization to the declared user intent for the current task and deny actions outside it — even if permission and capability would allow them. The orchestrator passes a signed, immutable, intent-locked task descriptor that sub-agents cannot rewrite mid-chain. This is the structural mitigation for the confused deputy problem.'),
              li('For MCP/OAuth proxy architectures, avoid static client IDs (vulnerable to consent-cookie reuse via dynamically registered malicious clients): use per-client consent storage and an MCP-level consent UI with CSRF protection, and prohibit token passthrough.'),
            ]),
          ),
          widget('obo-chain'),
        ],
      },
      {
        id: 'SAA-4.2.3',
        number: '4.2.3',
        title: 'Inter-Agent Communication',
        group: '4.2 Multi-Agent Systems with Central Orchestrator',
        summary: 'mTLS, verified agent identity, secure queues, policy enforcement points, and rate limits.',
        threats: ['T12', 'T9'],
        blocks: [
          ul(
            li('Implement secure communication protocols', 'Strong encryption for all interactions and mutual TLS (mTLS) for two-way authentication.'),
            li('Verify the identity of each communicating agent', 'Certificate- or token-based authentication. Resource: JWT authentication best practices.'),
            li('Use secure message queuing systems', 'Brokers with authentication and encryption (RabbitMQ, Kafka, NATS) for asynchronous communication.'),
            li('Deploy Policy Enforcement Points (PEPs)', 'Security checkpoints on communication channels, implemented as middleware or service proxies that validate each interaction.'),
            li('Apply rate limiting for agent interactions', 'Limit request frequency between agents and use exponential backoff for failed requests. Resource: GitHub API rate limiting.'),
          ),
        ],
      },
      {
        id: 'SAA-4.2.4',
        number: '4.2.4',
        title: 'Trust Boundaries',
        group: '4.2 Multi-Agent Systems with Central Orchestrator',
        summary: 'Zero trust, network segmentation and agent isolation, and containerized agents.',
        blocks: [
          ul(
            li('Apply Zero Trust principles', '"Never trust, always verify" across the architecture; verify every request regardless of source. Resource: NIST SP 800-207.'),
            li('Implement network segmentation and agent isolation', 'Distinct security zones; limit interconnectedness to contain breaches. Resource: NSA network segmentation guidance.'),
            li('Use containerization', 'Sandbox individual agents with Docker or similar and restrict OS/system resource access. Resource: Docker security best practices.'),
          ),
        ],
      },
      {
        id: 'SAA-4.3.1',
        number: '4.3.1',
        title: 'Authentication & Authorization (swarm)',
        group: '4.3 Multi-Agent Systems with Swarm Architecture',
        summary: 'Assign trust outside the agentic flow and keep humans in control of swarm membership.',
        blocks: [
          ul(
            li('Use the controls from 4.1.1 and 4.2.1.'),
            li('Identify trusted agents and actions', 'Swarms lack an obvious guide post for the correct action and trusted collaborators: assign trust and permitted actions outside the agentic flow, and limit or prevent the swarm from adding new agents without human guidance.'),
          ),
        ],
      },
      {
        id: 'SAA-4.3.2',
        number: '4.3.2',
        title: 'Decentralized Identity & Trust',
        group: '4.3 Multi-Agent Systems with Swarm Architecture',
        summary: 'DIDs and Verifiable Credentials for peer trust, reputation systems — and Sybil-resistance.',
        threats: ['T9', 'T13'],
        blocks: [
          ul(
            li('Implement Decentralized Identifiers (DIDs)', 'W3C DIDs for self-sovereign agent identities, verifiable without a central authority. Resource: W3C DID specification.'),
            li('Use Verifiable Credentials (VCs)', 'Agents prove specific attributes, capabilities, or authorizations. Resource: W3C Verifiable Credentials Data Model.'),
            li('Create decentralized reputation systems', 'Agents earn reputation from behavior, used for collaboration trust decisions. Resource: OpenCerts.'),
            li('Guard against Sybil-inflated reputation', 'Cheap identities can vouch for each other to inflate a malicious agent’s score faster than genuine behavior would. Pair reputation with a minting-cost control: staking, a human-sponsored first credential, or rate-limited DID registration.'),
          ),
          p('How it fits together:'),
          ul(
            li('Agent identity', 'Each agent has its own DID — a persistent, verifiable identity across interactions and environments.'),
            li('Credential-based trust', 'VCs establish capabilities, permissions, or trust level.'),
            li('Inter-agent authentication', 'Agents verify each other’s identities and credentials without central coordination.'),
            li('Provenance tracking', 'DIDs help trace the origin of information or actions.'),
            li('Access control', 'VCs determine which agents can access which resources or capabilities.'),
            li('Role specialization', 'Credentials formalize roles (e.g., reasoning agent, retrieval agent).'),
          ),
          callout('info', 'Per 3.1.8, a DID is an identifier and discovery mechanism — resolving one does not by itself authenticate or authorize. Always require fresh proof of control and application-level authorization.'),
        ],
      },
      {
        id: 'SAA-4.3.3',
        number: '4.3.3',
        title: 'Secure Peer-to-Peer Communication',
        group: '4.3 Multi-Agent Systems with Swarm Architecture',
        summary: 'Pick P2P protocols deliberately and require both encryption and authentication.',
        blocks: [
          ul(
            li('Select appropriate P2P protocols', 'Based on security and performance needs: TLS/SSL, DTLS, the Noise Protocol, or specialized frameworks. Resource: Noise Protocol Framework specification.'),
            li('Ensure both encryption and authentication', 'Strong encryption for confidentiality and robust authentication of participants. Resource: NIST SP 800-175B.'),
          ),
        ],
      },
      {
        id: 'SAA-4.4',
        number: '4.4',
        title: 'Cross-Architecture Security Considerations',
        summary: 'Secure agent APIs, continuous testing, architecture-aware monitoring, and integrity-checked updates.',
        blocks: [
          ul(
            li('Secure API design for agent communication', 'Standardized interfaces with comprehensive input validation; rate limiting and authentication regardless of architecture. Resource: OWASP API Security Top 10.'),
            li('Continuous security testing', 'Regular automated and manual testing of every architecture. Resource: NIST security testing guidelines.'),
            li('Security monitoring and threat detection', 'Comprehensive monitoring with detection tuned to each architecture. Resource: MITRE ATT&CK.'),
            li('Secure agent updates and maintenance', 'Secure update mechanisms and integrity verification before deployment. Resource: NIST Secure Software Development Framework.'),
          ),
        ],
      },
    ],
  },

  // ── Chapter 5 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH5',
    number: '5',
    title: 'Key Operational Capabilities',
    shortTitle: 'Capabilities',
    tagline: 'Classify every capability, then apply controls for APIs, code, databases, web, computers, and critical systems.',
    sections: [
      {
        id: 'SAA-5.0',
        number: '5.0',
        title: 'Capability Control Matrix',
        summary: 'Classify each capability on sensitivity, untrusted input, and external reach — the Rule of Two made concrete.',
        blocks: [
          p('Connecting agents to APIs, databases, code interpreters, browsers, or the OS unlocks great functionality — and each connection brings its own risks, from data breaches and illegal actions to system compromise. Before applying per-capability controls, classify every capability the agent holds. If one agent’s capabilities together cover untrusted input + sensitive data + external communication, the design must add sandboxing, HITL, runtime monitoring, or architectural separation — or remove a leg (2.7.3).'),
          widget('capability-matrix'),
          p('For each capability also record the required telemetry (what must be logged) and an escalation trigger — the condition that forces HITL, throttling, or a circuit-breaker action (3.3.8).'),
          ul(
            li('Trigger', 'A declared effect annotation moving in the permissive direction (e.g., destructiveHint changing from true to false).'),
            li('Binding requirement', 'When a gate consumes an effect annotation, bind the declaration to the contract it was declared against. Treat an absent annotation as unobserved, not safe.'),
          ),
        ],
      },
      {
        id: 'SAA-5.1',
        number: '5.1',
        title: 'KC6.1 – API Access',
        summary: 'Least-privilege scopes, allow/deny lists for destinations, and templates instead of fully LLM-generated calls.',
        threats: ['T3', 'T4', 'T2', 'T9'],
        blocks: [
          p('Core threats: unauthorized data access/leakage (T3); API abuse — DoS, cost overruns (T4, T2); compromised keys (T3, T9).'),
          ol(
            li('Enforce least privilege with fine-grained OAuth scopes or limited API keys', 'Define the minimum activities needed (never give an agent an admin’s full access); grant access only to essential assets and issue tokens only to the clients/agents that need them.', [
              li('OAuth 2.0', 'Specific scopes via Okta, Auth0, Keycloak, or cloud-provider services; SDKs such as Authlib or Passport.js.'),
              li('API keys', 'Provider limits — e.g., AWS API Gateway restrictions to specific stages/methods, IP restrictions, read-only access.'),
              li('Cloud IAM', 'For agents running as cloud services (AWS Lambda, Google Cloud Functions), assign restricted IAM roles.'),
            ]),
            li('Set up allow/deny lists for APIs', 'Prevent manipulation via prompt injection or compromised tools by defining authorized domains or URL paths: configure permitted base URLs or patterns; check target URLs against the list before requests; use an egress proxy or API gateway that allows only pre-approved destinations; and apply network policies to containerized agents.'),
            li('Prefer API templates over fully LLM-generated calls', 'Reduce unsafe or malformed calls and improve reliability by hard-coding unchanging fields.'),
            li('Best practices', '', [
              li('Use prepared templates where the LLM only fills established parameters (e.g., Jinja2).'),
              li('Use structured output with strictly defined schemas; define parameter types and requirements before sending.'),
              li('Sanitize web-fetched content (e.g., DOMPurify) and apply a Content Security Policy when rendering it.'),
            ]),
          ),
        ],
      },
      {
        id: 'SAA-5.2',
        number: '5.2',
        title: 'KC6.2 – Code Execution',
        summary: 'Mandatory sandboxing, static analysis of generated code, resource limits, and HITL for high-risk operations.',
        threats: ['T11', 'T3', 'T2', 'T4', 'T6'],
        blocks: [
          p('Core threats: arbitrary code execution (T11, T3); code injection (T11, T2); DoS via resource exhaustion (T4); leakage of confidential information (T6).'),
          ol(
            li('Implement mandatory sandboxing', 'OS-level isolation, containers, VMs, WebAssembly, or cloud solutions — e.g., NVIDIA’s WebAssembly sandboxing, LangChain’s E2B data analysis.'),
            li('Perform static analysis on agent-generated code', 'Bandit (Python), Semgrep (multi-language), CodeShield (LLM-generated code).'),
            li('Enforce resource limitations', 'Strict CPU, memory, and execution-time limits; timeouts for all operations.'),
            li('Additional measures', 'Code signing or verification where possible; strict filesystem and network restrictions; command allowlists; HITL approval for high-risk operations; sanitize all execution output; runtime monitoring during execution.'),
          ),
        ],
      },
      {
        id: 'SAA-5.3',
        number: '5.3',
        title: 'KC6.3 – Database Execution (Queries and RAG)',
        summary: 'Access-controlled vector stores, parameterized queries only, least-privilege accounts, and RAG-specific filtering.',
        threats: ['T2', 'T3', 'T1', 'T5'],
        blocks: [
          p('Core threats: SQL injection (T2); unauthorized data exposure/modification (T3); RAG data poisoning and sensitive data retrieval (T1, T5, T3).'),
          ol(
            li('Use managed vector databases with access controls', 'Never ingest data that cannot be protected from unauthorized users; apply classification labels to enforce user privilege — e.g., RBAC-aware RAG (Elastic), Pinecone with authentication platforms such as Clerk, or authorization platforms such as Aserto.'),
            li('Implement query safety measures', 'Parameterized or templated queries/ORMs only — never build SQL by string concatenation; least-privilege database accounts (SELECT only, limited tables, row/column-level security); filter dangerous keywords (DROP, TRUNCATE); validate inputs influencing queries and, where possible, derive them from controlled channels rather than the context window.'),
            li('RAG-specific controls', 'Post-retrieval filtering for sensitive content (PII) before agent use; content verification before embedding into vector stores; rate-limit retrieval operations.'),
            li('Limit excessive retrieval', 'Bound how much data any query can return (the source lists this control as a heading without further detail).'),
          ),
        ],
      },
      {
        id: 'SAA-5.4',
        number: '5.4',
        title: 'KC6.4 – Web Use',
        summary: 'Sandboxed browsers, URL security, SSRF segmentation, content inspection, and full logging.',
        threats: ['T11', 'T6', 'T7', 'T2', 'T3'],
        blocks: [
          p('Core threats: malicious web content — XSS, exploits (T11); leakage of confidential information (T6); phishing/deception (T7); Server-Side Request Forgery (T2, T3); access to the user’s browser data / sensitive data exposure (T3).'),
          ol(
            li('Sandbox browser components', 'Run in tightly controlled environments; avoid extensions or operating directly in the user’s browser.'),
            li('Implement URL security', 'Allowlist URL filtering; Secure Web Gateway (SWG) or DLP; domain reputation checks; strict TLS verification; detect and block open redirects or excessive redirect chains; add DNS-based filtering on top of HTTP-level filtering.'),
            li('Apply protective measures', 'Network segmentation to block internal systems (mitigating SSRF); throttle web access; restrict downloadable file types; sanitize content before processing; inspect embedded/linked content (iframes, JS-injected sources).'),
            li('Logging and monitoring', 'Log all URL accesses and HTTP responses.'),
          ),
        ],
      },
      {
        id: 'SAA-5.5',
        number: '5.5',
        title: 'KC6.5 – Controlling PC Operations (Filesystem, OS Commands)',
        summary: 'Strict isolation, command/path allowlists, no data accumulation, and full oversight of OS actions.',
        threats: ['T3', 'T11', 'T2'],
        blocks: [
          p('Core threats: unauthorized file access/modification (T3); arbitrary OS command execution (T11, T3, T2); lateral movement (T3).'),
          ol(
            li('Apply strict isolation', 'OS-level sandboxing; run as restricted users; consider dedicated containers or VMs.'),
            li('Implement access controls', 'Strict allow/deny lists for OS operations and file paths; virtual filesystem interfaces where appropriate; intercept OS command calls to enforce allowlists.'),
            li('Limit accumulation of sensitive data', 'A sandbox should not accumulate data and sessions, so it stays a sandbox.'),
            li('Enhance monitoring and oversight', 'Log all OS-level actions; consider HITL for critical operations; validate commands before execution.'),
          ),
        ],
      },
      {
        id: 'SAA-5.5.1',
        number: '5.5.1',
        title: 'Coding & Computer-Use Agent Guardrails',
        summary: 'Coding and computer-use agents are a Lethal Trifecta by definition — repo config is an untrusted supply-chain vector.',
        threats: ['T2', 'T3', 'T11'],
        blocks: [
          callout('warning', 'Coding agents and "computer use" agents are, by definition, a Lethal Trifecta (2.7.3): they process untrusted input (repositories, issues, web pages, screens), hold sensitive data (credentials, source, git, CI/CD, authenticated sessions), and can communicate externally. They need the controls below in addition to the general KC6.5 controls.'),
          ul(
            li('Treat repository-level configuration as an untrusted, execution-layer supply-chain vector', 'Files such as CLAUDE.md, .cursorrules, .github/copilot-instructions.md, mcp.json, and .cursorignore travel inside cloned/forked/shared repos and can control agent behavior (system prompts, allowed tools, MCP connections) before any trust dialog. Documented cases include a repo settings file redirecting the model API endpoint to an attacker (capturing requests and credentials) and a modified .cursorignore exposing credential files. Treat user-level config as trusted and repo-level config as untrusted; require user approval before repo-provided instructions or config can take effect; integrity-check MCP server configs.'),
            li('Command permission model', 'Default-deny plus an allowlist. Make allow/deny lists for commands, file paths, and network operator-configurable (not only developer-set). Check that a command is grounded in session intent before running it, and escalate to HITL instead of blanket-blocking the session. Use risk-based HITL to avoid approval fatigue.'),
            li('Restricted git / destructive-operation safety', 'Prevent destructive operations (force push, reset --hard, DROP TABLE), protect branch policies, and require commit signing.'),
            li('Path & credential hygiene', 'Use .ignore-style configs to keep credentials out of context and long-term memory; detect "toxic combinations" (sensitive-file access plus an external tool call in one session); validate arguments for directory traversal and symlinks before high-privilege writes.'),
            li('Repo isolation / sandboxing', 'Clone, read, and modify repositories in an OS- or cloud-VM-isolated sandbox (kernel-isolated filesystem and execution, restricted inbound/outbound network); make tools "sandbox-aware"; define permission-inheritance rules for sub-agents and worktrees.'),
            li('Session isolation for browser/computer use', 'Use dedicated browser profiles instead of the user’s authenticated sessions, and redact screenshots / sensitive on-screen output.'),
            li('Dry-run / preview', 'Preview risky operations before committing them, and intercept agent-to-LLM and agent-to-tool I/O via hooks (3.3.7) to scan for jailbreaks, sensitive data, malicious code/URLs, and drift between an action and prior intent.'),
          ),
        ],
      },
      {
        id: 'SAA-5.6',
        number: '5.6',
        title: 'KC6.6 – Operating Critical Systems (e.g., SCADA)',
        summary: 'Maximum isolation, out-of-band MFA, attention-worthy mandatory HITL, read-only defaults, and physical interlocks.',
        threats: ['T2', 'T3', 'T6', 'T7', 'T1', 'T5'],
        blocks: [
          p('Core threats: catastrophic physical outcomes (T2, T3, T6, T7); malicious control injection (T2, T6); false data influencing decisions (T1, T5).'),
          ol(
            li('Apply maximum isolation', 'Air-gapped or highly segmented networks plus physical security measures.'),
            li('Enforce multi-factor authentication', 'Require MFA for sensitive actions through an external flow — never let the agent mediate the MFA flow or retain a privileged session. Make HITL mandatory for every critical action, and succinct and engaging enough to keep the user’s attention each time (excessive or inefficient prompting leads to indiscriminate approval).'),
            li('Implement safety mechanisms', 'Default agent permissions to read-only monitoring; anomaly detection tuned to system safety parameters; adhere to industrial control security standards; ensure physical interlocks and emergency overrides exist.'),
          ),
        ],
      },
    ],
  },

  // ── Chapter 6 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH6',
    number: '6',
    title: 'Agentic AI and the Supply Chain',
    shortTitle: 'Supply Chain',
    tagline: 'Code, models, prompts, registries, and the MCP/skill tool lifecycle — from onboarding to anti rug-pull.',
    sections: [
      {
        id: 'SAA-6.1.1',
        number: '6.1.1',
        title: 'Third-party libraries & frameworks',
        group: '6.1 Code Security',
        summary: 'Standard supply-chain hygiene still applies.',
        blocks: [
          ul(
            li('Standard supply-chain practices apply.'),
            li('SCA scanning.'),
            li('Hashes and package locks for third-party versioning.'),
            li('SBOMs.'),
            li('Validate licenses and provenance of third-party libraries before installing.'),
          ),
        ],
      },
      {
        id: 'SAA-6.1.2',
        number: '6.1.2',
        title: 'LLM / agent-generated code',
        group: '6.1 Code Security',
        summary: 'Sandbox it, validate its packages, and gate high-risk execution.',
        threats: ['T11'],
        blocks: [
          ul(
            li('Sandbox any agent-generated or agent-run code (3.2.3).'),
            li('Validate packages before running generated code (beware hallucinated or "slopsquatted" names).'),
            li('Use HITL for high-risk code execution.'),
          ),
        ],
      },
      {
        id: 'SAA-6.2.1',
        number: '6.2.1',
        title: 'LLM / logic system',
        group: '6.2 Environments & Development',
        summary: 'Same models across environments and verified model provenance.',
        blocks: [
          ul(
            li('Use the same LLMs in lower environments and production for reliability.'),
            li('Verify the provenance of LLMs from public registries (e.g., Hugging Face) by checking hashes and contributors.'),
            li('Use LLM and SCA scanners for third-party package vulnerabilities and security issues in LLM code where applicable.'),
          ),
        ],
      },
      {
        id: 'SAA-6.2.2',
        number: '6.2.2',
        title: 'Version control & code management',
        group: '6.2 Environments & Development',
        summary: 'Version models, logic, prompts, and data.',
        blocks: [
          ul(
            li('Version-control LLMs and logic systems to track behavior.'),
            li('Version-control prompts and instructions for reliability and auditability.'),
            li('Use commit IDs and hashes for data changes.'),
          ),
        ],
      },
      {
        id: 'SAA-6.2.3',
        number: '6.2.3',
        title: 'Permission management',
        group: '6.2 Environments & Development',
        summary: 'Agents must not be able to modify the pipelines that build them.',
        threats: ['T3'],
        blocks: [
          ul(
            li('Don’t give agents access to the repositories or data sources that build or deploy them.'),
            li('Manage permissions to data sources outside the environments the agent runs in.'),
            li('Change agent IAM/role permissions through code so changes are reviewed.'),
          ),
        ],
      },
      {
        id: 'SAA-6.3.1',
        number: '6.3.1',
        title: 'Agent Cards',
        group: '6.3 Agent & Tool Discovery',
        summary: 'Minimize trust in unvalidated agents and treat changed cards as re-approval triggers.',
        threats: ['T9'],
        blocks: [
          ul(
            li('Identify trust relationships through agent cards and descriptions; minimize trust in unvalidated agent systems.'),
            li('Use DIDs for agent verification and authentication (with fresh proof of control, 3.1.8).'),
            li('Apply the tool-definition integrity controls (6.4.3) to agent cards: pin the card by digest at first trust, re-fetch and compare on a schedule, and treat a changed card as a re-approval trigger rather than a silent update.'),
          ),
        ],
      },
      {
        id: 'SAA-6.3.2',
        number: '6.3.2',
        title: 'Local vs. remote agent registries',
        group: '6.3 Agent & Tool Discovery',
        summary: 'Separate registries, separate private from public, and pin trust.',
        blocks: [
          ul(
            li('Put a logical or network barrier between local and remote registries to prevent registry confusion and accidental boundary traversal.'),
            li('Classify and separate private and public agents, data, and actions; prevent sharing data or acting across these boundaries.'),
            li('Use trust relationships and controls such as certificate pinning so agents only talk to approved registries and environments.'),
          ),
        ],
      },
      {
        id: 'SAA-6.4.1',
        number: '6.4.1',
        title: 'Standardized Provenance Record',
        group: '6.4 Tool Lifecycle & MCP-Specific Supply-Chain Controls',
        summary: 'One provenance schema for tools, skills, and memory so trust decisions are uniform.',
        blocks: [
          p('This section covers the supply chain for the tools an agent uses — including MCP servers and Agent Skills. The goal is actionable build/runtime control, not an AI-BOM or compliance artifact. MCP is treated as a tool-integration profile of KC5.'),
          p('All components should implement a unified Provenance Record so runtime enforcement and monitoring treat trust decisions uniformly across tools, skills, and memory:'),
          table(
            ['Field', 'Meaning'],
            [
              ['source_id', 'Unique identifier for the origin (e.g., server URI, repository URL).'],
              ['author', 'Verified publisher or entity identity (e.g., DID, signing principal).'],
              ['timestamp', 'ISO-8601 time the artifact was created or captured.'],
              ['trust_level', 'Categorical classification (System, Vetted, User, Untrusted).'],
              ['integrity_hash', 'Cryptographic digest (SHA-256 or better) of the artifact content.'],
              ['last_verified_at', 'Time of the most recent validation against the source.'],
            ],
          ),
        ],
      },
      {
        id: 'SAA-6.4.2',
        number: '6.4.2',
        title: 'Tool onboarding & catalog governance',
        group: '6.4 Tool Lifecycle & MCP-Specific Supply-Chain Controls',
        summary: 'Vetted registry, onboarding checks, an admission gate, and a signed, version-pinned manifest.',
        threats: ['T2'],
        blocks: [
          widget('tool-lifecycle'),
          ul(
            li('Vetted registry', 'Maintain an internal registry of approved tools/MCP servers and block direct pulls from public repositories in production. Tool/server "squatting" and "slopsquatting" (names a model is likely to hallucinate or suggest) make open registries an active attack surface.'),
            li('Onboarding checks', 'For each server/tool: SAST-scan its code, produce an SBOM of its dependencies, and run it in a behavioral sandbox to confirm it performs only its advertised function. Verify publisher identity and prefer canonical sources.'),
            li('Admission gate', 'Require a security review before any new tool is added; test tool updates in staging; actively decommission unused tools.'),
            li('Signed, version-pinned catalog manifest', 'Server URI, tool name, and approval timestamp, signed with a key held outside the agent runtime and stored in version control. Each entry follows the Standardized Provenance Record (6.4.1). An unsigned or unverifiable manifest is a deployment-gate failure.'),
          ),
        ],
      },
      {
        id: 'SAA-6.4.3',
        number: '6.4.3',
        title: 'Tool definition integrity (anti "rug-pull")',
        group: '6.4 Tool Lifecycle & MCP-Specific Supply-Chain Controls',
        summary: 'Pin by hash, re-verify every session, never "approve once, trust forever", and watch for catalog drift.',
        threats: ['T2'],
        blocks: [
          ul(
            li('Pin tool descriptions and schemas by cryptographic hash', 'At first registration. Re-hash at every session start and catalog refresh, compare with the pinned values, and block execution when a live definition no longer matches its approved digest.'),
            li('Mismatch handling', 'A mismatch blocks the tool pending operator re-approval, with an alert including the diff. Explicit re-approval triggers: a change to a tool’s name, schema, or description; a change to the server’s TLS certificate; the hostname resolving to a new address; or a changed tool list.'),
            li('Approval TTL', 'Never carry "approved" status across session boundaries — "approve once, trust forever" is the vulnerability. Apply a maximum approval TTL; expiry triggers automatic re-validation, not silent re-approval.'),
            li('Freshness of the evidence', 'Record, next to every pinned digest, the observation timestamp and the age of the source snapshot at approval. An approval is only as fresh as its input. Audit staleness has two independent causes: subject drift after judgment (which digest pinning catches) and instrument lag at judgment — when the evaluation postdates the last time the judged text was published — which stays invisible to models that assume the scanner sees the present.'),
            li('Catalog-drift detection', 'Alert when a server adds, removes, renames, or changes tools even if no approved definition changed, and keep an append-only catalog audit log.'),
          ),
        ],
      },
      {
        id: 'SAA-6.4.4',
        number: '6.4.4',
        title: 'Treat tool descriptions and responses as adversarial input',
        group: '6.4 Tool Lifecycle & MCP-Specific Supply-Chain Controls',
        summary: 'Scan for tool poisoning, isolate descriptions from each other, schema-validate every response.',
        threats: ['T2', 'T6'],
        blocks: [
          ul(
            li('Scan every tool name, description, and input/output schema for hidden instructions before admitting it to context (Tool Poisoning) and reject tools that fail', 'Baseline patterns: injection delimiters (<IMPORTANT>, IGNORE PREVIOUS), cross-tool orchestration phrases ("before using this tool…"), credential/path references, exfiltration patterns, base64 blobs, zero-width Unicode. Show the operator the full description at registration, not just the tool name.'),
            li('Enforce strict isolation between tool descriptions', 'A description must not reference, modify, or condition behavior on other tools (Cross-Tool Shadowing).'),
            li('Validate every tool response against the approved schema before it enters the model context', 'A non-conforming response must not enter context. MCP tool responses are a primary indirect-prompt-injection surface.'),
          ),
          callout('key', 'Pattern/regex sanitization is insufficient as the primary defense: fragmented multi-layer payloads evade filters and reassemble at the sink. Prioritize schema enforcement and runtime isolation over content sanitization.'),
        ],
      },
      {
        id: 'SAA-6.4.5',
        number: '6.4.5',
        title: 'Asset Access Control Matrix',
        group: '6.4 Tool Lifecycle & MCP-Specific Supply-Chain Controls',
        summary: 'Authoritative read/write boundaries for credentials, configuration, and identity assets.',
        threats: ['T3'],
        blocks: [
          p('To prevent data exfiltration and configuration hijacking, police access to sensitive security assets. Any deviation from these boundaries must trigger a behavioral circuit breaker (3.3.8).'),
          table(
            ['Entity', 'Credential assets (API keys, OAuth tokens, JIT credentials)', 'Configuration assets (mcp.json, model config, skill manifests)', 'Identity assets (DIDs, signing keys, service accounts)'],
            [
              ['MCP servers / tools', 'Read: ephemeral/scoped only. Write: PROHIBITED.', 'Read: own config only. Write: PROHIBITED (rug-pull protection).', 'Read: PROHIBITED. Write: PROHIBITED.'],
              ['Agent skills (packages)', 'Read: per-manifest scope. Write: PROHIBITED.', 'Read: sandbox-scoped. Write: signed updates only.', 'Read: PROHIBITED. Write: prohibited outside the registry.'],
              ['Model / LLM context', 'Read: masked/redacted. Write: PROHIBITED.', 'Read: masked/redacted. Write: PROHIBITED.', 'Read: public metadata only. Write: PROHIBITED.'],
              ['Orchestrator / proxy', 'Read: full (vault-backed). Write: full (audit-logged).', 'Read: full (hash-pinned). Write: admin-only.', 'Read: internal registry. Write: signing service only.'],
            ],
          ),
        ],
      },
    ],
  },

  // ── Chapter 7 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH7',
    number: '7',
    title: 'Assuring Agentic Applications',
    shortTitle: 'Assurance',
    tagline: 'From design scope to runtime evidence: red teaming, behavioral testing, custom benchmarks, and revalidation.',
    sections: [
      {
        id: 'SAA-7.0',
        number: '7.0',
        title: 'Assurance as Lifecycle Validation',
        summary: 'Design-time assurance first, then validation that the design holds — testing has nothing to falsify until assumptions are named.',
        blocks: [
          callout('info', 'This guide excludes red-teaming playbooks: methodology, attack recipes, and benchmark-tool catalogs belong to the OWASP ASI Red Teaming Guide (see also the GenAI Red Teaming Manual in this app). This chapter focuses on lifecycle validation — tying assurance back to intended scope, assumptions, threat model, controls, behavioral tests, runtime monitoring, and regression triggers.', 'Scope of this chapter'),
          p('The chapter follows the lifecycle in two halves: design-time assurance (architecture and configuration choices that bound what an agent can do before it runs) and validation that the design holds (red teaming, 7.1, and behavioral testing, 7.2). The order is deliberate: testing has nothing to falsify until the design has named its own assumptions.'),
          widget('assurance-chain'),
        ],
      },
      {
        id: 'SAA-7.0.1',
        number: '7.0.1',
        title: 'Assurance objective',
        group: '7.0 Assurance as Lifecycle Validation',
        summary: 'A risk-based, evidence-backed case that the design assumptions hold — not proof of perfect safety.',
        blocks: [
          p('The objective is to determine whether an agentic application is sufficiently constrained, tested, and monitored to operate within its intended scope. Assurance does not prove an application perfectly safe; it establishes a risk-based, evidence-backed case that its design assumptions hold under realistic and adversarial conditions.'),
          p('It applies familiar software-assurance practices — requirements traceability, control validation, regression testing, release evidence, change-impact analysis, and production monitoring: define what the system should do, identify what it must not do, implement controls, test whether they hold, and revalidate the affected parts when behavior-defining elements change.'),
          p('The assurance scope is the actual application being assessed — its purpose, trust boundaries, data flows and access, tools, memory, orchestration, identity model, integrations, deployment context, and operational controls — not a generic agent pattern, whether it is a simple single-agent workflow or a complex system with delegation, tool chains, retrieval, long-running state, or external protocols.'),
        ],
      },
      {
        id: 'SAA-7.0.2',
        number: '7.0.2',
        title: 'Definitions',
        group: '7.0 Assurance as Lifecycle Validation',
        summary: 'Intended scope, behavior-defining element, harness, configuration constraint — and the behavioral tuple.',
        blocks: [
          ul(
            li('Intended scope', 'What the application is for: its purpose, the behavior it should and should not exhibit, the data and tools it may use, and the trust boundaries within which these hold. It must be precise — "act as a helpful assistant" cannot be configured, tested, or monitored. A reviewer must be able to decide for any action whether it falls within the boundary, including capability compositions that stay out of scope even when each capability is individually permitted (2.7.3).'),
            li('Behavior-defining element', 'Any configurable element whose change may invalidate a prior design assumption, control, or test result: the model (KC1), system instructions, the tool/integration set (KC5), memory architecture and retrieval sources (KC4), orchestration and workflow logic (KC2, KC3), permission and identity scopes, and deployment/environment controls (KC6). A change to any of them triggers the partial replay in 7.0.5.'),
            li('Harness', 'All behavior-defining elements other than the model. It decides which decision points the model meets and what context each sees; the model’s outputs in turn set the harness’s next state. The application is the joint product of model and harness — which is why the trajectory, not any single decision, reflects the system as built (7.2.1 b).'),
            li('Configuration constraint', 'The specific value assigned to a behavior-defining element at design time (enabled tools, permitted memory scope, permission boundary). Intended scope states what the application should do; configuration constraints are how the design enforces it.'),
          ),
          callout('info', 'A proposed "KC7 – Behavioral Observation & Evidence" is kept as an evidence/observability concept, not a new key component. Its behavioral tuple — a structured record of one agent action capturing agent identity, session context, triggering input, reasoning step, action taken, state change, active policy context, and timestamp — is the audit record produced by the logging and hook instrumentation in 3.3.3 and 3.3.7, and the foundation for custom benchmarks (7.2.1).', 'Note on evidence (no new KC)'),
        ],
      },
      {
        id: 'SAA-7.0.3',
        number: '7.0.3',
        title: 'The assurance case',
        group: '7.0 Assurance as Lifecycle Validation',
        summary: 'Declared assumptions + validation evidence + runtime evidence + change traceability, owned by an accountable person.',
        blocks: [
          p('An application reaches an acceptable assurance state when its intended scope is explicitly defined, its design constraints are documented, its main risk paths are understood, its controls are linked to tests that can validate or challenge those assumptions, and its known limitations and residual risks are documented and accepted by an accountable owner. The assurance case combines:'),
          ul(
            li('Declared design assumptions', 'The scope, trust boundaries, capability constraints, and threat model the system was designed against.'),
            li('Validation evidence', 'Structured, traceable proof that those assumptions were tested under conditions that could falsify them.'),
            li('Runtime evidence', 'Continuous, queryable proof that the controls encoding those assumptions remain live and correct in production.'),
            li('Change traceability', 'A record of how the assurance case was updated when the system changed.'),
          ),
          p('Assurance is the connective layer of the guide: architecture defines boundaries, developer controls implement them, capability controls constrain high-risk actions, supply-chain controls preserve the integrity of behavior-defining artifacts, deployment controls enforce runtime limits, and monitoring detects drift. Section 7 asks whether the complete system still behaves within the scope it was designed to satisfy. It does not prescribe red-team playbooks, general model evaluation, accuracy benchmarks, compliance mappings, or governance processes.'),
        ],
      },
      {
        id: 'SAA-7.0.4',
        number: '7.0.4',
        title: 'Design-time assurance scoping',
        group: '7.0 Assurance as Lifecycle Validation',
        summary: 'Explicit, testable statements: capability boundaries, trust boundaries, threat assumptions, safe failure states, environment assumptions.',
        blocks: [
          p('Before testing begins, the design must produce explicit, testable statements of what the system should do, what it must not do, and under which conditions — the targets red teaming and behavioral validation will try to falsify:'),
          ul(
            li('Intended capability boundaries', 'For each capability exposed through KC5 and reachable in KC6, state what the agent is and is not permitted to do.'),
            li('Trust-boundary declarations', 'For each input source (user prompts, tool results, memory retrievals, inter-agent messages, web content), the assigned trust level and the controls applied before it influences reasoning or action.'),
            li('Threat assumptions', 'Which ASI T&M threats are mitigated, which are accepted as residual risk, which are out of scope — the reference for red-team prioritization.'),
            li('Safe failure states', 'For each high-risk capability, what the agent does when a control returns DENY/ESCALATE, when a tool call fails, or when a plan cannot be validated.'),
            li('Operational-environment assumptions', 'Any deployment assumption that, if violated, would invalidate the controls.'),
          ),
          callout('key', 'These statements are the living reference for every assurance activity, versioned alongside the codebase. When the system changes, update the scope first.'),
        ],
      },
      {
        id: 'SAA-7.0.5',
        number: '7.0.5',
        title: 'Design-to-validation handoff and revalidation triggers',
        group: '7.0 Assurance as Lifecycle Validation',
        summary: 'A contract from design to findings — and the changes that force a partial replay.',
        blocks: [
          p('Red teaming and behavioral validation are the means by which the design is challenged, not independent after-the-fact activities. The handoff is a contract:'),
          ol(
            li('Design', 'Defines the intended boundary and expected in-scope behavior.'),
            li('Threat modeling', 'Identifies how that boundary may fail.'),
            li('Controls', 'Are selected to prevent, reduce, detect, or contain those failures.'),
            li('Red teaming', 'Attempts to falsify the assumptions behind the controls.'),
            li('Behavioral validation', 'Checks the application stays useful within scope — doing authorized work reliably without overstepping or defensively blocking legitimate requests.'),
            li('Findings', 'Become remediation, regression tests, monitoring signals, or design updates.'),
          ),
          p('If a design assumption cannot be linked to a control, test, or monitoring signal, it is an unsupported assumption rather than part of the assurance case. These changes must trigger explicit revalidation of the affected scope elements — a partial replay of the affected design checks, red-team scenarios, and behavioral cases, not necessarily a full retest:'),
          ul(
            li('Any new tool integration or expansion of KC6 operational capabilities.'),
            li('Any change to memory architecture (a KC4 type change).'),
            li('Any modification to trust-boundary assignments for input sources.'),
            li('Any update to system prompts or agent instructions.'),
            li('Any change to orchestration logic or workflow transitions (KC2).'),
            li('Any infrastructure change affecting environment assumptions.'),
            li('Any incident or anomaly suggesting a declared mitigation did not operate as designed.'),
            li('Background catalog drift: tools or skills appearing, disappearing, or being renamed in the MCP catalog without explicit human intervention.'),
            li('Changes to third-party declarations the assurance case relies on (tool effect annotations, agent card claims, skill manifest permissions), including declarations that have aged past their evidence window.'),
          ),
          callout('warning', 'Document each scoping decision and its rationale. An undocumented decision to skip revalidation is itself an assurance gap.'),
        ],
      },
      {
        id: 'SAA-7.1',
        number: '7.1',
        title: 'Red Teaming Agentic Applications',
        summary: 'Why agents need continuous red teaming, plus frameworks for tool manipulation, privilege escalation, and memory poisoning.',
        threats: ['T1', 'T3', 'T6'],
        blocks: [
          p('Three properties make agentic systems hard to validate by design review alone:'),
          ul(
            li('Non-deterministic', 'The same input may not reliably produce the same output, so a passing test is one sample of possible behavior (one industry study ran a temperature-zero prompt 1,000 times and saw 80 distinct completions).'),
            li('Behavior emerges at runtime', 'Tool use, memory, autonomy, external data, and accumulated state create execution paths that only appear in context.'),
            li('Real-world consequences', 'When an agent invokes tools, accesses data, or acts with delegated privileges, a failure may be an unauthorized action, not just a wrong answer.'),
          ),
          p('Integrate red teaming across the lifecycle — pre-deployment, on material change to model/prompt/tool surface/data access/permission boundary, and on a regular cadence between changes — not as a one-time launch gate. For techniques, prompts, tools, and playbooks, refer to the OWASP ASI / CSA Agentic AI Red Teaming Guide and the OWASP GenAI Red Teaming Guide.'),
          p('Red teaming simulates adversarial attacks from a single application up to the whole organization’s security infrastructure. For agents it must cover complex interactions, autonomous decisions, and external integrations: not only prompt injection, but privilege escalation through tools, memory poisoning, and plan manipulation. The OWASP ASI Red Teaming Guide offers a risk-based methodology spanning model review, implementation testing, infrastructure assessment, and runtime behavior analysis, with cross-functional coordination (data science, cybersecurity, ethics, legal) and continuous improvement.'),
          ul(
            li('Prompt injection', 'Altered input causes unauthorized actions, sensitive data leakage, or guardrail bypass. Red-teaming tools such as Promptfoo can automate many prompt variants; continuous, proactive testing is needed to anticipate new tactics. (The ASI Red Teaming Guide lists tools and datasets in its Appendix B.)'),
            li('Privilege escalation', 'Gaining illegitimate higher control. Agent autonomy widens the scope — inter-agent relationships and external integrations can be leveraged, affecting the application, its infrastructure, and the connected agencies that reach external systems.'),
            li('Memory poisoning', 'Through short-term memory (poisoned context in the prompt) or long-term memory and knowledge bases that influence decisions. AgentPoison and ASB use memory-poisoning attacks to surface these weaknesses, with a high rate of poisoned-data retrieval.'),
          ),
          table(
            ['Tool', 'Description', 'URL'],
            [
              ['AgentDojo', 'Dynamic framework evaluating prompt-injection attacks and defenses for LLM agents, with targeted injections instructing the agent to perform malicious tasks using its tools.', 'https://agentdojo.spylab.ai/'],
              ['Agentic Radar', 'Analyzes agentic systems for security and operational insight, helping developers and researchers understand how they work and find vulnerabilities.', 'https://github.com/splx-ai/agentic-radar'],
              ['Agent-SafetyBench', 'Benchmark of prompts/situations assessing whether LLM agents follow safety norms and avoid damaging, unethical, or risky content or actions.', 'https://github.com/thu-coai/Agent-SafetyBench'],
              ['AgentFence', 'Red-team tool with attack scenarios for prompt injection, role confusion, and system-instruction leakage.', 'https://github.com/agentfence/agentfence'],
              ['Agent Security Bench (ASB)', 'Red-team scenarios including Direct and Indirect Prompt Injection, Plan-of-Thought backdoors, and memory poisoning.', 'https://github.com/agiresearch/ASB'],
              ['MAPS (Multilingual Benchmark for Agent Security)', 'Multilingual adaptation of well-known agentic benchmarks (such as ASB) translated into 10 languages.', 'https://huggingface.co/datasets/Fujitsu-FRE/MAPS'],
              ['AgentPoison', 'Injects malicious instances into the knowledge base or memory, retrieved when specific triggers appear in the query.', 'https://arxiv.org/abs/2407.12784'],
            ],
            'Frameworks targeting agentic key components (tool-call manipulation, privilege escalation, memory poisoning)',
          ),
        ],
      },
      {
        id: 'SAA-7.2',
        number: '7.2',
        title: 'Behavioral Testing for Agentic Applications',
        summary: 'Does the agent stay in scope during normal use? Five failure modes that need no attacker — and why over-refusal is a failure too.',
        blocks: [
          p('From a security perspective, behavioral testing measures whether the agent stays within its intended scope across representative in-scope usage, complementing red teaming’s adversarial probing of the same boundary. It surfaces failures that require no attacker:'),
          ol(
            li('Scope drift', 'Gradual departure from the intended boundary on routine inputs.'),
            li('Silent composition', 'Individually permitted actions that compose into an out-of-scope outcome.'),
            li('Encoding gaps', 'Declared constraints never correctly translated into operational controls.'),
            li('Over-restriction', 'Blocking or escalating legitimate in-scope requests.'),
            li('Control miscalibration', 'A binding guardrail, classifier, or policy control wrongly permits out-of-scope behavior or blocks legitimate behavior because its decisions are inaccurate or poorly calibrated.'),
          ),
          callout('key', 'An agent that over-refuses has failed its intended scope as surely as one that oversteps it. Persistent refusal may signal an encoding failure or a miscalibrated control rather than caution. Behavioral testing makes the security–utility trade-off measurable; its output is evidence, not a score: behavior categorized as in-scope, under-restrictive, or over-restrictive, each finding traceable to a design assumption and, where possible, its root control failure.'),
          p('Behavioral testing evaluates activities and interactions rather than only structure or code, uncovering unexpected actions, logic errors, or pursuit of harmful goals. It needs explicit objectives, benchmark datasets and metrics, simulations in controlled environments under varying conditions, and both human and automated assessment.'),
          ul(
            li('Benchmarks', 'Standardize evaluation with tasks, datasets, and metrics:', [
              li('AgentBench', 'Task-solving across operating systems, databases, and knowledge graphs; assesses planning, decision-making, and tool use.'),
              li('HELM (Stanford)', 'Accuracy, robustness, fairness, bias, and toxicity across standardized scenarios, with insight into truthfulness and potential harms.'),
              li('WebArena & The Agent Company', 'Autonomous agents in realistic web environments: navigation, form filling, retrieval, adapting to dynamic sites.'),
            ]),
            li('Evaluation frameworks', 'Systematize objectives, test selection, execution, and analysis against positive and negative behavioral standards:', [
              li('Google GenAI evaluation service', 'Evaluate any generative model or application against your own criteria.'),
              li('Amazon Bedrock Evaluations', 'Evaluate LLMs, including integration with external sources such as RAG.'),
            ]),
          ),
          callout('warning', 'General-purpose benchmarks (AgentBench, HELM, WebArena, …) give a useful baseline but are not designed to validate a deployed system and should not be primary assurance evidence: (1) generic context — they ignore your capability set, trust boundaries, and environment, so a high scorer may still over- or under-refuse against your boundaries; (2) no capability composition — they test capabilities in isolation and don’t model the lethal trifecta; (3) scores, not evidence — a score isn’t traceable to a design assumption. Use them for pre-deployment sanity checks, regression detection after model/prompt changes, and as templates for custom benchmarks — and state these limits when reporting.', 'Limits of general-purpose benchmarks'),
        ],
      },
      {
        id: 'SAA-7.2.1',
        number: '7.2.1',
        title: 'Custom Benchmark Construction',
        group: '7.2 Behavioral Testing',
        summary: 'Action-based and trajectory-based benchmarks built from your own scope — the path, not the endpoint, is the unit.',
        blocks: [
          p('A custom benchmark answers what a generic one cannot: is this agent refusing requests it should permit? Permitting actions it should block? Behaving correctly at the edges of its declared capability scope?'),
          p('a) Action-based construction — start from the behavioral tuple (7.0.2): the tuple provides the observation structure, the benchmark classifies whether a behavior was correct, incorrect, over-restrictive, or under-restrictive for this deployment.'),
          ol(
            li('Sample from the design-time scope (7.0.4)', 'Generate cases from capability boundaries, trust-boundary declarations, and threat assumptions; each targets a specific boundary (a permitted capability, a prohibited one, an untrusted source, a safe failure state).'),
            li('Classify expected tuples', 'For each case, define the expected action_taken and state_delta for correct behavior, and what over-/under-refusal would look like. This is the benchmark specification.'),
            li('Execute and compare', 'Run cases against the deployed agent, collect actual tuples, and compare field by field — reasoning step, policy context, and state delta, not just the final output.'),
            li('Classify failures by type', 'Security failures (permitted what should be blocked — under-refusal), usability failures (blocked what should be permitted — over-refusal), and instrumentation failures (incomplete tuple — a coverage gap, not an agent problem). Over-refusal often signals that capability boundaries weren’t correctly encoded into controls.'),
            li('Integrate into CI/CD', 'A change to behavior-defining elements that shifts behavior against declared boundaries should block release like a failing security test (see 7.0.5).'),
          ),
          p('b) Trajectory-based construction — classifying one action tests instruction-following at one decision, not whether the path stayed in scope. Two security-relevant properties are invisible at the single-action level: harness steering (the path is the joint product of model and harness) and composition (permitted actions composing into an out-of-scope outcome — the lethal trifecta is a property of a path). A trajectory is the ordered sequence of steps (reasoning, tool selection, memory read/write, output) with each resulting state change and active policy context; the benchmark classifies whether that sequence stayed in scope.'),
          table(
            ['Deviation type', 'Where', 'Trajectory signature', 'Benchmark assertion', 'Detection frame'],
            [
              ['Honest misexecution', 'In-session', 'Path wanders off task, incoherent toward any goal, stalls or self-corrects', 'Trajectory completes the intended task without leaving scope', 'Declared scope & task envelope'],
              ['Overreach', 'In-session', 'Goal-directed sequence of individually permitted steps that incrementally extends capability, data access, or egress past the boundary', 'No step sequence crosses a scope boundary, even where each step is allowed', 'Declared scope, evaluated over the sequence'],
              ['Prohibited composition', 'In-session, usually adversarially induced', 'Benign steps that jointly satisfy a prohibited composition (e.g., private-data read → untrusted content → external egress)', 'Prohibited compositions never co-occur on a path', 'Declared prohibited compositions (2.7.3)'],
              ['Cross-session drift', 'Across sessions', 'Step distribution diverges from the in-scope baseline (new tool patterns, rising frequency at scope edges)', 'Indirect: passing trajectories seed and recalibrate the baseline; drift is detected in production as divergence from it', 'Empirical baseline & declared scope'],
            ],
            'Four deviation types, each needing a different detection frame and response',
          ),
          p('Detection uses two reference frames. Declared scope is normative (what is allowed) and covers misexecution, overreach, and prohibited composition, assessed by running benchmark scenarios. The empirical baseline is descriptive (what is typical, aggregated from in-scope trajectories across sessions) and covers cross-session drift, detected in production monitoring. They complement each other: a trajectory may be in scope but atypical (emerging drift) or typical but newly out of scope (the scope or its controls shifted).'),
          p('Run trajectory scenarios with the same five steps lifted to the path level: sample scenarios that each include at least one benign-looking composition that should be prohibited; define the in-scope envelope plus labelled deviating sequences; execute and compare at trajectory level; classify by deviation type (plus instrumentation failures); and integrate into CI/CD so passing trajectories seed the cross-session baseline.'),
        ],
      },
      {
        id: 'SAA-7.2.2',
        number: '7.2.2',
        title: 'Selecting a Security Benchmark for Agentic AI',
        group: '7.2 Behavioral Testing',
        summary: 'Know your evaluation goal, meta-evaluate benchmarks, and follow an 8-step selection process.',
        blocks: [
          p('For agentic security, first decide which type of benchmark you need. Benchmarks vary widely in scope, method, and threat coverage, causing gaps and inconsistent comparisons. The OWASP GenAI Red Teaming Guide already curates AI security benchmarks by threat vector; a structured selection process makes testing comprehensive and reproducible without redundancy.'),
          ul(
            li('Not every benchmark measures security', 'Anthropic’s third-party evaluation initiative highlights that some benchmarks assess general performance such as accuracy. Decide whether you are measuring performance, security, or robustness before choosing.'),
            li('Security vs. safety', 'The EU AI Act Code of Practice emphasizes both: AI security protects systems from malicious threats; AI safety ensures they operate as intended without unintended harm.'),
            li('Meta-evaluate benchmarks', 'Check for inconsistency (variance), ambiguity (misunderstood tasks), incompleteness (missing user needs), and inaccuracy (bias).'),
            li('Keep them current', 'Scheduled updates, community peer review, and governance checks keep benchmarks aligned with evolving adversarial techniques.'),
          ),
          ol(
            li('Define security objectives', 'Confidentiality (training data and parameters), integrity (data and model), availability, adversarial robustness, privacy protection (e.g., anonymization), transparency and accountability (explainability, traceability), governance and compliance (e.g., NIST AI RMF).'),
            li('Assess the threat landscape', 'Data poisoning, adversarial attacks, model extraction, privacy breaches, denial of service, misuse of agent autonomy.'),
            li('Research existing benchmarks', 'For adversarial robustness, privacy protection, backdoor detection, model-extraction security.'),
            li('Evaluate benchmark criteria', 'Aligned with your objectives, covering relevant threats, standardized and widely accepted, providing actionable insights.'),
            li('Test benchmark suitability', 'On representative models or datasets, focusing on false positives, effectiveness under adversarial conditions, and resilience under attack.'),
            li('Compare and select', 'By coverage, relevance, and effectiveness.'),
            li('Establish continuous evaluation', 'Re-test with updated benchmarks, integrate into CI/CD, and adjust the threat model as risks emerge.'),
            li('Engage with the AI security community', 'Forums, workshops, and discussions keep you current on security and benchmark developments.'),
          ),
        ],
      },
      {
        id: 'SAA-7.2.3',
        number: '7.2.3',
        title: 'Explainability Audits',
        group: '7.2 Behavioral Testing',
        summary: 'CoT is insight, not truth; gate critical junctions; pick XAI methods that fit; log negotiations and identities.',
        threats: ['T8'],
        blocks: [
          ul(
            li('Use chain of thought for insight into agentic reasoning — knowing that what an agent says and what it "thinks" are not necessarily aligned.'),
            li('Use HITL at critical junctions to understand and gate actions; criticality is defined by regulations such as the EU AI Act.'),
            li('Choose explainable-AI methods to fit the model: SHAP/LIME for structured decision models; Grad-CAM only if the agent has a vision component; t-SNE for auditing memory/RAG embedding clusters rather than reasoning traces.'),
            li('Record agent-to-agent goal negotiations and tool interactions to spot inputs that may misdirect an agent — especially sensitive exchanges such as database modifications.'),
            li('Log which permission sets or identities were used for agentic actions, showing whom the agent "thought" it was acting for.'),
          ),
          { type: 'links', items: [{ label: 'On the Biology of a Large Language Model (attribution graphs)', url: 'https://transformer-circuits.pub/2025/attribution-graphs/biology.html' }] },
        ],
      },
    ],
  },

  // ── Chapter 8 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH8',
    number: '8',
    title: 'Secure Agentic Deployments',
    shortTitle: 'Deployments',
    tagline: 'Nine principles for running agents in production beyond the model’s own safety.',
    sections: [
      {
        id: 'SAA-8.1',
        number: '8',
        title: 'Secure pipelines and checks for rogue agents',
        summary: 'CI/CD that probes for injection and goal deviation, plus signing and provenance so only vetted agents ship.',
        threats: ['T13'],
        blocks: [
          p('Production deployment needs security beyond the model’s inherent capabilities. Rigorous CI/CD is necessary but not sufficient: pipelines must include automated dependency scanning, static analysis of insecure tool-usage patterns, and dynamic testing designed to probe prompt injection or unintended goal deviation before deployment. Add code signing, provenance tracking for agent versions, and manual security reviews for agents handling high-risk tasks, so only vetted, approved agent logic reaches production — keeping out both deliberately malicious and inadvertently vulnerable agents.'),
        ],
      },
      {
        id: 'SAA-8.2',
        number: '8',
        title: 'Role containerization or Function-as-a-Service',
        summary: 'Isolate each agent or role to limit blast radius.',
        blocks: [
          p('Each agent or distinct role should run in a strongly isolated environment to limit the blast radius of a compromise. Containers (Docker with Kubernetes) or FaaS platforms (AWS Lambda, Google Cloud Functions) enable strict resource limits (CPU, memory, network), network segmentation, and ephemeral execution — enforcing least privilege at the infrastructure level.'),
        ],
      },
      {
        id: 'SAA-8.3',
        number: '8',
        title: 'API access control, rate limits, and API gateways',
        summary: 'Mediate every tool invocation through a gateway that authenticates, authorizes per tool and parameter, rate-limits, and logs.',
        threats: ['T2', 'T4'],
        blocks: [
          p('Agents rely on tools reached through APIs or other integration points such as MCP servers or Google A2A agent servers via AgentCards — critical security boundaries. An API/agent gateway should mediate all tool invocations: authenticate the agent, authorize the specific tool and parameters, apply granular per-agent or per-tool rate limits (against intentional or accidental DoS and cost overruns), and log and audit every interaction.'),
        ],
      },
      {
        id: 'SAA-8.4',
        number: '8',
        title: 'Runtime security with memory isolation (e.g., Google CaMeL)',
        summary: 'Separate control-flow generation from untrusted data processing, and enforce data-flow policies before tool calls.',
        threats: ['T6'],
        blocks: [
          p('Runtime architectures such as Google’s CaMeL (CApabilities for MachinE Learning) provide defense in depth even if the LLM is vulnerable to prompt injection. A Privileged LLM that sees only trusted prompts generates control flow; a Quarantined LLM with no tool access processes untrusted data. Developers can then use static APIs or a custom interpreter that enforces policies based on fine-grained capabilities and data-flow tracking before executing tool calls — preventing untrusted data from steering actions or exfiltrating information through tool parameters. Security is enforced by system design rather than model alignment alone.'),
        ],
      },
      {
        id: 'SAA-8.5',
        number: '8',
        title: 'Separating data planes from control planes (multi-agent)',
        summary: 'Control messages need stronger authN/authZ and integrity than data messages.',
        threats: ['T12'],
        blocks: [
          p('In collaborating multi-agent systems, communication must distinguish control messages (task assignments, commands) from data messages (shared information). Control channels require stronger authentication, authorization, and integrity checks so a compromised agent handling untrusted data cannot issue malicious commands or disrupt coordination — limiting how far a single compromise can cascade.'),
        ],
      },
      {
        id: 'SAA-8.6',
        number: '8',
        title: 'Just-in-Time access and ephemeral credentials',
        summary: 'Least privilege in time: grant only when needed, for as short as possible, with auto-expiring credentials.',
        threats: ['T3'],
        blocks: [
          p('Agents needing sensitive tools or data should follow least privilege in time. Instead of long-lived static credentials, grant access just in time and for the shortest duration, using ephemeral credentials — short-lived API tokens (OAuth tokens, signed JWTs) or temporary cloud credentials (AWS STS, GCP IAM) — that expire automatically and shrink the window for misuse.'),
        ],
      },
      {
        id: 'SAA-8.7',
        number: '8',
        title: 'Alerting on anomalous behavior',
        summary: 'Baseline normal behavior and alert on deviations in tool use, goals, data access, or external communication.',
        threats: ['T13', 'T6'],
        blocks: [
          p('Baseline normal agent behavior (typical tool frequency and sequences, resource consumption) and alert on significant deviations — especially unexpected or unauthorized tool attempts, sudden shifts in apparent goal or task logic (possible injection or manipulation), and anomalous data access or external communication — to enable rapid investigation and response.'),
        ],
      },
      {
        id: 'SAA-8.8',
        number: '8',
        title: 'Human oversight in high-stakes environments',
        summary: 'Full autonomy is often inappropriate in finance, healthcare, education, or critical infrastructure.',
        threats: ['T10'],
        blocks: [
          p('In high-consequence domains (finance, healthcare, education, critical infrastructure), require explicit human review and approval for critical decisions, high-risk actions (large transfers, sharing sensitive data), or significant deviations from expected behavior. Adaptive trust can adjust oversight to the agent’s performance, context, and the risk of each action. For a fuller definition of high-risk systems, see the EU AI Act annex on high-risk systems.'),
        ],
      },
      {
        id: 'SAA-8.9',
        number: '8',
        title: 'Managing non-human identities',
        summary: 'Treat agent identities with the same rigor as human ones — including de-provisioning.',
        threats: ['T9'],
        blocks: [
          p('Each agent instance or service needs a distinct, manageable identity for APIs, tools, other agents, and system components. Treat these machine identities (service accounts, workload identities) with the same rigor as human ones: secure provisioning, robust credential management (secure storage and regular rotation via secrets managers), clear ownership, and reliable de-provisioning when an agent retires, so no orphaned, exploitable identities remain.'),
        ],
      },
    ],
  },

  // ── Chapter 9 ──────────────────────────────────────────────────────────────
  {
    id: 'SAA-CH9',
    number: '9',
    title: 'Securing Agentic Applications across Runtimes & Deployment Environments',
    shortTitle: 'Runtime Hardening',
    tagline: 'Concrete VM and runtime hardening, from the base image to deterministic enforcement points.',
    sections: [
      {
        id: 'SAA-9.0',
        number: '9',
        title: 'Overview and numbering note',
        summary: 'Traditional VM hardening plus agentic-specific sandboxing, auditability, capability constraints, and behavioral monitoring.',
        blocks: [
          callout('info', 'In V1 the deployment material spanned two headings — the prose principles (now Section 8) and a runtime-hardening block numbered 9.1–9.6 under a chapter still labelled "8". V2 fixes this: Section 8 holds the deployment principles and Section 9 the concrete VM/runtime hardening (9.1–9.7).', 'Numbering note'),
          p('Securing agents running in a VM means combining traditional VM hardening with agentic-specific controls such as sandboxing, auditability, capability constraints, and runtime behavioral monitoring — tailored here for LLM-driven or tool-augmented apps.'),
        ],
      },
      {
        id: 'SAA-9.1',
        number: '9.1',
        title: 'Harden the Virtual Machine (base level)',
        summary: 'Minimal images, secure boot, encrypted disks, default-deny firewalls, patch automation, and network isolation.',
        blocks: [
          p('Before anything agent-specific, the host VM must be secure.'),
          ul(
            li('Baseline VM hardening', '', [
              li('Use minimal base images (distroless, Alpine, microVMs).'),
              li('Enable Secure Boot and TPM-backed disk encryption (e.g., dm-crypt/LUKS).'),
              li('Disable all unnecessary services (sshd, cron, etc.).'),
              li('Apply firewall rules (iptables/nftables) restricting ingress/egress by default.'),
              li('Patch regularly with automation (unattended upgrades or distroless image re-pulls).'),
            ]),
            li('Network isolation', '', [
              li('Place the VM in a private subnet or VPC.'),
              li('Use service meshes or API gateways for controlled inter-agent communication.'),
              li('Prevent direct internet access unless explicitly needed — and monitor it.'),
            ]),
          ),
        ],
      },
      {
        id: 'SAA-9.2',
        number: '9.2',
        title: 'Contain the Agentic Runtime',
        summary: 'Per-agent sandboxes with syscall and filesystem restrictions, plus explicitly declared, session-scoped capabilities.',
        threats: ['T11', 'T3'],
        blocks: [
          ul(
            li('Sandbox the agent processes', '', [
              li('Run each agent or tool in its own restricted namespace or container inside the VM (gVisor, Firecracker, or even Docker-in-VM).'),
              li('Restrict syscalls with AppArmor/SELinux or seccomp profiles.'),
              li('Limit filesystem access with mount namespaces and read-only volumes.'),
              li('Use ephemeral storage (tmpfs) for memory-sensitive LLM tools.'),
            ]),
            li('Scoped capabilities', 'Use an AGNTCY-like capability control layer:', [
              li('Agents can only use explicitly declared tools (e.g., searchDocs, not shellExec).'),
              li('Introduce capability tokens scoped per session.'),
              li('Use JSON-RPC wrappers (like MCP) to enforce capability boundaries.'),
            ]),
          ),
        ],
      },
      {
        id: 'SAA-9.3',
        number: '9.3',
        title: 'Secure the Agent’s Memory, Tools, and Context',
        summary: 'Memory hygiene at session end and policy-gated tool execution.',
        threats: ['T1', 'T2'],
        blocks: [
          ul(
            li('Memory and state hygiene', '', [
              li('Encrypt in-memory state where feasible.'),
              li('Auto-clear memory at session end (e.g., clear Redis/vector-DB agent state).'),
              li('Use VM hooks (e.g., systemd unit stop triggers) to flush memory or rotate keys.'),
            ]),
            li('Tool execution control', '', [
              li('Runtime guards for tool calls: validate inputs and outputs, and scan for prompt injection or malicious redirection attempts.'),
              li('Gate access dynamically with a policy engine (e.g., AGNTCY’s) — for example, only allow call_api("billing") from the "finance-agent".'),
            ]),
          ),
        ],
      },
      {
        id: 'SAA-9.4',
        number: '9.4',
        title: 'Observability + Forensics',
        summary: 'Log every action with integrity guarantees and detect behavioral anomalies with policy engines.',
        threats: ['T8', 'T13'],
        blocks: [
          ul(
            li('Audit everything', 'Every agent action (tool use, messages, memory writes) should be logged with timestamp, agentID, sessionID, and payload hash, and include input/output signature fingerprints. Store logs with forward integrity (append-only plus Merkle proofs, or signed logs).'),
            li('Behavioral anomaly detection', 'Use runtime policy engines (e.g., Open Policy Agent) or LLM anomaly detectors to spot unusual tool-invocation patterns, cross-agent communication deviations, and memory bloat or frequent memory peeks.'),
          ),
        ],
      },
      {
        id: 'SAA-9.5',
        number: '9.5',
        title: 'Identity, Authentication, and Agent Authorization',
        summary: 'Per-session authentication and RBAC combined with capability tokens.',
        threats: ['T9', 'T3'],
        blocks: [
          ul(
            li('Identity & session management', 'Use JWTs, mTLS, or HMAC-based auth per agent session, and give each agent a unique ephemeral session context (e.g., via MCP).'),
            li('Role-based + capability-based access', 'Combine RBAC (agent classes) with capability tokens — e.g., research-agent → docSearch, summarize; ops-agent → issueCommand, getStatus.'),
          ),
        ],
      },
      {
        id: 'SAA-9.6',
        number: '9.6',
        title: '(Optional) Cloud-Specific Hardening',
        summary: 'Metadata-service protection, per-VM IAM roles, and confidential computing.',
        blocks: [
          p('If your VM runs in AWS, GCP, or Azure:'),
          ul(
            li('Restrict metadata-service access (e.g., IMDSv2 on AWS).'),
            li('Use IAM roles scoped per VM, not global.'),
            li('Enable confidential computing where supported (e.g., AMD SEV, Intel SGX).'),
          ),
        ],
      },
      {
        id: 'SAA-9.7',
        number: '9.7',
        title: 'Runtime Enforcement Additions',
        summary: 'Deterministic enforcement points that operationalize the design-time concepts — not prompt-level mitigations.',
        blocks: [
          p('These controls operationalize, at deployment time, concepts introduced earlier. They are deterministic enforcement points, not prompt-level mitigations.'),
          ul(
            li('Deterministic sandboxing vs. probabilistic safety', 'Deterministic boundaries (OS isolation, policy proxies, cryptographic checks) are primary controls; prompt-based safety is best-effort. Use gVisor/Firecracker for kernel isolation, eBPF for fine-grained syscall monitoring alongside AppArmor/SELinux/seccomp, and network/path isolation (3.2.3).'),
            li('Execution integrity', 'Authorization does not guarantee the executed request equals the approved one. Enforce authorized_request == executed_request — tool, target, parameters, and identity unchanged from model intent to execution — with a signed execution artifact (hash of the request payload), mandatory mediation through a tool proxy that re-verifies at execution time, and replay protection on authorization artifacts.'),
            li('Tool gateway / MCP proxy', 'Mediate all tool invocations through an API/agent gateway or MCP proxy/sidecar; direct agent-to-server connections are prohibited in production. The gateway enforces server-identity authentication, request/response schema validation, per-tool and per-session rate limits, least-privilege catalog scoping, and tool/server allowlisting at the proxy — not in the system prompt (Section 6).'),
            li('Memory provenance & trust metadata', 'Persist a Standardized Provenance Record (6.4.1) with every memory record. Integrity proves a record was not modified, not that it is safe — pair it with semantic validation and trust labelling so retrieved memory is re-checked before influencing reasoning or action (3.1.6). Segment memory by tenant/user/workflow and apply TTL/expiration.'),
            li('Hooks as lifecycle enforcement points', 'Wire the hooks from 3.3.7 into the runtime so input, tool-call request/response, memory store/retrieval, and final-output enforcement run synchronously and fail closed; where native hooks are observe-only, enforce through synchronous wrappers.'),
            li('Behavioral circuit breakers', 'Deploy the breakers from 3.3.8 as in-line, blocking runtime policy engines (e.g., Open Policy Agent) with graduated tiers (warn → throttle → suspend → kill). Enforcement is decentralized for speed; policy management can be centralized for coherence.'),
            li('Incident snapshots before kill/rollback', 'Before a breaker kills or rolls back an agent, freeze the context window and preserve the tamper-evident provenance chain (principals, decisions, tools, data accessed) using hash-chained harness events and signed export bundles, so the audit record is verifiable proof rather than a trust assertion.'),
          ),
        ],
      },
    ],
  },

  // ── Acknowledgements ───────────────────────────────────────────────────────
  {
    id: 'SAA-ACK',
    number: 'A',
    title: 'Acknowledgements, Sponsors & License',
    shortTitle: 'Credits',
    tagline: 'The contributors, sponsors, and supporters behind the guide — and how it may be reused.',
    sections: [
      {
        id: 'SAA-A.1',
        number: 'A.1',
        title: 'Contributors',
        summary: 'The community authors of Securing Agentic Applications V2.',
        blocks: [
          p('Aamir Syed · Aamiruddin Syed · Ambuj Kumar · Andrea Siposova · Angelika Szymanowska · Ariel Fogel · Bar Kaduri · Brian M. Green · Dipen Shah · Emile Delcourt · Francesco · Gautam Bharti · Guy Shtar · gyanendar manohar · Harel Gal · Hari Holla · Hariprasad Holla · Idan Habler · Jeff Ponte · Joan Ekaterin · Joshua Beck · Joshua Lochner · Karmvir Jadeja · Kaustubh Phatak · Krishna Puranik · Markus Hupfauer · Mohammed Ilyas Ahmed · Nir Dagan · Or Oxenberg · Eliran Suisa · Rani Kumar Rajah · Recep Meric Degirmenci · Rock Lambros · Sahil Mehta · Sanjeev Agarwal · Shaked Reiner · Shoval Abudraham · Sita Ram · Sita Ram Sai · Sriram Prasath Narayanan · Sumer Jagtap · Sushma Mahadevaswamy · Tal Dromi · Tom Barnea · Tom Stripling · Venkat Ragothaman · Volkan Kutal · Yuval Sarel'),
        ],
      },
      {
        id: 'SAA-A.2',
        number: 'A.2',
        title: 'OWASP GenAI Security Project Sponsors & Supporters',
        summary: 'Vendor-neutral funding and community support, as of publication date.',
        blocks: [
          p('Sponsors fund operational and outreach costs, augmenting the resources of the OWASP.org foundation. The project remains vendor neutral: sponsors receive recognition but no special governance consideration, and all materials are community-developed and released under open-source and Creative Commons licenses.'),
          table(
            ['Tier', 'Organizations (as shown at publication)'],
            [
              ['Gold sponsors', 'WitnessAI, HiddenLayer, Fujitsu, Palo Alto Networks, Straiker, Mend.io, Snyk, F5, ByteDance, Trend Micro'],
              ['Silver sponsors', 'Alice, Zscaler, Evoke Security, CrowdStrike, Protecto, SentinelOne, PromptArmor, Proofpoint, Cobalt, Securiti, Apiiro, Capsule, Synack, Akto, Starseer, NeuralTrust, Check Point, TrojAI, Lasso (plus further sponsors listed on the official page)'],
            ],
          ),
          p('Project supporters lend resources and expertise: Accenture · AddValueMachine Inc · Aeye Security Lab Inc. · AI informatics GmbH · AI Village · aigos · Aon · Aqua Security · Astra Security · AVID · AWARE7 GmbH · AWS · BBVA · Bearer · BeDisruptive · Bit79 · Blue Yonder · BroadBand Security, Inc. · BuddoBot · Bugcrowd · Cadea · Check Point · Cisco · Cloud Security Podcast · Cloudflare · Cloudsec.ai · Coalfire · Cobalt · Cohere · Comcast · Complex Technologies · Credal.ai · Databook · DistributedApps.ai · DreadNode · DSI · EPAM · Exabeam · EY Italy · F5 · FedEx · Forescout · GE HealthCare · Giskard · GitHub · Google · GuidePoint Security · HackerOne · HADESS · IBM · iFood · IriusRisk · IronCore Labs · IT University Copenhagen · Kainos · KLAVAN · Klavan Security Group · KPMG Germany FS · Kudelski Security · Lakera · Lasso Security · Layerup · Legato · Linkfire · LLM Guard · LOGIC PLUS · MaibornWolff · Mend.io · Microsoft · Modus Create · Nexus · Nightfall AI · Nordic Venture Family · Normalyze · NuBinary · Palo Alto Networks · Palosade · Praetorian · Preamble · Precize · Prompt Security · PromptArmor · Pynt · Quiq · Red Hat · RHITE · SAFE Security · Salesforce · SAP · Securiti · See-Docs & Thenavigo · ServiceTitan · SHI · Smiling Prophet · Snyk · Sourcetoad · Sprinklr · stackArmor · Tietoevry · Trellix · Trustwave SpiderLabs · U Washington · University of Illinois · VE3 · WhyLabs · Yahoo · Zenity.'),
          { type: 'links', items: [{ label: 'OWASP GenAI Security Project', url: 'https://genai.owasp.org/' }] },
        ],
      },
      {
        id: 'SAA-A.3',
        number: 'A.3',
        title: 'License, Usage & Attribution',
        summary: 'CC BY-SA 4.0 — share and adapt with credit, a license link, change notes, and the same license.',
        blocks: [
          p('Securing Agentic Applications V2 is licensed under Creative Commons CC BY-SA 4.0. You may share (copy and redistribute in any medium or format) and adapt (remix, transform, and build upon) the material for any purpose, even commercially, as long as you follow the terms:'),
          ul(
            li('Attribution', 'Give appropriate credit, provide a link to the license, and indicate if changes were made — in any reasonable manner, but not in a way that suggests the licensor endorses you or your use.'),
            li('ShareAlike', 'Distribute your contributions under the same license as the original.'),
            li('No additional restrictions', 'Do not apply legal terms or technological measures that restrict others from doing anything the license permits.'),
          ),
          p('The guide does not constitute legal advice; all information is for general informational purposes only. Links to third-party websites are for convenience and are not endorsements by OWASP.'),
          callout('info', 'Changes made in this application: the 106-page guide has been restructured into searchable, deep-linkable sections with interactive explorers (key components, threat heatmap, memory matrix, architecture patterns, control plane, effective-scope calculator, Rule of Two checker, validation gates, guardrail placement, hook explorer, circuit-breaker designer, capability matrix, OBO delegation chain, tool lifecycle, assurance chain). Text has been lightly edited for clarity, and cross-reference errors in the source are corrected (see editorial notes).', 'Adaptation notice'),
          { type: 'links', items: [{ label: 'CC BY-SA 4.0 legal code', url: 'https://creativecommons.org/licenses/by-sa/4.0/legalcode' }, { label: 'Official publication page', url: 'https://genai.owasp.org/resource/securing-agentic-applications-v2/' }] },
        ],
      },
    ],
  },
];

// ─── Editorial notes: corrections applied to the source cross-references ────

export const SAA_EDITORIAL_NOTES: string[] = [
  '1.1 — a garbled sentence in the source ("…ASI T&M documentFrameworks are great for proof of concept…") is split into the purpose statement and the framework caution it belongs to.',
  '2.5 — environment codes for the Reactive (web access) and Knowledge-Intensive (RAG & data sources) patterns are swapped in the source; corrected to KC6.4 and KC6.3 respectively.',
  '2.3.3 vs 2.5 — the Hierarchical pattern lists KC4.2 memory in 2.3.3 but KC4.3/KC4.4 in the comprehensive table; both are shown, each in its own context.',
  '3.3.7 — the hook table cites "hash-pin verification (6.4.2)" and "description-poisoning scan (6.4.3)"; per Section 6 these are 6.4.3 and 6.4.4. The "Skill hardening (6.4.6)" reference has no matching subsection and is shown as general Section 6.4 skill controls.',
  '4.2.1 — the "user assumption architecture pattern from section 2.2.1" is defined in 2.3.1.',
  '6.4.2 — "Standardized Provenance Record (6.4.0)" refers to 6.4.1.',
  '3.3.8 / 9.7 — tier names "limit" (3.3.8) and "throttle" (9.7) describe the same second tier.',
  'Threat names for T1–T15 follow the OWASP Agentic AI Threats and Mitigations taxonomy. "Related ASI" links to the OWASP Top 10 for Agentic Applications are editorial cross-references added by this application.',
];

// ─── Flat helpers ─────────────────────────────────────────────────────────────

export const SAA_ALL_SECTIONS: (SaaSection & { chapterId: string; chapterNumber: string; chapterTitle: string })[] =
  SAA_CHAPTERS.flatMap((ch) =>
    ch.sections.map((s) => ({ ...s, chapterId: ch.id, chapterNumber: ch.number, chapterTitle: ch.shortTitle })),
  );

const blockText = (b: SaaBlock): string => {
  const itemText = (i: SaaListItem): string => [i.label ?? '', i.text, ...(i.children ?? []).map(itemText)].join(' ');
  switch (b.type) {
    case 'p':
      return b.text;
    case 'list':
      return b.items.map(itemText).join(' ');
    case 'callout':
      return `${b.title ?? ''} ${b.text}`;
    case 'table':
      return `${b.caption ?? ''} ${b.headers.join(' ')} ${b.rows.map((r) => r.join(' ')).join(' ')}`;
    case 'formula':
      return `${b.text} ${b.caption ?? ''}`;
    case 'links':
      return b.items.map((l) => l.label).join(' ');
    case 'widget':
      return '';
  }
};

/** Lower-cased full text per section, used by in-view and global search. */
export const SAA_SECTION_SEARCH_TEXT: Record<string, string> = Object.fromEntries(
  SAA_ALL_SECTIONS.map((s) => [
    s.id,
    `${s.number} ${s.title} ${s.group ?? ''} ${s.summary} ${(s.threats ?? []).join(' ')} ${s.blocks.map(blockText).join(' ')}`.toLowerCase(),
  ]),
);
