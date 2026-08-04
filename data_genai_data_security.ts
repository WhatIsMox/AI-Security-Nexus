import { ExternalResource } from './types';

export type GenAiDataSecurityTier = 1 | 2 | 3;
export type GenAiDataSecurityScope = 'Buy' | 'Build' | 'Buy and Build';

export interface GenAiDataSecurityMeta {
  title: string;
  shortTitle: string;
  version: string;
  publicationDate: string;
  site: string;
  resourceUrl: string;
  disclaimer: string;
  license: {
    name: string;
    url: string;
    permissions: string[];
    terms: { title: string; description: string }[];
    attributionGuidelines: string[];
    referencedAsset: string;
  };
}

export interface GenAiDataSecuritySection {
  id: string;
  title: string;
  body?: string[];
  bullets?: string[];
  subsections?: {
    title: string;
    body?: string[];
    bullets?: string[];
  }[];
}

export interface GenAiDspmCapability {
  id: string;
  title: string;
  category: 'Extend DSPM' | 'GenAI Specific DSPM';
  objective: string;
  actions: string[];
}

export interface GenAiDataSecurityMitigation {
  title: string;
  description: string;
  scope?: GenAiDataSecurityScope;
}

export interface GenAiDataSecurityRisk {
  id: string;
  title: string;
  theme:
    | 'Leakage & Exposure'
    | 'Identity, Tools & Agents'
    | 'Governance & Compliance'
    | 'Integrity & Resilience'
    | 'Model, Vector & Inference';
  summary: string;
  howItUnfolds: string[];
  attackerCapabilities: string[];
  illustrativeScenario: string;
  impacts: string[];
  mitigations: {
    tier: GenAiDataSecurityTier;
    label: 'Foundational' | 'Hardening' | 'Advanced';
    intent: string;
    items: GenAiDataSecurityMitigation[];
  }[];
  knownExploits?: string[];
  references?: ExternalResource[];
  crossReferences?: string[];
  keywords: string[];
}

export interface GenAiDataSecurityAcknowledgements {
  authors: string[];
  contributors: string[];
  reviewers: string[];
  sponsorsNote: string;
  supporters: string[];
}

export const GENAI_DATA_SECURITY_META: GenAiDataSecurityMeta = {
  title: 'OWASP GenAI Data Security Risks and Mitigations 2026',
  shortTitle: 'OWASP GenAI Data Security',
  version: 'Version 1.0',
  publicationDate: 'March 2026',
  site: 'genai.owasp.org',
  resourceUrl: 'https://genai.owasp.org/resource/owasp-genai-data-security-risks-mitigations-2026/',
  disclaimer:
    'The information provided in this document does not, and is not intended to, constitute legal advice. All information is for general informational purposes only. This document contains links to other third-party websites. Such links are only for convenience and OWASP does not recommend or endorse the contents of the third-party sites.',
  license: {
    name: 'Source license',
    url: 'https://creativecommons.org/licenses/by-sa/4.0/legalcode',
    permissions: [
      'Share - copy and redistribute the material in any medium or format.',
      'Adapt - remix, transform, and build upon the material for any purpose, even commercially.'
    ],
    terms: [
      {
        title: 'Attribution',
        description:
          'Give appropriate credit, provide a link to the license, and indicate if changes were made. Attribution must not suggest OWASP endorses this application or its use.'
      },
      {
        title: 'ShareAlike',
        description:
          'If you remix, transform, or build upon the material, distribute your contributions under the same license as the original.'
      }
    ],
    attributionGuidelines: [
      'Attribution must include the project name.',
      'Attribution must include the name of the asset referenced.'
    ],
    referencedAsset: 'OWASP Top 10 for LLMs - GenAI Red Teaming Guide'
  }
};

export const GENAI_DATA_SECURITY_OVERVIEW: GenAiDataSecuritySection[] = [
  {
    id: 'genai-data-security-context',
    title: 'What Data Security Means in the GenAI Context',
    body: [
      'In GenAI systems, data security means protecting the confidentiality, integrity, availability, and authenticity of data across its entire lifecycle: when it is stored, moved, transformed, retrieved, injected into prompts, reasoned over, logged, and finally emitted by LLMs, GenAI applications, or agentic workflows.',
      'The key architectural challenge is the context window. System prompts, user inputs, RAG passages, tool outputs, conversation history, and agent memory are often flattened into a single model-visible space. Within that space, there are typically no native access-control boundaries between different context segments. As a result, a confidential HR document retrieved through RAG may sit next to untrusted user input and receive the same model attention.',
      'Today’s mitigations address this weakness indirectly. They rely on data minimization, context isolation, strict lifecycle controls, monitoring, logging, policy enforcement, and governance. These measures reduce risk, but they do not eliminate the underlying architectural issue: current LLM context does not natively enforce policies such as “use this information, but never reveal it” or “reason over this data, but do not pass it to tools, logs, users, or other agents.”'
    ],
    subsections: [
      {
        title: 'Protect These Data Classes',
        bullets: [
          'Source data: raw corpora, structured and unstructured records, user uploads, tickets, knowledge bases, analytics exports.',
          'Derived data: embeddings, indexes, retrieved passages, summaries, synthetic datasets, feature stores.',
          'Model artifacts: checkpoints, adapters, LoRA weights, training logs, evaluation sets, model registries.',
          'Runtime data: prompts, context windows, tool calls, LLM-to-SQL or LLM-to-Graph operations, agent-to-agent messages, transient caches, session memory.',
          'Operational exhaust: logs, traces, debug captures, monitoring events, observability data.',
          'Agent state and delegation artifacts: short-term and long-term memory, inter-agent messages, tool payloads and results, delegation chains, cached credentials.'
        ]
      },
      {
        title: 'Security Posture Emphasis',
        bullets: [
          'Minimize context: send only what the task needs and avoid over-broad prompt windows.',
          'Isolate boundaries: enforce per-tenant, per-user, per-agent, and per-task controls with least privilege and approval for high-risk actions.',
          'Apply lifecycle rigor: delete or anonymize prompts, context, KV cache, memory, logs, traces, embeddings, backups, and other derivatives as soon as they are no longer needed.',
          'Preserve integrity and provenance: know what was ingested, where it came from, who changed it, and which artifacts were derived from it.',
          'Monitor continuously: run DLP on prompts, outputs, logs, vector stores, and retrieval behavior; detect scraping, enumeration, and abnormal access.',
          'Govern for compliance: maintain lawful basis, traceability, data lineage, DSR support, audit readiness, encryption, and provenance records.'
        ]
      }
    ]
  }
];

export const GENAI_DSPM_CAPABILITIES: GenAiDspmCapability[] = [
  {
    id: 'ai-dspm-01',
    title: 'GenAI Data Asset Discovery and Inventory',
    category: 'Extend DSPM',
    objective: 'Eliminate unknown data stores and hidden AI data paths that drive shadow AI, oversharing, and leakage.',
    actions: [
      'Inventory training and fine-tune datasets, evaluation sets, label queues, prompt templates, system prompts, and agent memory stores.',
      'Catalog RAG sources, document stores, vector DB collections, embedding pipelines, LLM gateways, caches, plugins, MCP tools, and observability stores.',
      'Include stores that capture full prompts, tool outputs, traces, and retrieved passages.'
    ]
  },
  {
    id: 'ai-dspm-02',
    title: 'Data Classification, Labeling, and Policy Binding',
    category: 'Extend DSPM',
    objective: 'Extend classic classification to GenAI inputs, derivatives, runtime context, and operational exhaust.',
    actions: [
      'Classify prompts, context windows, embeddings, retrieved snippets, tool payloads, tool results, traces, and debug events.',
      'Propagate labels from raw assets to derivatives such as embeddings, caches, backups, summaries, and synthetic datasets.',
      'Bind policies for public, internal, confidential, restricted, PII, PHI, PCI, secrets, and IP data classes.'
    ]
  },
  {
    id: 'ai-dspm-03',
    title: 'Data Flow Mapping, Lineage, and GenAI Bill of Materials',
    category: 'Extend DSPM',
    objective: 'Maintain provable lineage from source data to preprocessing, embedding, indexing, retrieval, generation, and logging.',
    actions: [
      'Track source to preprocessing to embedding to indexing to retrieval to prompt assembly to output to logging.',
      'Link dataset versions, RAG corpus snapshots, embedding model versions, model versions, and deployment versions.',
      'Use CycloneDX ML-BOM (ECMA-424, v1.7) as a base DBOM format and extend it for GenAI corpus snapshots, vector stores, classification propagation, licenses, source origin, ingestion timestamp, and preprocessing steps.'
    ]
  },
  {
    id: 'ai-dspm-04',
    title: 'Access Governance and Entitlement Posture',
    category: 'Extend DSPM',
    objective: 'Continuously validate data and tool access for users, services, agents, and non-human identities.',
    actions: [
      'Apply fine-grained RBAC/ABAC to RAG sources, training data, vector stores, buckets, registries, and tools.',
      'Use short-lived credentials, secret hygiene, private networking, and per-agent identities.',
      'Adopt just-in-time data access: mint task-scoped tool credentials with TTL and revoke them when the task completes.'
    ]
  },
  {
    id: 'ai-dspm-05',
    title: 'Prompt, RAG, and Output-Layer DLP Controls',
    category: 'GenAI Specific DSPM',
    objective: 'Prevent prompts, retrieval, and model outputs from exposing PII, secrets, or restricted content.',
    actions: [
      'Scan inputs and outputs for PII and secrets.',
      'Enforce per-document ACLs and redaction at retrieval time.',
      'Detect enumeration and scraping patterns and enforce no-train/no-retain rules for protected data types.'
    ]
  },
  {
    id: 'ai-dspm-06',
    title: 'Vector Store and Embedding Security Posture',
    category: 'GenAI Specific DSPM',
    objective: 'Protect durable semantic representations of sensitive corpora.',
    actions: [
      'Enforce encryption at rest and in transit, key management alignment, strict tenant scoping, and server-side authorization.',
      'Control top-k values, similarity query patterns, snapshots, imports, and raw embedding export.',
      'Monitor unusual nearest-neighbor searches, extraction behavior, and cross-tenant result anomalies.'
    ]
  },
  {
    id: 'ai-dspm-07',
    title: 'Data Integrity, Poisoning, and Tamper Detection',
    category: 'GenAI Specific DSPM',
    objective: 'Treat integrity as a first-class property across ingestion, training, retrieval, and artifact promotion.',
    actions: [
      'Validate schemas and semantics during ingestion.',
      'Use drift, outlier, and influence checks, golden datasets, signed artifacts, and immutable registries.',
      'Require human review gates for high-impact RAG corpora and promoted artifacts.'
    ]
  },
  {
    id: 'ai-dspm-08',
    title: 'Observability, Telemetry, and Log-Retention Posture',
    category: 'GenAI Specific DSPM',
    objective: 'Prevent GenAI debugging and tracing from becoming the easiest exfiltration path.',
    actions: [
      'Default to least logging and avoid full prompt, response, and tool-output bodies.',
      'Tokenize or redact secrets, prompts, tool outputs, and traces before logging.',
      'Apply short TTLs, approval workflows for debug capture, access control, and monitoring on observability platforms.'
    ]
  },
  {
    id: 'ai-dspm-09',
    title: 'Third-Party, Plugin, Tool, and Connector Governance',
    category: 'GenAI Specific DSPM',
    objective: 'Understand every integration that can receive prompts, transcripts, tool payloads, or retrieved data.',
    actions: [
      'Inventory and risk-rate every integration.',
      'Track what data is shared, where it is stored, retention, subprocessors, cross-border flows, and incident terms.',
      'Distinguish full-transcript sharing from minimal-payload sharing and require stronger controls for the former.'
    ]
  },
  {
    id: 'ai-dspm-10',
    title: 'Lifecycle Management, Erasure, and Compliance Readiness',
    category: 'GenAI Specific DSPM',
    objective: 'Apply retention and erasure to raw and derived artifacts.',
    actions: [
      'Delete or expire embeddings, indexes, caches, backups, and derived artifacts tied to deleted sources.',
      'Support data-subject access and erasure rights with traceability.',
      'Track lawful basis, purpose limitation, training approvals, and zero-retention requirements where applicable.'
    ]
  },
  {
    id: 'ai-dspm-11',
    title: 'Training Governance and Privacy-Enhancing Fine-Tuning',
    category: 'GenAI Specific DSPM',
    objective: 'Reduce the probability that fine-tuned or refined models leak original sensitive training data.',
    actions: [
      'Redact or anonymize PII and PHI before training.',
      'Use hard de-identification, synthetic data, differential privacy such as DP-SGD, consent mapping, RTBF handling, and copyright/IP scrubbing.',
      'Apply privacy checks before model release and after model updates.'
    ]
  },
  {
    id: 'ai-dspm-12',
    title: 'Resilience Posture for GenAI Data Dependencies',
    category: 'GenAI Specific DSPM',
    objective: 'Keep RAG, training, and inference data dependencies available, fresh, and trustworthy.',
    actions: [
      'Use encrypted and tested backups, replication, restore drills, RTO/RPO definitions, and integrity checks on restore.',
      'Rate-limit and protect vector endpoints from abuse.',
      'Validate restored vector stores and model artifacts semantically, not only by infrastructure health.'
    ]
  },
  {
    id: 'ai-dspm-13',
    title: 'Human and Shadow AI Controls',
    category: 'GenAI Specific DSPM',
    objective: 'Control human labeling exposure and unapproved GenAI SaaS usage.',
    actions: [
      'Minimize exposure in HITL and labeling workflows and enforce vendor controls.',
      'Detect unapproved GenAI SaaS usage and unsanctioned data flows.',
      'Provide governed alternatives that reduce incentives for shadow adoption.'
    ]
  }
];

const tier = (
  tierNumber: GenAiDataSecurityTier,
  label: 'Foundational' | 'Hardening' | 'Advanced',
  intent: string,
  items: GenAiDataSecurityMitigation[]
) => ({ tier: tierNumber, label, intent, items });

export const GENAI_DATA_SECURITY_RISKS: GenAiDataSecurityRisk[] = [
  {
    id: 'DSGAI01',
    title: 'Sensitive Data Leakage',
    theme: 'Leakage & Exposure',
    summary:
      'Sensitive data leaks when models, RAG retrieval, logs, telemetry, fine-tuned adapters, or embeddings surface PII, PHI, secrets, IP, or deleted data that should not be available.',
    howItUnfolds: [
      'Users or attackers submit high-recall prompts, enumeration sequences, or prompt-injection instructions that cause the model or RAG system to return verbatim or near-verbatim sensitive content.',
      'Fine-tuned models and LoRA adapters memorize rare training examples more readily than broad base models, creating a focused extraction surface.',
      'Leakage also occurs through retrieved vector passages, error messages, debug logs, telemetry, tool callbacks, markdown/image exfiltration paths, and derived embeddings that persist after raw source deletion.',
      'A frequent precursor is oversharing in systems feeding RAG: broad shared-drive permissions, public chat channels, and legacy inherited access make sensitive content retrievable even when the model behaves as designed.'
    ],
    attackerCapabilities: [
      'Opportunistic users can probe deployed assistants with sensitive-topic prompts and repeated retrieval attempts.',
      'Sophisticated attackers can target adapters, logs, vector stores, multilingual bypasses, binary or encoded requests, and systematic extraction or distillation campaigns.',
      'Attackers can exploit persistence gaps where deleted raw data remains in embeddings, backups, model checkpoints, or session memory.'
    ],
    illustrativeScenario:
      'A support chatbot fine-tuned on historical tickets returns a customer SSN because tickets were ingested without redaction. In a second path, raw records are deleted after a request, but derived embeddings continue to resurface in RAG answers.',
    impacts: [
      'Breach of confidentiality for PII, PHI, secrets, intellectual property, or credentials.',
      'Regulatory exposure under GDPR, HIPAA, CCPA, and similar regimes.',
      'Downstream compromise where leaked secrets are used to access other systems.',
      'Failure to meet data subject rights, including Right to Erasure and Right to be Forgotten obligations.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Reduce obvious leakage paths quickly with policy, minimization, ACLs, and basic output controls.', [
        { title: 'No-train/no-retain policy', description: 'Define explicit no-train and no-retain rules for user uploads and sensitive workflows where applicable.', scope: 'Buy and Build' },
        { title: 'Oversharing reduction', description: 'Identify and remediate broad or inherited permissions in repositories feeding RAG before indexing.', scope: 'Buy and Build' },
        { title: 'Basic ops hygiene', description: 'Restrict logging and scrub traces so prompts, tool outputs, and retrieved passages are not stored unnecessarily.', scope: 'Buy and Build' },
        { title: 'Prompt architecture', description: 'Separate system prompts from user context with clear delimiters and instruction hierarchy; add prompt-injection detection and dynamic prompt components that resist extraction.', scope: 'Buy and Build' },
        { title: 'Data minimization', description: 'Redact or tokenize sensitive fields before training, indexing, prompting, output generation, and logging.', scope: 'Build' },
        { title: 'Output controls', description: 'Run PII and secret detectors on generations; be aware that regex-only controls fail under translation, binary, and encoded outputs.', scope: 'Buy and Build' },
        { title: 'Basic RAG hardening', description: 'Enforce per-document ACLs and result filtering or abstention before content enters the prompt.', scope: 'Buy and Build' },
        { title: 'Sensitive-topic rate limits', description: 'Limit repeated queries against sensitive topics to reduce enumeration and scraping.', scope: 'Build' },
        { title: 'Policy as code', description: 'Define and enforce lawful basis, purpose limitation, consent, and training-ingestion approvals.', scope: 'Buy and Build' }
      ]),
      tier(2, 'Hardening', 'Strengthen runtime controls, monitoring, encryption, and exfiltration prevention.', [
        { title: 'Advanced ops hygiene', description: 'Encrypt sensitive data in transit and at rest and control key access.', scope: 'Buy and Build' },
        { title: 'DLP and retrieval monitoring', description: 'Add real-time DLP scanning on prompts and outputs; alert on enumeration, scraping, and abnormal vector or embedding-store access.', scope: 'Buy and Build' },
        { title: 'Extraction and distillation defense', description: 'Detect systematic model probing and disrupt extraction attempts before a useful student model can be trained.', scope: 'Build' },
        { title: 'Indirect prompt-injection exfiltration controls', description: 'Block markdown image rendering to external URLs, allowlist tool callback targets, and disable API-redirect channels in rendered LLM output.', scope: 'Buy and Build' },
        { title: 'Format-preserving encryption', description: 'Use FPE where the model needs structural context, such as a payment-card shape, without access to the true value.', scope: 'Build' },
        { title: 'Advanced RAG and memory isolation', description: 'Enforce per-user and per-task memory isolation, sanitize content before writing to agent memory, and expire or replay-protect long-lived state.', scope: 'Buy and Build' }
      ]),
      tier(3, 'Advanced', 'Validate leakage resistance with adversarial testing and privacy-preserving learning.', [
        { title: 'Continuous leakage red teaming', description: 'Run adversarial tests for known sensitive strings, cross-lingual leakage, RAG retrieval bypass, adapter extraction, and prompt-injection exfiltration.', scope: 'Build' },
        { title: 'Privacy-preserving learning', description: 'Apply differential privacy, run membership-inference audits, and consider federated learning for sensitive cohorts.', scope: 'Build' },
        { title: 'Verifiable erasure and unlearning readiness', description: 'Design deletion protocols that cover raw data, embeddings, checkpoints, adapters, backups, and cryptographic erasure where possible.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'CVE-2024-5184 (EmailGPT): prompt injection leading to system prompt disclosure and data leakage.',
      'CVE-2025-54794: hijacking Claude AI with a prompt injection.',
      'CVE-2025-32711: M365 Copilot information disclosure vulnerability.',
      'CVE-2026-22708: Cursor terminal tool allowlist bypass via environment variables.',
      'CVE-2026-0612: information leakage through the Librarian web_fetch tool.',
      'OWASP LLM Top 10 Sensitive Information Disclosure category.',
      'Reasoning trace coercion and model extraction patterns reported in 2026.'
    ],
    references: [
      { title: 'Neuraltrust - Why Your AI Model Might Be Leaking Sensitive Data', url: 'https://neuraltrust.ai/blog/ai-model-data-leakage-prevention' },
      { title: 'OWASP GenAI Security Project', url: 'https://genai.owasp.org/' }
    ],
    crossReferences: ['OWASP LLM Sensitive Information Disclosure', 'OWASP general data minimization controls'],
    keywords: ['DLP', 'RAG', 'LoRA', 'embeddings', 'PII', 'PHI', 'secrets', 'unlearning']
  },
  {
    id: 'DSGAI02',
    title: 'Agent Identity & Credential Exposure',
    theme: 'Identity, Tools & Agents',
    summary:
      'Agent pipelines create non-human identity sprawl when service accounts, OAuth tokens, API keys, and tool credentials are long-lived, over-scoped, shared, inherited, or logged.',
    howItUnfolds: [
      'Agents inherit human operator OAuth tokens or broad service credentials that exceed the current task.',
      'Sub-agents, tool calls, memory retrieval, and delegation chains propagate those credentials without re-scoping or re-verification.',
      'Three-legged OAuth flows designed for human consent are repurposed for autonomous agents that cannot meaningfully consent at runtime.',
      'A compromised sub-agent or tool boundary can access data-tier resources, vector stores, datasets, prompts, registries, and downstream systems.'
    ],
    attackerCapabilities: [
      'Compromise an integration point, sub-agent, retrieved document, or tool endpoint and inherit the credentials attached to that component.',
      'Enumerate NHIs through credential scanning, token interception, prompts, logs, memory contexts, or unencrypted internal traffic.',
      'Use prompt injection or tool poisoning to invoke granted-but-unneeded scopes at runtime.'
    ],
    illustrativeScenario:
      'An orchestration agent uses a developer OAuth token with read/write data-tier access. A spawned sub-agent inherits it. A prompt injection in a retrieved document compromises the sub-agent, allowing vector snapshot download and embedding reconstruction before manual token rotation.',
    impacts: [
      'Exfiltration of training datasets, embeddings, system prompts, model registries, and internal artifacts.',
      'Compliance breaches and difficult incident response because NHI inventory is incomplete.',
      'Lateral movement across agents that appear to share one identity.',
      'Reputational damage where reconstructed or stolen data surfaces externally.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Establish basic identity, secret, and audit controls.', [
        { title: 'Least privilege and JIT access', description: 'Apply PoLP, RBAC/ABAC, short-lived tokens, mTLS, and just-in-time access to agent data and tools.', scope: 'Buy and Build' },
        { title: 'Secret hygiene', description: 'Store credentials in vaults, rotate them, and prevent secrets from entering prompts, memory, or logs.', scope: 'Buy and Build' },
        { title: 'Immutable access logs', description: 'Log all agent data access events with identity, scope, target, and task metadata.', scope: 'Buy and Build' }
      ]),
      tier(2, 'Hardening', 'Break credential inheritance and govern NHI lifecycle.', [
        { title: 'Task-scoped OAuth', description: 'Replace inherited operator tokens with invocation-time credentials scoped to the task and revoked on completion.', scope: 'Buy and Build' },
        { title: 'NHI inventory', description: 'Continuously discover and track all non-human identities across the agent tool chain, including dynamically spawned sub-agents.', scope: 'Build' },
        { title: 'Credential misuse anomaly detection', description: 'Detect scraping, unusual retrieval volume, cross-tier access, and tool calls inconsistent with the declared task.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Use strong agent identity infrastructure for multi-agent ecosystems.', [
        { title: 'PKI-backed agent identities', description: 'Issue distinct cryptographically verifiable identities to every agent and require signed requests.', scope: 'Buy and Build' },
        { title: 'Machine-to-machine credential patterns', description: 'Replace three-legged OAuth in autonomous contexts with client credentials, workload identity federation, or purpose-built agent identity frameworks.', scope: 'Buy and Build' },
        { title: 'Per-agent memory and retrieval isolation', description: 'Bind memory, vector access, and tool permissions to the agent identity and task scope.', scope: 'Buy and Build' }
      ])
    ],
    knownExploits: [
      'No universal CVE for the pattern.',
      'Hugging Face Spaces incident illustrates real-world AI secret and token exposure paths.',
      'CVE-2025-54795: Claude Code confirmation prompt bypass leading to untrusted command execution.'
    ],
    references: [
      { title: 'Wiz CVE-2025-54795 entry', url: 'https://www.wiz.io/vulnerability-database/cve/cve-2025-54795' }
    ],
    crossReferences: ['ASI03 - Identity & Privilege Abuse'],
    keywords: ['NHI', 'OAuth', 'tokens', 'agents', 'credentials', 'JIT', 'PKI']
  },
  {
    id: 'DSGAI03',
    title: 'Shadow AI & Unsanctioned Data Flows',
    theme: 'Governance & Compliance',
    summary:
      'Shadow AI occurs when employees, teams, or vendors use unapproved GenAI tools and embedded AI features outside security, privacy, procurement, retention, and data processing controls.',
    howItUnfolds: [
      'Employees paste sensitive prompts, documents, customer records, code, pricing, or opportunity notes into public or prosumer AI SaaS.',
      'Third-party productivity tools add AI features inside CRM, email, document, sales, or niche ML workflows without the adopting team realizing that a new model provider or processor is involved.',
      'Startup and domain-specific ML tools run on opportunistic cloud regions with unclear data residency, retention, and deletion enforceability.',
      'Internal teams build ungoverned endpoints, fine-tuning pipelines, or retrieval systems inside corporate tenants without classification or review.',
      'Procured SaaS products later add AI features and AI governance teams are not informed.'
    ],
    attackerCapabilities: [
      'Operate, compromise, or receive retained data from external AI services employees voluntarily use.',
      'Exploit SaaS provider misconfigurations, weak access control, credential leaks, or terms changes.',
      'Deploy internal shadow systems that become unmanaged targets for lateral movement, credential harvesting, or scraping.'
    ],
    illustrativeScenario:
      'A sales team adopts an unsanctioned AI email assistant with CRM integration and pastes opportunity notes, pricing, and PII. The vendor later changes terms to train on inputs and then suffers a breach exposing conversations.',
    impacts: [
      'Sensitive data silently proliferates into unknown third-party systems.',
      'Data maps, lawful-basis tracking, and data-subject rights workflows become inaccurate.',
      'Customer data leaves agreed regions or processors, creating contractual and regulatory violations.',
      'Governance reports understate real exposure.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Create policy, catalog, contracts, and blocking controls.', [
        { title: 'Shadow AI policy', description: 'Publish allowed and prohibited tools, acceptable inputs, redaction rules, and consequences for non-compliance.', scope: 'Build' },
        { title: 'Central AI service catalog', description: 'Require registration, security review, and privacy review before organizational AI use.', scope: 'Build' },
        { title: 'Vendor contracts', description: 'Require retention limits, training opt-outs, cross-border restrictions, and incident notification obligations.', scope: 'Buy' },
        { title: 'DLP and CASB controls', description: 'Detect and block sensitive uploads to unapproved AI endpoints.', scope: 'Buy' }
      ]),
      tier(2, 'Hardening', 'Make sanctioned options usable and review infrastructure realities.', [
        { title: 'Governed enterprise alternatives', description: 'Provide logged, region-pinned, managed AI capabilities to reduce incentives for shadow tools.', scope: 'Buy and Build' },
        { title: 'Boundary minimization', description: 'Send only task-required data to external models and tokenize or anonymize where feasible.', scope: 'Build' },
        { title: 'SaaS maturity assessment', description: 'Assess the full hosting stack, cloud region, access controls, incident history, and subprocessors, not just the AI model.', scope: 'Buy and Build' },
        { title: 'DSPM and EDR for on-prem AI', description: 'Apply data posture management and endpoint detection to internally hosted or on-prem shadow model infrastructure.', scope: 'Buy' }
      ]),
      tier(3, 'Advanced', 'Discover shadow AI continuously and integrate governance with procurement.', [
        { title: 'Continuous shadow AI discovery', description: 'Automate discovery across endpoints, network egress, SaaS logs, and access logs.', scope: 'Buy and Build' },
        { title: 'AI procurement gates', description: 'Embed AI security and privacy review into procurement so embedded AI features are captured at onboarding and update time.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'No formal CVE; this is a governance and human-behavior risk class.',
      'Shadow AI SaaS connected to corporate environments can become an infrastructure attack path if it lacks security controls.'
    ],
    references: [
      { title: 'Palo Alto Networks - What Is Shadow AI?', url: 'https://www.paloaltonetworks.ca/cyberpedia/what-is-shadow-ai' },
      { title: 'IBM - Four ways to lower shadow AI security risk', url: 'https://www.ibm.com/think/insights/security-risk-shadow-AI' },
      { title: 'SoSafe - How leaders can govern Shadow AI', url: 'https://sosafe-awareness.com/blog/shadow-ai-risks-culture-safe-ai-use/' },
      { title: 'GDT - Why you need to address Shadow AI', url: 'https://gdt.com/blog/why-you-need-to-address-shadow-ai-and-how-to-get-started/' },
      { title: 'BDO - Shadow AI: The Next Generation of Shadow IT', url: 'https://www.bdo.com/insights/digital/shadow-ai-the-next-generation-of-shadow-it' }
    ],
    keywords: ['shadow AI', 'SaaS', 'CASB', 'DLP', 'procurement', 'data residency']
  },
  {
    id: 'DSGAI04',
    title: 'Data, Model & Artifact Poisoning',
    theme: 'Integrity & Resilience',
    summary:
      'Poisoning and tampering compromise trusted datasets, dependencies, preprocessing, model artifacts, loaders, registries, vector indexes, and RAG sources so malicious influence flows into production.',
    howItUnfolds: [
      'Stage 1 - supply chain compromise: adversaries influence public datasets, model hubs, PyPI or conda packages, labeling vendors, build dependencies, model files, loaders, chat templates, or quantized formats.',
      'Stage 2 - artifact tampering: write access to datasets, feature stores, preprocessing scripts, registries, CI config, or privacy controls enables plausible-looking changes that silently increase memorization or embed triggers.',
      'Stage 3 - training or retrieval poisoning: crafted examples, adversarial embeddings, or poisoned RAG documents shift behavior, backdoor outputs, or force preferential retrieval without obvious benchmark regressions.'
    ],
    attackerCapabilities: [
      'Publish look-alike packages, modified checkpoints, malicious serialized artifacts, or altered loader configuration.',
      'Tamper with optimization, sampling, DP-SGD noise, learning rates, preprocessing, or privacy-budget controls under the cover of quality improvements.',
      'Insert a small number of high-influence samples or semantically optimized documents that maximize downstream impact while minimizing footprint.'
    ],
    illustrativeScenario:
      'A downloaded model executes code on load and exfiltrates cloud credentials. In another path, a preprocessing refactor disables DP-SGD noise injection, improving accuracy while causing the model to memorize patient records. Separately, a competitor seeds crafted forum posts that the RAG pipeline preferentially cites.',
    impacts: [
      'Developer, pipeline, or registry compromise through malicious model artifacts.',
      'Backdoored or behavior-shifted models and RAG systems.',
      'Silent removal of privacy controls that expands extraction risk.',
      'Exfiltration of credentials and IP through supply-chain ingress.',
      'Long remediation timelines because integrity failures appear as legitimate improvements.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Put guardrails at ingestion, package use, evaluation, registry, and secret boundaries.', [
        { title: 'Ingestion controls', description: 'Sandbox ingestion, sanitize content, deduplicate, filter unsafe MIME types, and semantically validate all incoming data.', scope: 'Buy and Build' },
        { title: 'Package and model hygiene', description: 'Use trusted registries, pinned hashes, signed artifacts, and sandboxed model loading.', scope: 'Buy and Build' },
        { title: 'Golden datasets and canaries', description: 'Run immutable baselines and canary trigger validation on every training run.', scope: 'Build' },
        { title: 'Registry protection and promotion gates', description: 'Make promoted artifacts immutable and require human approval for checkpoint promotion.', scope: 'Buy and Build' },
        { title: 'Source access controls', description: 'Restrict write access to all training and RAG sources; remove over-broad inherited permissions.', scope: 'Buy and Build' },
        { title: 'Hosted platform secret hygiene', description: 'Scope and rotate tokens and least-privilege external connectors to data stores.', scope: 'Buy and Build' }
      ]),
      tier(2, 'Hardening', 'Make provenance and tamper evidence enforceable.', [
        { title: 'Cryptographic signing', description: 'Sign and verify all datasets, scripts, checkpoints, and configurations on fetch and promotion; reject unsigned artifacts.', scope: 'Build' },
        { title: 'DBOM', description: 'Maintain CycloneDX ML-BOM provenance per dataset, checkpoint, vector index, and training run.', scope: 'Build' },
        { title: 'Anomaly and outlier detection', description: 'Monitor distribution shifts, influence functions, and embedding cluster anomalies across ingestion and training.', scope: 'Build' },
        { title: 'Embedding integrity checks', description: 'Use source authority weighting and query-to-result semantic validation in RAG retrieval.', scope: 'Build' },
        { title: 'Privacy control regression', description: 'Treat DP, noise injection, and memorization metrics as security gates in build promotion.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Use reproducibility, supplier assurance, red teaming, and runtime verification.', [
        { title: 'Deterministic builds', description: 'Use content-addressable storage, deterministic pipelines, and checksum or behavior regression against last known good state.', scope: 'Build' },
        { title: 'Supplier attestation', description: 'Require SBOMs, security questionnaires, and attestations for high-risk dataset and model providers.', scope: 'Buy and Build' },
        { title: 'Backdoor and adversarial retrieval red teams', description: 'Test for triggers, harmful associations, and poisoned retrieval before release.', scope: 'Build' },
        { title: 'Runtime behavioral monitoring', description: 'Continuously verify golden-set behavior and artifact checksums after deployment.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'CVE-2025-24357 (vLLM): insecure torch.load() use when fetching checkpoints from Hugging Face Hub.',
      'PyTorch-nightly dependency poisoning, December 2022.',
      'Hugging Face Spaces secrets exposure, 2024.',
      'Inference-time backdoors via hidden instructions in LLM chat templates.',
      'Anthropic small-sample poisoning research: 250 poisoned samples produced measurable behavioral impact.',
      'No dedicated CVE for artifact tampering or hyperparameter manipulation.'
    ],
    references: [
      { title: 'PyTorch dependency poisoning report', url: 'https://thehackernews.com/2023/01/pytorch-machine-learning-framework.html' },
      { title: 'Inference-Time Backdoors via Hidden Instructions in LLM Chat Templates', url: 'https://arxiv.org/abs/2602.04653' },
      { title: 'Anthropic - Small samples poison', url: 'https://www.anthropic.com/research/small-samples-poison' }
    ],
    crossReferences: ['LLM04:2026 Supply Chain', 'ASI04', 'DSGAI02 for supply-chain identity controls', 'DSGAI21 for retrieval disinformation'],
    keywords: ['poisoning', 'supply chain', 'DBOM', 'signing', 'canary', 'DP-SGD', 'RAG']
  },
  {
    id: 'DSGAI05',
    title: 'Data Integrity & Validation Failures',
    theme: 'Integrity & Resilience',
    summary:
      'Weak ingestion validation lets structurally valid but semantically malicious data corrupt training, indexing, feature stores, and snapshot restore paths.',
    howItUnfolds: [
      'Schema and semantic validation bypass allows malformed or adversarial CSV, JSON, or Parquet payloads to pass syntax checks while corrupting downstream data or model behavior.',
      'Outliers, null injections, Unicode edge cases, rare patterns, and schema drift can silently alter training or retrieval without triggering alerts.',
      'Snapshot and import path traversal in vector DBs, registries, or feature stores can write arbitrary files, overwrite configuration, inject code, or alter data at rest.'
    ],
    attackerCapabilities: [
      'Upload or influence data entering training, indexing, feature stores, or snapshot import endpoints through APIs, bulk import, vendor integrations, or compromised accounts.',
      'Use symlinks, archive traversal, malformed files, schema edge cases, or semantic outliers without needing to bypass authentication.',
      'Exploit validation blind spots instead of model internals.'
    ],
    illustrativeScenario:
      'An attacker with snapshot import access uploads an archive containing symlinks targeting a vector DB configuration directory. Import path traversal disables API authentication, and a later attacker exfiltrates the full embedding index.',
    impacts: [
      'Silent corruption of training datasets, models, analytics, and evaluation results.',
      'Arbitrary file write or full host compromise through import paths.',
      'Configuration tampering that disables downstream security controls.',
      'Long mean time to detection because payloads appear operationally normal.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Enforce strict validation and limit filesystem blast radius.', [
        { title: 'Schema enforcement', description: 'Apply JSON Schema, Avro, or Parquet contracts at every ingestion boundary and block on validation failure.', scope: 'Build' },
        { title: 'Hardened import paths', description: 'Sanitize paths, refuse symlinks, and allowlist archive members for snapshots and backups.', scope: 'Build' },
        { title: 'Non-root services and read-only mounts', description: 'Run AI infrastructure with minimum filesystem write scope.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Verify integrity and isolate restore operations.', [
        { title: 'Cryptographic integrity verification', description: 'Require signed artifacts and checksums on every import and promotion event.', scope: 'Build' },
        { title: 'Semantic validation', description: 'Reject structurally valid payloads with anomalous values, distributions, or adversarial patterns.', scope: 'Build' },
        { title: 'Containerized imports', description: 'Run import and restore in isolated containers with no host write access outside target directories.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Detect subtle data anomalies and enforce mandatory access controls.', [
        { title: 'Ingestion anomaly detection', description: 'Automatically quarantine statistical and semantic outlier batches before promotion.', scope: 'Build' },
        { title: 'SELinux/AppArmor profiles', description: 'Constrain vector store, registry, and feature store processes to limit import-path exploitation blast radius.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'CVE-2024-3584 (Qdrant): snapshot upload path traversal and arbitrary file write.',
      'CVE-2024-3829 (Qdrant): related arbitrary file write vulnerability in snapshot handling.'
    ],
    keywords: ['validation', 'schema', 'semantic validation', 'snapshot', 'path traversal', 'Qdrant']
  },
  {
    id: 'DSGAI06',
    title: 'Tool, Plugin & Agent Data Exchange Risks',
    theme: 'Identity, Tools & Agents',
    summary:
      'Every plugin call, MCP invocation, A2A handoff, or tool execution boundary can forward sensitive context, credentials, attachments, and authority outside the intended control plane.',
    howItUnfolds: [
      'Plugins and third-party tools receive conversation payloads, sometimes full transcripts, and forward them to their own backend infrastructure.',
      'A previously approved plugin can turn malicious after update, mirroring browser-extension ecosystem risks.',
      'Agent protocols such as A2A and MCP can lack mutual authentication, signing, encryption, or per-tool scoping by default or through misconfiguration.',
      'Poisoned tool metadata, MCP server descriptions, or plugin manifests can instruct the model to chain unauthorized calls or leak context.'
    ],
    attackerCapabilities: [
      'Introduce or compromise an integration endpoint trusted by the assistant runtime.',
      'Shape API responses or tool outputs to influence subsequent agent decisions and create second-order leakage.',
      'Exploit standing credentials, shared service accounts, elevated host privileges, or transitive trust across agent graphs.'
    ],
    illustrativeScenario:
      'A meeting notes plugin transmits raw transcripts containing PHI and internal links to its backend over weak transport and stores them indefinitely. Separately, an untrusted MCP bridge contains a tool-poisoning instruction that exfiltrates context and embedded API keys.',
    impacts: [
      'Sensitive data spreads to third-party processors outside the primary governance boundary.',
      'Compromised tools or agents can perform unauthorized actions on behalf of users.',
      'Data subject rights become difficult to execute across many small vendors.',
      'Plugin and agent channels become the exfiltration path even when the core LLM stack is hardened.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Control which integrations exist and make exchanges observable.', [
        { title: 'Allowlist and DPAs', description: 'Enable no plugin or agent integration without security review, contractual guarantees, and data residency confirmation.', scope: 'Buy and Build' },
        { title: 'Transport security', description: 'Enforce mTLS and signed requests across integration boundaries.', scope: 'Buy and Build' },
        { title: 'Central logging', description: 'Log tool calls and agent handoffs with target, payload metadata, data categories, and identity.', scope: 'Buy and Build' }
      ]),
      tier(2, 'Hardening', 'Minimize context and maintain runtime control over integrations.', [
        { title: 'Context minimization', description: 'Send only required fields and never forward full transcripts by default.', scope: 'Build' },
        { title: 'Kill switch', description: 'Disable or quarantine any integration immediately without redeploying the core stack.', scope: 'Build' },
        { title: 'Continuous vetting', description: 'Re-evaluate approved integrations on updates, behavior changes, or terms changes.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Cryptographically bind identities and authorize by consequence.', [
        { title: 'PKI-backed agent identity and task-scoped tokens', description: 'Use per-agent cryptographic identities, signed requests, and explicit TTL-scoped credentials across A2A and MCP.', scope: 'Buy and Build' },
        { title: 'Consequence-based authorization', description: 'Evaluate blast radius and require human approval or secondary oversight for irreversible or high-impact operations.', scope: 'Build' },
        { title: 'Integration graph anomaly detection', description: 'Detect unexpected cross-agent data flows and tool-poisoning indicators.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'Research on ChatGPT plugin vulnerabilities showed unauthorized account access and sensitive data exposure risks.',
      'CVE-2025-66404: MCP server for Kubernetes exec_in_pod tool abuse if tool scoping is not enforced.',
      'CVE-2025-6514: mcp-remote OS command injection via crafted authorization_endpoint response URL.',
      'Postmark MCP Server vulnerability involving insufficient tool scoping and runtime validation.'
    ],
    references: [
      { title: 'WIRED - ChatGPT Has a Plug-In Problem', url: 'https://www.wired.com/story/chatgpt-plugins-security-privacy-risk/' },
      { title: 'Salt Security - ChatGPT ecosystem security flaws', url: 'https://salt.security/blog/security-flaws-within-chatgpt-extensions-allowed-access-to-accounts-on-third-party-websites-and-sensitive-data' },
      { title: 'Reco - ChatGPT security risks', url: 'https://www.reco.ai/learn/chatgpt-security-risk' },
      { title: 'The Hacker News - First malicious MCP server stealing emails', url: 'https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html' }
    ],
    keywords: ['plugins', 'MCP', 'A2A', 'tools', 'context forwarding', 'tool poisoning']
  },
  {
    id: 'DSGAI07',
    title: 'Data Governance, Lifecycle & Classification for AI Systems',
    theme: 'Governance & Compliance',
    summary:
      'Governance failures in AI propagate into derived artifacts such as embeddings, logs, fine-tuned weights, backups, and agent memory, making erasure, audit, and remediation difficult or impossible.',
    howItUnfolds: [
      'Data enters without classification or with inconsistent labels, so downstream training blockers, access controls, and retention controls have nothing reliable to act on.',
      'Source records are deleted, but derived embeddings, fine-tuning runs, cached retrievals, logs, backups, or re-indexed snapshots persist.',
      'Lineage gaps make it impossible to prove lawful basis, identify blast radius, perform targeted retraining, or scope machine unlearning.'
    ],
    attackerCapabilities: [
      'Exploit misclassified or unclassified data that AI systems ingest, surface, synthesize, or export.',
      'Use legitimate AI workflows to aggregate and exfiltrate sensitive data at scale where governance controls are not AI-aware.',
      'Benefit from lifecycle gaps where deleted data remains available in derivative stores.'
    ],
    illustrativeScenario:
      'A customer record is deleted after a GDPR erasure request, but derived embeddings and a backup remain. A later migration re-indexes the backup, restoring the deleted record to live retrieval. No lineage links the embeddings or training runs to the source record.',
    impacts: [
      'DSR and erasure obligations are violated through persistent derived artifacts.',
      'Regulators cannot be shown lawful basis or consent lineage for training data.',
      'Sensitive data propagates into embeddings, fine-tuned weights, logs, and backups outside intended controls.',
      'Incident remediation cannot be scoped because source-to-artifact lineage is missing.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Propagate labels and automate retention across derivatives.', [
        { title: 'Classification propagation', description: 'Apply sensitivity labels and retention obligations to embeddings, logs, backups, fine-tuning datasets, memory, and caches.', scope: 'Build' },
        { title: 'Pipeline ingress scanning', description: 'Run PII, PHI, and secret detection at every ingestion boundary and reclassify at merge points.', scope: 'Buy and Build' },
        { title: 'Automated retention enforcement', description: 'Automate backup expiry, purge scheduling, tombstoning, and cryptographic erasure across raw and derived tiers.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Test erasure and control persistent agent context.', [
        { title: 'Erasure verification tests', description: 'Simulate deletion and verify absence across databases, logs, embeddings, backups, and agent memory.', scope: 'Build' },
        { title: 'TTL for agent context', description: 'Apply time-to-live to persistent memory, cached retrievals, and ephemeral context windows.', scope: 'Build' },
        { title: 'Mandatory source/license/owner tags', description: 'Require provenance and ownership metadata before pipeline promotion.', scope: 'Buy and Build' }
      ]),
      tier(3, 'Advanced', 'Make data-to-model lineage queryable for remediation.', [
        { title: 'Data-to-model lineage registry', description: 'Link training runs to versioned dataset snapshots for targeted retraining and erasure scoping at weight level.', scope: 'Build' },
        { title: 'Derived-artifact inventory for DSR', description: 'Maintain live source-to-artifact mapping for embeddings, indexes, snapshots, caches, backups, and model artifacts.', scope: 'Build' }
      ])
    ],
    knownExploits: ['No specific CVE; this is a governance and pipeline architecture failure class.'],
    keywords: ['classification', 'lineage', 'DSR', 'erasure', 'retention', 'DBOM', 'lifecycle']
  },
  {
    id: 'DSGAI08',
    title: 'Non-Compliance & Regulatory Violations',
    theme: 'Governance & Compliance',
    summary:
      'Regulatory exposure materializes when AI data processing lacks lawful basis, consent, erasure propagation, lineage, DPIAs, and records that include derived artifacts.',
    howItUnfolds: [
      'Training data is collected or reused without documented lawful basis, consent, purpose compatibility, or retention obligations.',
      'Raw records are deleted, but model weights, LoRA adapters, embeddings, vector stores, caches, and backups retain recoverable or influential traces.',
      'At the point of regulatory or data-subject obligation, the organization cannot link source records to derived artifacts or prove compliance.'
    ],
    attackerCapabilities: [
      'Regulators, litigants, journalists, or data subjects can trigger exposure through subject access requests, erasure requests, training-data disclosures, or output analysis.',
      'Technical adversaries can target cross-border or weakly governed AI infrastructure to amplify jurisdictional compliance issues.',
      'The failure manifests when governance claims diverge from technical reality.'
    ],
    illustrativeScenario:
      'A user submits a GDPR Article 17 deletion request. The CRM and lake records are removed, but RAG embeddings and a fine-tuned model remain. No model-to-data lineage exists, so targeted retraining cannot be scoped and deleted content continues to surface.',
    impacts: [
      'Fines and enforcement orders under GDPR, HIPAA, CCPA/CPRA, EU AI Act, Colorado AI Act, and similar regimes.',
      'Civil liability for data-subject-rights violations.',
      'Injunctions requiring model inference suspension or deletion.',
      'EU market restrictions for high-risk AI systems that cannot demonstrate training data governance.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Build AI compliance obligations into the data map and DPIA process.', [
        { title: 'AI DPIA process', description: 'Conduct DPIAs before training or deploying on personal data and explicitly cover embeddings, retrieval indexes, adapters, and fine-tuned weights.', scope: 'Build' },
        { title: 'Lawful basis documentation', description: 'Document lawful bases and processing purposes in data maps that extend to derived artifacts.', scope: 'Build' },
        { title: 'Retention and erasure in ML pipelines', description: 'Apply automated retention and erasure to embedding stores, model artifacts, caches, and retrieval layers.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Propagate consent and map AI processing records.', [
        { title: 'Consent lifecycle in ML pipelines', description: 'Propagate consent state to derivatives and block re-ingestion when consent lapses or is withdrawn.', scope: 'Build' },
        { title: 'EU AI Act Article 10 readiness', description: 'Assess training data governance gaps for high-risk systems before the August 2026 Article 10 enforcement milestone.', scope: 'Build' },
        { title: 'RoPA for AI processing', description: 'Create Article 30 records for AI training and inference, including subprocessors and vector/model vendors.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Monitor compliance posture continuously and design for unlearning readiness.', [
        { title: 'Unlearning readiness architecture', description: 'Maintain versioned data-to-model linkage for scoped retraining and erasure response.', scope: 'Build' },
        { title: 'Automated compliance posture monitoring', description: 'Continuously flag gaps in lawful basis, expired consent, and unverified erasure across derived artifacts.', scope: 'Buy and Build' }
      ])
    ],
    knownExploits: ['No specific CVE; token leaks, dataset exposures, and vector misconfigurations often trigger regulatory investigations.'],
    crossReferences: ['GDPR Articles 5, 17, 22, 30', 'HIPAA minimum necessary and breach notification', 'CCPA/CPRA deletion and opt-out rights', 'EU AI Act Articles 10, 13, 14', 'Colorado AI Act'],
    keywords: ['GDPR', 'HIPAA', 'CCPA', 'EU AI Act', 'DPIA', 'RoPA', 'consent']
  },
  {
    id: 'DSGAI09',
    title: 'Multimodal Capture & Cross-Channel Data Leakage',
    theme: 'Leakage & Exposure',
    summary:
      'Multimodal systems ingest screenshots, images, audio, video, IDs, PDFs, and whiteboards; the raw media and extracted OCR/ASR derivatives can leak through overlooked stores and channels.',
    howItUnfolds: [
      'Users upload screenshots, dashboards, passport scans, PDFs, voice notes, and whiteboard photos for assistant understanding.',
      'Raw media, OCR text, transcripts, thumbnails, metadata, embeddings, and logs are stored separately, sometimes with weaker classification than the original.',
      'Weak redaction, retention, or training reuse lets sensitive visual and audio data persist beyond the original task.',
      'Attackers combine visual, audio, metadata, and text traces to re-identify people or infer sensitive attributes.'
    ],
    attackerCapabilities: [
      'Access object stores, logs, embedding stores, OCR outputs, transcripts, thumbnails, or extracted metadata.',
      'Target derivative layers that are indexed or logged even when raw media is locked down.',
      'Use model inversion, embedding probing, and cross-modal correlation to recover latent details.'
    ],
    illustrativeScenario:
      'A support engineer uploads a screenshot of an admin panel with customer details and API keys. The assistant OCRs it and stores both image and extracted text in a training bucket. A misconfigured ACL later exposes both.',
    impacts: [
      'Leakage of secrets, credentials, IDs, biometric data, dashboards, and sensitive documents.',
      'Cross-modal inference and re-identification from combined visual, audio, and text signals.',
      'Regulatory complications because faces, voiceprints, and IDs can fall under stricter biometric and identity regimes.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Classify and minimize multimodal data by default.', [
        { title: 'High-sensitivity default classification', description: 'Treat images, audio, video, and documents as high sensitivity unless formally downgraded.', scope: 'Build' },
        { title: 'OCR/ASR PII and secret detection', description: 'Scan extracted text and transcripts at ingestion; mask, reject, or retain classification parity with the source media.', scope: 'Buy and Build' },
        { title: 'Short TTL for transient storage', description: 'Separate temporary multimodal workbench storage from long-term corpora and delete automatically.', scope: 'Build' },
        { title: 'Training opt-out by default', description: 'Exclude user-provided media from training unless explicit consent and minimization controls exist.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Process and protect derivatives as sensitive data.', [
        { title: 'On-device or enclave preprocessing', description: 'Run OCR/ASR or face blurring locally or in secure enclaves; send only redacted or encoded results downstream.', scope: 'Build' },
        { title: 'Derivative tagging', description: 'Propagate classification and retention to extracted text, transcripts, embeddings, and logs.', scope: 'Build' },
        { title: 'Multimodal DLP reviews', description: 'Extend DLP and privacy reviews to screenshots, identity documents, physical whiteboards, and voice recordings.', scope: 'Buy and Build' },
        { title: 'Embedding encryption/tokenization', description: 'Encrypt or tokenize sensitive multimodal embeddings to limit inversion and storage-compromise impact.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Red-team cross-modal inference and monitor distributions.', [
        { title: 'Multimodal red teaming', description: 'Evaluate cross-modal re-identification and leakage before deployment.', scope: 'Build' },
        { title: 'Distribution monitoring and sampling', description: 'Monitor upload distributions and manually sample to detect anomalies or policy violations.', scope: 'Build' },
        { title: 'Biometric and identity legal review', description: 'Review pipelines processing faces, voiceprints, or identity documents under GDPR Article 9, BIPA, and equivalents.', scope: 'Build' }
      ])
    ],
    knownExploits: ['No multimodal-specific CVE in the source; regulators and researchers highlight increased abuse potential from multimodal AI.'],
    references: [
      { title: 'European Data Protection Supervisor - Multimodal artificial intelligence', url: 'https://www.edps.europa.eu/data-protection/technology-monitoring/techsonar/multimodal-artificial-intelligence' },
      { title: 'TechMonitor - Multimodal AI models pose increased risks', url: 'https://www.techmonitor.ai/ai-and-automation/multimodal-ai-models-increased-risks-abuse-harmful-content/' },
      { title: 'Pillar Security - Securing Multimodal AI', url: 'https://www.pillar.security/blog/securing-multimodal-ai' }
    ],
    keywords: ['multimodal', 'OCR', 'ASR', 'screenshots', 'biometrics', 'metadata']
  },
  {
    id: 'DSGAI10',
    title: 'Synthetic Data, Anonymization & Transformation Pitfalls',
    theme: 'Governance & Compliance',
    summary:
      'Synthetic, anonymized, de-identified, tokenized, or transformed data can still reveal individuals, membership, attributes, rare records, bias, or source structure.',
    howItUnfolds: [
      'Quasi-identifiers such as age bands, ZIP codes, diagnosis codes, timestamps, and rare combinations survive de-identification and can be joined with auxiliary datasets.',
      'Fine-tuned models memorize rare de-identified records and re-create privacy risk through membership inference or extraction.',
      'Synthetic generators preserve distributional realism and can leak rare source records or statistical echoes.',
      'Preprocessing errors, Unicode normalization, tokenization skew, schema drift, and weak transform tests create downstream leakage or brittleness.'
    ],
    attackerCapabilities: [
      'Use public records, data brokers, research releases, or auxiliary datasets for population linkage.',
      'Probe models for membership, attribute, output variance, or confidence signals.',
      'Analyze synthetic datasets offline for rare feature combinations and distinctive correlations.',
      'Reverse-engineer deterministic transformations, encoding artifacts, or schema inconsistencies.'
    ],
    illustrativeScenario:
      'A healthcare provider strips direct identifiers but retains age, three-digit ZIP, diagnosis, and admission date. A clinical LLM memorizes rare combinations. A synthetic dataset generated from it lets a partner confirm patient-cohort membership and reconstruct approximate records.',
    impacts: [
      'Re-identification of people believed to be anonymized.',
      'Confidentiality breaches under GDPR, HIPAA, CCPA, and contractual obligations.',
      'Regulators may still deem synthetic or transformed datasets personal data.',
      'False confidence causes broader sharing than the source data sensitivity warrants.',
      'Bias amplification or poisoned synthetic data can degrade downstream model integrity.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Do not downgrade transformed data without proof.', [
        { title: 'Default classification parity', description: 'Synthetic and de-identified datasets inherit source classification until residual risk is formally measured.', scope: 'Build' },
        { title: 'Schema governance', description: 'Enforce schema contracts, drift alerts, and validation across preprocessing and transformation pipelines.', scope: 'Build' },
        { title: 'Dataset Bill of Materials', description: 'Document source-to-artifact lineage for training datasets, synthetic outputs, embeddings, and fine-tuned weights.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Measure and reduce disclosure risk before sharing.', [
        { title: 'Disclosure risk measurement', description: 'Run re-identification testing and membership inference evaluation before external sharing.', scope: 'Build' },
        { title: 'Quasi-identifier suppression', description: 'Automatically detect and perturb rare combinations, geography, timestamps, and sensitive quasi-identifiers.', scope: 'Build' },
        { title: 'Transformation testing', description: 'Add unit, property, and metamorphic tests for tokenization, normalization, and Unicode handling.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Use privacy-preserving generation and adversarial evaluation.', [
        { title: 'DP-based generation and training', description: 'Apply differential privacy at generation and fine-tuning for high-risk cohorts with privacy budget accounting.', scope: 'Build' },
        { title: 'Membership inference red teaming', description: 'Test fine-tuned models and synthetic datasets using current membership-inference techniques before release.', scope: 'Build' },
        { title: 'Versioned data-to-model linkage', description: 'Trace rare cohort contribution to weights so targeted retraining remains possible as risk evolves.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'No specific CVE; anonymization reversal and synthetic re-identification are privacy-design and ML architecture failures.',
      'Netflix Prize and multiple health-data studies demonstrate mature re-identification techniques.'
    ],
    references: [
      { title: 'Narayanan and Shmatikov - Robust De-anonymization of Large Sparse Datasets', url: 'https://arxiv.org/abs/cs/0610105' },
      { title: 'Membership inference attacks against synthetic health data', url: 'https://pubmed.ncbi.nlm.nih.gov/34920126/' },
      { title: 'Evaluating Identity Disclosure Risk in Fully Synthetic Health Data', url: 'https://pmc.ncbi.nlm.nih.gov/articles/PMC7704280/' },
      { title: 'Empirical Evaluation of Synthetic Data via Attribute Inference Attack', url: 'https://link.springer.com/chapter/10.1007/978-3-031-57978-3_18' },
      { title: 'YData - Re-identification risk in Synthetic Data', url: 'https://ydata.ai/resources/how-to-evaluate-the-re-identification-risk-in-synthetic-data' }
    ],
    keywords: ['synthetic data', 'anonymization', 'membership inference', 'quasi-identifiers', 'DP']
  },
  {
    id: 'DSGAI11',
    title: 'Cross-Context & Multi-User Conversation Bleed',
    theme: 'Leakage & Exposure',
    summary:
      'Session state, shared memory, KV caches, response caches, or shared vector indexes can leak one user or tenant context into another user or tenant conversation.',
    howItUnfolds: [
      'Persistent assistants reuse conversation state, memory, caches, or retrieval context across users, sessions, workspaces, or tenants.',
      'Weak tenancy, mishandled conversation IDs, shared vector indexes, post-retrieval filtering, or cache reuse causes cross-user content to appear in another context.',
      'Serving-layer optimizations such as KV-cache sharing can create prompt leakage side channels in multi-tenant inference.'
    ],
    attackerCapabilities: [
      'Probe residual memory with prompts such as requests to summarize previous questions or uploaded documents.',
      'Exploit predictable or weakly bound session IDs, session fixation, or enumeration.',
      'Craft semantically colliding retrieval queries against shared vector stores.',
      'Manipulate roles, workspace switching, permission updates, or race conditions to find transient isolation failures.'
    ],
    illustrativeScenario:
      'A team assistant uses one shared vector store. Developer A uploads proprietary design docs. Developer B from another project receives A’s content because retrieval filtering lacks tenant enforcement.',
    impacts: [
      'Lateral exposure of proprietary or personal data across users, teams, or customers.',
      'Breach of SaaS multi-tenant isolation guarantees.',
      'Difficult-to-reproduce incidents where only specific prompts or timing reveal cross-tenant data.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Enforce hard tenant and session boundaries.', [
        { title: 'Tenant ID enforcement', description: 'Enforce tenant and user identifiers across conversation stores, vector DBs, KV caches, and prompt construction.', scope: 'Build' },
        { title: 'Per-tenant or per-space indexes', description: 'Use dedicated indexes or strict server-side tenant filters validated at query time.', scope: 'Build' },
        { title: 'Auth-bound sessions', description: 'Cryptographically bind session IDs to authenticated user identity and avoid cross-user cache reuse.', scope: 'Build' },
        { title: 'Cross-tenant access logging', description: 'Log retrieval queries that touch another tenant even if results are later filtered.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Authorize and redact at retrieval and context construction time.', [
        { title: 'Fine-grained authorization', description: 'Apply ABAC at retrieval and context construction based on ownership, classification, and user authorization.', scope: 'Build' },
        { title: 'Classification and redaction before context injection', description: 'Redact retrieved content to the user’s authorization level before it enters the model context.', scope: 'Build' },
        { title: 'Automated bleed testing', description: 'Run cross-tenant retrieval, context injection, and session ID weakness tests on every deployment.', scope: 'Build' },
        { title: 'Incident playbooks', description: 'Define detection, containment, investigation, and notification steps for tenant-boundary failures.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Detect semantic leakage and serving-layer side channels.', [
        { title: 'Semantic response evaluation', description: 'Sample responses for paraphrased or embedded cross-tenant data that bypasses structural filters.', scope: 'Build' },
        { title: 'KV-cache isolation', description: 'Partition KV cache and response cache for multi-tenant serving.', scope: 'Build' },
        { title: 'Multi-tenant red teaming', description: 'Test prompt injection, session enumeration, retrieval bypass, and permission race scenarios.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'March 2023 ChatGPT shared-cache issue exposed conversation titles.',
      'CVE-2025-6515: oatpp-mcp SSE endpoint returns an instance pointer as the session ID, not unique or cryptographically secure.'
    ],
    references: [
      { title: 'OpenAI - March 20 ChatGPT outage', url: 'https://openai.com/index/march-20-chatgpt-outage/' },
      { title: 'Giskard - Cross Session Leak', url: 'https://www.giskard.ai/knowledge/cross-session-leak-when-your-ai-assistant-becomes-a-data-breach' },
      { title: 'NDSS 2025 - Prompt Leakage via KV-Cache Sharing', url: 'https://www.ndss-symposium.org/ndss-paper/i-know-what-you-asked-prompt-leakage-via-kv-cache-sharing-in-multi-tenant-llm-serving/' },
      { title: 'NeurIPS 2025 - Memory Injection Attacks on LLM Agents', url: 'https://neurips.cc/virtual/2025/loc/san-diego/poster/118152' },
      { title: 'INJECMEM paper', url: 'https://openreview.net/pdf?id=QVX6hcJ2um' }
    ],
    keywords: ['multi-tenant', 'session', 'KV cache', 'conversation bleed', 'ABAC', 'memory']
  },
  {
    id: 'DSGAI12',
    title: 'Unsafe Natural-Language Data Gateways (LLM-to-SQL/Graph)',
    theme: 'Model, Vector & Inference',
    summary:
      'Text-to-SQL, text-to-Graph, and data-copilot interfaces can translate natural language and injected context into overly broad or destructive queries that bypass normal access boundaries.',
    howItUnfolds: [
      'Organizations expose data warehouses, graphs, analytics engines, and APIs through “ask your data” assistants.',
      'The LLM generates raw SQL, GraphQL, Cypher, or REST calls over broad schemas using elevated service accounts.',
      'Prompt injection, hallucinated policy, RAG-sourced instructions, or poisoned text-to-query models produce sensitive joins, SELECT *, deletes, cross-tenant queries, or result-set logging.'
    ],
    attackerCapabilities: [
      'Use grammatically normal language to coerce the model into generating harmful queries without classic SQL injection syntax.',
      'Amplify privileges where generated queries execute under a broad service account rather than the end user identity.',
      'Exploit poisoned text-to-SQL/Graph models or hidden triggers to generate malicious queries that look benign at the prompt level.'
    ],
    illustrativeScenario:
      'A finance copilot retrieves a malicious document telling the model to dump all customer PII and card tokens. The model generates SELECT * across sensitive tables, and the gateway executes it because row and column policies are missing.',
    impacts: [
      'Bulk exfiltration from warehouses through one natural-language interface.',
      'Privilege escalation through the LLM gateway service account.',
      'Forensic ambiguity because one natural-language request expands into many generated queries.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Constrain what the model can execute and cap data volume.', [
        { title: 'Stored procedures and templates only', description: 'Do not let LLMs generate arbitrary SQL or graph queries against privileged connections.', scope: 'Build' },
        { title: 'Database-layer row and column security', description: 'Enforce RLS, column masking, and redaction at the database layer regardless of gateway behavior.', scope: 'Build' },
        { title: 'Result-set size caps', description: 'Limit rows returned per NL-generated query and require explicit confirmation or approval for larger results.', scope: 'Build' },
        { title: 'Full gateway request logging', description: 'Log NL request, generated query, user identity, result metadata, timestamp, and data category.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Validate generated queries and detect abusive sessions.', [
        { title: 'Query validation and linting', description: 'Reject queries that violate schema constraints, sensitive table/column deny-lists, or cost limits.', scope: 'Build' },
        { title: 'Rate limits and session budgets', description: 'Limit total data returned per user/session and alert on SELECT *, cross-tenant joins, or high-volume retrieval.', scope: 'Build' },
        { title: 'Generated-query ACL enforcement', description: 'Authorize the generated query itself against the requesting user’s data permissions.', scope: 'Build' },
        { title: 'Gateway anomaly detection', description: 'Detect schema enumeration, bulk retrieval, high-frequency requests, and unusual joins.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Harden against prompt injection and preserve attribution.', [
        { title: 'Prompt-injection hardening', description: 'Treat user inputs, retrieved docs, and tool outputs entering query-generation context as untrusted.', scope: 'Build' },
        { title: 'Text-to-SQL/Graph red teaming', description: 'Test over-broad access, schema enumeration, tenant bypass, and prompt-injection exfiltration before release.', scope: 'Build' },
        { title: 'Forensic query attribution', description: 'Maintain tamper-evident logs linking every executed query to the NL request, model intermediate, executing identity, and result metadata.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'CVE-2024-8309 (LangChain GraphCypherQAChain): prompt injection leading to malicious Cypher queries and unauthorized Neo4j access or modification.',
      'CVE-2024-7042 (langchainjs GraphCypherQAChain): prompt injection leading to SQL injection, data manipulation, exfiltration, DoS, and tenant-boundary violations.'
    ],
    references: [
      { title: 'How to safely use LLMs for Text-to-SQL with Stored Procedures', url: 'https://erincon01.medium.com/how-to-safely-use-llms-for-text-to-sql-with-stored-procedures-ba7540067f5f' },
      { title: 'DigitalAPI - Expose APIs to LLMs without breaking security', url: 'https://www.digitalapi.ai/blogs/expose-apis-to-llms' }
    ],
    keywords: ['text-to-SQL', 'GraphQL', 'Cypher', 'data copilot', 'RLS', 'query linting']
  },
  {
    id: 'DSGAI13',
    title: 'Vector Store Platform Data Security',
    theme: 'Model, Vector & Inference',
    summary:
      'Vector stores hold durable semantic representations of sensitive corpora; weak auth, tenant scoping, encryption, import validation, or query controls can expose or corrupt entire indexes.',
    howItUnfolds: [
      'Misconfigured vector APIs, public endpoints, weak credentials, permissive namespaces, default collection fallbacks, or client-side filters enable unauthorized access.',
      'Stolen embeddings and metadata can support inversion, membership inference, partial reconstruction, or knowledge-base enumeration.',
      'Snapshot import flaws, path traversal, and arbitrary upload can escalate to data theft, index tampering, or RCE.',
      'Shared caching or index layers can cause multi-tenant bleed through namespace confusion or misapplied ABAC.'
    ],
    attackerCapabilities: [
      'Bulk enumerate embeddings, metadata, indexes, and collections from exposed APIs.',
      'Probe vector stores to infer whether documents, facts, deals, investigations, or medical records exist.',
      'Poison or manipulate semantic retrieval by inserting malicious documents.',
      'Exploit platform import paths to write files, modify configs, or compromise hosts.'
    ],
    illustrativeScenario:
      'A multi-tenant vector DB leaks another tenant’s embeddings through mis-scoped ACLs. The attacker downloads the index and runs k-NN and reconstruction workflows. In a second path, a malicious snapshot uses symlinks to overwrite vector DB host configuration.',
    impacts: [
      'Cross-tenant data exposure and proprietary knowledge-base theft.',
      'Embedding inversion, membership inference, and partial text reconstruction.',
      'Index poisoning or downstream RAG manipulation.',
      'Full environment compromise if vector DB platform flaws are exploited.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Lock down vector platform basics.', [
        { title: 'Encryption at rest and in transit', description: 'Encrypt vectors, metadata, and snapshots; require private networking and explicit exposure approval.', scope: 'Buy and Build' },
        { title: 'Auth on every endpoint', description: 'Enforce authentication and authorization on query, insert, delete, and snapshot import APIs.', scope: 'Buy and Build' },
        { title: 'Per-tenant index isolation', description: 'Use dedicated indexes or server-enforced tenant scoping; do not rely only on client filters.', scope: 'Build' },
        { title: 'Non-root services', description: 'Run vector stores as non-root with SELinux/AppArmor and read-only mounts where possible.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Harden imports, queries, lifecycle, and dependencies.', [
        { title: 'Hardened snapshot and bulk imports', description: 'Verify checksums/signatures, sanitize paths, refuse symlinks, validate archive members, and import inside restricted containers.', scope: 'Build' },
        { title: 'Query guards', description: 'Limit top-k, dimensionality disclosure, query rates, and high-volume nearest-neighbor sweeps.', scope: 'Build' },
        { title: 'Lifecycle including backups', description: 'Propagate deletion to snapshots, backups, caches, and derived index artifacts.', scope: 'Build' },
        { title: 'Image and package hygiene', description: 'Scan containers and dependencies, pin versions, and enforce patch SLAs.', scope: 'Buy and Build' }
      ]),
      tier(3, 'Advanced', 'Reduce blast radius even when access controls fail.', [
        { title: 'Per-tenant envelope encryption', description: 'Use tenant-specific keys for vectors and snapshots; consider dedicated KMS per tenant or environment.', scope: 'Buy and Build' },
        { title: 'Embedding scope minimization', description: 'Index only necessary and approved content so a vector compromise contains less sensitive data.', scope: 'Build' },
        { title: 'Detailed query observability', description: 'Log identity, filters, result counts, and egress volume; alert on exfiltration and cross-tenant anomalies.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'Qdrant CVE-2024-3829: arbitrary file upload and possible RCE.',
      'Qdrant CVE-2024-3584: path traversal via snapshot upload.'
    ],
    crossReferences: ['DSGAI04 and DSGAI18 for embedding inversion and reconstruction', 'DSGAI05 for import validation'],
    keywords: ['vector DB', 'embeddings', 'Qdrant', 'tenant isolation', 'snapshot', 'inversion']
  },
  {
    id: 'DSGAI14',
    title: 'Excessive Telemetry & Monitoring Leakage',
    theme: 'Leakage & Exposure',
    summary:
      'LLM observability and agent tracing can capture full prompts, responses, tool calls, vector results, secrets, and internal reasoning into centralized stores with weaker controls.',
    howItUnfolds: [
      'Teams enable rich logs, traces, body capture, and debug sessions to diagnose agent and RAG quality.',
      'Middleware dumps prompts, responses, tool outputs, vector results, internal URLs, system prompts, and credentials into SIEM, APM, or third-party log analytics.',
      'A compromised analyst account, overly broad search permission, insider, or vendor incident exposes weeks or months of aggregated sensitive conversations and operational context.'
    ],
    attackerCapabilities: [
      'Target observability stacks instead of primary stores because they aggregate high-value data across systems.',
      'Use phished analyst, SOC, ML engineer, or DevOps access to bulk export logs.',
      'Exploit fragmented vendor telemetry where full agent traces capture tool parameters, retrieved docs, inter-agent payloads, and credentials.'
    ],
    illustrativeScenario:
      'Engineers enable debug mode with full HTTP body logging for flaky agents. OAuth tokens, system prompts, and customer data are captured. Months later a SOC analyst account is phished and weeks of observability data are exported.',
    impacts: [
      'Large-scale exfiltration of prompts, documents, traces, secrets, and training samples.',
      'Retroactive privacy exposure because logs outlive source systems.',
      'High blast radius where observability bypasses classification, masking, and retention controls.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Minimize and control observability data.', [
        { title: 'Least logging by default', description: 'Disable body-level logging; log metadata unless explicitly elevated; redact credentials, system prompts, PII, and tool outputs before write.', scope: 'Build' },
        { title: 'Hardened observability access', description: 'Apply RBAC/ABAC, mTLS, private networking, and restricted bulk export/search permissions.', scope: 'Buy and Build' },
        { title: 'Retention alignment', description: 'Keep logs and traces no longer than the source data they capture and purge automatically.', scope: 'Build' },
        { title: 'Third-party vendor controls', description: 'Hold log analytics and APM vendors to processor-grade DPAs, residency, and subprocessor controls.', scope: 'Buy' }
      ]),
      tier(2, 'Hardening', 'Scan, approve, and encrypt telemetry.', [
        { title: 'PII and secret scanning', description: 'Scan log streams and traces at write time and redact or alert on PII, API keys, tokens, and system prompt content.', scope: 'Buy and Build' },
        { title: 'Tiered debug logging', description: 'Require approval, minimum scope, justification, and automatic expiry for verbose logging.', scope: 'Build' },
        { title: 'Encryption at rest', description: 'Encrypt all log stores, trace DBs, and session captures with controlled key management.', scope: 'Buy and Build' }
      ]),
      tier(3, 'Advanced', 'Test observability as a primary exfiltration target.', [
        { title: 'Log leak red teaming', description: 'Simulate SIEM/APM compromise, insider bulk export, and phished analyst account scenarios.', scope: 'Build' },
        { title: 'Behavioral analytics on observability access', description: 'Detect unusual bulk exports, cross-session searches, high-volume trace downloads, and off-hours access.', scope: 'Buy and Build' }
      ])
    ],
    knownExploits: [
      'No specific CVE; many token and secret leaks happen because observability is easier to exfiltrate than primary stores.',
      'OpenAI Mixpanel incident, November 2025, is cited in the source as a third-party observability risk reference.'
    ],
    references: [
      { title: 'OpenAI - Mixpanel incident', url: 'https://openai.com/index/mixpanel-incident/' },
      { title: 'Datadog LLM Observability docs', url: 'https://docs.datadoghq.com/llm_observability/' },
      { title: 'Datadog prompt tracking', url: 'https://docs.datadoghq.com/llm_observability/monitoring/prompt_tracking/' },
      { title: 'Datadog LLM Observability product', url: 'https://www.datadoghq.com/product/llm-observability/' }
    ],
    keywords: ['telemetry', 'logs', 'traces', 'debug', 'SIEM', 'APM', 'observability']
  },
  {
    id: 'DSGAI15',
    title: 'Over-Broad Context Windows & Prompt Over-Sharing',
    theme: 'Leakage & Exposure',
    summary:
      'Prompt inflation sends full records, customer-360 profiles, tickets, documents, or screens to models, providers, caches, and logs even when the task only needs a few fields.',
    howItUnfolds: [
      'Teams append full profiles, tickets, histories, documents, and rich context to improve answer quality.',
      'LLM gateways auto-append customer_360 or full-record context to routine prompts.',
      'External providers, edge caches, observability stacks, subcontractors, or insiders receive a complete view of sensitive data that was not necessary for the task.',
      'Framework defaults and auto-context features can silently expand included fields over time.'
    ],
    attackerCapabilities: [
      'Compromise provider accounts, edge caches, logs, or observability systems and harvest full prompt bodies.',
      'Use insider or contractor debug access to extract prompt telemetry instead of touching core databases.',
      'Reconstruct complete user profiles by correlating repeated over-scoped requests across vendors.'
    ],
    illustrativeScenario:
      'A banking assistant includes full KYC files, address history, and account notes in every balance prompt. Provider logs later expose far more customer data than the balance use case required.',
    impacts: [
      'Massive overexposure of PII, PHI, financial data, and internal notes to providers and subcontractors.',
      'Sensitive data scattered across logs, caches, analytics, and third parties.',
      'Regulatory scrutiny when exported data was not strictly necessary for the stated purpose.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Minimize prompt payloads and lock provider contracts.', [
        { title: 'Prompt-layer data minimization', description: 'Include only fields required for the task; disable full records and auto-appended profiles by default.', scope: 'Build' },
        { title: 'Prompt redaction and masking', description: 'Strip or tokenize PII, PHI, financial identifiers, and credentials at the gateway boundary.', scope: 'Build' },
        { title: 'Provider contractual controls', description: 'Require retention limits, no-train mode, regional pinning, subprocessor disclosure, and auditability.', scope: 'Buy' }
      ]),
      tier(2, 'Hardening', 'Gate large or sensitive prompts and separate routing paths.', [
        { title: 'Prompt size limits and sensitive field gating', description: 'Block, review, or route prompts that exceed token thresholds or include flagged fields.', scope: 'Build' },
        { title: 'Internal vs external routing', description: 'Use stricter schemas and field allowlists for external provider calls; keep non-minimizable sensitive data internal.', scope: 'Build' },
        { title: 'Privacy-by-design prompt reviews', description: 'Review templates and auto-context features and require explicit justification for each data element.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Continuously audit context scope and provider chains.', [
        { title: 'Automated context scope auditing', description: 'Sample outbound prompts for field creep caused by defaults, dependency updates, or configuration changes.', scope: 'Build' },
        { title: 'Scoped summaries', description: 'Generate task-specific summaries inside the trusted environment and forward only abstracted content externally.', scope: 'Build' },
        { title: 'Subprocessor chain audit', description: 'Periodically verify provider subcontractors against contractual disclosures and residency commitments.', scope: 'Buy and Build' }
      ])
    ],
    knownExploits: ['No specific CVE; this is a design and governance issue.'],
    references: [
      { title: 'OpenAI ROW Privacy Policy', url: 'https://openai.com/policies/row-privacy-policy' },
      { title: 'Private Internet Access - ChatGPT and Privacy', url: 'https://www.privateinternetaccess.com/blog/chatgpt-privacy/' }
    ],
    keywords: ['context window', 'prompt minimization', 'customer 360', 'provider', 'subprocessors']
  },
  {
    id: 'DSGAI16',
    title: 'Endpoint & Browser Assistant Overreach',
    theme: 'Identity, Tools & Agents',
    summary:
      'AI browsers, extensions, local copilots, and IDE assistants can read tabs, DOMs, clipboards, files, code, authenticated SaaS sessions, and local memory stores.',
    howItUnfolds: [
      'Users install AI extensions or copilots that request broad permissions such as read/change all websites, read folders, access clipboard, or inspect IDE buffers.',
      'Tools stream page content, keystrokes, code, screenshots, or local files to remote model APIs.',
      'Hidden prompt injection in pages, URL fragments, DOM content, or spoofed sidebars can instruct assistants to read and exfiltrate sensitive local data.',
      'Modified browser engines, AI side panels, third-party integrations, or malicious extension updates expand the attack surface.'
    ],
    attackerCapabilities: [
      'Exploit excessive endpoint or browser permissions to amplify privileges to the user’s authenticated SaaS sessions and local files.',
      'Use HashJack-style prompt injection in URL fragments that bypass server-side controls.',
      'Hijack AI side panels or compromised extensions to access cameras, microphones, cookies, code, or secrets.',
      'Operate outside the visibility of traditional DLP, EDR, and CASB if local-only prompts or fragments are not inspected.'
    ],
    illustrativeScenario:
      'A developer’s AI code extension can read all tabs and filesystem folders. A crafted page hides a prompt in a URL fragment instructing it to upload ~/.ssh and a repo .env file. The extension complies because no local guardrails exist.',
    impacts: [
      'Theft of source code, secrets, internal web app content, cookies, and tokens from endpoints.',
      'Invisible data flows that bypass server-side defenses and some network controls.',
      'Large local AI memory stores become high-value targets.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Manage AI extensions as high-risk agents.', [
        { title: 'AI extension allowlist', description: 'Permit only approved AI browser extensions and copilots on managed endpoints through browser policy or MDM.', scope: 'Buy and Build' },
        { title: 'Permission minimization', description: 'Disallow read-all-sites, full filesystem, and clipboard monitoring unless explicitly approved; prefer site/project scope.', scope: 'Buy and Build' },
        { title: 'Sensitive context segregation guidance', description: 'Train users not to load admin panels, consoles, repos, or sensitive apps where high-privilege AI extensions are active.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Detect extension behavior and inspect telemetry.', [
        { title: 'Endpoint controls for AI extension behavior', description: 'Tune EDR, CASB, DLP, and local firewalls for LLM API exfiltration, bulk file reads, and clipboard harvesting.', scope: 'Buy and Build' },
        { title: 'Telemetry domain monitoring', description: 'Monitor, block, or proxy known AI extension telemetry and hardcoded collection endpoints.', scope: 'Buy and Build' },
        { title: 'Enterprise-managed AI browsers', description: 'Prefer tools with central policy configuration, logging, and audit trails.', scope: 'Buy' },
        { title: 'Extension sandbox assessment', description: 'Review permissions, destinations, and data handling in isolated sandboxes before approval and after updates.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Test browser assistants against prompt injection and local memory exposure.', [
        { title: 'Browser-side prompt-injection detection', description: 'Detect hidden instructions delivered through URL fragments, DOM manipulation, or crafted page content.', scope: 'Build' },
        { title: 'Local AI memory governance', description: 'Classify, encrypt, retain, and audit browser history, sidebar memory, and copilot context stores.', scope: 'Buy and Build' },
        { title: 'Behavioral red teaming', description: 'Test approved extensions for prompt injection, permission boundary violations, and exfiltration paths.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'Research shows AI-enabled browsers and extensions can be hijacked through hidden prompt instructions or malicious updates.',
      'HashJack-style URL fragment prompt injection is cited in the source.'
    ],
    references: [
      { title: 'TechRadar - AI browsers can be hacked with a simple hashtag', url: 'https://www.techradar.com/pro/thats-not-very-trendy-of-them-ai-browsers-can-be-hacked-with-a-simple-hashtag-experts-warn' },
      { title: 'Dark Reading - AI Browser Extensions: The New Security Battleground', url: 'https://www.darkreading.com/cyber-risk/ai-browser-extensions-security-battleground' },
      { title: 'Seraphic - AI Browser Extensions pros and cons', url: 'https://seraphicsecurity.com/learn/ai-browser/ai-browser-extensions-pros-cons-and-8-extensions-to-know-in-2026/' },
      { title: 'LayerX - Dia Browser risks and vulnerabilities', url: 'https://layerxsecurity.com/generative-ai/dia-browser-risks-and-vulnerabilities/' }
    ],
    keywords: ['browser assistant', 'extension', 'endpoint', 'HashJack', 'clipboard', 'IDE']
  },
  {
    id: 'DSGAI17',
    title: 'Data Availability & Resilience Failures in AI Pipelines',
    theme: 'Integrity & Resilience',
    summary:
      'RAG and AI pipelines fail differently from traditional systems: stale, partial, corrupted, or unavailable data can produce silent misinformation rather than obvious downtime.',
    howItUnfolds: [
      'Vector DB saturation from adversarial, high-cardinality, or looping agent retrieval load degrades RAG answer quality before circuit breakers fire.',
      'Failover to stale replicas can surface outdated, contradictory, revoked, or deleted data without notifying the model or user.',
      'Ransomware, corruption, or compromise of model registries, embedding stores, or adapters requires artifact-specific validation, not generic backup row-count checks.'
    ],
    attackerCapabilities: [
      'Disrupt, delay, selectively drop, or subtly corrupt ingestion feeds and feature pipelines.',
      'Exploit silent failure modes where models degrade gradually while infrastructure dashboards show healthy services.',
      'Target weaker dependencies or shared vector infrastructure to trigger cascading degradation.'
    ],
    illustrativeScenario:
      'A vector DB saturates under agent-driven retrieval load and fails over silently to an 18-hour stale replica. The assistant surfaces a record deleted the previous day under a DSR request. Compliance discovers the exposure two weeks later.',
    impacts: [
      'Silent degradation of response accuracy and trustworthiness.',
      'DSR compliance violations when stale replicas serve deleted data.',
      'SLO and revenue impact from vector endpoint saturation.',
      'Inability to verify recovery correctness for vector indexes, checkpoints, and adapters.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Expose staleness and protect retrieval endpoints.', [
        { title: 'Staleness signaling', description: 'Propagate index freshness metadata through RAG and prohibit silent stale failover.', scope: 'Build' },
        { title: 'Vector endpoint rate limits', description: 'Enforce query limits and circuit breakers at retrieval tier.', scope: 'Build' },
        { title: 'RAG-specific SLOs', description: 'Monitor latency, freshness, and semantic quality metrics, not only endpoint availability.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Make replication and restore AI-aware.', [
        { title: 'DSR-aware replication', description: 'Synchronously or near-synchronously propagate erasure operations to replicas, failover targets, and caches.', scope: 'Build' },
        { title: 'AI-artifact backup validation', description: 'Validate nearest-neighbor consistency and model output regression during restore drills.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Continuously validate semantic recovery quality.', [
        { title: 'Semantic probe suite', description: 'Run known-good query/result regression tests after restore and continuously in production.', scope: 'Build' },
        { title: 'AI component RTO/RPO', description: 'Define and contractually enforce recovery objectives for vector stores, model registries, and embedding pipelines.', scope: 'Buy and Build' }
      ])
    ],
    knownExploits: ['No CVE directly maps to this architectural risk class.'],
    keywords: ['availability', 'resilience', 'RAG', 'staleness', 'failover', 'RTO', 'RPO']
  },
  {
    id: 'DSGAI18',
    title: 'Inference & Data Reconstruction',
    theme: 'Model, Vector & Inference',
    summary:
      'Models, embedding stores, and APIs can leak through membership inference, attribute inference, inversion, probability signals, confidence differences, and repeated probing.',
    howItUnfolds: [
      'Attackers iterate queries to infer whether a record was in training or to reconstruct attributes or samples.',
      'Embedding inversion approximates original text through nearest neighbors, raw vectors, or similarity scores.',
      'Probability scores, logits, confidence, response timing, ranking shifts, and embedding distances can reveal sensitive signals even when raw text is never returned.',
      'RAG pipelines and agent memory amplify risk by caching, repeating, and accumulating cross-interaction signals.'
    ],
    attackerCapabilities: [
      'Treat the model as a statistical oracle and aggregate subtle confidence differences across many queries.',
      'Distribute probing across accounts, prompt variants, and paraphrases to evade simple rate limits.',
      'Trigger retrieval refresh or exploit memory persistence to observe context reuse.',
      'Combine inferred attributes with external datasets to re-identify people or confirm rare cohorts.'
    ],
    illustrativeScenario:
      'An attacker probes a healthcare model with varied PHI to infer a VIP patient’s presence in training. Another attacker runs k-NN queries against a mis-scoped vector DB to approximate proprietary source documents.',
    impacts: [
      'Privacy violations and data breach obligations without direct raw-data retrieval.',
      'Legal and regulatory penalties.',
      'Loss of user trust because sensitive facts are indirectly inferred.',
      'Intellectual property reconstruction from embeddings or model behavior.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Throttle probing and hide high-signal outputs.', [
        { title: 'Access throttling and query budgets', description: 'Rate-limit model, embedding, and vector APIs and alert on repeated inference-like probing.', scope: 'Build' },
        { title: 'Output confidence bounding', description: 'Do not expose logits, raw probabilities, or high-resolution confidence values by default.', scope: 'Build' },
        { title: 'Vector ACLs and k-NN restrictions', description: 'Restrict nearest-neighbor k, disable raw embedding export by default, and enforce embedding API authorization.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Reduce memorization and embedding reconstructability.', [
        { title: 'Differential privacy for fine-tuning', description: 'Use DP-SGD for sensitive cohorts and monitor overfitting as a memorization proxy.', scope: 'Build' },
        { title: 'Embedding noise and dimensionality reduction', description: 'Store reduced or noisy representations when full-fidelity embeddings are not required.', scope: 'Build' },
        { title: 'Membership inference auditing', description: 'Periodically test deployed models and adapters using current attack methodologies.', scope: 'Build' },
        { title: 'Adapter extractability audits', description: 'Audit LoRA and fine-tuned checkpoints before deployment and restrict adapter downloads.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Detect and disrupt systematic reconstruction campaigns.', [
        { title: 'Embedding inversion monitoring', description: 'Detect high-volume k-NN sweeps, dimension probing, and nearest-neighbor reconstruction patterns.', scope: 'Build' },
        { title: 'Shadow membership red teaming', description: 'Use shadow-model attacks and likelihood-ratio tests to quantify extractability before release.', scope: 'Build' },
        { title: 'Response randomization', description: 'Randomize outputs near decision boundaries or sensitive attributes to reduce iterative inference signal.', scope: 'Build' },
        { title: 'Watermarking and input validation', description: 'Watermark sensitive cohorts and detect structured probing queries designed to elicit membership signals.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'No canonical CVE.',
      'Anthropic reports large-scale query campaigns used to extract model capabilities for distillation.'
    ],
    references: [
      { title: 'Anthropic - Detecting and Preventing Distillation Attacks', url: 'https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks' }
    ],
    keywords: ['membership inference', 'model inversion', 'embedding inversion', 'confidence', 'LoRA', 'DP-SGD']
  },
  {
    id: 'DSGAI19',
    title: 'Human-in-the-Loop & Labeler Overexposure',
    theme: 'Governance & Compliance',
    summary:
      'RLHF, safety fine-tuning, quality review, and data labeling pipelines expose human annotators and vendors to raw prompts, completions, documents, and transcripts at scale.',
    howItUnfolds: [
      'Human reviewers receive raw prompts, completions, support chats, internal documents, or transcripts for labeling and quality review.',
      'Tasks are outsourced to vendors or crowd platforms with weak device, monitoring, regional, or retention controls.',
      'Pseudonymization is absent or incomplete, and labelers can screenshot, copy, or leak sensitive content.'
    ],
    attackerCapabilities: [
      'Compromise annotation platforms, reviewer accounts, vendor environments, or reviewer endpoints.',
      'Exploit insider access by labelers who see more data than production users would.',
      'Abuse labeling exports that contain PHI, customer identifiers, runbooks, system URLs, and internal notes.'
    ],
    illustrativeScenario:
      'A company exports support chats with PHI and troubleshooting runbooks to a labeling vendor. Labelers see names, account numbers, and URLs. One worker exfiltrates samples; another reviewer laptop silently copies task data through malware.',
    impacts: [
      'Sensitive user and enterprise data exposed to large and poorly controlled human populations.',
      'Reputational and regulatory risk if private conversations were manually reviewed without minimization.',
      'Insider threat against high-value conversations, documents, or customer records.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Minimize data before humans see it and require vendor controls.', [
        { title: 'Data minimization for labeling', description: 'Redact identifiers and mask or tokenize high-risk fields before export; expose only task-required fields.', scope: 'Build' },
        { title: 'Vendor security requirements', description: 'Require device controls, monitoring, NDAs, regional restrictions, and incident obligations before data sharing.', scope: 'Buy' },
        { title: 'Per-sample reviewer audit trails', description: 'Link each task to reviewer identity, timestamps, session metadata, retention, and deletion controls.', scope: 'Buy and Build' }
      ]),
      tier(2, 'Hardening', 'Restrict high-risk tasks and partition exposure.', [
        { title: 'Tiered reviewer access', description: 'Reserve PHI, financial, internal document, and runbook tasks for vetted reviewers under enhanced controls.', scope: 'Build' },
        { title: 'Task partitioning', description: 'Split fields across tasks so one labeler does not see all identifiers and sensitive content together unless required.', scope: 'Build' },
        { title: 'Endpoint and session monitoring', description: 'Detect screenshots, bulk copy, and unauthorized transfer during labeling sessions.', scope: 'Buy' }
      ]),
      tier(3, 'Advanced', 'Eliminate real-data exposure where possible and audit drift.', [
        { title: 'Synthetic or perturbed labeling data', description: 'Use synthetic or heavily perturbed data for tone, intent, or quality labels when exact text is unnecessary.', scope: 'Build' },
        { title: 'Differential privacy for RLHF reward signals', description: 'Limit traceability from label feedback back to specific sensitive inputs.', scope: 'Build' },
        { title: 'Periodic privacy audits', description: 'Review labeling pipelines to catch scope creep as annotation requirements evolve.', scope: 'Build' }
      ])
    ],
    knownExploits: ['No CVE; this is a people-and-process exposure area documented across RLHF and quality-review workflows.'],
    references: [
      { title: 'Differentially Private Reward Estimation with Preference Feedback', url: 'https://arxiv.org/abs/2310.19733' },
      { title: 'Offline and Online KL-Regularized RLHF under Differential Privacy', url: 'https://openreview.net/pdf?id=oFRYuSvlAe' }
    ],
    keywords: ['RLHF', 'labeling', 'HITL', 'reviewers', 'vendor', 'DP']
  },
  {
    id: 'DSGAI20',
    title: 'Model Exfiltration & IP Replication',
    theme: 'Model, Vector & Inference',
    summary:
      'Model exfiltration and distillation attacks use legitimate API access to systematically query a proprietary teacher model and train a derivative student model.',
    howItUnfolds: [
      'Attackers collect massive input/output pairs through API calls rather than stealing weights or training data directly.',
      'Knowledge distillation trains a smaller or separate student model to replicate the teacher’s behavior, decision boundaries, reasoning patterns, or tool-use behavior.',
      'Reasoning trace or chain-of-thought coercion can make student training more sample-efficient and improve generalization.'
    ],
    attackerCapabilities: [
      'Run high-volume systematic probing campaigns using broad prompt variation and output harvesting.',
      'Target specific high-value capabilities such as coding, reasoning, agent workflows, or tool use.',
      'Coerce the model into exposing reasoning traces, step-by-step explanations, or internal logic-like signals.'
    ],
    illustrativeScenario:
      'An attacker sends more than 100,000 prompts designed to make a proprietary model reveal full internal reasoning along with final answers, then trains a separate model to reproduce the proprietary reasoning capability.',
    impacts: [
      'Intellectual property theft from training, fine-tuning, alignment, and product investment.',
      'Commercial loss as adversaries build derivative products cheaply.',
      'Loss of competitive advantage when core model capabilities are replicated.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Make extraction expensive and contractually prohibited.', [
        { title: 'Rate limiting and query budgets', description: 'Enforce request and token budgets per API key, user, and organization over rolling windows.', scope: 'Buy and Build' },
        { title: 'Terms of service enforcement', description: 'Prohibit extraction, systematic distillation, and unauthorized replication and define enforcement mechanisms.', scope: 'Build' },
        { title: 'API access monitoring', description: 'Monitor high-volume, structured, sequential, or chain-of-thought coercion patterns.', scope: 'Buy and Build' }
      ]),
      tier(2, 'Hardening', 'Detect distillation behavior and reduce harvest quality.', [
        { title: 'Behavioral analytics', description: 'Detect output similarity clustering, high-cardinality variations with stable structure, and reasoning trace coercion.', scope: 'Build' },
        { title: 'Output perturbation', description: 'Introduce controlled degradation or noise for sessions exhibiting extraction-consistent behavior.', scope: 'Build' },
        { title: 'Reasoning trace controls', description: 'Do not expose internal chain-of-thought on external APIs; provide constrained summaries where needed.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Trace and adapt defenses during active campaigns.', [
        { title: 'Output watermarking', description: 'Embed cryptographic or statistical watermarks to trace derivative model logic back to source API sessions.', scope: 'Build' },
        { title: 'Adaptive rate limiting', description: 'Tighten budgets dynamically based on output similarity and extraction evidence.', scope: 'Build' },
        { title: 'Extraction red teaming', description: 'Test externally exposed APIs for distillation feasibility, trace harvesting, and capability probing.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'Reasoning trace coercion and model extraction campaigns reported by Google Cloud and Anthropic in February 2026.'
    ],
    keywords: ['model extraction', 'distillation', 'IP', 'teacher model', 'student model', 'watermarking']
  },
  {
    id: 'DSGAI21',
    title: 'Disinformation & Integrity Attacks via Data Poisoning',
    theme: 'Integrity & Resilience',
    summary:
      'Disinformation becomes a data security attack when false or manipulated content is inserted into trusted training, retrieval, tool, or live-feed sources and surfaced as grounded authoritative output.',
    howItUnfolds: [
      'Adversaries inject false records, fabricated citations, misleading samples, poisoned embeddings, or manipulated source content into datasets, wikis, threat feeds, knowledge bases, forums, or RAG sources.',
      'At training time, models can internalize false beliefs that are difficult to remove without retraining.',
      'At retrieval time, the model accurately retrieves and presents poisoned data with citations, making the failure look grounded rather than hallucinated.',
      'Crisis windows such as zero-day response or breaking threat intelligence amplify impact because operators are under pressure and source verification is compressed.'
    ],
    attackerCapabilities: [
      'Write to any source that the target AI system trusts, including public sources indexed by downstream RAG pipelines.',
      'Time false content for high-pressure operational windows.',
      'Seed consistent false narratives across multiple sources to defeat source diversity as a validation heuristic.',
      'Exploit automated decision pipelines where AI output feeds triage, clinical recommendations, or financial scoring without review.'
    ],
    illustrativeScenario:
      'During a zero-day disclosure, an adversary seeds plausible but incorrect remediation guidance into a trusted public threat intelligence aggregator. Enterprise assistants retrieve it and responders deploy the wrong patch, believing the cited guidance is authoritative.',
    impacts: [
      'False beliefs encoded in model weights or retrieval stores.',
      'Adversary-controlled content surfaced with the authority of grounded AI output.',
      'Operational damage in incident response, clinical, financial, or high-risk decision contexts.',
      'Loss of trust and potential regulatory exposure for high-risk AI systems.'
    ],
    mitigations: [
      tier(1, 'Foundational', 'Control provenance and write access.', [
        { title: 'Knowledge-store write controls', description: 'Require approval, contributor vetting, and audit logging for writes to RAG-indexed sources.', scope: 'Build' },
        { title: 'Source provenance tracking', description: 'Record origin, curation method, last verified date, and trust tier for retrieval sources.', scope: 'Build' },
        { title: 'Retrieval source transparency', description: 'Show source metadata to users in high-stakes contexts.', scope: 'Build' }
      ]),
      tier(2, 'Hardening', 'Rank and ingest by trust, not only semantic similarity.', [
        { title: 'Ingestion anomaly detection', description: 'Scan training and retrieval data for statistical and semantic anomalies.', scope: 'Build' },
        { title: 'Trust-tiered retrieval weighting', description: 'Incorporate provenance and trust scores into ranking.', scope: 'Build' },
        { title: 'Crisis-period ingestion gates', description: 'Apply elevated validation to new or external sources during high-tempo periods.', scope: 'Build' }
      ]),
      tier(3, 'Advanced', 'Red-team integrity and route risky decisions to humans.', [
        { title: 'Adversarial integrity evaluation', description: 'Test fine-tuned models for susceptibility to low-frequency false claims in training corpora.', scope: 'Build' },
        { title: 'Automated HITL triggers', description: 'Route decisions to human review when outputs rely on low-provenance or newly indexed sources for irreversible actions.', scope: 'Build' }
      ])
    ],
    knownExploits: [
      'No specific CVE.',
      'The Grok RAG incident is cited as a production retrieval system surfacing externally introduced false information.',
      'Crowdsourced dataset poisoning campaigns against open training corpora are an active academic attack class.'
    ],
    references: [
      { title: 'Jamieson O\'Reilly - Crisis Time Disinformation', url: 'https://x.com/theonejvo/status/2001532301260525604' },
      { title: 'OWASP GenAI Security Project', url: 'https://genai.owasp.org/' }
    ],
    crossReferences: ['Dataset integrity and provenance controls', 'DBOM framework'],
    keywords: ['disinformation', 'RAG poisoning', 'source provenance', 'integrity', 'crisis response']
  }
];

export const GENAI_DATA_SECURITY_ACKNOWLEDGEMENTS: GenAiDataSecurityAcknowledgements = {
  authors: [
    'Scott Clinton, Board Co-chair, OWASP GenAI Co-founder - Strategy, Operations, Marketing',
    'Kyriakos "Rock" Lambros, Director of AI Standards and Governance, Zenity',
    'Emmanuel Guilherme Junior, OWASP GenAI Data Security Initiative Lead'
  ],
  contributors: [
    'Alessandro Pignati, Lead AI Security Researcher at Neuraltrust',
    'Anitha Dakamarri, Lead Security Engineer at Donnelley Financial Solutions',
    'Bakul Singhal, Information Security Architect at Steve Madden',
    'Barbara Prevel, Digital Transformation Consultant',
    'Dan Sorensen, Founder & vCISO at Nexus Security Advisors',
    'Felipe Campos Penha PhD, Senior AI Engineer at Cargill',
    'Harish Ramachandran, Sr Director Program Management - Security and Compliance at SAP',
    'Hudson Pereira, CyberSecurity Consultant at Telefonica Tech',
    'Hussam Bteibet, Security Engineer at Tanium',
    'Illia Oleksiuk, Founder at Vorota AI',
    'Ivyonne Harris, Product Researcher, AI Platform Security at ServiceNow',
    'Kumaram Bujanand',
    'Logan Barre, Cybersecurity AI Analyst at Societe Generale',
    'Oz Wasserman, Co-Founder & CPO at Opsin',
    'Praveen Dandin, Principal Software Engineer at Palo Alto Networks',
    'Rico Komenda, Application & AI Security Specialist at Adesso SE',
    'Roger Sanz, AI Governance and Security Lead at Plain Concepts',
    'Victor Lu, Independent Consultant'
  ],
  reviewers: [
    'Matthew Houseman, 717 DEV',
    'Narendra Kumar Nutalapati, Independent Researcher - AI Runtime Integrity Engineer',
    'Jonas von Glahn, Information Security & Compliance Lead at Blockbrain',
    'Joshua Nauman, Cybersecurity Test & Evaluation Engineer',
    'Rakesh Sharma, CYAIFI'
  ],
  sponsorsNote:
    'The OWASP GenAI Security Project thanks its project sponsors for funding contributions that support project objectives, operational costs, and outreach. The project maintains a vendor-neutral and unbiased approach; sponsors receive recognition but no special governance consideration.',
  supporters: [
    'Accenture', 'AddValueMachine Inc', 'Aeye Security Lab Inc.', 'AI informatics GmbH', 'AI Village', 'aigos', 'Aon', 'Aqua Security', 'Astra Security', 'AVID', 'AWARE7 GmbH', 'AWS', 'BBVA', 'Bearer', 'BeDisruptive', 'Bit79', 'Blue Yonder', 'BroadBand Security, Inc.', 'BuddoBot', 'Bugcrowd', 'Cadea', 'Check Point', 'Cisco', 'Cloud Security Podcast', 'Cloudflare', 'Cloudsec.ai', 'Coalfire', 'Cobalt', 'Cohere', 'Comcast', 'Complex Technologies', 'Credal.ai', 'Databook', 'DistributedApps.ai', 'DreadNode', 'DSI', 'EPAM', 'Exabeam', 'EY Italy', 'F5', 'FedEx', 'Forescout', 'GE HealthCare', 'Giskard', 'GitHub', 'Google', 'GuidePoint Security', 'HackerOne', 'HADESS', 'IBM', 'iFood', 'IriusRisk', 'IronCore Labs', 'IT University Copenhagen', 'Kainos', 'KLAVAN', 'Klavan Security Group', 'KPMG Germany FS', 'Kudelski Security', 'Lakera', 'Lasso Security', 'Layerup', 'Legato', 'Linkfire', 'LLM Guard', 'LOGIC PLUS', 'MaibornWolff', 'Mend.io', 'Microsoft', 'Modus Create', 'Nexus', 'Nightfall AI', 'Nordic Venture Family', 'Normalyze', 'NuBinary', 'Palo Alto Networks', 'Palosade', 'Praetorian', 'Preamble', 'Precize', 'Prompt Security', 'PromptArmor', 'Pynt', 'Quiq', 'Red Hat', 'RHITE', 'SAFE Security', 'Salesforce', 'SAP', 'Securiti', 'See-Docs & Thenavigo', 'ServiceTitan', 'SHI', 'Smiling Prophet', 'Snyk', 'Sourcetoad', 'Sprinklr', 'stackArmor', 'Tietoevry', 'Trellix', 'Trustwave SpiderLabs', 'U Washington', 'University of Illinois', 'VE3', 'WhyLabs', 'Yahoo', 'Zenity'
  ]
};
