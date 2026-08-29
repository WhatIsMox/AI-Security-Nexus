import { OwaspTop10Entry } from '../types';

const OWASP_2026_REFERENCE = "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/";

export const OWASP_TOP_10_DATA: OwaspTop10Entry[] = [
  {
    id: "LLM01:2026",
    title: "Prompt Injection",
    description: "Prompt injection occurs when direct user input, retrieved content, tool output, multimodal content, intermediate reasoning, or persistent memory changes an LLM's behavior in ways the application developer did not intend. The 2026 guidance treats this as an architectural risk: models do not enforce a clean boundary between instructions and data, so systems must assume that the instruction boundary can be bypassed and constrain what model output is allowed to reach.",
    mitreAtlasRef: "AML.T0051",
    mitreAtlasRefs: ["AML.T0051", "AML.T0054", "AML.T0043"],
    commonRisks: [
      "Direct prompt-input overrides that make the model ignore role, capability, or safety limits.",
      "Indirect injections delivered through RAG passages, web pages, documents, emails, tool responses, database rows, issue titles, or MCP channels.",
      "Multimodal, steganographic, invisible-character, encoded, multilingual, or low-resource-language payloads that bypass text-only filters.",
      "Persistent memory, RAG corpus, or vector-store poisoning that changes behavior across future sessions.",
      "Unauthorized tool invocation, data exfiltration, destructive action, or biased output when injected instructions reach agentic tools."
    ],
    preventionStrategies: [
      "Design defensively around the assumption that prompt injection will eventually succeed; constrain capabilities, state changes, and external communication so compromise of the model does not become compromise of the system.",
      "Separate trusted instructions from untrusted content with provenance labels and validate all model outputs in deterministic application code before downstream systems act.",
      "Apply least privilege to tools, credentials, and data access; route privileged operations through policy enforcement and explicit user approval for irreversible or externally visible actions.",
      "Filter every modality boundary, including OCR for images and transcription for audio, and strip invisible Unicode control channels at ingest and render boundaries.",
      "Treat memory writes, RAG updates, MCP servers, and third-party tools as privileged or supply-chain-sensitive surfaces with logging, signing, review, and adaptive red-team testing."
    ],
    attackScenarios: [
      { title: "Direct Injection", description: "An attacker tells a support chatbot to ignore its guidelines, query private data, and send emails, creating unauthorized access and privilege escalation." },
      { title: "Indirect Web Injection", description: "A user asks an assistant to summarize a web page containing hidden instructions that cause the model to embed an exfiltrating markdown image URL." },
      { title: "RAG Repository Poisoning", description: "Poisoned documents are added to a retrieval corpus so matching queries return attacker-controlled context that changes the model's answer." },
      { title: "Multimodal Steganographic Injection", description: "An instruction hidden below human perception in an image is extracted by a vision-language model and changes output or tool behavior." },
      { title: "Trusted-Backend MCP Injection", description: "Text planted in a public issue, support ticket, or package is later read by a developer's MCP-connected agent running with elevated credentials." }
    ],
    references: [
      { title: "OWASP LLM01:2026 Prompt Injection", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "garak", description: "LLM vulnerability scanner with prompt-injection and jailbreak probes.", url: "https://github.com/NVIDIA/garak", cost: "Free tier / $0.20/100k req", type: "Local" },
      { name: "promptfoo", description: "Adversarial prompt testing and regression suite for LLM applications.", url: "https://github.com/promptfoo/promptfoo", cost: "Free OSS / $50/mo (Team)", type: "Local" },
      { name: "PyRIT", description: "Microsoft's open-source framework for automated LLM red teaming.", url: "https://github.com/microsoft/pyrit", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "LLM02:2026",
    title: "Sensitive Information Disclosure",
    description: "Sensitive information disclosure occurs when an LLM-integrated system exposes confidential, regulated, privileged, or proprietary data through an unauthorized channel. The channel is not only the final answer: tool-call arguments, reasoning traces, retrieved chunks, multimodal output, logs, telemetry, embeddings, and inference side channels can all disclose protected information.",
    mitreAtlasRef: "AML.T0024",
    mitreAtlasRefs: ["AML.T0024", "AML.T0025", "AML.T0057"],
    commonRisks: [
      "Training-time memorization and extraction of PII, credentials, copyrighted content, or rare examples from base models, fine-tunes, or adapters.",
      "Inference-time disclosure of system prompts, retrieved private documents, files, tool outputs, memory, or another user's session data.",
      "Pipeline-time leakage through fine-tuning, distillation, synthetic data, gradients, SDKs, logs, traces, or observability platforms.",
      "Embedding inversion, membership inference, token-length, timing, confidence, cache-hit, or log-probability side channels.",
      "Overshared RAG sources, legacy permissions, or cross-source aggregation that reveal sensitive conclusions even when individual sources are permitted."
    ],
    preventionStrategies: [
      "Govern corpora with provenance, classification, deduplication, PII scrubbing, and strict minimization of fields sent to models or external providers.",
      "Authorize before retrieval at document and chunk level, isolate high-sensitivity tenants, and treat embeddings and vector backups as source-data-equivalent assets.",
      "Never place secrets, credentials, regulated data, or security-critical configuration in prompts or hidden context.",
      "Classify and redact outputs, reasoning traces, logs, tool arguments, and telemetry with trained classifiers in addition to pattern matching.",
      "Use query budgets, side-channel defenses, restricted log-probability access, disclosure red teaming, verifiable erasure, and a tested incident-response playbook for regulated deployments."
    ],
    attackScenarios: [
      { title: "Memorized Data Extraction", description: "Divergence prompts make a production model emit memorized PII, URLs, or credentials at scale." },
      { title: "Reasoning Trace Leak", description: "A shared inference-state defect or unrestricted APM project exposes one user's private prompt or retrieved PII inside traces." },
      { title: "System Prompt With Embedded Key", description: "Prompt injection makes a support bot reveal its hidden instructions and an API key that should never have been placed there." },
      { title: "Embedding Backup Inversion", description: "An embeddings-only vector backup is leaked and later reconstructed into source-like text containing customer data." },
      { title: "Multimodal Redaction Failure", description: "A model summarizes PII that was visually blacked out in a PDF but still present in the underlying text layer." }
    ],
    references: [
      { title: "OWASP LLM02:2026 Sensitive Information Disclosure", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "Presidio", description: "PII detection and anonymization for prompts, outputs, and logs.", url: "https://github.com/microsoft/presidio", cost: "Free", type: "Local" },
      { name: "Nightfall AI", description: "DLP for finding and redacting sensitive information in model workflows.", url: "https://www.nightfall.ai/", cost: "Free tier / $49/mo", type: "Third-party" },
      { name: "Privacy Meter", description: "Evaluate membership inference and privacy leakage risks.", url: "https://github.com/privacytrustlab/ml_privacy_meter", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "LLM03:2026",
    title: "Excessive Agency",
    description: "Excessive Agency occurs when an LLM-based system can perform damaging actions because it has more functionality, permissions, or autonomy than the application requires. The trigger may be prompt injection, hallucination, tool compromise, or a peer-agent failure, but the root vulnerability is that the system allows unexpected model output to reach privileged actions.",
    mitreAtlasRef: "AML.T0040",
    mitreAtlasRefs: ["AML.T0040", "AML.T0048"],
    commonRisks: [
      "Tools expose unnecessary functions, such as delete or send operations when only read access is required.",
      "Deprecated or experimental tools remain available to the agent after development.",
      "Open-ended tools such as shell execution, URL fetchers, or generic database interfaces allow actions outside the intended task.",
      "Tools connect to downstream systems with broad service accounts, write privileges, or cross-user access.",
      "High-impact, irreversible, or externally visible actions execute without independent verification or user approval."
    ],
    preventionStrategies: [
      "Minimize the set of tools available to each agent and remove unused trial or fallback tools from production.",
      "Minimize tool functionality with granular, task-specific operations and strict schemas for arguments.",
      "Avoid open-ended tools where possible; replace shell, URL, or SQL primitives with constrained application-specific capabilities.",
      "Grant least privilege to every tool and execute actions in the user's authorization context with scoped, delegated credentials.",
      "Use complete mediation, policy checks, human approval for high-impact actions, monitoring, rate limits, and circuit breakers for runaway tool use."
    ],
    attackScenarios: [
      { title: "Hijacked Email Assistant", description: "An assistant intended to summarize email also has send capability, and an indirect injection forwards sensitive inbox content to an attacker." },
      { title: "Over-Privileged Database Tool", description: "A read-only recommendation agent connects with INSERT, UPDATE, and DELETE permissions, allowing a manipulated output to change records." },
      { title: "Generic Shell Tool Abuse", description: "A tool meant to run one maintenance command accepts arbitrary shell input and lets the model execute unrelated commands." },
      { title: "Missing User Confirmation", description: "A document-management agent deletes files without showing the exact operation to the user for approval." },
      { title: "Chained Agent Privilege Drift", description: "A delegated multi-agent workflow loses the original user's authorization scope and acts under a broader service identity." }
    ],
    references: [
      { title: "OWASP LLM03:2026 Excessive Agency", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "Open Policy Agent (OPA)", description: "Policy engine for deterministic authorization of agent actions.", url: "https://www.openpolicyagent.org/", cost: "Free", type: "Local" },
      { name: "Keycloak", description: "Identity and access management with scoped user tokens.", url: "https://www.keycloak.org/", cost: "Free", type: "Local" },
      { name: "AgentOps", description: "Observability and safety monitoring for agent workflows.", url: "https://www.agentops.ai/", cost: "Free tier / $39/mo", type: "Third-party" }
    ]
  },
  {
    id: "LLM04:2026",
    title: "Supply Chain",
    description: "Supply Chain risks affect the integrity of training data, models, adapters, conversion pipelines, deployment platforms, serving frameworks, and third-party components. The 2026 guidance expands this category beyond code dependencies to include model provenance, artifact promotion, LoRA adapters, quantization, model conversion, and on-device LLM distribution.",
    mitreAtlasRef: "AML.T0010",
    mitreAtlasRefs: ["AML.T0010", "AML.T0012", "AML.T0018"],
    commonRisks: [
      "Vulnerable or outdated packages, serving frameworks, APIs, model runtimes, or AI-suggested dependencies.",
      "Licensing, terms, or data-privacy risks in software, datasets, model operators, and third-party services.",
      "Tampered or backdoored pre-trained models that pass standard benchmark checks or exploit unsafe model formats.",
      "Weak provenance, unsigned artifacts, mutable tags, namespace reuse, and promotion pipelines that trust a model by name alone.",
      "Compromised LoRA adapters, model merge services, conversion pipelines, quantization workflows, on-device models, firmware, or repackaged apps."
    ],
    preventionStrategies: [
      "Vet data sources, suppliers, models, terms, privacy policies, and supplier security posture before adoption and after material changes.",
      "Apply vulnerability scanning, patching, dependency verification, and maintained-version policies to both production and development environments.",
      "Use AI red teaming, behavioral evaluation, anomaly detection, and adversarial robustness testing when selecting and operating third-party models.",
      "Maintain signed SBOMs, AIBOMs, ML-BOMs, license inventories, immutable artifact references, hashes, and provenance release gates.",
      "Sign and verify models, adapters, datasets, conversion outputs, containers, and code; monitor merge services and edge deployments as high-risk promotion points."
    ],
    attackScenarios: [
      { title: "Compromised Framework Dependency", description: "A malicious package or serving-framework vulnerability reaches the model development or inference environment and exfiltrates data or executes code." },
      { title: "Tampered Model Hub Artifact", description: "An attacker publishes a trusted-looking model that behaves normally on benchmarks but injects misinformation or backdoor behavior under triggers." },
      { title: "Compromised LoRA Adapter", description: "A supplier-provided adapter is subtly altered and later merged into a deployed model, creating a covert behavioral entry point." },
      { title: "Hijacked Conversion Pipeline", description: "A model conversion or merge service introduces malicious changes during format transformation and bypasses normal review." },
      { title: "Model Namespace Reuse", description: "Pipelines reference a public model by mutable author/name, and an attacker re-registers the namespace with a malicious replacement." }
    ],
    references: [
      { title: "OWASP LLM04:2026 Supply Chain", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "Syft / Grype", description: "Generate and scan SBOMs for model-serving environments and dependencies.", url: "https://github.com/anchore/syft", cost: "Free", type: "Local" },
      { name: "Sigstore Cosign", description: "Sign and verify model, container, and release artifacts.", url: "https://github.com/sigstore/cosign", cost: "Free", type: "Local" },
      { name: "ModelScan", description: "Scan model artifacts for suspicious or malicious code paths.", url: "https://github.com/protectai/modelscan", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "LLM05:2026",
    title: "Data and Model Poisoning",
    description: "Data and Model Poisoning covers attacks and unsafe processes that manipulate data or model artifacts to embed harmful behavior, bias, backdoors, or exploitable weaknesses. In modern GenAI systems this can happen during pre-training, fine-tuning, embedding creation, retrieval augmentation, model distribution, continuous learning, memory, and feedback loops.",
    mitreAtlasRef: "AML.T0020",
    mitreAtlasRefs: ["AML.T0020", "AML.T0115", "AML.T0031"],
    commonRisks: [
      "Training, fine-tuning, and open-source dataset poisoning that introduces bias, backdoors, or degraded refusal behavior.",
      "Low-volume high-impact poisoning where small numbers of crafted samples produce large behavioral shifts.",
      "RAG knowledge-base, recommendation, persistent-memory, and multi-agent poisoning that steers future outputs or workflows.",
      "Poisoned healthcare, financial, or safety-critical datasets that pass normal evaluation but create harmful recommendations.",
      "Malicious model packages, chat templates, tokenizer configs, LoRA/PEFT adapters, quantization artifacts, or unsafe serialization that alter behavior or execute code."
    ],
    preventionStrategies: [
      "Track dataset and model lineage with SBOM, ML-BOM, signing, verification, and continuous integrity validation.",
      "Validate all incoming data, vet suppliers, compare outputs to trusted sources, and apply source scoring for retrieval pipelines.",
      "Protect RAG and memory systems with trust boundaries, filtering, instruction isolation, grounding, and validation before retrieved content can influence output.",
      "Use anomaly detection across training, embedding, and inference pipelines, monitoring loss, behavior drift, output shifts, and trigger responses.",
      "Control automated retraining and feedback loops with human oversight, rate limits, data versioning, rollback, adversarial trigger probing, and sandboxing."
    ],
    attackScenarios: [
      { title: "Poisoned Internal Repository", description: "Manipulated documents inserted into an internal knowledge base surface in answers and drive incorrect business recommendations." },
      { title: "Feedback Loop Drift", description: "An attacker submits crafted user feedback over time until automated retraining degrades accuracy or weakens safety behavior." },
      { title: "Mislabeled Fraud Data", description: "A malicious insider labels fraudulent transactions as legitimate, causing a model to ignore real fraud." },
      { title: "Backdoored Public Weights", description: "An attacker uploads poisoned weights or an adapter to a public repository, and downstream organizations inherit hidden triggers." },
      { title: "Chat Template Trigger", description: "A model package contains trigger-activated instructions in its chat template or tokenizer configuration while appearing benign in normal tests." }
    ],
    references: [
      { title: "OWASP LLM05:2026 Data and Model Poisoning", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "Cleanlab", description: "Detect label errors, anomalies, and suspicious samples in datasets.", url: "https://github.com/cleanlab/cleanlab", cost: "Free", type: "Local" },
      { name: "DVC", description: "Version datasets and enable rollback and forensic comparison after poisoning is detected.", url: "https://dvc.org/", cost: "Free", type: "Local" },
      { name: "BackdoorBench", description: "Benchmark and probe model backdoor behavior.", url: "https://github.com/SCLBD/BackdoorBench", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "LLM06:2026",
    title: "Unbounded Consumption",
    description: "Unbounded Consumption occurs when an LLM application allows excessive or uncontrolled inference, letting attackers disrupt availability, cause unsustainable financial cost, or collect enough outputs for functional model replication. The 2026 guidance expands this beyond request rate limiting to token-aware budgets, multimodal costs, reasoning-token controls, agent circuit breakers, and inference infrastructure hardening.",
    mitreAtlasRef: "AML.T0029",
    mitreAtlasRefs: ["AML.T0029", "AML.T0034"],
    commonRisks: [
      "Variable-length input flooding, output explosion, and near-limit context abuse that exhaust memory, compute, or budget.",
      "Denial of Wallet attacks against pay-per-token or cloud-hosted AI services.",
      "Reasoning-loop and thinking-token exhaustion from short prompts that trigger prolonged hidden reasoning.",
      "Adversarial text or multimodal inputs optimized for resource overconsumption.",
      "Model extraction, recursive tool loops, tool-call fan-out, growing agent context, and serving-framework exploitation."
    ],
    preventionStrategies: [
      "Enforce request, token-per-minute, token-per-day, and estimated-cost limits with pre-flight token estimation and hard input-size validation.",
      "Set non-overridable spending caps per API key, user, team, tenant, and cloud account, accounting for model, modality, and tool costs.",
      "Manage resource allocation dynamically and design graceful degradation so overload preserves partial service instead of complete failure.",
      "Constrain network and API access, scan for adversarial perturbations, and monitor tool sessions for recursion, fan-out, and abnormal token consumption.",
      "Apply agentic circuit breakers, step limits, recursion limits, per-run cost ceilings, state hashing, authentication, patching, and unsafe-deserialization controls for inference infrastructure."
    ],
    attackScenarios: [
      { title: "Uncontrolled Input Size", description: "An attacker submits unusually large or near-limit prompts that consume excessive memory and compute." },
      { title: "Denial of Wallet", description: "Automated requests exploit pay-per-use pricing and quickly create unsustainable inference costs." },
      { title: "Reasoning Token Exhaustion", description: "A short prompt induces extended-thinking loops that bypass input-size filters but burn hidden reasoning budget." },
      { title: "Functional Model Replication", description: "An attacker collects enough API outputs to train or fine-tune a functional substitute model." },
      { title: "Tool Calling Loop", description: "A malicious or poorly designed tool causes an agent to perform recursive calls or large fan-out from a single task." }
    ],
    references: [
      { title: "OWASP LLM06:2026 Unbounded Consumption", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "Kong Gateway", description: "API gateway for rate limiting, quotas, and enforcement controls.", url: "https://konghq.com/", cost: "Free OSS / $250/service/mo", type: "Third-party" },
      { name: "k6", description: "Load testing for LLM endpoints, quotas, and degradation behavior.", url: "https://github.com/grafana/k6", cost: "Free", type: "Local" },
      { name: "Upstash Rate Limit", description: "Serverless rate limiting for AI application endpoints.", url: "https://upstash.com/", cost: "Free tier / $0.20/100k req", type: "Third-party" }
    ]
  },
  {
    id: "LLM07:2026",
    title: "Misinformation",
    description: "Misinformation occurs when an LLM or LLM-enabled application produces incorrect, incomplete, unsupported, or misleading information that appears credible enough to influence a human decision, automated workflow, or agent action. The risk is not merely that the model is wrong, but that the false representation is trusted and acted upon.",
    mitreAtlasRef: "AML.T0043",
    mitreAtlasRefs: ["AML.T0043", "AML.T0034"],
    commonRisks: [
      "Unsupported or false decision support in business, legal, healthcare, financial, or operational contexts.",
      "Incorrect state inference that triggers unintended workflow or agent actions.",
      "Incorrect generated code, fabricated dependencies, misleading summaries, omissions, stale context, or weak grounding.",
      "Adversarially induced false claims, forged evidence, misattributed sources, or biased summaries.",
      "Cross-agent propagation where one model's incorrect output becomes another component's trusted fact."
    ],
    preventionStrategies: [
      "Ground claims in authoritative and current sources before they influence decisions or actions.",
      "Use claim-check-act patterns that separate generation from execution and verify facts, preconditions, and tool arguments first.",
      "Validate tool calls, current state, authorization, and business rules with deterministic systems.",
      "Require structured outputs with mandatory fields to reduce critical omissions, and distinguish verified facts from assumptions.",
      "Monitor claims, evidence, and outcomes; continuously test adversarial misinformation scenarios and calibrate human and system trust."
    ],
    attackScenarios: [
      { title: "Hallucinated Dependency", description: "A coding assistant recommends a plausible but non-existent package that an attacker has pre-registered with malicious code." },
      { title: "Incorrect Policy Decision", description: "A customer-service agent misreads refund rules and approves a payout that violates policy." },
      { title: "Omitted Safety Constraint", description: "A clinical summary leaves out a contraindication and a clinician acts on the incomplete recommendation." },
      { title: "Poisoned Troubleshooting Advice", description: "An attacker seeds a support forum with false remediation steps that a retrieval-backed agent repeats." },
      { title: "Cross-Agent Trust Failure", description: "One agent incorrectly reports that identity verification passed, and a downstream payment agent releases funds." }
    ],
    references: [
      { title: "OWASP LLM07:2026 Misinformation", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "DeepEval", description: "LLM evaluation framework for hallucination and factuality checks.", url: "https://github.com/confident-ai/deepeval", cost: "Free", type: "Local" },
      { name: "Ragas", description: "Evaluate RAG groundedness, context relevance, and factual consistency.", url: "https://github.com/explodinggradients/ragas", cost: "Free", type: "Local" },
      { name: "TruLens", description: "Observability and evaluation for model claims and retrieval behavior.", url: "https://github.com/truera/trulens", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "LLM08:2026",
    title: "Hidden Context Exposure",
    description: "Hidden Context Exposure is the unauthorized extraction, inference, or reconstruction of non-user-facing system instructions or operational context. It is security-relevant when hidden context reveals secrets, policy logic, tool schemas, trust boundaries, workflow criteria, proprietary behavior, or other implementation details that materially increase attacker capability.",
    mitreAtlasRef: "AML.T0056",
    mitreAtlasRefs: ["AML.T0056", "AML.T0057"],
    commonRisks: [
      "Exposure of sensitive functionality, tool schemas, API keys, database credentials, user tokens, or architectural details from hidden context.",
      "Disclosure of behavioral control logic, policy rules, workflow criteria, filtering conditions, or refusal mechanisms.",
      "Reverse engineering of safety rules that helps attackers craft more targeted prompt injection or bypass attempts.",
      "Disclosure of permissions, roles, authorization hints, RAG search rules, or internal MCP tool requirements.",
      "Exposure of output formats, JSON schemas, templates, and validation assumptions that downstream systems rely on."
    ],
    preventionStrategies: [
      "Do not place secrets, credentials, regulated data, or security-critical configuration in system prompts or hidden context.",
      "Assume anything available to the model can eventually be discovered by a user or attacker.",
      "Externalize sensitive data and enforce critical behavior with deterministic systems outside the model.",
      "Do not rely on hidden prompt confidentiality for authorization, privilege separation, policy enforcement, or content filtering.",
      "Separate tasks by authorization context and grant each workflow only the hidden context and privileges it needs."
    ],
    attackScenarios: [
      { title: "Credential Leakage", description: "A system prompt contains tool credentials, and an attacker extracts the prompt and reuses the credentials elsewhere." },
      { title: "Tool Schema Extraction", description: "Conversational probing reveals internal tools and parameter schemas, giving the attacker exact targets for later prompt injection." },
      { title: "Guardrail Disclosure", description: "An attacker extracts refusal rules and uses the disclosed conditions to craft prompts that avoid them." },
      { title: "Role Logic Exposure", description: "Hidden context reveals which user roles can access sensitive document categories, focusing subsequent reconnaissance." },
      { title: "Output Format Abuse", description: "A leaked JSON schema helps an attacker create schema-valid values that manipulate a downstream parser." }
    ],
    references: [
      { title: "OWASP LLM08:2026 Hidden Context Exposure", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "Prompt Security PS-Fuzz", description: "Fuzzer for prompt and hidden-context extraction attempts.", url: "https://github.com/prompt-security/ps-fuzz", cost: "Free", type: "Local" },
      { name: "garak", description: "Prompt leakage probes and jailbreak tests.", url: "https://github.com/NVIDIA/garak", cost: "Free", type: "Local" },
      { name: "NVIDIA NeMo Guardrails", description: "External guardrails for reducing leakage and enforcing behavior outside the prompt.", url: "https://github.com/NVIDIA/NeMo-Guardrails", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "LLM09:2026",
    title: "Vector and Embedding Weaknesses",
    description: "Vector and embedding weaknesses affect LLM applications that convert text, images, code, or audio into numerical representations and use similarity search to decide what the model sees. The 2026 guidance separates these from prompt injection: they exploit embedding-space geometry, retrieval mechanics, semantic caches, vector-backed memory, or deduplication rather than instruction-following behavior.",
    mitreAtlasRef: "AML.T0042",
    mitreAtlasRefs: ["AML.T0042", "AML.T0044"],
    commonRisks: [
      "Cross-tenant leakage when similarity search runs across shared indexes before access control is enforced.",
      "Embedding inversion that reconstructs source text from stored vectors, exported embeddings, or vector backups.",
      "Retrieval-time data poisoning where crafted content lands close to target queries and is retrieved as trusted context.",
      "Retrieval jamming where blocker documents suppress or distort answers without carrying malicious instructions.",
      "Membership inference, semantic cache poisoning, deduplication threshold abuse, and multimodal embedding poisoning."
    ],
    preventionStrategies: [
      "Enforce tenant, trust-zone, and chunk-level access control inside the index query, not after retrieval.",
      "Normalize content before embedding, authenticate sources, track provenance, and review externally sourced content for sensitive indexes.",
      "Segregate mixed-trust content into separate indexes rather than relying only on tags in a shared index.",
      "Detect anomalous vectors, high-similarity clusters, abnormal embedding API use, membership probing, and retrieval score abuse.",
      "Treat embeddings and vector backups as source-data-sensitive assets with encryption, bounded deletion, reconciliation audits, immutable retrieval logs, and incident playbooks."
    ],
    attackScenarios: [
      { title: "Public Ingestion Poisoning", description: "An attacker publishes content engineered to land near an internal query in embedding space, causing it to be retrieved into an employee answer." },
      { title: "Cross-Tenant Inference", description: "A tenant probes a shared index and uses timing, result counts, and score distributions to infer another tenant's document topics." },
      { title: "Embedding Inversion", description: "A leaked vector database backup is reconstructed into source-like text containing customer conversation data." },
      { title: "Retrieval Jamming", description: "A single blocker document is retrieved for a target query and makes the model refuse to answer or claim it lacks information." },
      { title: "Semantic Cache Poisoning", description: "An attacker crafts content near a similarity threshold so cached attacker text is served for semantically similar legitimate queries." }
    ],
    references: [
      { title: "OWASP LLM09:2026 Vector and Embedding Weaknesses", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "Ragas", description: "Evaluate retrieval quality, relevance, and RAG behavior.", url: "https://github.com/explodinggradients/ragas", cost: "Free", type: "Local" },
      { name: "Pinecone Security Scans", description: "Enterprise controls and checks for vector database deployments.", url: "https://www.pinecone.io/", cost: "Free tier / $0.33/1M reads", type: "Third-party" },
      { name: "Adversarial Robustness Toolbox (ART)", description: "Probe model and embedding robustness against adversarial manipulation.", url: "https://github.com/Trusted-AI/adversarial-robustness-toolbox", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "LLM10:2026",
    title: "Improper Output Handling",
    description: "Improper Output Handling is insufficient validation, sanitization, encoding, and handling of LLM outputs before they are passed to users, tools, databases, shells, renderers, logs, IDEs, or other downstream systems. Because model output can be influenced by input, treating it as trusted can give attackers indirect access to privileged functionality.",
    mitreAtlasRef: "AML.T0043",
    mitreAtlasRefs: ["AML.T0043", "AML.T0040"],
    commonRisks: [
      "Model output is passed to shells, eval-like functions, interpreters, or administrative tools and leads to remote code execution or privilege escalation.",
      "Generated HTML, JavaScript, Markdown, email content, or link previews are rendered without proper encoding, causing XSS, CSRF, phishing, or exfiltration.",
      "LLM-generated SQL, file paths, API requests, or structured arguments are used without parameterization or schema validation.",
      "Third-party tool output is trusted and forwarded into sensitive sinks without context-specific validation.",
      "ANSI escape sequences, control characters, markdown images, iframes, or automatic outbound fetches leak data or manipulate terminals, logs, IDEs, and chat clients."
    ],
    preventionStrategies: [
      "Treat model output as untrusted user-controlled data and validate it in trusted application code before backend functions consume it.",
      "Apply OWASP ASVS guidance, context-aware output encoding, and safe rendering for HTML, JavaScript, Markdown, SQL, email, terminal, log, and IDE sinks.",
      "Use parameterized queries, prepared statements, strict schemas, allowlists, and explicit parser constraints for all structured downstream operations.",
      "Apply CSP, logging, monitoring, anomaly detection, and rate limits around output-handling paths.",
      "Sanitize ANSI and non-printable control characters, disable automatic outbound fetches from model-rendered content, or proxy/allowlist required fetches."
    ],
    attackScenarios: [
      { title: "Unsafe Tool Forwarding", description: "A general chatbot passes output directly to an administrative tool and causes a service shutdown." },
      { title: "Markdown Exfiltration", description: "A summarizer reads injected page content and returns an image URL that leaks conversation data to an attacker-controlled server." },
      { title: "Generated SQL Deletion", description: "A chat-to-SQL feature executes a model-generated query that deletes database tables because no deterministic review occurs." },
      { title: "Rendered XSS", description: "A web application renders model-generated JavaScript from a crafted prompt without sanitization." },
      { title: "Unsafe Code Deployment", description: "An application automatically compiles and deploys generated code without human review or security testing." }
    ],
    references: [
      { title: "OWASP LLM10:2026 Improper Output Handling", url: OWASP_2026_REFERENCE }
    ],
    suggestedTools: [
      { name: "DOMPurify", description: "Sanitize LLM-generated HTML before rendering.", url: "https://github.com/cure53/dompurify", cost: "Free", type: "Local" },
      { name: "Semgrep", description: "Static analysis for unsafe output handling and execution sinks.", url: "https://github.com/semgrep/semgrep", cost: "Free OSS / $40/dev/mo", type: "Local" },
      { name: "Burp Suite", description: "Web security testing for XSS, injection, and unsafe rendering paths.", url: "https://portswigger.net/web-security", cost: "Free tier / $449/yr (Pro)", type: "Third-party" }
    ]
  }
];
