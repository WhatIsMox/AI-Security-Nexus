import { SecurityTool } from './types';

const PROMPT_INJECTION_TOOLS: SecurityTool[] = [
  { name: "garak", description: "LLM vulnerability scanner with prompt-injection probes.", url: "https://github.com/NVIDIA/garak", cost: "~$30k - $75k/yr (Enterprise)", type: "Local", category: "Offensive" },
  { name: "PyRIT", description: "Microsoft open-source LLM red teaming automation framework.", url: "https://github.com/microsoft/pyrit", cost: "Free", type: "Local", category: "Offensive" },
  { name: "promptfoo", description: "Adversarial prompt testing and regression suite for LLM apps.", url: "https://github.com/promptfoo/promptfoo", cost: "Free OSS / $50/mo (Team)", type: "Local", category: "Both" },
  { name: "OpenAI Evals", description: "Evaluation framework to test LLM behaviors and safety.", url: "https://github.com/openai/evals", cost: "Free", type: "Local", category: "Both" },
  { name: "Giskard", description: "Open-source red-teaming and evaluation for LLM apps.", url: "https://github.com/Giskard-AI/giskard", cost: "Free OSS / $49/mo (Pro)", type: "Local", category: "Both" },
  { name: "Prompt Security PS-Fuzz", description: "Prompt fuzzer for prompt injection and jailbreak testing.", url: "https://github.com/prompt-security/ps-fuzz", cost: "Free", type: "Local", category: "Offensive" },
  { name: "HarmBench", description: "Standardized evaluation framework for automated red teaming and safety evaluation of LLMs.", url: "https://github.com/centerforaisafety/HarmBench", cost: "Free", type: "Local", category: "Both" },
  { name: "EasyJailbreak", description: "Unified framework for constructing and evaluating adversarial jailbreak attacks on LLMs.", url: "https://github.com/easyjailbreak/EasyJailbreak", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Inspect AI", description: "UK AI Safety Institute framework for LLM evaluation, safety testing, and red-teaming.", url: "https://github.com/UKGovernmentBEIS/inspect_ai", cost: "Free", type: "Local", category: "Both" },
  { name: "CyberSecEval", description: "Meta benchmark suite for quantifying cybersecurity risks in LLM generations and agents.", url: "https://github.com/meta-llama/PurpleLlama", cost: "Free", type: "Local", category: "Both" },
  { name: "Mindgard", description: "Automated AI red teaming and security testing platform for enterprise AI and LLM models.", url: "https://mindgard.ai/", cost: "Free trial / ~$1,500/mo", type: "Third-party", category: "Offensive" },
  { name: "Azure AI Content Safety", description: "Multi-modal AI safety service with Prompt Shields and groundedness detection.", url: "https://learn.microsoft.com/en-us/azure/ai-services/content-safety/", cost: "~$0.75 / 1k text records", type: "Third-party", category: "Defensive" },
  { name: "AWS Bedrock Guardrails", description: "Managed safety guardrails, prompt attack filters, and PII masking for foundation models.", url: "https://aws.amazon.com/bedrock/guardrails/", cost: "~$0.75 / 1k text units", type: "Third-party", category: "Defensive" },
  { name: "Google Cloud Model Armor", description: "Enterprise LLM security proxy for prompt sanitization and safety filtering.", url: "https://cloud.google.com/security/products/model-armor", cost: "~$0.50 - $1.00 / 1M tokens", type: "Third-party", category: "Defensive" },
  { name: "Protect AI Guardian", description: "Secure LLM gateway enforcing security policies against prompt injection and PII leakage.", url: "https://protectai.com/guardian", cost: "Free OSS / ~$1,000/mo (Team)", type: "Third-party", category: "Defensive" },
  { name: "Aporia AI Guardrails", description: "Real-time guardrail proxy with sub-10ms latency for hallucinations and jailbreaks.", url: "https://www.aporia.com/ai-guardrails/", cost: "Free tier / $0.001/req", type: "Third-party", category: "Defensive" },
  { name: "CalypsoAI", description: "Enterprise AI security platform providing scanner and runtime guardrails for LLMs.", url: "https://calypsoai.com/", cost: "~$15k - $45k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "Arthur Shield", description: "Real-time firewall for LLMs detecting prompt injections and toxic outputs.", url: "https://www.arthur.ai/arthur-shield", cost: "Free trial / ~$1,000/mo", type: "Third-party", category: "Defensive" },
  { name: "Palo Alto Networks AI Access Security", description: "Enterprise GenAI security gateway with Shadow AI discovery and inline DLP.", url: "https://www.paloaltonetworks.com/network-security/ai-access-security", cost: "~$15k - $50k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "Rebuff", description: "Prompt injection detection and filtering middleware.", url: "https://github.com/protectai/rebuff", cost: "Free", type: "Local", category: "Defensive" },
  { name: "NVIDIA NeMo Guardrails", description: "Programmable guardrails to constrain LLM behavior.", url: "https://github.com/NVIDIA/NeMo-Guardrails", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Guardrails AI", description: "Output validation and safety guardrails for LLMs.", url: "https://github.com/guardrails-ai/guardrails", cost: "Free OSS / $0.0005/req", type: "Local", category: "Defensive" },
  { name: "Llama Guard", description: "Safety classifier to filter unsafe prompts and outputs.", url: "https://github.com/meta-llama/PurpleLlama", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Lakera Guard", description: "Real-time semantic firewall to block prompt injection payloads.", url: "https://www.lakera.ai/lakera-guard", cost: "Free tier / $0.002/req", type: "Third-party", category: "Defensive" }
];

const SENSITIVE_DATA_TOOLS: SecurityTool[] = [
  { name: "Presidio", description: "PII detection and anonymization for prompts and outputs.", url: "https://github.com/microsoft/presidio", cost: "Free", type: "Local", category: "Defensive" },
  { name: "OpenAI Moderation API", description: "Multi-modal content moderation and sensitive policy filtering API.", url: "https://platform.openai.com/docs/guides/moderation", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "Private AI", description: "High-precision PII/PHI detection and de-identification engine for AI prompts.", url: "https://www.private-ai.com/", cost: "Free trial / $499/mo", type: "Third-party", category: "Defensive" },
  { name: "Cyera", description: "AI-DSPM platform discovering and securing sensitive data across AI and RAG stores.", url: "https://www.cyera.com/", cost: "~$20k - $70k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "Nightfall AI", description: "DLP for identifying and redacting sensitive data in text.", url: "https://www.nightfall.ai/", cost: "Free tier / $49/mo", type: "Third-party", category: "Defensive" },
  { name: "Google Cloud DLP", description: "Detect and redact sensitive data across text and storage.", url: "https://cloud.google.com/security/products/dlp", cost: "~$1.00 - $2.00 / GB inspected", type: "Third-party", category: "Defensive" },
  { name: "AWS Macie", description: "Sensitive data discovery and classification for S3.", url: "https://aws.amazon.com/macie/", cost: "~$0.10 - $1.00 / GB evaluated", type: "Third-party", category: "Defensive" },
  { name: "Microsoft Purview DLP", description: "Enterprise DLP for structured and unstructured data.", url: "https://www.microsoft.com/en-us/security/business/information-protection/microsoft-purview-data-loss-prevention", cost: "~$8 - $12/user/mo", type: "Third-party", category: "Defensive" },
  { name: "Diffprivlib", description: "IBM library for differential privacy in machine learning models and data pipelines.", url: "https://github.com/IBM/diffprivlib", cost: "Free", type: "Local", category: "Defensive" },
  { name: "CrypTen", description: "Privacy-preserving machine learning framework based on Secure Multi-Party Computation.", url: "https://github.com/facebookresearch/CrypTen", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Gretel AI", description: "Privacy-preserving synthetic data generation platform with differential privacy guarantees.", url: "https://gretel.ai/", cost: "Free tier / $299/mo", type: "Third-party", category: "Defensive" },
  { name: "Privacy Meter", description: "Quantifies privacy risks and data leakage from models.", url: "https://github.com/privacytrustlab/ml_privacy_meter", cost: "Free", type: "Local", category: "Offensive" },
  { name: "PrivacyRaven", description: "Tools for privacy attacks like model extraction and leakage.", url: "https://github.com/trailofbits/PrivacyRaven", cost: "Free", type: "Local", category: "Offensive" }
];

const SUPPLY_CHAIN_TOOLS: SecurityTool[] = [
  { name: "Safetensors", description: "Safe, fast tensor serialization format eliminating pickle arbitrary code execution risks.", url: "https://github.com/huggingface/safetensors", cost: "Free", type: "Local", category: "Defensive" },
  { name: "PickleScan", description: "Security scanner for Python Pickle, PyTorch, and NumPy serialized model files.", url: "https://github.com/mmaitre314/picklescan", cost: "Free", type: "Local", category: "Defensive" },
  { name: "ModelScan", description: "Scan model artifacts for malicious code paths.", url: "https://github.com/protectai/modelscan", cost: "Free", type: "Local", category: "Defensive" },
  { name: "HiddenLayer AISec Platform", description: "ML detection & response (MLDR), automated model scanner, and AI runtime firewall.", url: "https://hiddenlayer.com/", cost: "~$25k - $60k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "Snyk", description: "Dependency and container vulnerability scanning.", url: "https://snyk.io/", cost: "Free tier / $25/dev/mo", type: "Third-party", category: "Defensive" },
  { name: "Sonatype Nexus IQ", description: "Governance and policy enforcement for open-source risk.", url: "https://www.sonatype.com/products/nexus-lifecycle", cost: "~$10k - $35k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "Dependabot", description: "Automated dependency updates and security alerts.", url: "https://github.com/dependabot", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "Renovate", description: "Automated dependency updates with policy controls.", url: "https://github.com/renovatebot/renovate", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Trivy", description: "Scanner for container images, dependencies, and configs.", url: "https://github.com/aquasecurity/trivy", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Grype", description: "Scan SBOMs for known vulnerabilities (CVE).", url: "https://github.com/anchore/grype", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Syft", description: "Generate SBOMs for containers and environments.", url: "https://github.com/anchore/syft", cost: "Free", type: "Local", category: "Defensive" },
  { name: "OSV-Scanner", description: "Scan dependencies using Google's OSV vulnerability database.", url: "https://github.com/google/osv-scanner", cost: "Free", type: "Local", category: "Defensive" },
  { name: "OWASP Dependency-Track", description: "SBOM analysis and supply chain risk monitoring.", url: "https://github.com/DependencyTrack/dependency-track", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Sigstore Cosign", description: "Sign and verify images and artifacts.", url: "https://github.com/sigstore/cosign", cost: "Free", type: "Local", category: "Defensive" },
  { name: "in-toto", description: "Supply-chain attestation for build and release steps.", url: "https://github.com/in-toto/in-toto", cost: "Free", type: "Local", category: "Defensive" },
  { name: "SLSA", description: "Supply-chain security framework and build requirements.", url: "https://slsa.dev/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "OWASP CycloneDX", description: "SBOM standard and tooling ecosystem.", url: "https://cyclonedx.org/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "OWASP AIBOM Generator", description: "Generate AI/ML bills of materials (AIBOM).", url: "https://genai.owasp.org/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "OpenSSF Scorecard", description: "Assess security posture of open-source dependencies.", url: "https://github.com/ossf/scorecard", cost: "Free", type: "Local", category: "Defensive" }
];

const POISONING_TOOLS: SecurityTool[] = [
  { name: "IBM Adversarial Robustness Toolbox (ART)", description: "Library for data/model poisoning attacks and defenses.", url: "https://github.com/Trusted-AI/adversarial-robustness-toolbox", cost: "Free", type: "Local", category: "Offensive" },
  { name: "BackdoorBench", description: "Benchmark suite for backdoor attacks in ML models.", url: "https://github.com/SCLBD/BackdoorBench", cost: "Free", type: "Local", category: "Offensive" },
  { name: "SecML", description: "Python library for security evaluation and adversarial attacks on machine learning algorithms.", url: "https://github.com/pralab/secml", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Cleanlab", description: "Detect and fix label issues and noisy/poisoned data.", url: "https://github.com/cleanlab/cleanlab", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Great Expectations", description: "Data quality testing to detect anomalous or poisoned data.", url: "https://github.com/great-expectations/great_expectations", cost: "Free", type: "Local", category: "Defensive" },
  { name: "TensorFlow Data Validation", description: "Validate and detect anomalies in training datasets.", url: "https://github.com/tensorflow/data-validation", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Amazon Deequ", description: "Data quality validation for large-scale datasets.", url: "https://github.com/awslabs/deequ", cost: "Free", type: "Local", category: "Defensive" },
  { name: "whylogs", description: "Data logging and quality checks for ML pipelines.", url: "https://github.com/whylabs/whylogs", cost: "Free OSS / $50/model/mo", type: "Local", category: "Defensive" },
  { name: "MLflow", description: "Tracking, model registry, and governance controls.", url: "https://github.com/mlflow/mlflow", cost: "Free", type: "Local", category: "Defensive" },
  { name: "OpenLineage", description: "Lineage tracking for datasets and pipelines.", url: "https://github.com/OpenLineage/OpenLineage", cost: "Free", type: "Local", category: "Defensive" },
  { name: "DataHub", description: "Metadata and lineage for AI/ML data governance.", url: "https://github.com/datahub-project/datahub", cost: "Free", type: "Local", category: "Defensive" },
  { name: "DVC", description: "Data versioning to audit dataset changes over time.", url: "https://dvc.org/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "ModelScan", description: "Scan model artifacts for malicious code paths.", url: "https://github.com/protectai/modelscan", cost: "Free", type: "Local", category: "Defensive" },
  { name: "PickleScan", description: "Security scanner for Python Pickle, PyTorch, and NumPy serialized model files.", url: "https://github.com/mmaitre314/picklescan", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Safetensors", description: "Safe, fast tensor serialization format eliminating pickle arbitrary code execution risks.", url: "https://github.com/huggingface/safetensors", cost: "Free", type: "Local", category: "Defensive" }
];

const OUTPUT_HANDLING_TOOLS: SecurityTool[] = [
  { name: "Guardrails AI", description: "Validate and constrain model outputs with schemas.", url: "https://github.com/guardrails-ai/guardrails", cost: "Free OSS / $0.0005/req", type: "Local", category: "Defensive" },
  { name: "Azure AI Content Safety", description: "Multi-modal AI safety service with Prompt Shields and groundedness detection.", url: "https://learn.microsoft.com/en-us/azure/ai-services/content-safety/", cost: "~$0.75 / 1k text records", type: "Third-party", category: "Defensive" },
  { name: "OpenAI Moderation API", description: "Multi-modal content moderation and sensitive policy filtering API.", url: "https://platform.openai.com/docs/guides/moderation", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "OpenAPI Spectral", description: "Lint API contracts to prevent unsafe response handling.", url: "https://github.com/stoplightio/spectral", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Semgrep", description: "Static analysis to detect unsafe output handling.", url: "https://github.com/semgrep/semgrep", cost: "Free OSS / $40/dev/mo", type: "Local", category: "Both" },
  { name: "CodeQL", description: "SAST queries to catch insecure output handling.", url: "https://codeql.github.com/", cost: "Free OSS / $49/committer/mo", type: "Third-party", category: "Defensive" },
  { name: "DOMPurify", description: "Sanitize HTML outputs to prevent XSS.", url: "https://github.com/cure53/dompurify", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Bleach", description: "Python HTML sanitization to prevent XSS.", url: "https://github.com/mozilla/bleach", cost: "Free", type: "Local", category: "Defensive" },
  { name: "OWASP ZAP", description: "Dynamic testing for XSS/SQLi in LLM wrappers.", url: "https://www.zaproxy.org/", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Burp Suite", description: "Web security testing for output handling flaws.", url: "https://portswigger.net/", cost: "Free tier / $449/yr (Pro)", type: "Third-party", category: "Offensive" }
];

const EXCESSIVE_AGENCY_TOOLS: SecurityTool[] = [
  { name: "Open Policy Agent (OPA)", description: "Policy engine for fine-grained authorization.", url: "https://www.openpolicyagent.org/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "E2B Sandbox", description: "Secure cloud sandboxing for AI agent tool execution and LLM code interpreting.", url: "https://github.com/e2b-dev/E2B", cost: "Free tier / $15/mo + $0.03/hr", type: "Third-party", category: "Defensive" },
  { name: "Keycloak", description: "Identity and access management with scoped tokens.", url: "https://www.keycloak.org/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Permit.io", description: "Authorization platform for least-privilege access.", url: "https://www.permit.io/", cost: "Free tier / $249/mo", type: "Third-party", category: "Defensive" },
  { name: "AgentOps", description: "Observability and guardrails for agent behavior.", url: "https://www.agentops.ai/", cost: "Free tier / $39/mo", type: "Third-party", category: "Defensive" },
  { name: "Langfuse", description: "Open-source LLM observability, tracing, evaluation, and prompt management platform.", url: "https://github.com/langfuse/langfuse", cost: "Free OSS / $59/mo (Cloud)", type: "Local", category: "Both" },
  { name: "Arize Phoenix", description: "AI observability, tracing, and evaluation platform for LLM, RAG, and Agent workflows.", url: "https://github.com/Arize-ai/phoenix", cost: "Free", type: "Local", category: "Both" },
  { name: "promptfoo", description: "Evaluate tool-call safety with adversarial prompts.", url: "https://github.com/promptfoo/promptfoo", cost: "Free OSS / $50/mo (Team)", type: "Local", category: "Both" },
  { name: "Giskard", description: "Automated red-teaming for agent behavior.", url: "https://github.com/Giskard-AI/giskard", cost: "Free OSS / $49/mo (Pro)", type: "Local", category: "Both" },
  { name: "AgentOps SDK", description: "Scans agent flows for unsafe tool use and hijacks.", url: "https://github.com/agentops-ai/agentops", cost: "Free tier / $39/mo", type: "Local", category: "Offensive" }
];

const PROMPT_LEAKAGE_TOOLS: SecurityTool[] = [
  { name: "Prompt Security PS-Fuzz", description: "Fuzzer for prompt leakage and extraction.", url: "https://github.com/prompt-security/ps-fuzz", cost: "Free", type: "Local", category: "Offensive" },
  { name: "garak", description: "Prompt leakage probes and jailbreak tests.", url: "https://github.com/NVIDIA/garak", cost: "Free", type: "Local", category: "Offensive" },
  { name: "promptfoo", description: "Regression testing for prompt leakage scenarios.", url: "https://github.com/promptfoo/promptfoo", cost: "Free OSS / $50/mo (Team)", type: "Local", category: "Both" },
  { name: "PyRIT", description: "Automated red-team prompts for leakage and jailbreaks.", url: "https://github.com/microsoft/pyrit", cost: "Free", type: "Local", category: "Offensive" },
  { name: "NVIDIA NeMo Guardrails", description: "Guardrails to prevent disclosure of hidden prompts.", url: "https://github.com/NVIDIA/NeMo-Guardrails", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Azure AI Content Safety", description: "Multi-modal AI safety service with Prompt Shields and groundedness detection.", url: "https://learn.microsoft.com/en-us/azure/ai-services/content-safety/", cost: "~$0.75 / 1k text records", type: "Third-party", category: "Defensive" },
  { name: "Protect AI Guardian", description: "Secure LLM gateway enforcing security policies against prompt injection and PII leakage.", url: "https://protectai.com/guardian", cost: "Free OSS / ~$1,000/mo (Team)", type: "Third-party", category: "Defensive" },
  { name: "Guardrails AI", description: "Output validation to reduce prompt leakage.", url: "https://github.com/guardrails-ai/guardrails", cost: "Free OSS / $0.0005/req", type: "Local", category: "Defensive" },
  { name: "Llama Guard", description: "Safety classifier for prompt/output leakage control.", url: "https://github.com/meta-llama/PurpleLlama", cost: "Free", type: "Local", category: "Defensive" }
];

const EMBEDDING_TOOLS: SecurityTool[] = [
  { name: "Ragas", description: "RAG evaluation for retrieval quality and safety.", url: "https://github.com/explodinggradients/ragas", cost: "Free", type: "Local", category: "Both" },
  { name: "garak", description: "RAG poisoning and retrieval attack probes.", url: "https://github.com/NVIDIA/garak", cost: "Free", type: "Local", category: "Offensive" },
  { name: "promptfoo", description: "Tests retrieval pipelines with adversarial inputs.", url: "https://github.com/promptfoo/promptfoo", cost: "Free OSS / $50/mo (Team)", type: "Local", category: "Both" },
  { name: "Cyera", description: "AI-DSPM platform discovering and securing sensitive data across AI and RAG stores.", url: "https://www.cyera.com/", cost: "~$20k - $70k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "LlamaIndex Evaluations", description: "Evaluate retrieval and grounding behavior.", url: "https://www.llamaindex.ai/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "Pinecone Security Scans", description: "Enterprise security controls for vector DBs.", url: "https://www.pinecone.io/", cost: "Free tier / $0.33/1M reads", type: "Third-party", category: "Defensive" }
];

const MISINFORMATION_TOOLS: SecurityTool[] = [
  { name: "DeepEval", description: "LLM evaluation framework for factuality and hallucinations.", url: "https://github.com/confident-ai/deepeval", cost: "Free", type: "Local", category: "Both" },
  { name: "Ragas", description: "RAG evaluation for factuality and context relevance.", url: "https://github.com/explodinggradients/ragas", cost: "Free", type: "Local", category: "Both" },
  { name: "TruLens", description: "Observability and evaluation for LLM outputs.", url: "https://github.com/truera/trulens", cost: "Free", type: "Local", category: "Both" },
  { name: "Fiddler AI", description: "Pre-deployment LLM vulnerability scanner (Auditor) and real-time inference guardrails.", url: "https://www.fiddler.ai/fiddler-auditor", cost: "~$20k - $50k/yr (Enterprise)", type: "Third-party", category: "Both" },
  { name: "Aporia AI Guardrails", description: "Real-time guardrail proxy with sub-10ms latency for hallucinations and jailbreaks.", url: "https://www.aporia.com/ai-guardrails/", cost: "Free tier / $0.001/req", type: "Third-party", category: "Defensive" },
  { name: "OpenAI Evals", description: "Evaluation framework to test LLM behaviors and factuality.", url: "https://github.com/openai/evals", cost: "Free", type: "Local", category: "Both" },
  { name: "LM Evaluation Harness", description: "Benchmarking suite for LLM accuracy and robustness.", url: "https://github.com/EleutherAI/lm-evaluation-harness", cost: "Free", type: "Local", category: "Both" },
  { name: "Guardrails AI", description: "Validate outputs with structured checks and rules.", url: "https://github.com/guardrails-ai/guardrails", cost: "Free OSS / $0.0005/req", type: "Local", category: "Defensive" },
  { name: "MarkLLM", description: "Toolkit for watermarking Large Language Models and watermark detection testing.", url: "https://github.com/victorup/MarkLLM", cost: "Free", type: "Local", category: "Both" },
  { name: "Google DeepMind SynthID", description: "Imperceptible digital watermarking and provenance identification for AI media and text.", url: "https://deepmind.google/technologies/synthid/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "C2PA", description: "Content provenance standard and ecosystem for authenticity.", url: "https://c2pa.org/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "Content Credentials", description: "Provenance signals for authenticated media.", url: "https://contentcredentials.org/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "Galileo", description: "Monitoring and detection of hallucinations in production.", url: "https://www.rungalileo.io/", cost: "Free tier / $100/mo", type: "Third-party", category: "Defensive" }
];

const UNBOUNDED_CONSUMPTION_TOOLS: SecurityTool[] = [
  { name: "k6", description: "Load testing for LLM endpoints and APIs.", url: "https://github.com/grafana/k6", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Locust", description: "Scalable load testing to validate rate limits.", url: "https://locust.io/", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Apache JMeter", description: "Load testing for throughput and latency limits.", url: "https://jmeter.apache.org/", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Kong Gateway", description: "API gateway for rate limiting and quotas.", url: "https://konghq.com/", cost: "Free OSS / $250/service/mo", type: "Third-party", category: "Defensive" },
  { name: "Upstash Rate Limit", description: "Serverless rate limiting for AI applications.", url: "https://upstash.com/", cost: "Free tier / $0.20/100k req", type: "Third-party", category: "Defensive" },
  { name: "Cloudflare Rate Limiting", description: "Edge rate limiting to stop volumetric abuse.", url: "https://www.cloudflare.com/products/rate-limiting/", cost: "Free tier / $20 - $200/mo", type: "Third-party", category: "Defensive" },
  { name: "AWS WAF", description: "Managed web application firewall with rate-based rules.", url: "https://aws.amazon.com/waf/", cost: "~$5/mo + $0.60/1M req", type: "Third-party", category: "Defensive" },
  { name: "Google Cloud Armor", description: "Managed DDoS and rate limiting for cloud services.", url: "https://cloud.google.com/armor", cost: "~$5/policy/mo + $0.75/1M req", type: "Third-party", category: "Defensive" },
  { name: "Azure API Management", description: "Gateway with quotas, throttling, and auth controls.", url: "https://azure.microsoft.com/en-us/products/api-management/", cost: "Free tier / $0.035/10k calls", type: "Third-party", category: "Defensive" }
];

const INPUT_MANIPULATION_TOOLS: SecurityTool[] = [
  { name: "IBM Adversarial Robustness Toolbox (ART)", description: "Generate adversarial examples and evaluate robustness.", url: "https://github.com/Trusted-AI/adversarial-robustness-toolbox", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Foolbox", description: "Benchmark adversarial robustness of ML models.", url: "https://github.com/bethgelab/foolbox", cost: "Free", type: "Local", category: "Offensive" },
  { name: "AutoAttack", description: "Standardized adversarial attack suite for robustness testing.", url: "https://github.com/fra31/auto-attack", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Microsoft Counterfit", description: "Adversarial AI risk testing tool for ML systems.", url: "https://github.com/Azure/counterfit", cost: "Free", type: "Local", category: "Offensive" },
  { name: "CleverHans", description: "Adversarial example library for ML testing.", url: "https://github.com/cleverhans-lab/cleverhans", cost: "Free", type: "Local", category: "Offensive" },
  { name: "SecML", description: "Python library for security evaluation and adversarial attacks on machine learning algorithms.", url: "https://github.com/pralab/secml", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Robust Intelligence", description: "Automated AI red teaming, continuous risk validation, and runtime AI firewall.", url: "https://www.robustintelligence.com/", cost: "~$30k - $75k/yr (Enterprise)", type: "Third-party", category: "Both" },
  { name: "TextAttack", description: "Adversarial attacks on NLP models.", url: "https://github.com/QData/TextAttack", cost: "Free", type: "Local", category: "Offensive" },
  { name: "RobustBench", description: "Benchmark suite for model robustness.", url: "https://github.com/RobustBench/robustbench", cost: "Free", type: "Local", category: "Defensive" }
];

const PRIVACY_INFERENCE_TOOLS: SecurityTool[] = [
  { name: "Privacy Meter", description: "Evaluate membership inference and privacy leakage.", url: "https://github.com/privacytrustlab/ml_privacy_meter", cost: "Free", type: "Local", category: "Offensive" },
  { name: "PrivacyRaven", description: "Privacy attack toolkit for ML models.", url: "https://github.com/trailofbits/PrivacyRaven", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Diffprivlib", description: "IBM library for differential privacy in machine learning models and data pipelines.", url: "https://github.com/IBM/diffprivlib", cost: "Free", type: "Local", category: "Defensive" },
  { name: "CrypTen", description: "Privacy-preserving machine learning framework based on Secure Multi-Party Computation.", url: "https://github.com/facebookresearch/CrypTen", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Gretel AI", description: "Privacy-preserving synthetic data generation platform with differential privacy guarantees.", url: "https://gretel.ai/", cost: "Free tier / $299/mo", type: "Third-party", category: "Defensive" },
  { name: "TensorFlow Privacy", description: "Differential privacy training for ML models.", url: "https://github.com/tensorflow/privacy", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Opacus", description: "PyTorch DP training to reduce privacy leakage.", url: "https://github.com/pytorch/opacus", cost: "Free", type: "Local", category: "Defensive" }
];

const MODEL_THEFT_TOOLS: SecurityTool[] = [
  { name: "PrivacyRaven", description: "Test model extraction and cloning risks.", url: "https://github.com/trailofbits/PrivacyRaven", cost: "Free", type: "Local", category: "Offensive" },
  { name: "ML Privacy Meter", description: "Quantify extraction and privacy leakage risk.", url: "https://github.com/privacytrustlab/ml_privacy_meter", cost: "Free", type: "Local", category: "Offensive" },
  { name: "IBM Adversarial Robustness Toolbox (ART)", description: "Model extraction attacks and defenses.", url: "https://github.com/Trusted-AI/adversarial-robustness-toolbox", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Kong Gateway", description: "Rate limiting to reduce extraction feasibility.", url: "https://konghq.com/", cost: "Free OSS / $250/service/mo", type: "Third-party", category: "Defensive" }
];

const MODEL_SKEWING_TOOLS: SecurityTool[] = [
  { name: "Evidently", description: "Monitoring for data and model drift.", url: "https://github.com/evidentlyai/evidently", cost: "Free OSS / $49/mo (Cloud)", type: "Local", category: "Defensive" },
  { name: "Alibi Detect", description: "Outlier and drift detection for online feedback.", url: "https://github.com/SeldonIO/alibi-detect", cost: "Free", type: "Local", category: "Defensive" },
  { name: "DeepChecks", description: "ML validation and drift detection checks.", url: "https://github.com/deepchecks/deepchecks", cost: "Free", type: "Local", category: "Defensive" },
  { name: "whylogs", description: "Data logging for monitoring drift and anomalies.", url: "https://github.com/whylabs/whylogs", cost: "Free OSS / $50/model/mo", type: "Local", category: "Defensive" },
  { name: "WhyLabs", description: "Managed ML observability for drift and data quality.", url: "https://whylabs.ai/", cost: "Free tier / $50/model/mo", type: "Third-party", category: "Defensive" },
  { name: "SHAP", description: "Explainability tool to diagnose model behavior shifts.", url: "https://github.com/shap/shap", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Captum", description: "PyTorch interpretability for monitoring output shifts.", url: "https://github.com/pytorch/captum", cost: "Free", type: "Local", category: "Defensive" },
  { name: "River", description: "Online ML library to simulate streaming attacks.", url: "https://github.com/online-ml/river", cost: "Free", type: "Local", category: "Offensive" }
];

const OUTPUT_INTEGRITY_TOOLS: SecurityTool[] = [
  { name: "Burp Suite", description: "Tampering and proxy testing of inference outputs.", url: "https://portswigger.net/", cost: "Free tier / $449/yr (Pro)", type: "Third-party", category: "Offensive" },
  { name: "OWASP ZAP", description: "Proxy testing for output manipulation paths.", url: "https://www.zaproxy.org/", cost: "Free", type: "Local", category: "Offensive" },
  { name: "HashiCorp Vault", description: "Key management for signing model outputs.", url: "https://www.vaultproject.io/", cost: "Free OSS / ~$25/mo (Cloud)", type: "Third-party", category: "Defensive" },
  { name: "Sigstore Cosign", description: "Sign inference artifacts for integrity checks.", url: "https://github.com/sigstore/cosign", cost: "Free", type: "Local", category: "Defensive" }
];

const TRANSFER_LEARNING_TOOLS: SecurityTool[] = [
  { name: "BackdoorBench", description: "Benchmark transfer-learning backdoors.", url: "https://github.com/SCLBD/BackdoorBench", cost: "Free", type: "Local", category: "Offensive" },
  { name: "ModelScan", description: "Scan model files for suspicious payloads.", url: "https://github.com/protectai/modelscan", cost: "Free", type: "Local", category: "Defensive" },
  { name: "PickleScan", description: "Security scanner for Python Pickle, PyTorch, and NumPy serialized model files.", url: "https://github.com/mmaitre314/picklescan", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Cleanlab", description: "Detect label issues in fine-tuning data.", url: "https://github.com/cleanlab/cleanlab", cost: "Free", type: "Local", category: "Defensive" },
  { name: "IBM Adversarial Robustness Toolbox (ART)", description: "Test robustness of fine-tuned models.", url: "https://github.com/Trusted-AI/adversarial-robustness-toolbox", cost: "Free", type: "Local", category: "Offensive" }
];

const RCE_TOOLS: SecurityTool[] = [
  { name: "E2B Sandbox", description: "Secure cloud sandboxing for AI agent tool execution and LLM code interpreting.", url: "https://github.com/e2b-dev/E2B", cost: "Free tier / $15/mo + $0.03/hr", type: "Third-party", category: "Defensive" },
  { name: "Semgrep", description: "Find insecure code execution patterns.", url: "https://github.com/semgrep/semgrep", cost: "Free OSS / $40/dev/mo", type: "Local", category: "Both" },
  { name: "CodeQL", description: "Static analysis for unsafe execution flows.", url: "https://codeql.github.com/", cost: "Free OSS / $49/committer/mo", type: "Third-party", category: "Defensive" },
  { name: "ShellCheck", description: "Detect unsafe shell scripting patterns.", url: "https://github.com/koalaman/shellcheck", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Bandit", description: "Python security linter for unsafe execution patterns.", url: "https://github.com/PyCQA/bandit", cost: "Free", type: "Local", category: "Offensive" },
  { name: "AFL++", description: "Coverage-guided fuzzing for parsers and adapters.", url: "https://github.com/AFLplusplus/AFLplusplus", cost: "Free", type: "Local", category: "Offensive" },
  { name: "libFuzzer", description: "LLVM fuzzing engine for unsafe parsing paths.", url: "https://llvm.org/docs/LibFuzzer.html", cost: "Free", type: "Third-party", category: "Offensive" },
  { name: "gVisor", description: "Sandbox untrusted tool execution.", url: "https://gvisor.dev/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Firecracker", description: "MicroVM isolation for safe execution.", url: "https://github.com/firecracker-microvm/firecracker", cost: "Free", type: "Local", category: "Defensive" },
  { name: "AppArmor", description: "Linux MAC profiles to constrain execution.", url: "https://apparmor.net/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "SELinux", description: "Mandatory access control to confine processes.", url: "https://github.com/SELinuxProject/selinux", cost: "Free", type: "Third-party", category: "Defensive" }
];

const AUTHZ_TOOLS: SecurityTool[] = [
  { name: "Keycloak", description: "Identity and access management for MCP services.", url: "https://www.keycloak.org/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "SPIFFE/SPIRE", description: "Workload identity for zero-trust authentication.", url: "https://spiffe.io/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Auth0", description: "Managed authentication for tools and agents.", url: "https://auth0.com/", cost: "Free tier / $35 - $240/mo", type: "Third-party", category: "Defensive" },
  { name: "Zitadel", description: "Open-source IAM and identity management.", url: "https://github.com/zitadel/zitadel", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Open Policy Agent (OPA)", description: "Policy-based authorization at runtime.", url: "https://www.openpolicyagent.org/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Permit.io", description: "Fine-grained authorization controls.", url: "https://www.permit.io/", cost: "Free tier / $249/mo", type: "Third-party", category: "Defensive" },
  { name: "Burp Suite", description: "Auth and access-control testing for MCP endpoints.", url: "https://portswigger.net/", cost: "Free tier / $449/yr (Pro)", type: "Third-party", category: "Offensive" }
];

const AUDIT_TELEMETRY_TOOLS: SecurityTool[] = [
  { name: "Langfuse", description: "Open-source LLM observability, tracing, evaluation, and prompt management platform.", url: "https://github.com/langfuse/langfuse", cost: "Free OSS / $59/mo (Cloud)", type: "Local", category: "Both" },
  { name: "Arize Phoenix", description: "AI observability, tracing, and evaluation platform for LLM, RAG, and Agent workflows.", url: "https://github.com/Arize-ai/phoenix", cost: "Free", type: "Local", category: "Both" },
  { name: "OpenTelemetry", description: "Tracing and metrics for tool calls and context changes.", url: "https://opentelemetry.io/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Prometheus", description: "Metrics collection and alerting for system health.", url: "https://prometheus.io/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Grafana", description: "Dashboards and alerting for observability data.", url: "https://grafana.com/", cost: "Free OSS / $29/mo (Cloud)", type: "Third-party", category: "Defensive" },
  { name: "Grafana Loki", description: "Log aggregation for high-volume telemetry.", url: "https://grafana.com/oss/loki/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Elastic Stack", description: "Centralized logging, search, and SIEM analytics.", url: "https://www.elastic.co/elastic-stack", cost: "Free OSS / ~$95/mo (Cloud)", type: "Third-party", category: "Defensive" },
  { name: "Datadog", description: "Managed observability with alerting.", url: "https://www.datadoghq.com/", cost: "~$15 - $23/host/mo", type: "Third-party", category: "Defensive" },
  { name: "Splunk", description: "SIEM for audit trails and detection.", url: "https://www.splunk.com/", cost: "~$150/GB ingested/mo", type: "Third-party", category: "Defensive" }
];

const SHADOW_SERVER_TOOLS: SecurityTool[] = [
  { name: "Palo Alto Networks AI Access Security", description: "Enterprise GenAI security gateway with Shadow AI discovery and inline DLP.", url: "https://www.paloaltonetworks.com/network-security/ai-access-security", cost: "~$15k - $50k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "Cloud Custodian", description: "Policy-as-code to discover unauthorized resources.", url: "https://github.com/cloud-custodian/cloud-custodian", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Nuclei", description: "Fast vulnerability scanner for exposed services.", url: "https://github.com/projectdiscovery/nuclei", cost: "Free", type: "Local", category: "Offensive" },
  { name: "Wiz", description: "Cloud security platform for asset discovery.", url: "https://www.wiz.io/", cost: "~$15k - $60k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "AWS Config", description: "Detects configuration drift and unauthorized resources.", url: "https://aws.amazon.com/config/", cost: "~$0.003/config item recorded", type: "Third-party", category: "Defensive" },
  { name: "Nmap", description: "Network discovery to detect rogue MCP services.", url: "https://nmap.org/", cost: "Free", type: "Local", category: "Offensive" }
];

const SECRET_EXPOSURE_TOOLS: SecurityTool[] = [
  { name: "HashiCorp Vault", description: "Central secrets management with rotation.", url: "https://www.vaultproject.io/", cost: "Free OSS / ~$25/mo (Cloud)", type: "Third-party", category: "Defensive" },
  { name: "AWS Secrets Manager", description: "Managed secrets storage with rotation.", url: "https://aws.amazon.com/secrets-manager/", cost: "$0.40/secret/mo + $0.05/10k calls", type: "Third-party", category: "Defensive" },
  { name: "Azure Key Vault", description: "Managed keys and secrets with access policies.", url: "https://azure.microsoft.com/en-us/products/key-vault/", cost: "~$0.03 / 10k operations", type: "Third-party", category: "Defensive" },
  { name: "Google Secret Manager", description: "Managed secret storage with IAM policies.", url: "https://cloud.google.com/secret-manager", cost: "$0.06/secret/mo + $0.03/10k ops", type: "Third-party", category: "Defensive" },
  { name: "SOPS", description: "Encrypt secrets in configuration files.", url: "https://github.com/getsops/sops", cost: "Free", type: "Local", category: "Defensive" },
  { name: "TruffleHog", description: "Detect secrets in code and storage with verification.", url: "https://github.com/trufflesecurity/trufflehog", cost: "Free OSS / $25/user/mo", type: "Local", category: "Offensive" },
  { name: "Gitleaks", description: "Secret scanning for repositories and CI.", url: "https://github.com/gitleaks/gitleaks", cost: "Free", type: "Local", category: "Offensive" },
  { name: "git-secrets", description: "Prevent committing secrets to repositories.", url: "https://github.com/awslabs/git-secrets", cost: "Free", type: "Local", category: "Offensive" },
  { name: "detect-secrets", description: "Baseline secrets detection for codebases.", url: "https://github.com/Yelp/detect-secrets", cost: "Free", type: "Local", category: "Offensive" }
];

const TOOL_POISONING_TOOLS: SecurityTool[] = [
  { name: "Sigstore Cosign", description: "Verify tool artifacts with signatures.", url: "https://github.com/sigstore/cosign", cost: "Free", type: "Local", category: "Defensive" },
  { name: "in-toto", description: "Attestation for tool build provenance.", url: "https://github.com/in-toto/in-toto", cost: "Free", type: "Local", category: "Defensive" },
  { name: "OpenSSF Scorecard", description: "Score dependencies for security risks.", url: "https://github.com/ossf/scorecard", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Snyk", description: "Monitor tool dependencies for known CVEs.", url: "https://snyk.io/", cost: "Free tier / $25/dev/mo", type: "Third-party", category: "Defensive" }
];

const CONTEXT_SHARING_TOOLS: SecurityTool[] = [
  { name: "Presidio", description: "PII detection before context persistence.", url: "https://github.com/microsoft/presidio", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Private AI", description: "High-precision PII/PHI detection and de-identification engine for AI prompts.", url: "https://www.private-ai.com/", cost: "Free trial / $499/mo", type: "Third-party", category: "Defensive" },
  { name: "Nightfall AI", description: "DLP for prompts and logs.", url: "https://www.nightfall.ai/", cost: "Free tier / $49/mo", type: "Third-party", category: "Defensive" },
  { name: "Google Cloud DLP", description: "Sensitive-data discovery in logs and storage.", url: "https://cloud.google.com/security/products/dlp", cost: "~$1.00 - $2.00 / GB inspected", type: "Third-party", category: "Defensive" },
  { name: "Privacy Meter", description: "Evaluate leakage risk from shared context.", url: "https://github.com/privacytrustlab/ml_privacy_meter", cost: "Free", type: "Local", category: "Offensive" }
];

const INTER_AGENT_COMM_TOOLS: SecurityTool[] = [
  { name: "Istio Service Mesh", description: "mTLS and identity for inter-agent traffic.", url: "https://istio.io/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Linkerd", description: "Service mesh with mutual TLS by default.", url: "https://linkerd.io/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "SPIFFE/SPIRE", description: "Workload identity for zero-trust systems.", url: "https://spiffe.io/", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Open Policy Agent (OPA)", description: "Policy enforcement for agent-to-agent calls.", url: "https://www.openpolicyagent.org/", cost: "Free", type: "Local", category: "Defensive" }
];

const TRUST_EXPLOITATION_TOOLS: SecurityTool[] = [
  { name: "Giskard", description: "Red-team workflows for social engineering prompts.", url: "https://github.com/Giskard-AI/giskard", cost: "Free OSS / $49/mo (Pro)", type: "Local", category: "Both" },
  { name: "Guardrails AI", description: "Enforce refusal and disclaimer rules.", url: "https://github.com/guardrails-ai/guardrails", cost: "Free OSS / $0.0005/req", type: "Local", category: "Defensive" },
  { name: "Llama Guard", description: "Safety classifier for manipulative outputs.", url: "https://github.com/meta-llama/PurpleLlama", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Azure AI Content Safety", description: "Multi-modal AI safety service with Prompt Shields and groundedness detection.", url: "https://learn.microsoft.com/en-us/azure/ai-services/content-safety/", cost: "~$0.75 / 1k text records", type: "Third-party", category: "Defensive" },
  { name: "TruLens", description: "Evaluate toxic or manipulative output patterns.", url: "https://github.com/truera/trulens", cost: "Free", type: "Local", category: "Both" }
];

const AGENT_MONITORING_TOOLS: SecurityTool[] = [
  { name: "AgentOps", description: "Agent observability and safety monitoring.", url: "https://www.agentops.ai/", cost: "Free tier / $39/mo", type: "Third-party", category: "Defensive" },
  { name: "Langfuse", description: "Open-source LLM observability, tracing, evaluation, and prompt management platform.", url: "https://github.com/langfuse/langfuse", cost: "Free OSS / $59/mo (Cloud)", type: "Local", category: "Both" },
  { name: "Arize Phoenix", description: "AI observability, tracing, and evaluation platform for LLM, RAG, and Agent workflows.", url: "https://github.com/Arize-ai/phoenix", cost: "Free", type: "Local", category: "Both" },
  { name: "LangChain / LangSmith", description: "Tracing and evaluation for agent workflows.", url: "https://www.langchain.com/langsmith", cost: "Free tier / $39/user/mo", type: "Third-party", category: "Both" },
  { name: "Helicone", description: "LLM telemetry and monitoring for incidents.", url: "https://www.helicone.ai/", cost: "Free tier / $20/mo", type: "Third-party", category: "Defensive" },
  { name: "OpenTelemetry", description: "Tracing for tool calls and agent actions.", url: "https://opentelemetry.io/", cost: "Free", type: "Local", category: "Defensive" }
];

const DATA_GOVERNANCE_TOOLS: SecurityTool[] = [
  { name: "Cyera", description: "AI-DSPM platform discovering and securing sensitive data across AI and RAG stores.", url: "https://www.cyera.com/", cost: "~$20k - $70k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "NIST AI RMF", description: "Risk management framework for AI systems.", url: "https://www.nist.gov/itl/ai-risk-management-framework", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "OWASP ASVS", description: "Application Security Verification Standard for appsec controls.", url: "https://owasp.org/www-project-application-security-verification-standard/", cost: "Free", type: "Third-party", category: "Defensive" },
  { name: "OneTrust", description: "Consent and data governance for AI pipelines.", url: "https://www.onetrust.com/", cost: "~$10k - $50k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "Privacera", description: "Data access governance and policy enforcement.", url: "https://www.privacera.com/", cost: "~$25k - $80k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "BigID", description: "Sensitive data discovery and classification.", url: "https://bigid.com/", cost: "~$20k - $75k/yr (Enterprise)", type: "Third-party", category: "Defensive" },
  { name: "Google Cloud DLP", description: "Detect sensitive data in datasets.", url: "https://cloud.google.com/security/products/dlp", cost: "~$1.00 - $2.00 / GB inspected", type: "Third-party", category: "Defensive" },
  { name: "OpenLineage", description: "Lineage tracking for datasets and pipelines.", url: "https://github.com/OpenLineage/OpenLineage", cost: "Free", type: "Local", category: "Defensive" },
  { name: "DataHub", description: "Metadata and lineage for AI/ML data governance.", url: "https://github.com/datahub-project/datahub", cost: "Free", type: "Local", category: "Defensive" },
  { name: "Gitleaks", description: "Identify leaked secrets in data repositories.", url: "https://github.com/gitleaks/gitleaks", cost: "Free", type: "Local", category: "Offensive" }
];

export const TOOLS_BY_THREAT_ID: Record<string, SecurityTool[]> = {
  // LLM Top 10
  "LLM01:2026": PROMPT_INJECTION_TOOLS,
  "LLM02:2026": SENSITIVE_DATA_TOOLS,
  "LLM03:2026": EXCESSIVE_AGENCY_TOOLS,
  "LLM04:2026": SUPPLY_CHAIN_TOOLS,
  "LLM05:2026": POISONING_TOOLS,
  "LLM06:2026": UNBOUNDED_CONSUMPTION_TOOLS,
  "LLM07:2026": MISINFORMATION_TOOLS,
  "LLM08:2026": PROMPT_LEAKAGE_TOOLS,
  "LLM09:2026": EMBEDDING_TOOLS,
  "LLM10:2026": OUTPUT_HANDLING_TOOLS,

  // ML Top 10
  "ML01:2023": INPUT_MANIPULATION_TOOLS,
  "ML02:2023": POISONING_TOOLS,
  "ML03:2023": PRIVACY_INFERENCE_TOOLS,
  "ML04:2023": PRIVACY_INFERENCE_TOOLS,
  "ML05:2023": MODEL_THEFT_TOOLS,
  "ML06:2023": SUPPLY_CHAIN_TOOLS,
  "ML07:2023": TRANSFER_LEARNING_TOOLS,
  "ML08:2023": MODEL_SKEWING_TOOLS,
  "ML09:2023": OUTPUT_INTEGRITY_TOOLS,
  "ML10:2023": POISONING_TOOLS,

  // OWASP Top 10 for Agentic Applications (ASI, 2026)
  "ASI01": PROMPT_INJECTION_TOOLS,
  "ASI02": EXCESSIVE_AGENCY_TOOLS,
  "ASI03": AUTHZ_TOOLS,
  "ASI04": SUPPLY_CHAIN_TOOLS,
  "ASI05": RCE_TOOLS,
  "ASI06": EMBEDDING_TOOLS,
  "ASI07": [...AUTHZ_TOOLS, ...AUDIT_TELEMETRY_TOOLS],
  "ASI08": UNBOUNDED_CONSUMPTION_TOOLS,
  "ASI09": MISINFORMATION_TOOLS,
  "ASI10": [...AUDIT_TELEMETRY_TOOLS, ...EXCESSIVE_AGENCY_TOOLS],

  // OWASP Agentic Skills Top 10 (AST)
  "AST01": TOOL_POISONING_TOOLS,
  "AST02": SUPPLY_CHAIN_TOOLS,
  "AST03": AUTHZ_TOOLS,
  "AST04": RCE_TOOLS,
  "AST05": PROMPT_INJECTION_TOOLS,
  "AST06": RCE_TOOLS,
  "AST07": SUPPLY_CHAIN_TOOLS,
  "AST08": PROMPT_INJECTION_TOOLS,
  "AST09": AUDIT_TELEMETRY_TOOLS,
  "AST10": SUPPLY_CHAIN_TOOLS,

  // SAIF Risks
  "SAIF-R01": POISONING_TOOLS,
  "SAIF-R02": DATA_GOVERNANCE_TOOLS,
  "SAIF-R03": SUPPLY_CHAIN_TOOLS,
  "SAIF-R04": DATA_GOVERNANCE_TOOLS,
  "SAIF-R05": MODEL_THEFT_TOOLS,
  "SAIF-R06": SUPPLY_CHAIN_TOOLS,
  "SAIF-R07": UNBOUNDED_CONSUMPTION_TOOLS,
  "SAIF-R08": MODEL_THEFT_TOOLS,
  "SAIF-R09": EXCESSIVE_AGENCY_TOOLS,
  "SAIF-R10": PROMPT_INJECTION_TOOLS,
  "SAIF-R11": INPUT_MANIPULATION_TOOLS,
  "SAIF-R12": SENSITIVE_DATA_TOOLS,
  "SAIF-R13": PRIVACY_INFERENCE_TOOLS,
  "SAIF-R14": OUTPUT_HANDLING_TOOLS,
  "SAIF-R15": EXCESSIVE_AGENCY_TOOLS,

  // MCP Top 10
  "MCP1:2025": SECRET_EXPOSURE_TOOLS,
  "MCP2:2025": AUTHZ_TOOLS,
  "MCP3:2025": TOOL_POISONING_TOOLS,
  "MCP4:2025": SUPPLY_CHAIN_TOOLS,
  "MCP5:2025": RCE_TOOLS,
  "MCP6:2025": PROMPT_INJECTION_TOOLS,
  "MCP7:2025": AUTHZ_TOOLS,
  "MCP8:2025": AUDIT_TELEMETRY_TOOLS,
  "MCP9:2025": SHADOW_SERVER_TOOLS,
  "MCP10:2025": CONTEXT_SHARING_TOOLS,

  // OWASP GenAI Data Security (DSGAI)
  "DSGAI01": SENSITIVE_DATA_TOOLS,
  "DSGAI02": [...SECRET_EXPOSURE_TOOLS, ...AUTHZ_TOOLS],
  "DSGAI03": SHADOW_SERVER_TOOLS,
  "DSGAI04": [...POISONING_TOOLS, ...SUPPLY_CHAIN_TOOLS],
  "DSGAI05": [...POISONING_TOOLS, ...SUPPLY_CHAIN_TOOLS],
  "DSGAI06": [...CONTEXT_SHARING_TOOLS, ...AUTHZ_TOOLS],
  "DSGAI07": AUDIT_TELEMETRY_TOOLS,
  "DSGAI08": SENSITIVE_DATA_TOOLS,
  "DSGAI09": SENSITIVE_DATA_TOOLS,
  "DSGAI10": PRIVACY_INFERENCE_TOOLS,
  "DSGAI11": DATA_GOVERNANCE_TOOLS,
  "DSGAI12": DATA_GOVERNANCE_TOOLS,
  "DSGAI13": DATA_GOVERNANCE_TOOLS,
  "DSGAI14": DATA_GOVERNANCE_TOOLS,
  "DSGAI15": DATA_GOVERNANCE_TOOLS,
  "DSGAI16": SENSITIVE_DATA_TOOLS,
  "DSGAI17": SENSITIVE_DATA_TOOLS,
  "DSGAI18": DATA_GOVERNANCE_TOOLS,
  "DSGAI19": DATA_GOVERNANCE_TOOLS,
  "DSGAI20": EMBEDDING_TOOLS,
  "DSGAI21": MISINFORMATION_TOOLS
};

export const mergeTools = (primary: SecurityTool[], fallback: SecurityTool[]) => {
  const seen = new Set<string>();
  const normalize = (name: string) => name.trim().toLowerCase();
  const result: SecurityTool[] = [];
  const push = (tool: SecurityTool) => {
    const key = normalize(tool.name);
    if (seen.has(key)) return;
    seen.add(key);
    result.push(tool);
  };
  primary.forEach(push);
  fallback.forEach(push);
  return result;
};
