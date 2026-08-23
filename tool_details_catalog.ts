import { SecurityTool } from './types';

/**
 * AI Security Nexus - Master Enriched Tool Database
 * Comprehensive, verified metadata for all AI security tools in the directory.
 */
export const TOOL_DATABASE: Record<string, SecurityTool> = {
  "garak": {
    name: "garak",
    description: "LLM vulnerability scanner with prompt-injection probes.",
    url: "https://github.com/NVIDIA/garak",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "NVIDIA / Leon Derczynski",
    license: "Apache-2.0",
    ecosystem: ["Python", "PyTorch", "Hugging Face", "OpenAI", "REST APIs"],
    longDescription: "Garak (Generative AI Red-teaming & Assessment Kit) is an automated vulnerability scanner specifically architected for Large Language Models. It operates like nmap or Nessus for generative AI, systematically probing models with thousands of attack vectors across jailbreaks, prompt injection, data extraction, toxicity, hallucinations, and package hallucination attacks.",
    typicalUseCase: "Automated CI/CD security regression testing and pre-deployment red-teaming of custom LLM system prompts and fine-tuned checkpoints against known jailbreak payloads.",
    keyFeatures: [
      "Modular probe & detector architecture spanning 50+ vulnerability types",
      "Native integrations with HuggingFace, OpenAI, Replicate, and local inference engines",
      "Automated DAN, character injection, and covert encoding probes",
      "Detailed HTML & JSON vulnerability assessment reporting"
    ],
    installationOrQuickstart: "pip install -U garak\npython -m garak --model_type openai --model_name gpt-4o --probes promptinject,dan"
  },

  "PyRIT": {
    name: "PyRIT",
    description: "Microsoft open-source LLM red teaming automation framework.",
    url: "https://github.com/microsoft/pyrit",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Microsoft AI Red Team",
    license: "MIT",
    ecosystem: ["Python", "Azure OpenAI", "Hugging Face", "Docker"],
    longDescription: "PyRIT (Python Risk Identification Tool) is an open-source red-teaming automation framework built by Microsoft's AI Red Team. It automates multi-turn attack strategies (such as Crescendo attacks, covert jailbreaks, and iterative prompt modification) to assess risk postures in generative AI systems.",
    typicalUseCase: "Orchestrating dynamic, multi-turn red-teaming campaigns against enterprise Copilots and agentic AI systems to identify evasive jailbreaks and policy violations.",
    keyFeatures: [
      "Multi-turn conversational attack orchestrators (Crescendo, Tree of Attacks)",
      "Automated converters for ROT13, Base64, translation, and character substitution",
      "Integrated scoring engine to evaluate target model responses",
      "Extensible target architecture supporting REST endpoints and local models"
    ],
    installationOrQuickstart: "pip install pyrit\n# Configure pyrit.orchestrator and execute automated campaign against target"
  },

  "promptfoo": {
    name: "promptfoo",
    description: "Adversarial prompt testing and regression suite for LLM apps.",
    url: "https://github.com/promptfoo/promptfoo",
    cost: "Free+Paid",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "Promptfoo Inc.",
    license: "MIT",
    ecosystem: ["Node.js", "TypeScript", "Python", "GitHub Actions", "CI/CD"],
    longDescription: "Promptfoo is a lightweight, battle-tested CLI tool and CI/CD assertion engine for testing LLM applications against prompt injections, PII leaks, harmful content, and quality regressions. It evaluates prompts, agents, and RAG pipelines with custom deterministic and model-graded assertions.",
    typicalUseCase: "Running automated pull request security checks that assert LLM responses don't leak API keys, execute malicious tool calls, or succumb to indirect prompt injections.",
    keyFeatures: [
      "Automated red-team probe generator for OWASP Top 10 for LLMs",
      "High-concurrency parallel evaluation across 30+ LLM providers",
      "Rich web dashboard for comparing prompt versions and security scores",
      "Deterministic and model-graded security assertions (PII, toxicity, regex)"
    ],
    installationOrQuickstart: "npm install -g promptfoo\npromptfoo init\npromptfoo redteam run"
  },

  "OpenAI Evals": {
    name: "OpenAI Evals",
    description: "Evaluation framework to test LLM behaviors and safety.",
    url: "https://github.com/openai/evals",
    cost: "Free",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "OpenAI",
    license: "MIT",
    ecosystem: ["Python", "OpenAI API", "CLI"],
    longDescription: "OpenAI Evals is a framework for creating and running evaluations that benchmark large language models and systems built on top of them. It enables security researchers to construct custom benchmark datasets and test models against specific failure modes and alignment benchmarks.",
    typicalUseCase: "Creating custom safety evaluation suites to test whether fine-tuned models maintain compliance with corporate acceptable use policies and refusal boundaries.",
    keyFeatures: [
      "Standardized evaluation harness for OpenAI models and custom endpoints",
      "Support for model-graded evaluation protocols",
      "Extensive repository of community-contributed safety evaluation sets",
      "Co-occurrence and exact-match metric calculations"
    ],
    installationOrQuickstart: "pip install evals\noaieval gpt-4o sec-eval-dataset"
  },

  "Giskard": {
    name: "Giskard",
    description: "Open-source red-teaming and evaluation for LLM apps.",
    url: "https://github.com/Giskard-AI/giskard",
    cost: "Free+Paid",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "Giskard AI",
    license: "Apache-2.0",
    ecosystem: ["Python", "LangChain", "LlamaIndex", "Hugging Face", "Scikit-learn"],
    longDescription: "Giskard is an open-source testing framework tailored for AI and LLM applications, offering automated vulnerability scans for hallucination, prompt injection, bias, data leakage, and harmful outputs across both generative models and traditional ML classifiers.",
    typicalUseCase: "Scanning RAG pipelines and enterprise conversational agents for retrieval hallucination, sycophancy, and prompt injection vulnerabilities prior to release.",
    keyFeatures: [
      "Automated vulnerability scanner generating adversarial test cases",
      "Dedicated LLM-as-a-judge evaluators for hallucination and safety",
      "Integration with CI/CD pipelines via PyTest and GitHub Actions",
      "Visual debugging hub for inspection of failed test cases"
    ],
    installationOrQuickstart: "pip install giskard\n# Run giskard.scan(model, dataset) in your test workflow"
  },

  "Prompt Security PS-Fuzz": {
    name: "Prompt Security PS-Fuzz",
    description: "Prompt fuzzer for prompt injection and jailbreak testing.",
    url: "https://github.com/prompt-security/ps-fuzz",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Prompt Security",
    license: "Apache-2.0",
    ecosystem: ["Python", "CLI", "REST APIs"],
    longDescription: "PS-Fuzz is an open-source prompt fuzzing engine designed to stress-test LLMs against adversarial jailbreaks, system prompt extraction, and input manipulation through automated token mutations and adversarial perturbation techniques.",
    typicalUseCase: "Black-box fuzzing of LLM API gateways to identify character mutations and token obfuscation tricks that bypass system filters.",
    keyFeatures: [
      "Mutation-based prompt generation algorithms",
      "Adaptive fuzzing loop tracking target model degradation",
      "Curated library of jailbreak seeds and prompt extraction probes",
      "Detailed vulnerability scoring and payload export"
    ],
    installationOrQuickstart: "pip install ps-fuzz\nps-fuzz --target http://localhost:8000/chat --payloads jailbreaks"
  },

  "Rebuff": {
    name: "Rebuff",
    description: "Prompt injection detection and filtering middleware.",
    url: "https://github.com/protectai/rebuff",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Protect AI",
    license: "Apache-2.0",
    ecosystem: ["Python", "Pinecone", "Chroma", "OpenAI"],
    longDescription: "Rebuff is an open-source, multi-layered prompt injection detection and defense framework that utilizes heuristics, vector similarity search, and canary tokens to detect prompt manipulation before it reaches downstream language models.",
    typicalUseCase: "Embedding inside API gateway middleware to catch prompt injection payloads and drop poisoned user queries before they hit backend models.",
    keyFeatures: [
      "Canary token injection into prompts to detect context hijacking",
      "Vector database matching against known prompt injection embeddings",
      "Multi-model LLM-based detector ensemble",
      "Low-latency classification pipeline"
    ],
    installationOrQuickstart: "pip install rebuff\nfrom rebuff import Rebuff\nrb = Rebuff(api_token='...', openai_apikey='...')\nresult = rb.detect_injection(user_input)"
  },

  "NVIDIA NeMo Guardrails": {
    name: "NVIDIA NeMo Guardrails",
    description: "Programmable guardrails to constrain LLM behavior.",
    url: "https://github.com/NVIDIA/NeMo-Guardrails",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "NVIDIA",
    license: "Apache-2.0",
    ecosystem: ["Python", "LangChain", "Colang", "FastAPI"],
    longDescription: "NeMo Guardrails is an open-source toolkit for adding programmable topical, safety, and security guardrails to LLM-based conversational applications using Colang, ensuring conversational AI systems adhere to defined boundaries.",
    typicalUseCase: "Restricting an enterprise customer-support bot to only discuss permitted support topics while blocking jailbreaks, hallucinated claims, and unsafe tool invocations.",
    keyFeatures: [
      "Colang modeling language for defining conversational flows and guardrails",
      "Input rails for prompt injection and toxic content blocking",
      "Output rails for hallucination detection and fact-checking",
      "Execution rails for parameter validation of tool and action calls"
    ],
    installationOrQuickstart: "pip install nemoguardrails\nnemo-guardrails server --config=./config"
  },

  "Guardrails AI": {
    name: "Guardrails AI",
    description: "Output validation and safety guardrails for LLMs.",
    url: "https://github.com/guardrails-ai/guardrails",
    cost: "Free+Paid",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Guardrails AI",
    license: "Apache-2.0",
    ecosystem: ["Python", "TypeScript", "LangChain", "LlamaIndex"],
    longDescription: "Guardrails AI provides a framework for specifying semantic validation rules, structural schemas, and quality constraints on LLM inputs and outputs, with automatic re-asking on failure to guarantee structured, safe generations.",
    typicalUseCase: "Enforcing strict JSON output schemas, preventing PII disclosure, and validating that SQL queries generated by LLMs conform to read-only constraints.",
    keyFeatures: [
      "Guardrails Hub ecosystem with 50+ pre-built community validators",
      "Automatic corrective re-prompting on schema validation errors",
      "PII redaction, SQL validation, and toxic content detectors",
      "Support for streaming response verification"
    ],
    installationOrQuickstart: "pip install guardrails-ai\nguardrails hub install hub://guardrails/regex_match"
  },

  "Llama Guard": {
    name: "Llama Guard",
    description: "Safety classifier to filter unsafe prompts and outputs.",
    url: "https://github.com/meta-llama/PurpleLlama",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Meta AI / Purple Llama",
    license: "Llama 3 Community License",
    ecosystem: ["PyTorch", "vLLM", "Hugging Face", "Ollama"],
    longDescription: "Llama Guard is an open-weights safety classification model fine-tuned on the MLCommons taxonomy to evaluate prompts and responses across 14 risk categories, including violent crimes, cybersecurity exploits, PII, and non-violent crimes.",
    typicalUseCase: "Serving as a lightweight input and output filter directly before and after primary inference to block policy-violating prompts and generations.",
    keyFeatures: [
      "Evaluates both user prompts and model completions against 14 safety categories",
      "Customizable safety taxonomies through prompt customization",
      "High inference throughput when served via vLLM or Ollama",
      "Fine-tuned specifically for adversarial jailbreak detection"
    ],
    installationOrQuickstart: "pip install vllm\nvllm serve meta-llama/Llama-Guard-3-8B"
  },

  "Lakera Guard": {
    name: "Lakera Guard",
    description: "Real-time semantic firewall to block prompt injection payloads.",
    url: "https://www.lakera.ai/lakera-guard",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Lakera",
    license: "Commercial / SaaS API",
    ecosystem: ["REST API", "Python SDK", "Node.js", "Cloudflare Workers"],
    longDescription: "Lakera Guard is an ultra-low latency semantic firewall API engineered to safeguard LLM applications against prompt injections, jailbreaks, data leakage, and harmful content in real time (<30ms latency).",
    typicalUseCase: "Inline API gateway screening of all incoming prompts and outgoing generations in production consumer-facing applications.",
    keyFeatures: [
      "Sub-30ms classification latency for high-throughput production workloads",
      "Continuous threat intelligence derived from Gandalf prompt injection game datasets",
      "Detects direct injections, indirect injections, and multi-modal attacks",
      "Zero-configuration developer SDKs for Python and JavaScript"
    ],
    installationOrQuickstart: "curl -X POST 'https://api.lakera.ai/v2/guard' \\\n  -H 'Authorization: Bearer $LAKERA_API_KEY' \\\n  -d '{\"messages\": [{\"role\": \"user\", \"content\": \"Analyze this text\"}]}'"
  },

  "Presidio": {
    name: "Presidio",
    description: "PII detection and anonymization for prompts and outputs.",
    url: "https://github.com/microsoft/presidio",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Microsoft",
    license: "MIT",
    ecosystem: ["Python", "spaCy", "Docker", "Kubernetes"],
    longDescription: "Presidio is a fast, customizable data protection and anonymization framework that detects PII entities (names, SSNs, credit cards, emails, medical IDs) in text and redact/anonymizes them using customized operators.",
    typicalUseCase: "Pre-processing user prompts to scrub customer personal data before sending context to public LLM APIs or storing in vector databases.",
    keyFeatures: [
      "Extensible entity recognizer engine combining NER, regex, and context rules",
      "Modular anonymizers: redaction, masking, encryption, and synthesis",
      "Multi-language PII recognition support",
      "Scalable containerized deployment for high-volume pipelines"
    ],
    installationOrQuickstart: "pip install presidio-analyzer presidio-anonymizer\npython -m spacy download en_core_web_lg"
  },

  "IBM Adversarial Robustness Toolbox (ART)": {
    name: "IBM Adversarial Robustness Toolbox (ART)",
    description: "Library for data/model poisoning attacks and defenses.",
    url: "https://github.com/Trusted-AI/adversarial-robustness-toolbox",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Linux Foundation AI & Data / IBM",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "TensorFlow", "Scikit-learn", "ONNX"],
    longDescription: "ART is a comprehensive Python library for Machine Learning security, offering over 30+ adversarial evasion attacks (FGSM, PGD, CW), data poisoning attacks (Clean-Label, Backdoor), model extraction, and membership inference defenses.",
    typicalUseCase: "Benchmarking model resilience against adversarial perturbation, poison injection, and model inversion across vision, tabular, and NLP models.",
    keyFeatures: [
      "30+ evasion attack algorithms (Fast Gradient Method, Projected Gradient Descent)",
      "Comprehensive poisoning attack suite (Backdoor, Clean-Label, Model Poisoning)",
      "Defensive distillation and adversarial training wrappers",
      "Broad framework support across PyTorch, TensorFlow, Keras, and Scikit-learn"
    ],
    installationOrQuickstart: "pip install adversarial-robustness-toolbox\nfrom art.attacks.evasion import FastGradientMethod"
  },

  "ModelScan": {
    name: "ModelScan",
    description: "Scan model artifacts for malicious code paths.",
    url: "https://github.com/protectai/modelscan",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Protect AI",
    license: "Apache-2.0",
    ecosystem: ["Python", "Hugging Face", "CI/CD", "MLOps"],
    longDescription: "ModelScan is an open-source static scanner that inspects serialized ML model files (PyTorch .pt/.bin, Pickle .pkl, Keras .h5, ONNX, PMML) for embedded malicious code and arbitrary code execution exploits without loading untrusted weights into memory.",
    typicalUseCase: "Automated CI/CD scanning of untrusted model weights downloaded from HuggingFace, Model Zoo, or S3 buckets before deserialization.",
    keyFeatures: [
      "Inspects serialized pickle streams, PyTorch checkpoints, and SavedModel archives",
      "Detects reverse shells, arbitrary OS executions, and malicious import payloads",
      "Zero-execution static AST analysis prevents exploit triggering during scan",
      "Integrates with MLOps pipelines and HuggingFace download hooks"
    ],
    installationOrQuickstart: "pip install modelscan\nmodelscan -p ./models/weights.pkl"
  },

  "Trivy": {
    name: "Trivy",
    description: "Scanner for container images, dependencies, and configs.",
    url: "https://github.com/aquasecurity/trivy",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Aqua Security",
    license: "Apache-2.0",
    ecosystem: ["Go", "Docker", "Kubernetes", "GitHub Actions"],
    longDescription: "Trivy is a comprehensive, fast security scanner for container images, file systems, Git repositories, Kubernetes configurations, and software bills of materials (SBOM), pinpointing CVEs in base images and dependencies.",
    typicalUseCase: "Scanning AI inference Docker containers and PyTorch/CUDA runtime base images for known OS and language package vulnerabilities in CI/CD.",
    keyFeatures: [
      "Scans OS packages (Debian, Ubuntu, Alpine) and language packages (pip, npm, Go)",
      "Misconfiguration scanning for Kubernetes, Terraform, and Dockerfiles",
      "Generates CycloneDX and SPDX SBOMs automatically",
      "Ultra-fast local caching and vulnerability database updates"
    ],
    installationOrQuickstart: "trivy image pytorch/pytorch:2.3.0-cuda12.1-cudnn8-runtime"
  },

  "Semgrep": {
    name: "Semgrep",
    description: "Static analysis to detect unsafe output handling.",
    url: "https://github.com/semgrep/semgrep",
    cost: "Free+Paid",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "Semgrep Inc.",
    license: "LGPL-2.1 / Commercial",
    ecosystem: ["Python", "TypeScript", "Java", "Go", "CI/CD"],
    longDescription: "Semgrep is a fast, open-source static analysis engine that searches code for security vulnerabilities, secret leaks, and insecure API handling patterns using intuitive AST-based pattern matching.",
    typicalUseCase: "Catching unsafe deserialization (`pickle.load`), dynamic evaluation (`eval(llm_output)`), and unparameterized SQL queries in LLM tool execution logic.",
    keyFeatures: [
      "AST-aware semantic code search that ignores formatting variations",
      "Comprehensive rule registry covering OWASP Top 10 and CWEs",
      "Fast local execution with zero dependencies",
      "Seamless integration into GitHub Actions, GitLab CI, and pre-commit hooks"
    ],
    installationOrQuickstart: "pip install semgrep\nsemgrep --config=p/owasp-top-ten"
  },

  "Open Policy Agent (OPA)": {
    name: "Open Policy Agent (OPA)",
    description: "Policy engine for fine-grained authorization.",
    url: "https://www.openpolicyagent.org/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "CNCF / Styra",
    license: "Apache-2.0",
    ecosystem: ["Go", "Kubernetes", "Envoy", "Docker", "REST APIs"],
    longDescription: "OPA is an open-source, general-purpose policy engine that enables unified, context-aware policy enforcement across microservices, Kubernetes, CI/CD pipelines, and AI agent tool invocations using the declarative Rego language.",
    typicalUseCase: "Enforcing runtime access control and parameter limits on autonomous AI agent tool executions (e.g. limiting database queries to read-only mode).",
    keyFeatures: [
      "Declarative Rego query language for policy-as-code",
      "Sub-millisecond policy decision latency",
      "Decoupled policy enforcement from application business logic",
      "Full unit testing and coverage tooling for security policies"
    ],
    installationOrQuickstart: "opa run --server --bundle ./agent-policies"
  },

  "HashiCorp Vault": {
    name: "HashiCorp Vault",
    description: "Key management for signing model outputs.",
    url: "https://www.vaultproject.io/",
    cost: "Free+Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "HashiCorp",
    license: "BSL / Community",
    ecosystem: ["Go", "Kubernetes", "Terraform", "AWS", "Azure", "GCP"],
    longDescription: "Vault secures, stores, and tightly controls access to tokens, passwords, certificates, API keys, and other secrets in modern computing environments with automatic rotation, leasing, and audit logging.",
    typicalUseCase: "Managing dynamic, short-lived API credentials and tokens for LLM tool agents to prevent credential leakage in agent memory or context.",
    keyFeatures: [
      "Dynamic secret generation with automated leasing and revocation",
      "Cryptographic encryption-as-a-service (transit engine)",
      "Fine-grained role-based access control policies",
      "Immutable audit log streams for compliance verification"
    ],
    installationOrQuickstart: "vault server -dev\nvault kv put secret/ai/openai_key value='sk-...'"
  },

  "Gitleaks": {
    name: "Gitleaks",
    description: "Secret scanning for repositories and CI.",
    url: "https://github.com/gitleaks/gitleaks",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Gitleaks / Zach Rice",
    license: "MIT",
    ecosystem: ["Go", "Git", "GitHub Actions", "Pre-commit"],
    longDescription: "Gitleaks is a SAST tool for detecting and preventing hardcoded secrets like passwords, API keys, and tokens in git repos, files, and commit histories using regex patterns and Shannon entropy scoring.",
    typicalUseCase: "Pre-commit hook and CI scanner to prevent developers from accidentally committing OpenAI API keys or vector database credentials into repositories.",
    keyFeatures: [
      "Fast scanning of entire git commit histories and uncommitted staged files",
      "Shannon entropy analysis to catch high-entropy random keys",
      "Customizable TOML rulesets for proprietary secret tokens",
      "Native GitHub Action and pre-commit hook integrations"
    ],
    installationOrQuickstart: "brew install gitleaks\ngitleaks detect --source . --verbose"
  },

  "Ragas": {
    name: "Ragas",
    description: "RAG evaluation for retrieval quality and safety.",
    url: "https://github.com/explodinggradients/ragas",
    cost: "Free",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "Exploding Gradients",
    license: "Apache-2.0",
    ecosystem: ["Python", "LangChain", "LlamaIndex", "OpenAI", "Hugging Face"],
    longDescription: "Ragas is an open-source evaluation framework for Retrieval Augmented Generation (RAG) pipelines, measuring faithfulness, answer relevancy, context precision, context recall, and aspect critique.",
    typicalUseCase: "Continuous automated evaluation of RAG systems to detect context poisoning, retrieval degradation, and hallucinated answers.",
    keyFeatures: [
      "Faithfulness and groundedness evaluation metrics",
      "Context recall and context precision scoring",
      "Automated test dataset generator using evolutionary synthesis",
      "Integrates seamlessly with LangChain, LlamaIndex, and Haystack"
    ],
    installationOrQuickstart: "pip install ragas\nfrom ragas import evaluate"
  },

  "DeepEval": {
    name: "DeepEval",
    description: "LLM evaluation framework for factuality and hallucinations.",
    url: "https://github.com/confident-ai/deepeval",
    cost: "Free",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "Confident AI",
    license: "Apache-2.0",
    ecosystem: ["Python", "PyTest", "LangChain", "OpenAI", "Ollama"],
    longDescription: "DeepEval is an open-source LLM evaluation framework for unit testing LLM applications with PyTest-like assertions covering hallucinations, bias, toxicity, G-Eval, and RAG triad metrics.",
    typicalUseCase: "Writing unit tests for LLM outputs and assertions that verify generation factuality before merging changes to system prompts.",
    keyFeatures: [
      "14+ evaluation metrics: Hallucination, Faithfulness, Toxicity, Bias, G-Eval",
      "Native PyTest integration with test assertion decorators",
      "Synthetic test data generator for adversarial prompt simulation",
      "Local test result tracking and Confident AI cloud reporting"
    ],
    installationOrQuickstart: "pip install deepeval\ndeepeval test run test_llm_safety.py"
  },

  "DOMPurify": {
    name: "DOMPurify",
    description: "Sanitize HTML outputs to prevent XSS.",
    url: "https://github.com/cure53/dompurify",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Cure53 / Mario Heiderich",
    license: "Apache-2.0 / MPL-2.0",
    ecosystem: ["JavaScript", "TypeScript", "Node.js", "Browser"],
    longDescription: "DOMPurify is a DOM-only, super-fast, ubiquitously tolerant XSS sanitizer for HTML, MathML and SVG, written in JavaScript. It strips dangerous executable scripts and malicious attributes from generated HTML.",
    typicalUseCase: "Sanitizing LLM-generated markdown, HTML, and rich text before rendering it in client-side web interfaces to eliminate stored Cross-Site Scripting (XSS).",
    keyFeatures: [
      "Deep DOM-tree sanitization preventing parser mutation XSS (mXSS)",
      "Strict allowlist of HTML5 elements and attributes",
      "Zero dependencies and ultra-fast execution",
      "Configurable hook system for customized attribute transformations"
    ],
    installationOrQuickstart: "npm install dompurify\nimport DOMPurify from 'dompurify';\nconst cleanHtml = DOMPurify.sanitize(untrustedLlmOutput);"
  },

  "Sigstore Cosign": {
    name: "Sigstore Cosign",
    description: "Sign and verify images and artifacts.",
    url: "https://github.com/sigstore/cosign",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Sigstore / OpenSSF",
    license: "Apache-2.0",
    ecosystem: ["Go", "Docker", "Kubernetes", "OCI Registries"],
    longDescription: "Cosign is a tool for container signing, verification and storage in an OCI registry, enabling cryptographic signatures and software bill of materials (SBOM) attestations for model files and container images.",
    typicalUseCase: "Signing AI model weights and container images in CI/CD to prevent unauthorized tampering or poisoned artifacts from executing in production clusters.",
    keyFeatures: [
      "Keyless signing using OpenID Connect identities (Fulcio / Rekor)",
      "Direct signature storage in OCI registries alongside artifacts",
      "Attestation verification for in-toto supply chain metadata and SBOMs",
      "Kubernetes admission controller integration for signature enforcement"
    ],
    installationOrQuickstart: "cosign sign --key cosign.key registry.example.com/ai-model:v1\ncosign verify --key cosign.pub registry.example.com/ai-model:v1"
  },

  "Cleanlab": {
    name: "Cleanlab",
    description: "Detect and fix label issues and noisy/poisoned data.",
    url: "https://github.com/cleanlab/cleanlab",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Cleanlab Inc.",
    license: "AGPL-3.0",
    ecosystem: ["Python", "PyTorch", "Scikit-learn", "Hugging Face"],
    longDescription: "Cleanlab is an open-source machine learning library designed for data-centric AI that automatically detects label errors, mislabeled samples, outliers, and poisoned training data in datasets.",
    typicalUseCase: "Auditing training datasets to detect poisoned or maliciously labeled training samples before fine-tuning classification and embedding models.",
    keyFeatures: [
      "Confident Learning algorithms to identify mislabeled training examples",
      "Outlier and anomaly scoring across tabular, text, and vision datasets",
      "Data valuation and dataset quality scoring",
      "Works with any model providing predicted class probabilities"
    ],
    installationOrQuickstart: "pip install cleanlab\nfrom cleanlab.filter import find_label_issues\nissues = find_label_issues(labels=labels, pred_probs=pred_probs)"
  },

  "Snyk": {
    name: "Snyk",
    description: "Dependency and container vulnerability scanning.",
    url: "https://snyk.io/",
    cost: "Free+Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Snyk Ltd.",
    license: "Commercial / Free Tier",
    ecosystem: ["CLI", "GitHub Actions", "Docker", "Kubernetes", "IDE Plugins"],
    longDescription: "Snyk is a developer security platform that integrates directly into development workflows to find and automatically fix known vulnerabilities in open-source dependencies, container images, and IaC scripts.",
    typicalUseCase: "Automated scanning of Python requirements and container images in AI pipelines to detect vulnerable versions of PyTorch, Transformers, or LangChain.",
    keyFeatures: [
      "Continuous dependency vulnerability scanning (Snyk Open Source)",
      "Automated pull requests with verified security version upgrades",
      "Container base image remediation recommendations",
      "AI-assisted code vulnerability analysis (Snyk Code)"
    ],
    installationOrQuickstart: "npm install -g snyk\nsnyk test --file=requirements.txt"
  },

  "Burp Suite": {
    name: "Burp Suite",
    description: "Web security testing for output handling flaws.",
    url: "https://portswigger.net/",
    cost: "Free+Paid",
    type: "Third-party",
    category: "Offensive",
    authorOrMaintainer: "PortSwigger",
    license: "Commercial / Community Edition",
    ecosystem: ["Java", "HTTP Proxy", "REST APIs", "WebSocket"],
    longDescription: "Burp Suite is the industry-standard web application penetration testing toolkit, providing an intercepting proxy, automated scanner, intruder fuzzing module, and custom extensions for testing modern APIs and LLM wrappers.",
    typicalUseCase: "Intercepting and manipulating API traffic between LLM agents, plugins, and backend services to test for SSRF, authorization bypass, and output injection.",
    keyFeatures: [
      "Full HTTP/HTTPS/WebSocket traffic interception and tampering",
      "Burp Intruder for custom payload fuzzing and parameter brute-forcing",
      "Burp Collaborator for out-of-band (OAST) blind injection detection",
      "BApp Store extensions for LLM and GenAI vulnerability testing"
    ],
    installationOrQuickstart: "Launch Burp Suite -> Configure browser proxy (127.0.0.1:8080) -> Intercept LLM API requests"
  },

  "OWASP ZAP": {
    name: "OWASP ZAP",
    description: "Dynamic testing for XSS/SQLi in LLM wrappers.",
    url: "https://www.zaproxy.org/",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Crash Diagnostics / OWASP Foundation",
    license: "Apache-2.0",
    ecosystem: ["Java", "Docker", "CI/CD", "REST APIs"],
    longDescription: "OWASP ZAP (Zed Attack Proxy) is the world's most widely used open-source dynamic web application security scanner, offering automated vulnerability discovery and manual testing tools for APIs and web interfaces.",
    typicalUseCase: "Dynamic application security testing (DAST) of web applications exposing LLM chat interfaces and tool endpoints to detect XSS and SQL injection.",
    keyFeatures: [
      "Automated active and passive vulnerability scanning",
      "REST API and automation framework for CI/CD integration",
      "WebSocket interception and fuzzing capabilities",
      "Dockerized scanning daemon for headless testing"
    ],
    installationOrQuickstart: "docker run -v $(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://ai-app.example.com"
  },

  "AgentOps": {
    name: "AgentOps",
    description: "Observability and guardrails for agent behavior.",
    url: "https://www.agentops.ai/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "AgentOps Inc.",
    license: "Commercial / Free Tier",
    ecosystem: ["Python", "CrewAI", "AutoGen", "LangChain"],
    longDescription: "AgentOps provides specialized observability, monitoring, and compliance guardrails for autonomous AI agent workflows, tracking multi-agent tool execution, goal deviation, and recursive loop traps.",
    typicalUseCase: "Monitoring production autonomous agent sessions to detect rogue loops, excessive tool invocation costs, and unintended external actions.",
    keyFeatures: [
      "Session replay and step-by-step visual trace of agent reasoning chains",
      "Detection of recursive infinite loops and goal deviation",
      "Multi-agent communication topology mapping",
      "Cost and latency tracking per tool execution"
    ],
    installationOrQuickstart: "pip install agentops\nimport agentops\nagentops.init(api_key='...')"
  },

  "SPIFFE/SPIRE": {
    name: "SPIFFE/SPIRE",
    description: "Workload identity for zero-trust authentication.",
    url: "https://spiffe.io/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "CNCF",
    license: "Apache-2.0",
    ecosystem: ["Go", "Kubernetes", "Envoy", "Docker"],
    longDescription: "SPIFFE (Secure Production Identity Framework for Everyone) and SPIRE provide universal cryptographic workload identities, issuing short-lived X.509 SVID certificates to microservices and AI agents for mutual TLS authentication.",
    typicalUseCase: "Issuing cryptographic zero-trust identities to AI agent microservices and Model Context Protocol servers to enforce mutual TLS and prevent rogue server spoofing.",
    keyFeatures: [
      "Cryptographic X.509 SVID workload identities without static API keys",
      "Automatic certificate issuance and zero-downtime rotation",
      "Integration with Envoy and service meshes for transparent mTLS",
      "Attestation plugins for Kubernetes, Docker, and bare-metal nodes"
    ],
    installationOrQuickstart: "spire-server run -config /etc/spire/server.conf\nspire-agent run -config /etc/spire/agent.conf"
  },

  "Nuclei": {
    name: "Nuclei",
    description: "Fast vulnerability scanner for exposed services.",
    url: "https://github.com/projectdiscovery/nuclei",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "ProjectDiscovery",
    license: "MIT",
    ecosystem: ["Go", "YAML Templates", "CLI", "CI/CD"],
    longDescription: "Nuclei is a fast and customizable vulnerability scanner based on simple YAML DSL templates, capable of scanning thousands of hosts for exposed endpoints, misconfigurations, and known CVEs.",
    typicalUseCase: "Scanning network perimeters for exposed Ollama, vLLM, LM Studio, LangChain, or Model Context Protocol endpoints with default configurations.",
    keyFeatures: [
      "Community-driven library of 7,000+ vulnerability templates",
      "Support for HTTP, DNS, TCP, SSL, and Headless protocols",
      "Ultra-fast asynchronous execution across CIDR blocks",
      "Custom template authoring in intuitive YAML format"
    ],
    installationOrQuickstart: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\nnuclei -target https://target.ai.example.com -tags ai,llm,ollama"
  },

  "TruffleHog": {
    name: "TruffleHog",
    description: "Detect secrets in code and storage with verification.",
    url: "https://github.com/trufflesecurity/trufflehog",
    cost: "Free+Paid",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Truffle Security",
    license: "AGPL-3.0",
    ecosystem: ["Go", "Git", "S3", "Docker", "CI/CD"],
    longDescription: "TruffleHog is an advanced secrets scanner that scans git repositories, S3 buckets, filesystems, and container images for 800+ secret types, actively verifying detected credentials against upstream APIs to confirm whether they are live.",
    typicalUseCase: "Auditing internal git repositories, model training scripts, and S3 datasets to detect live OpenAI, Anthropic, or Hugging Face API keys.",
    keyFeatures: [
      "Active secret verification against upstream service APIs (zero false positives)",
      "800+ secret detectors covering major AI platforms (OpenAI, Pinecone, HuggingFace)",
      "Scans git history, filesystem directories, S3 buckets, and Docker images",
      "High-throughput concurrent scanning engine"
    ],
    installationOrQuickstart: "brew install trufflehog\ntrufflehog git https://github.com/my-org/ai-repo"
  },

  "Istio Service Mesh": {
    name: "Istio Service Mesh",
    description: "mTLS and identity for inter-agent traffic.",
    url: "https://istio.io/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "CNCF",
    license: "Apache-2.0",
    ecosystem: ["Kubernetes", "Envoy", "Go"],
    longDescription: "Istio is an open-source service mesh that transparently layers onto distributed applications to provide traffic management, telemetry, and strong mutual TLS encryption with cryptographic workload identity.",
    typicalUseCase: "Securing inter-agent network communication and API calls between autonomous worker agents and Model Context Protocol servers in Kubernetes.",
    keyFeatures: [
      "Transparent mutual TLS encryption and identity verification",
      "Granular AuthorizationPolicy enforcement at Layer 7",
      "Distributed tracing and metrics collection via OpenTelemetry",
      "Fault injection and rate limiting capabilities"
    ],
    installationOrQuickstart: "istioctl install --set profile=default -y\nkubectl label namespace default istio-injection=enabled"
  },

  "TruLens": {
    name: "TruLens",
    description: "Observability and evaluation for LLM outputs.",
    url: "https://github.com/truera/trulens",
    cost: "Free",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "TruEra / Snowflake",
    license: "Apache-2.0",
    ecosystem: ["Python", "LangChain", "LlamaIndex", "Snowflake"],
    longDescription: "TruLens is an open-source evaluation and tracking library for LLM and RAG applications, introducing the RAG Triad (Context Relevance, Groundedness, Answer Relevance) and feedback functions to detect hallucinations and bias.",
    typicalUseCase: "Instrumenting enterprise LLM applications to systematically measure the RAG triad and detect drift in response quality and safety over time.",
    keyFeatures: [
      "RAG Triad evaluation functions (Context Relevance, Groundedness, Answer Relevance)",
      "TruLens Dashboard for visual exploration of evaluation logs",
      "Feedback functions supporting HuggingFace, OpenAI, and custom judges",
      "Instrumentation wrappers for LangChain, LlamaIndex, and custom agents"
    ],
    installationOrQuickstart: "pip install trulens-eval\nfrom trulens_eval import Tru\ntru = Tru()\ntru.run_dashboard()"
  },

  "OpenTelemetry": {
    name: "OpenTelemetry",
    description: "Tracing and metrics for tool calls and context changes.",
    url: "https://opentelemetry.io/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "CNCF",
    license: "Apache-2.0",
    ecosystem: ["Python", "TypeScript", "Go", "Java", "Kubernetes"],
    longDescription: "OpenTelemetry is the CNCF standard observability framework providing vendor-neutral APIs, SDKs, and tooling to generate, collect, and export distributed traces, metrics, and logs from LLM applications and agent pipelines.",
    typicalUseCase: "Generating distributed traces for prompt processing, model inference, vector searches, and agent tool executions to analyze latency bottlenecks and security events.",
    keyFeatures: [
      "Standardized OpenInference semantic conventions for LLM operations",
      "Vendor-neutral collectors exporting to Prometheus, Jaeger, Datadog, Grafana",
      "Automatic instrumentation for HTTP requests, gRPC, and database queries",
      "High-performance sampling and batch processing"
    ],
    installationOrQuickstart: "pip install opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation\nopentelemetry-bootstrap -a install"
  },

  "Keycloak": {
    name: "Keycloak",
    description: "Identity and access management with scoped tokens.",
    url: "https://www.keycloak.org/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Red Hat / CNCF",
    license: "Apache-2.0",
    ecosystem: ["Java", "OAuth2", "OIDC", "SAML", "Kubernetes"],
    longDescription: "Keycloak is an open-source identity and access management solution that provides single sign-on (SSO), user federation, identity brokering, and fine-grained authorization using OAuth 2.0 and OpenID Connect standards.",
    typicalUseCase: "Issuing scoped OAuth2 access tokens to authenticated human users and AI agents to enforce least-privilege permissions across Model Context Protocol servers.",
    keyFeatures: [
      "Single-Sign On (SSO) and OpenID Connect (OIDC) authentication",
      "Fine-grained authorization policies and role-based access control (RBAC)",
      "LDAP and Active Directory user federation",
      "Short-lived access token issuance and refresh workflows"
    ],
    installationOrQuickstart: "docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev"
  },

  "LangChain / LangSmith": {
    name: "LangChain / LangSmith",
    description: "Tracing and evaluation for agent workflows.",
    url: "https://www.langchain.com/langsmith",
    cost: "Free+Paid",
    type: "Third-party",
    category: "Both",
    authorOrMaintainer: "LangChain Inc.",
    license: "Commercial / Free Tier",
    ecosystem: ["Python", "TypeScript", "LangChain", "LangGraph"],
    longDescription: "LangSmith is a unified DevOps and observability platform for LLM applications that lets developers debug, test, evaluate, and monitor LLM chains, multi-agent systems, and prompt versions in production.",
    typicalUseCase: "Debugging multi-step agent reasoning failures and tracking malicious prompt injections across complex LangGraph workflows.",
    keyFeatures: [
      "Full execution traces capturing prompts, model outputs, tool inputs and responses",
      "Interactive prompt playground and version control",
      "Dataset curation and automated regression evaluation suites",
      "Real-time monitoring of token consumption, latency, and error rates"
    ],
    installationOrQuickstart: "export LANGCHAIN_TRACING_V2=true\nexport LANGCHAIN_API_KEY='lsv2_...'\n# Run your LangChain / LangGraph application normally"
  },

  "whylogs": {
    name: "whylogs",
    description: "Data logging and quality checks for ML pipelines.",
    url: "https://github.com/whylabs/whylogs",
    cost: "Free+Paid",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "WhyLabs",
    license: "Apache-2.0",
    ecosystem: ["Python", "Java", "PySpark", "Pandas"],
    longDescription: "whylogs is an open-source statistical data logging library that computes lightweight, mergeable statistical profiles of datasets, embeddings, and model inputs/outputs for data monitoring without storing raw data.",
    typicalUseCase: "Profiling prompt and embedding distributions in production RAG systems to detect data drift, distribution shift, and abnormal input patterns.",
    keyFeatures: [
      "Generates lightweight statistical profiles with zero raw data retention",
      "Mergeable profiles allow distributed computation across Spark and Dask",
      "Text and embedding drift detection metrics (KL divergence, PSI)",
      "Integrated data constraint verification and schema checks"
    ],
    installationOrQuickstart: "pip install whylogs\nimport whylogs as why\nprofile = why.log(dataframe).profile()"
  },

  "Evidently": {
    name: "Evidently",
    description: "Monitoring for data and model drift.",
    url: "https://github.com/evidentlyai/evidently",
    cost: "Free+Paid",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Evidently AI",
    license: "Apache-2.0",
    ecosystem: ["Python", "Pandas", "Scikit-learn", "FastAPI"],
    longDescription: "Evidently is an open-source ML and LLM observability framework that evaluates, tests, and monitors data quality, data drift, model performance, target drift, and text quality metrics.",
    typicalUseCase: "Detecting semantic drift and quality degradation in streaming LLM embeddings and customer support chatbot response logs.",
    keyFeatures: [
      "Interactive visual HTML reports and JSON metric exports",
      "Pre-built test suites for data quality, drift, and classification performance",
      "LLM evaluators for toxicity, tone, sentiment, and context relevance",
      "Time-series monitoring dashboards for production pipelines"
    ],
    installationOrQuickstart: "pip install evidently\nfrom evidently.report import Report\nfrom evidently.metric_preset import DataDriftPreset"
  },

  "SHAP": {
    name: "SHAP",
    description: "Explainability tool to diagnose model behavior shifts.",
    url: "https://github.com/shap/shap",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Scott Lundberg / Community",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "TensorFlow", "Scikit-learn", "XGBoost"],
    longDescription: "SHAP (SHapley Additive exPlanations) is a game theoretic approach to explain the output of any machine learning model, connecting optimal credit allocation with local explanations using Shapley values.",
    typicalUseCase: "Diagnosing anomalous model predictions and identifying whether specific adversarial perturbation features triggered classification decisions.",
    keyFeatures: [
      "Exact Shapley value calculations for tree ensembles (TreeSHAP)",
      "Model-agnostic KernelSHAP and DeepSHAP for neural networks",
      "Rich visualization plots (waterfall, summary, force plots)",
      "Identifies key feature attribution and bias drivers"
    ],
    installationOrQuickstart: "pip install shap\nimport shap\nexplainer = shap.Explainer(model)\nshap_values = explainer(X_test)"
  },

  "Captum": {
    name: "Captum",
    description: "PyTorch interpretability for monitoring output shifts.",
    url: "https://github.com/pytorch/captum",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "PyTorch / Meta AI",
    license: "BSD-3-Clause",
    ecosystem: ["Python", "PyTorch"],
    longDescription: "Captum is an open-source, modular model interpretability library for PyTorch, providing state-of-the-art attribution algorithms to understand feature importance and neuron contributions.",
    typicalUseCase: "Analyzing attention weights and token attribution in LLM completions to verify what input tokens caused safety filter triggers.",
    keyFeatures: [
      "Integrated Gradients, Layer Conductance, and DeepLIFT attribution algorithms",
      "Neuron and layer-level interpretability modules",
      "Native support for multimodal (vision, text, tabular) PyTorch models",
      "Captum Insights visual web interface"
    ],
    installationOrQuickstart: "pip install captum\nfrom captum.attr import IntegratedGradients"
  },

  "MLflow": {
    name: "MLflow",
    description: "Tracking, model registry, and governance controls.",
    url: "https://github.com/mlflow/mlflow",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Linux Foundation / Databricks",
    license: "Apache-2.0",
    ecosystem: ["Python", "R", "Java", "Docker", "Kubernetes"],
    longDescription: "MLflow is an open-source platform for managing the end-to-end machine learning lifecycle, providing experiment tracking, reproducible packaging (MLflow Projects), centralized model management (MLflow Model Registry), and LLM deployment gateways.",
    typicalUseCase: "Governing model provenance and maintaining an immutable model registry with signature verification before deployment into production.",
    keyFeatures: [
      "MLflow Model Registry for stage transitions and version approvals",
      "MLflow AI Gateway providing centralized access control and rate limiting",
      "Experiment tracking logging hyperparams, artifacts, and metrics",
      "Standardized deployment packaging for Docker and Kubernetes"
    ],
    installationOrQuickstart: "pip install mlflow\nmlflow server --host 0.0.0.0 --port 5000"
  },

  "gVisor": {
    name: "gVisor",
    description: "Sandbox untrusted tool execution.",
    url: "https://gvisor.dev/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Google",
    license: "Apache-2.0",
    ecosystem: ["Go", "Docker", "Kubernetes", "runsc", "Linux"],
    longDescription: "gVisor is an application kernel written in Go that implements a substantial portion of the Linux system call interface, creating a strong isolation barrier between running containers and the host kernel.",
    typicalUseCase: "Sandboxing untrusted code generation engines and AI agent tool environments to prevent container breakout and host kernel compromise.",
    keyFeatures: [
      "User-space kernel intercepting and handling Linux syscalls (runsc)",
      "Strong isolation barrier mitigating kernel vulnerability exploits",
      "Drop-in OCI runtime compatibility with Docker and Kubernetes",
      "Sub-second container startup overhead"
    ],
    installationOrQuickstart: "apt-get install runsc\ndocker run --runtime=runsc -it python:3.11 /bin/bash"
  },

  "Firecracker": {
    name: "Firecracker",
    description: "MicroVM isolation for safe execution.",
    url: "https://github.com/firecracker-microvm/firecracker",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "AWS Labs",
    license: "Apache-2.0",
    ecosystem: ["Rust", "KVM", "Linux"],
    longDescription: "Firecracker is an open-source virtualization technology built by Amazon Web Services in Rust that enables lightweight, secure micro virtual machines (microVMs) on Linux with hardware-backed KVM isolation.",
    typicalUseCase: "Executing untrusted Python scripts generated by LLM code interpreters in ephemeral, hardware-isolated microVMs with 5ms startup latency.",
    keyFeatures: [
      "Hardware-backed KVM virtualization security with minimal memory footprint (<5MB)",
      "Sub-5ms startup latency enables on-demand per-execution sandboxing",
      "RESTful API for microVM configuration and lifecycle management",
      "Jailer process dropping privileges and applying chroot + seccomp"
    ],
    installationOrQuickstart: "curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v1.7.0/firecracker-v1.7.0-x86_64.tgz | tar -xz\n./firecracker-v1.7.0-x86_64 --api-sock /tmp/firecracker.socket"
  },

  "k6": {
    name: "k6",
    description: "Load testing for LLM endpoints and APIs.",
    url: "https://github.com/grafana/k6",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Grafana Labs",
    license: "AGPL-3.0",
    ecosystem: ["Go", "JavaScript", "CLI", "CI/CD"],
    longDescription: "k6 is a developer-centric, open-source load and performance testing tool written in Go that executes test scenarios scripted in JavaScript, designed for testing API throughput, latency, and resource starvation resilience.",
    typicalUseCase: "Executing concurrent volumetric load tests against LLM inference APIs to test rate limiting, GPU memory exhaustion, and denial-of-wallet protections.",
    keyFeatures: [
      "High-performance concurrency engine capable of thousands of virtual users",
      "Test scripting in standard JavaScript (ES6)",
      "Configurable thresholds asserting 95th/99th percentile latency and error rates",
      "Rich output telemetry streaming directly to Prometheus and Grafana"
    ],
    installationOrQuickstart: "brew install k6\nk6 run load_test_llm.js"
  },

  "TextAttack": {
    name: "TextAttack",
    description: "Adversarial attacks on NLP models.",
    url: "https://github.com/QData/TextAttack",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "University of Virginia / QData Lab",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "Hugging Face", "Transformers"],
    longDescription: "TextAttack is a Python framework for adversarial attacks, data augmentation, and adversarial training in NLP, modularizing attacks into goal functions, constraints, transformations, and search methods.",
    typicalUseCase: "Evaluating BERT and Transformer classification model robustness against character perturbations, synonym replacement, and word deletion attacks.",
    keyFeatures: [
      "Modular components: Goal Functions, Constraints, Transformations, Search Methods",
      "Pre-built recipes for TextFooler, BAE, Genetic Algorithm, and DeepWordBug attacks",
      "Direct integration with HuggingFace datasets and models",
      "Adversarial data augmentation workflows"
    ],
    installationOrQuickstart: "pip install textattack\ntextattack attack --model bert-base-uncased-imdb --recipe textfooler"
  },

  "Foolbox": {
    name: "Foolbox",
    description: "Benchmark adversarial robustness of ML models.",
    url: "https://github.com/bethgelab/foolbox",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Bethge Lab / University of Tübingen",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "TensorFlow", "JAX", "NumPy"],
    longDescription: "Foolbox is a Python library that lets developers easily run adversarial attacks against machine learning models to quantify robustness, supporting PyTorch, TensorFlow, and JAX with native batch execution.",
    typicalUseCase: "Benchmarking the minimum perturbation budget required to evade deep learning classifiers across L0, L2, and Linf norms.",
    keyFeatures: [
      "Native batch execution with high GPU acceleration",
      "Extensive attack catalog: PGD, FGSM, Carlini-Wagner, Boundary Attack",
      "Model-agnostic wrappers for PyTorch, TensorFlow, and JAX",
      "Precise distance metric measurement (L0, L1, L2, Linf)"
    ],
    installationOrQuickstart: "pip install foolbox\nimport foolbox as fb\nfmodel = fb.PyTorchModel(model, bounds=(0, 1))\nattack = fb.attacks.LinfPGD()"
  },

  "Opacus": {
    name: "Opacus",
    description: "PyTorch DP training to reduce privacy leakage.",
    url: "https://github.com/pytorch/opacus",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Meta AI / PyTorch",
    license: "Apache-2.0",
    ecosystem: ["Python", "PyTorch"],
    longDescription: "Opacus is a high-speed library for training PyTorch models with Differential Privacy (DP-SGD), enabling machine learning practitioners to train models while mathematically bounding personal data leakage.",
    typicalUseCase: "Fine-tuning language and embedding models on sensitive corporate documents with mathematically guaranteed differential privacy bounds.",
    keyFeatures: [
      "DP-SGD optimizer with per-sample gradient clipping and noise injection",
      "Rényi Differential Privacy (RDP) privacy budget accounting (epsilon, delta)",
      "High training throughput optimized for modern GPU architectures",
      "Drop-in integration with standard PyTorch training loops"
    ],
    installationOrQuickstart: "pip install opacus\nfrom opacus import PrivacyEngine\nprivacy_engine = PrivacyEngine()"
  },

  "TensorFlow Privacy": {
    name: "TensorFlow Privacy",
    description: "Differential privacy training for ML models.",
    url: "https://github.com/tensorflow/privacy",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Google / TensorFlow",
    license: "Apache-2.0",
    ecosystem: ["Python", "TensorFlow", "Keras"],
    longDescription: "TensorFlow Privacy is a Python library that includes implementations of TensorFlow optimizers for training machine learning models with differential privacy, protecting user privacy during model training.",
    typicalUseCase: "Training predictive models on sensitive healthcare or financial datasets with verifiable differential privacy guarantees.",
    keyFeatures: [
      "DP-SGD and DP-Adam optimizers with privacy accounting",
      "Membership inference attack evaluation module to empirical test leakage",
      "Differential privacy metric visualizers",
      "Compatible with standard TensorFlow Keras models"
    ],
    installationOrQuickstart: "pip install tensorflow-privacy\nfrom tensorflow_privacy.privacy.optimizers.dp_optimizer_keras import DPKerasSGDOptimizer"
  },

  "Bandit": {
    name: "Bandit",
    description: "Python security linter for unsafe execution patterns.",
    url: "https://github.com/PyCQA/bandit",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "PyCQA",
    license: "Apache-2.0",
    ecosystem: ["Python", "AST", "CI/CD", "Pre-commit"],
    longDescription: "Bandit is a security-focused static analyzer designed to find common security issues in Python code by parsing the AST and running plugins against AST nodes.",
    typicalUseCase: "Scanning AI application codebases in CI/CD to detect hardcoded credentials, unsafe `pickle` loading, shell injection, and insecure tempfile creation.",
    keyFeatures: [
      "AST-based vulnerability scanning for Python scripts and packages",
      "Detects unsafe imports (`pickle`, `subprocess`, `eval`, `exec`)",
      "Configurable severity and confidence thresholds",
      "Outputs in JSON, CSV, XML, and HTML report formats"
    ],
    installationOrQuickstart: "pip install bandit\nbandit -r ./ai_pipeline/ -ll"
  },

  "ShellCheck": {
    name: "ShellCheck",
    description: "Detect unsafe shell scripting patterns.",
    url: "https://github.com/koalaman/shellcheck",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Vidar Holen / Koalaman",
    license: "GPL-3.0",
    ecosystem: ["Haskell", "Bash", "Sh", "CI/CD"],
    longDescription: "ShellCheck is a static analysis tool for shell scripts (Bash, sh, ksh) that automatically detects syntax issues, semantic bugs, and dangerous shell execution patterns.",
    typicalUseCase: "Auditing deployment scripts and model compilation bash jobs in MLOps pipelines to eliminate command injection and privilege escalation bugs.",
    keyFeatures: [
      "Pinpoints quoting mistakes and word splitting vulnerabilities",
      "Identifies unsafe command substitutions and variable expansions",
      "Offers specific, automated remediation guidance",
      "Native integrations with editors, Git hooks, and GitHub Actions"
    ],
    installationOrQuickstart: "brew install shellcheck\nshellcheck ./scripts/deploy_model.sh"
  },

  "Cloud Custodian": {
    name: "Cloud Custodian",
    description: "Policy-as-code to discover unauthorized resources.",
    url: "https://github.com/cloud-custodian/cloud-custodian",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Cloud Custodian Project / CNCF",
    license: "Apache-2.0",
    ecosystem: ["Python", "AWS", "Azure", "GCP", "YAML"],
    longDescription: "Cloud Custodian is a rules engine for managing public cloud environments using declarative YAML policies for security, compliance, asset discovery, and cost management.",
    typicalUseCase: "Scanning AWS/GCP accounts to discover unencrypted S3 vector database dumps, exposed SageMaker notebook instances, and unauthorized GPU instances.",
    keyFeatures: [
      "Declarative YAML policies for multi-cloud governance (AWS, GCP, Azure)",
      "Real-time event-driven enforcement via cloud audit logs",
      "Automated remediation actions (stop instance, enable encryption, tag)",
      "Comprehensive cloud inventory and compliance reporting"
    ],
    installationOrQuickstart: "pip install c7n\ncustodian run --output-dir=. policies.yml"
  },

  "Wiz": {
    name: "Wiz",
    description: "Cloud security platform for asset discovery.",
    url: "https://www.wiz.io/",
    cost: "€€€",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Wiz Inc.",
    license: "Commercial / Enterprise",
    ecosystem: ["AWS", "Azure", "GCP", "Kubernetes", "SaaS"],
    longDescription: "Wiz is a cloud-native application protection platform (CNAPP) that uses an agentless graph analysis engine to correlate cloud vulnerabilities, misconfigurations, identity risks, and secrets.",
    typicalUseCase: "Continuously mapping the cloud architecture of AI platforms to discover toxic risk combinations linking public endpoints to exposed model weights and sensitive training databases.",
    keyFeatures: [
      "Agentless multi-cloud asset discovery and deep vulnerability scanning",
      "Security Graph correlating network exposure, permissions, and CVEs",
      "AI-SPM capabilities tailored for SageMaker, Vertex AI, and Bedrock",
      "Automated compliance auditing against CIS, SOC2, and ISO standards"
    ],
    installationOrQuickstart: "Connect cloud account via Wiz console for 100% agentless scanning"
  },

  "Nmap": {
    name: "Nmap",
    description: "Network discovery to detect rogue MCP services.",
    url: "https://nmap.org/",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Gordon Lyon / Insecure.Org",
    license: "Nmap Public Source License (NPSL)",
    ecosystem: ["C/C++", "Lua", "Cross-platform"],
    longDescription: "Nmap (Network Mapper) is the quintessential open-source tool for network discovery, port scanning, service version detection, and vulnerability scanning using the Nmap Scripting Engine (NSE).",
    typicalUseCase: "Scanning local subnetworks and developer workstations to identify unauthorized Model Context Protocol servers or unsecured local LLM inference engines (Ollama, LM Studio).",
    keyFeatures: [
      "Ultra-fast TCP/UDP port scanning and OS fingerprinting",
      "Service and application version detection across network ports",
      "Nmap Scripting Engine (NSE) for custom vulnerability detection scripts",
      "Raw packet analysis supporting multiple network topologies"
    ],
    installationOrQuickstart: "nmap -sV -p 11434,8000,8080,50051 192.168.1.0/24"
  },

  "SOPS": {
    name: "SOPS",
    description: "Encrypt secrets in configuration files.",
    url: "https://github.com/getsops/sops",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Getsops / Mozilla",
    license: "MPL-2.0",
    ecosystem: ["Go", "AWS KMS", "GCP KMS", "Azure Key Vault", "age", "PGP"],
    longDescription: "SOPS (Secrets OPerationS) is an editor of encrypted files that supports YAML, JSON, ENV, INI and BINARY formats and encrypts with AWS KMS, GCP KMS, Azure Key Vault, age, and PGP.",
    typicalUseCase: "Encrypting sensitive API keys and database credentials inside version-controlled configuration files for AI deployments without exposing raw secret values in Git.",
    keyFeatures: [
      "Encrypts values while keeping structure keys unencrypted for clean diffs",
      "Multi-key encryption and key rotation capabilities",
      "Native integrations with age, PGP, AWS KMS, GCP KMS, and Azure Key Vault",
      "Direct integration with GitOps workflows like Flux and ArgoCD"
    ],
    installationOrQuickstart: "sops -e -i --kms 'arn:aws:kms:...' config/ai-secrets.yaml"
  },

  "Prometheus": {
    name: "Prometheus",
    description: "Metrics collection and alerting for system health.",
    url: "https://prometheus.io/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "CNCF",
    license: "Apache-2.0",
    ecosystem: ["Go", "Kubernetes", "Linux", "Docker"],
    longDescription: "Prometheus is a leading open-source monitoring and alerting toolkit that collects and stores metrics as time-series data, providing a powerful PromQL query language for alerting.",
    typicalUseCase: "Scraping inference latency, GPU memory utilization, error rates, and token consumption metrics from vLLM and Triton Inference Server clusters.",
    keyFeatures: [
      "Multi-dimensional time-series data model with metric names and key/value labels",
      "PromQL flexible query language for computing rates and aggregations",
      "Service discovery integration with Kubernetes and cloud providers",
      "Integrated Alertmanager for real-time incident notifications"
    ],
    installationOrQuickstart: "prometheus --config.file=prometheus.yml"
  },

  "Grafana": {
    name: "Grafana",
    description: "Dashboards and alerting for observability data.",
    url: "https://grafana.com/",
    cost: "Free+Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Grafana Labs",
    license: "AGPL-3.0 / Commercial",
    ecosystem: ["Go", "TypeScript", "Prometheus", "Loki", "OpenTelemetry"],
    longDescription: "Grafana is the leading open-source analytics and interactive visualization web application, enabling users to query, visualize, alert on, and explore operational metrics and logs regardless of where they are stored.",
    typicalUseCase: "Building real-time executive and red-team dashboards displaying LLM token throughput, guardrail block rates, and inference latency across production clusters.",
    keyFeatures: [
      "Dynamic dashboards with hundreds of visualization panel types",
      "Unified alerting across multiple datasources (Prometheus, Loki, Elastic)",
      "Role-based access control and dashboard sharing",
      "Rich plugin ecosystem with support for 100+ telemetry data sources"
    ],
    installationOrQuickstart: "docker run -d -p 3000:3000 grafana/grafana-oss"
  },

  "Grafana Loki": {
    name: "Grafana Loki",
    description: "Log aggregation for high-volume telemetry.",
    url: "https://grafana.com/oss/loki/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Grafana Labs",
    license: "AGPL-3.0",
    ecosystem: ["Go", "Grafana", "Promtail", "Kubernetes"],
    longDescription: "Loki is a horizontally-scalable, highly-available, multi-tenant log aggregation system inspired by Prometheus, indexing only log stream labels rather than full text to maximize efficiency.",
    typicalUseCase: "Aggregating high-volume audit logs and tool execution events from AI agents across distributed clusters with minimal storage costs.",
    keyFeatures: [
      "Indexes only metadata labels, drastically reducing storage costs",
      "LogQL query language closely mirroring PromQL",
      "Seamless integration with Grafana for unified trace-to-log pivoting",
      "Scalable multi-tenant architecture designed for object storage (S3)"
    ],
    installationOrQuickstart: "docker run -d -p 3100:3100 grafana/loki:latest"
  },

  "Elastic Stack": {
    name: "Elastic Stack",
    description: "Centralized logging, search, and SIEM analytics.",
    url: "https://www.elastic.co/elastic-stack",
    cost: "Free+Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Elastic",
    license: "ELv2 / SSPL / Commercial",
    ecosystem: ["Java", "Kibana", "Logstash", "Elasticsearch", "Beats"],
    longDescription: "The Elastic Stack (Elasticsearch, Kibana, Beats, Logstash) securely ingests, searches, analyzes, and visualizes log and telemetry data in real time, serving as an enterprise SIEM and security analytics engine.",
    typicalUseCase: "Centralized SIEM monitoring of user prompt streams, model inferences, and API gateway access logs to detect coordinated prompt injection attacks.",
    keyFeatures: [
      "Distributed full-text search and real-time analytical engine",
      "Elastic Security SIEM with pre-built threat detection rules",
      "Kibana visual analytics and threat hunting dashboards",
      "Machine learning anomaly detection on streaming log data"
    ],
    installationOrQuickstart: "docker run -p 9200:9200 -p 9300:9300 -e 'discovery.type=single-node' docker.elastic.co/elasticsearch/elasticsearch:8.13.0"
  },

  "Datadog": {
    name: "Datadog",
    description: "Managed observability with alerting.",
    url: "https://www.datadoghq.com/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Datadog Inc.",
    license: "Commercial / SaaS",
    ecosystem: ["SaaS", "Agent", "Kubernetes", "AWS", "Azure", "GCP"],
    longDescription: "Datadog is a comprehensive observability and security platform for cloud applications, providing LLM Observability to track prompt traces, model token consumption, latency, and hallucination rates.",
    typicalUseCase: "End-to-end monitoring of production enterprise LLM applications, tracking user sessions, model cost breakdowns, and security anomalies.",
    keyFeatures: [
      "LLM Observability module specifically tracking prompt chains and model tokens",
      "Automated anomaly detection and root-cause analysis",
      "Cloud Security Management detecting misconfigured infrastructure",
      "Real-time alerting through Slack, PagerDuty, and webhooks"
    ],
    installationOrQuickstart: "pip install ddtrace\nddtrace-run python my_llm_app.py"
  },

  "Splunk": {
    name: "Splunk",
    description: "SIEM for audit trails and detection.",
    url: "https://www.splunk.com/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Cisco / Splunk Inc.",
    license: "Commercial / Enterprise",
    ecosystem: ["Enterprise", "SIEM", "SPL", "REST API"],
    longDescription: "Splunk is an enterprise-grade SIEM and log analysis platform that ingests, searches, and analyzes machine-generated data across complex distributed infrastructures to provide actionable security intelligence.",
    typicalUseCase: "Ingesting audit trails from Model Context Protocol servers and LLM gateways to perform correlation analysis and generate SOC incident alerts.",
    keyFeatures: [
      "Search Processing Language (SPL) for sophisticated security threat hunting",
      "Splunk Enterprise Security (ES) SIEM with correlation search rules",
      "Real-time alerting, dashboards, and automated incident response integration",
      "High-throughput indexing engine supporting petabyte-scale data"
    ],
    installationOrQuickstart: "Configure Splunk Universal Forwarder to ingest /var/log/ai-gateway/*.log"
  },

  "Kong Gateway": {
    name: "Kong Gateway",
    description: "API gateway for rate limiting and quotas.",
    url: "https://konghq.com/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Kong Inc.",
    license: "Apache-2.0 / Enterprise",
    ecosystem: ["Lua", "Nginx", "OpenResty", "Kubernetes", "Docker"],
    longDescription: "Kong Gateway is a cloud-native, high-performance API gateway built on OpenResty/Nginx that provides authentication, rate limiting, IP restriction, and traffic shaping for modern microservices and AI APIs.",
    typicalUseCase: "Enforcing per-user rate limits, API key authentication, and traffic throttling in front of costly LLM inference clusters to stop Denial-of-Wallet attacks.",
    keyFeatures: [
      "AI Gateway plugin suite for multi-LLM routing, failover, and prompt caching",
      "Granular rate limiting and quota management plugins",
      "OAuth 2.0, JWT, and Key Authentication enforcement",
      "Sub-millisecond routing latency with high concurrency"
    ],
    installationOrQuickstart: "docker run -d --name kong -e 'KONG_DATABASE=off' -p 8000:8000 -p 8443:8443 kong:latest"
  },

  "Cloudflare Rate Limiting": {
    name: "Cloudflare Rate Limiting",
    description: "Edge rate limiting to stop volumetric abuse.",
    url: "https://www.cloudflare.com/products/rate-limiting/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Cloudflare",
    license: "Commercial / Cloudflare Edge",
    ecosystem: ["Cloudflare Edge", "WAF", "DDoS"],
    longDescription: "Cloudflare Rate Limiting protects applications against denial-of-service attacks, brute-force login attempts, and API abuse by inspecting incoming traffic at global edge locations and enforcing request limits.",
    typicalUseCase: "Shielding public LLM endpoints at the network edge from volumetric scraping, automated extraction attacks, and API resource exhaustion.",
    keyFeatures: [
      "Global edge enforcement stopping volumetric attacks before reaching origin",
      "Customizable rate rules based on IP, API headers, cookies, or JWT claims",
      "Integrated with Cloudflare WAF and bot management intelligence",
      "Dynamic response actions (Block, Challenge, Log)"
    ],
    installationOrQuickstart: "Configure Rate Limiting Rules via Cloudflare Dashboard -> Security -> WAF -> Rate limiting"
  },

  "AWS WAF": {
    name: "AWS WAF",
    description: "Managed web application firewall with rate-based rules.",
    url: "https://aws.amazon.com/waf/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Amazon Web Services",
    license: "Commercial / AWS Cloud",
    ecosystem: ["AWS CloudFront", "ALB", "API Gateway", "AppSync"],
    longDescription: "AWS WAF is a web application firewall that helps protect web applications and APIs against common web exploits and bots that may affect availability, compromise security, or consume excessive resources.",
    typicalUseCase: "Deploying rate-based rules and managed IP reputation lists in front of Amazon API Gateway and CloudFront distributions serving LLM applications.",
    keyFeatures: [
      "Rate-based rules calculating requests per 5-minute rolling window per IP",
      "AWS Managed Rules for common vulnerabilities (SQLi, XSS, Bot Control)",
      "Custom regex and string matching on request headers, body, and query parameters",
      "Real-time CloudWatch metrics and Athena log analysis"
    ],
    installationOrQuickstart: "aws wafv2 create-web-acl --name ai-gateway-waf --scope REGIONAL --default-action Allow={}"
  },

  "Google Cloud Armor": {
    name: "Google Cloud Armor",
    description: "Managed DDoS and rate limiting for cloud services.",
    url: "https://cloud.google.com/armor",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Google Cloud",
    license: "Commercial / GCP",
    ecosystem: ["Google Cloud Load Balancing", "GKE", "Compute Engine"],
    longDescription: "Google Cloud Armor delivers enterprise DDoS defense and Web Application Firewall (WAF) services at Google scale to protect applications and APIs against volumetric attacks and application-layer exploits.",
    typicalUseCase: "Protecting public Vertex AI endpoints and Google Kubernetes Engine (GKE) inference clusters against distributed Layer 7 denial of service.",
    keyFeatures: [
      "Global terabit-scale L3/L4/L7 DDoS mitigation",
      "Adaptive Protection utilizing ML to detect abnormal traffic patterns",
      "Pre-configured WAF rules based on OWASP Top 10",
      "Granular rate limiting and IP geo-fencing"
    ],
    installationOrQuickstart: "gcloud compute security-policies create ai-waf-policy --description 'AI protection'"
  },

  "C2PA": {
    name: "C2PA",
    description: "Content provenance standard and ecosystem for authenticity.",
    url: "https://c2pa.org/",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Coalition for Content Provenance and Authenticity",
    license: "Open Standard / C2PA Specifications",
    ecosystem: ["Rust", "JavaScript", "C++", "Image/Audio/Video Formats"],
    longDescription: "The C2PA (Coalition for Content Provenance and Authenticity) standard defines an open technical specification for embedding verifiable cryptographic provenance manifests into media files (images, audio, video, text).",
    typicalUseCase: "Cryptographically signing and watermarking AI-generated imagery and synthesized voice recordings at generation time to provide tamper-evident origin provenance.",
    keyFeatures: [
      "Cryptographic provenance manifest embedding directly into media containers",
      "Tamper-evident chain of editing history and generative tool attribution",
      "Open-source reference SDKs (c2pa-rs, c2patool)",
      "Supported across major cameras, editing tools, and social platforms"
    ],
    installationOrQuickstart: "cargo install c2patool\nc2patool image.jpg --manifest manifest.json"
  },

  "Content Credentials": {
    name: "Content Credentials",
    description: "Provenance signals for authenticated media.",
    url: "https://contentcredentials.org/",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Adobe / Content Authenticity Initiative (CAI)",
    license: "MIT / Open Source",
    ecosystem: ["JavaScript", "Rust", "Web Components", "Cloudflare"],
    longDescription: "Content Credentials is a technology developed by the Content Authenticity Initiative (CAI) built on the C2PA standard, providing UI badges and inspection tools for digital content provenance.",
    typicalUseCase: "Rendering interactive 'CR' attribution badges in web applications that allow users to inspect the verifiable creator, AI tool, and history of generated media.",
    keyFeatures: [
      "Drop-in web components for interactive manifest inspection",
      "Verification service for validating cryptographic signature chains",
      "Cloudflare worker integrations for on-the-fly provenance signing",
      "Preserves provenance metadata across publishing platforms"
    ],
    installationOrQuickstart: "npm install @contentauth/sdk\n# Embed Content Credentials verification badge into web UI"
  },

  "Google Cloud DLP": {
    name: "Google Cloud DLP",
    description: "Detect and redact sensitive data across text and storage.",
    url: "https://cloud.google.com/security/products/dlp",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Google Cloud",
    license: "Commercial / GCP",
    ecosystem: ["GCP", "BigQuery", "Cloud Storage", "REST API"],
    longDescription: "Cloud Data Loss Prevention (Sensitive Data Protection) provides automated discovery, classification, and de-identification of sensitive data elements across unstructured text, images, and relational databases.",
    typicalUseCase: "Scanning petabyte-scale training datasets in Google Cloud Storage to identify and redact sensitive personal data before training foundational models.",
    keyFeatures: [
      "150+ built-in infoType detectors for PII, financial, and healthcare data",
      "Transformations: masking, cryptographic tokenization, bucketization, and redaction",
      "Automated profiling of BigQuery tables and Cloud Storage buckets",
      "Low-latency REST API for real-time text inspection"
    ],
    installationOrQuickstart: "gcloud dlp text inspect --content 'My email is user@example.com' --info-types EMAIL_ADDRESS"
  },

  "AWS Secrets Manager": {
    name: "AWS Secrets Manager",
    description: "Managed secrets storage with rotation.",
    url: "https://aws.amazon.com/secrets-manager/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Amazon Web Services",
    license: "Commercial / AWS Cloud",
    ecosystem: ["AWS Cloud", "Lambda", "IAM", "ECS", "EKS"],
    longDescription: "AWS Secrets Manager helps manage, rotate, and retrieve database credentials, API keys, and other secrets throughout their lifecycle, securing credentials with fine-grained IAM policies.",
    typicalUseCase: "Securely storing and automatically rotating API keys used by AI agent microservices and background RAG indexing jobs.",
    keyFeatures: [
      "Automated secret rotation using pre-built AWS Lambda functions",
      "Integration with AWS KMS for envelope encryption",
      "Granular IAM resource policies controlling secret access",
      "Native SDK caching libraries for high performance"
    ],
    installationOrQuickstart: "aws secretsmanager get-secret-value --secret-id ai/prod/openai_api_key"
  },

  "Azure Key Vault": {
    name: "Azure Key Vault",
    description: "Managed keys and secrets with access policies.",
    url: "https://azure.microsoft.com/en-us/products/key-vault/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Microsoft Azure",
    license: "Commercial / Azure",
    ecosystem: ["Azure Cloud", "Entra ID", "AKS", "Managed Identity"],
    longDescription: "Azure Key Vault is a cloud service for securely storing and accessing secrets, encryption keys, and certificates, backed by Hardware Security Modules (HSMs).",
    typicalUseCase: "Managing encryption keys and secrets for Azure OpenAI deployments using Azure Managed Identities to eliminate hardcoded credentials.",
    keyFeatures: [
      "Hardware Security Module (HSM) FIPS 140-2 validated key protection",
      "Fine-grained RBAC access policies linked to Microsoft Entra ID",
      "Automated certificate lifecycle and renewal management",
      "Comprehensive diagnostic logging to Azure Monitor"
    ],
    installationOrQuickstart: "az keyvault secret show --name 'OpenAiApiKey' --vault-name 'MyAiKeyVault'"
  },

  "Google Secret Manager": {
    name: "Google Secret Manager",
    description: "Managed secret storage with IAM policies.",
    url: "https://cloud.google.com/secret-manager",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Google Cloud",
    license: "Commercial / GCP",
    ecosystem: ["GCP", "IAM", "Cloud Run", "GKE"],
    longDescription: "Secret Manager is a secure and convenient storage system for API keys, passwords, certificates, and other sensitive data, providing a unified source of truth with strong IAM governance.",
    typicalUseCase: "Injecting API keys and Model Context Protocol authorization tokens directly into containerized AI services running on Cloud Run or GKE.",
    keyFeatures: [
      "Global replication across Google Cloud regions",
      "Versioned secrets with immutable historical payloads",
      "Granular Cloud IAM role assignment per secret version",
      "Audit logging via Cloud Audit Logs for compliance"
    ],
    installationOrQuickstart: "gcloud secrets versions access latest --secret='openai-api-key'"
  },

  "OpenSSF Scorecard": {
    name: "OpenSSF Scorecard",
    description: "Assess security posture of open-source dependencies.",
    url: "https://github.com/ossf/scorecard",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Open Source Security Foundation (OpenSSF)",
    license: "Apache-2.0",
    ecosystem: ["Go", "GitHub Actions", "CLI"],
    longDescription: "Scorecard is an automated security assessment tool created by the OpenSSF that analyzes open-source projects for risky practices, branch protection, code review, pinned dependencies, and binary artifacts.",
    typicalUseCase: "Evaluating the supply chain security posture and trustworthiness of third-party open-source AI libraries and Model Context Protocol packages before adoption.",
    keyFeatures: [
      "Evaluates 18+ supply chain security checks (Maintained, Vulnerabilities, Signed-Releases, Dependency-Update-Tool)",
      "Scores projects from 0 to 10 with actionable remediation recommendations",
      "Public Scorecards API for querying thousands of open-source packages",
      "Native GitHub Action integration for continuous repository scoring"
    ],
    installationOrQuickstart: "scorecard --repo=github.com/langchain-ai/langchain"
  },

  "in-toto": {
    name: "in-toto",
    description: "Attestation for tool build provenance.",
    url: "https://github.com/in-toto/in-toto",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "CNCF",
    license: "Apache-2.0",
    ecosystem: ["Python", "Go", "Sigstore", "Supply Chain"],
    longDescription: "in-toto is a framework to secure the integrity of software supply chains by capturing cryptographic attestations of every step performed from source code checkout to binary deployment.",
    typicalUseCase: "Generating tamper-evident cryptographic metadata that proves an AI model weight checkpoint was compiled strictly from verified, clean training scripts in an authorized CI/CD pipeline.",
    keyFeatures: [
      "Step-by-step cryptographic link attestations signed by build agents",
      "Enforces layout policy verifying that all defined build steps were executed",
      "Integrates with Sigstore and Cosign for keyless attestation signing",
      "Standardized in-toto attestation format supported by SLSA"
    ],
    installationOrQuickstart: "in-toto-run --step-name build --key signer.key --products model.bin -- python train.py"
  },

  "SLSA": {
    name: "SLSA",
    description: "Supply-chain security framework and build requirements.",
    url: "https://slsa.dev/",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "OpenSSF / SLSA Community",
    license: "Open Standard",
    ecosystem: ["CI/CD", "GitHub Actions", "Google Cloud Build"],
    longDescription: "SLSA (Supply-chain Levels for Software Artifacts) is a security framework, a check-list of standards and controls to prevent tampering, improve integrity, and secure packages in your projects.",
    typicalUseCase: "Implementing SLSA Level 3 build standards on AI training pipelines to guarantee non-falsifiable build provenance and prevent insider tampering.",
    keyFeatures: [
      "Incremental security levels (Build L1 through L3)",
      "Guarantees provenance generation by isolated, tamper-proof build platforms",
      "Prevents unauthorized modifications to source code and dependencies",
      "Standard verification tools (slsa-verifier)"
    ],
    installationOrQuickstart: "slsa-verifier verify-artifact ./model.tar.gz --provenance-path ./provenance.intoto.jsonl --source-uri github.com/my-org/ai-model"
  },

  "OWASP CycloneDX": {
    name: "OWASP CycloneDX",
    description: "SBOM standard and tooling ecosystem.",
    url: "https://cyclonedx.org/",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "OWASP Foundation",
    license: "Apache-2.0",
    ecosystem: ["JSON", "XML", "Protobuf", "Cross-language"],
    longDescription: "OWASP CycloneDX is a full-stack Software Bill of Materials (SBOM), Software-as-a-Service Bill of Materials (SaaSBOM), and Hardware/AI Bill of Materials (AIBOM) standard designed for application security and supply chain analysis.",
    typicalUseCase: "Generating standardized AI Bills of Materials (AIBOM) that detail the exact dataset lineage, model hyperparameters, base models, and dependencies used in a generative AI system.",
    keyFeatures: [
      "Native specifications for ML/AI models, training datasets, and hyperparameters",
      "Rich vulnerability, license, and cryptographic asset tracking",
      "Broad ecosystem of generators for pip, npm, Go, Docker, and Maven",
      "Lightweight, machine-readable JSON and XML schema formats"
    ],
    installationOrQuickstart: "cyclonedx-py requirements requirements.txt --output-file bom.json"
  },

  "OWASP Dependency-Track": {
    name: "OWASP Dependency-Track",
    description: "SBOM analysis and supply chain risk monitoring.",
    url: "https://github.com/DependencyTrack/dependency-track",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "OWASP Foundation / Steve Springett",
    license: "Apache-2.0",
    ecosystem: ["Java", "Docker", "REST API", "CycloneDX"],
    longDescription: "OWASP Dependency-Track is an intelligent Component Analysis platform that allows organizations to identify and reduce risk from the use of third-party and open-source components by continuously monitoring SBOMs.",
    typicalUseCase: "Ingesting CycloneDX AIBOM files generated by CI/CD and continuously alerting whenever new CVEs are published against deployed AI libraries.",
    keyFeatures: [
      "Continuous real-time vulnerability monitoring against NVD, GitHub Advisories, and OSV",
      "Tracks Component, Service, and AI Model Bills of Materials",
      "Policy violation engine enforcing license compliance and vulnerability SLAs",
      "Rich REST API and webhook notifications to Slack and SIEM platforms"
    ],
    installationOrQuickstart: "docker-compose -f docker-compose.yml up -d\n# Upload CycloneDX bom.json via API or Web UI"
  },

  "Great Expectations": {
    name: "Great Expectations",
    description: "Data quality testing to detect anomalous or poisoned data.",
    url: "https://github.com/great-expectations/great_expectations",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Great Expectations",
    license: "Apache-2.0",
    ecosystem: ["Python", "SQLAlchemy", "Pandas", "PySpark"],
    longDescription: "Great Expectations is a leading open-source tool for validating, documenting, and profiling data pipelines, enforcing declarative expectations (assertions) on datasets to eliminate silent data corruption.",
    typicalUseCase: "Validating data integrity and distribution constraints on incoming data batches before ingestion into fine-tuning or vector databases.",
    keyFeatures: [
      "Declarative expectation assertions (e.g. `expect_column_values_to_be_between`)",
      "Automated data documentation generation (Data Docs)",
      "Native integrations with Snowflake, BigQuery, S3, Spark, and Pandas",
      "Automated profiling to infer baseline expectations from golden datasets"
    ],
    installationOrQuickstart: "pip install great_expectations\ngreat_expectations init"
  },

  "DVC": {
    name: "DVC",
    description: "Data versioning to audit dataset changes over time.",
    url: "https://dvc.org/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Iterative.ai",
    license: "Apache-2.0",
    ecosystem: ["Python", "Git", "S3", "GCS", "Azure Blob"],
    longDescription: "DVC (Data Version Control) is an open-source version control system for machine learning projects that tracks large data files, models, and pipelines alongside Git repositories without bloating Git history.",
    typicalUseCase: "Tracking exact cryptographic hashes of training datasets and vector store snapshots to maintain auditable data lineage and detect unauthorized tampering.",
    keyFeatures: [
      "Git-compatible version control for multi-gigabyte data files and weights",
      "Storage agnostic (supports AWS S3, Google Cloud Storage, Azure Blob, SSH)",
      "Reproducible data processing pipelines with dependency tracking",
      "Data metric and plot diffing across Git commits and branches"
    ],
    installationOrQuickstart: "pip install dvc\ndvc init\ndvc add data/training_dataset.json\ngit add data/training_dataset.json.dvc"
  },

  "OpenAPI Spectral": {
    name: "OpenAPI Spectral",
    description: "Lint API contracts to prevent unsafe response handling.",
    url: "https://github.com/stoplightio/spectral",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Stoplight",
    license: "Apache-2.0",
    ecosystem: ["Node.js", "TypeScript", "JSON Schema", "OpenAPI", "CLI"],
    longDescription: "Spectral is a flexible, JSON/YAML linter for OpenAPI, AsyncAPI, and JSON Schema definitions that helps teams enforce strict schema validation, parameter constraints, and security best practices on API contracts.",
    typicalUseCase: "Validating Model Context Protocol and agent tool schemas to ensure strict parameter types and descriptions are properly defined without permissive catch-all objects.",
    keyFeatures: [
      "Validates OpenAPI v2/v3 and AsyncAPI specifications against security rules",
      "Custom JSONPath-based rule authoring for bespoke security policies",
      "CLI, JavaScript API, and GitHub Action integrations",
      "Automated linting prevents schema bypass vulnerabilities"
    ],
    installationOrQuickstart: "npm install -g @stoplight/spectral-cli\nspectral lint openapi-tool-spec.yaml"
  },

  "AutoAttack": {
    name: "AutoAttack",
    description: "Standardized adversarial attack suite for robustness testing.",
    url: "https://github.com/fra31/auto-attack",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Francesco Croce & Matthias Hein (Univ. of Tübingen)",
    license: "MIT",
    ecosystem: ["Python", "PyTorch"],
    longDescription: "AutoAttack is an ensemble of diverse, parameter-free adversarial attacks (APGD-CE, APGD-DLR, FAB, Square Attack) widely regarded as the gold standard benchmark for evaluating neural network adversarial robustness.",
    typicalUseCase: "Benchmarking the adversarial robustness of computer vision and embedding models against gradient-based and black-box evasion attacks.",
    keyFeatures: [
      "Ensemble combining step-size adaptive gradient attacks and black-box search",
      "Reliably defeats gradient masking and false robustness defenses",
      "Standard evaluation engine powering the RobustBench leaderboard",
      "Simple two-line PyTorch evaluation interface"
    ],
    installationOrQuickstart: "pip install git+https://github.com/fra31/auto-attack\nfrom autoattack import AutoAttack\nadversary = AutoAttack(model, norm='Linf', eps=8/255)"
  },

  "Microsoft Counterfit": {
    name: "Microsoft Counterfit",
    description: "Adversarial AI risk testing tool for ML systems.",
    url: "https://github.com/Azure/counterfit",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Microsoft",
    license: "MIT",
    ecosystem: ["Python", "CLI", "Azure", "PyTorch"],
    longDescription: "Counterfit is an open-source command-line tool designed by Microsoft to help security engineers automate adversarial testing and vulnerability assessments of AI and machine learning systems.",
    typicalUseCase: "Interactive penetration testing of deployed enterprise classification and embedding endpoints using a Metasploit-like terminal interface.",
    keyFeatures: [
      "Interactive terminal interface with Metasploit-style workflow (use attack, set target, run)",
      "Wraps adversarial attack frameworks including ART, TextAttack, and custom algorithms",
      "Supports black-box endpoints, REST APIs, and local PyTorch/TensorFlow models",
      "Automated logging and telemetry export for security audits"
    ],
    installationOrQuickstart: "pip install counterfit\ncounterfit\n> set_target my_endpoint\n> list attacks\n> run"
  },

  "CleverHans": {
    name: "CleverHans",
    description: "Adversarial example library for ML testing.",
    url: "https://github.com/cleverhans-lab/cleverhans",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Ian Goodfellow & Nicolas Papernot / CleverHans Lab",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "TensorFlow", "JAX"],
    longDescription: "CleverHans is one of the pioneering open-source Python libraries for benchmarking machine learning vulnerability to adversarial examples, created by foundational AI security researchers.",
    typicalUseCase: "Academic research and adversarial perturbation testing of deep learning models using gradient-based attack primitives.",
    keyFeatures: [
      "Reference implementations of FGSM, Projected Gradient Descent, and SPSA",
      "Native support for PyTorch, TensorFlow 2, and JAX computational graphs",
      "Adversarial training utilities for hardening model weights",
      "Clean, educational codebase ideal for security research"
    ],
    installationOrQuickstart: "pip install cleverhans\nfrom cleverhans.torch.attacks.fast_gradient_method import fast_gradient_method"
  },

  "Alibi Detect": {
    name: "Alibi Detect",
    description: "Outlier and drift detection for online feedback.",
    url: "https://github.com/SeldonIO/alibi-detect",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Seldon Technologies",
    license: "Apache-2.0",
    ecosystem: ["Python", "PyTorch", "TensorFlow", "Scikit-learn"],
    longDescription: "Alibi Detect is an open-source Python library focused on outlier, adversarial, and drift detection for tabular, image, text, and time-series data.",
    typicalUseCase: "Monitoring streaming embeddings and input tokens in production to flag adversarial evasion attempts and concept drift in real time.",
    keyFeatures: [
      "Adversarial detector algorithms based on autoencoders and Maximum Mean Discrepancy",
      "Statistical drift detection tests (Kolmogorov-Smirnov, Cramér-von Mises, MMD, Chi-Square)",
      "Online and offline drift detection modules for streaming inference",
      "Integration with Seldon Core and KFServing for Kubernetes deployment"
    ],
    installationOrQuickstart: "pip install alibi-detect\nfrom alibi_detect.cd import KSDrift\ncd = KSDrift(x_ref)"
  },

  "DeepChecks": {
    name: "DeepChecks",
    description: "ML validation and drift detection checks.",
    url: "https://github.com/deepchecks/deepchecks",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Deepchecks",
    license: "AGPL-3.0",
    ecosystem: ["Python", "Pandas", "Scikit-learn", "PyTorch", "NLP"],
    longDescription: "Deepchecks is an open-source Python package for comprehensively validating machine learning models and datasets throughout the research, training, and production phases.",
    typicalUseCase: "Running automated data integrity and train-test leakage checks before training embedding models and classifiers.",
    keyFeatures: [
      "40+ pre-built checks for data integrity, train-test leakage, and distribution drift",
      "NLP suite validating text properties, token lengths, and language distribution",
      "Comprehensive interactive HTML report generation",
      "Integration with CI/CD pipelines via PyTest assertion rules"
    ],
    installationOrQuickstart: "pip install deepchecks\nfrom deepchecks.nlp.suites import data_integrity\nsuite = data_integrity()\nsuite.run(train_dataset=dataset)"
  },

  "LM Evaluation Harness": {
    name: "LM Evaluation Harness",
    description: "Benchmarking suite for LLM accuracy and robustness.",
    url: "https://github.com/EleutherAI/lm-evaluation-harness",
    cost: "Free",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "EleutherAI",
    license: "MIT",
    ecosystem: ["Python", "Hugging Face", "vLLM", "PyTorch"],
    longDescription: "The Language Model Evaluation Harness is the industry-standard benchmarking framework created by EleutherAI to evaluate generative language models on hundreds of academic and safety tasks.",
    typicalUseCase: "Evaluating base models on standardized safety, reasoning, and alignment benchmarks (MMLU, TruthfulQA, HellaSwag, GSM8k) across model releases.",
    keyFeatures: [
      "Over 60+ standard benchmark tasks covering truthfulness, bias, and reasoning",
      "Standard evaluation engine powering the Hugging Face Open LLM Leaderboard",
      "High-throughput inference support via vLLM and TensorRT-LLM",
      "Custom task configuration via lightweight YAML declarations"
    ],
    installationOrQuickstart: "pip install lm-eval\nlm_eval --model hf --model_args pretrained=meta-llama/Meta-Llama-3-8B --tasks truthfulqa,mmlu"
  },

  "Bleach": {
    name: "Bleach",
    description: "Python HTML sanitization to prevent XSS.",
    url: "https://github.com/mozilla/bleach",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Mozilla",
    license: "Apache-2.0",
    ecosystem: ["Python", "HTML5"],
    longDescription: "Bleach is an HTML sanitizing library that escapes or strips markup and attributes from untrusted text, using a whitelist of allowed tags and attributes.",
    typicalUseCase: "Sanitizing LLM-generated HTML and Markdown in Python backend microservices before sending responses to downstream frontend clients.",
    keyFeatures: [
      "Whitelist-based HTML tag and attribute sanitization",
      "Safe linkification of URLs and email addresses",
      "HTML5 compliant parser built on html5lib",
      "Customizable protocols and style attribute filters"
    ],
    installationOrQuickstart: "pip install bleach\nimport bleach\nclean_text = bleach.clean(untrusted_html, tags=['p', 'b', 'i', 'code'])"
  },

  "Grype": {
    name: "Grype",
    description: "Scan SBOMs for known vulnerabilities (CVE).",
    url: "https://github.com/anchore/grype",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Anchore",
    license: "Apache-2.0",
    ecosystem: ["Go", "Syft", "Docker", "CycloneDX"],
    longDescription: "Grype is a vulnerability scanner for container images and filesystems that easily matches software packages and SBOMs against vulnerability databases to discover known CVEs.",
    typicalUseCase: "Scanning container images and software bills of materials (SBOM) produced during AI container builds for published CVE vulnerabilities.",
    keyFeatures: [
      "Directly scans SBOM files (CycloneDX, SPDX, Syft format)",
      "Matches against comprehensive vulnerability feeds updated daily",
      "Fast scanning of local container images and filesystems",
      "Configurable failure thresholds based on CVSS severity scores"
    ],
    installationOrQuickstart: "brew install grype\ngrype sbom:./bom.json"
  },

  "Syft": {
    name: "Syft",
    description: "Generate SBOMs for containers and environments.",
    url: "https://github.com/anchore/syft",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Anchore",
    license: "Apache-2.0",
    ecosystem: ["Go", "Docker", "CycloneDX", "SPDX"],
    longDescription: "Syft is a CLI tool and Go library for generating a Software Bill of Materials (SBOM) from container images, filesystems, and archives, supporting CycloneDX and SPDX formats.",
    typicalUseCase: "Cataloging all operating system packages and Python wheels present inside an AI inference container image for compliance and supply chain tracking.",
    keyFeatures: [
      "Deep cataloging of container layers, package catalogs, and binary files",
      "Generates standardized CycloneDX and SPDX SBOM outputs",
      "Scans Python, Node.js, Go, Rust, Java, and Linux distribution packages",
      "Integrates with Grype for instant downstream vulnerability scanning"
    ],
    installationOrQuickstart: "brew install syft\nsyft pytorch/pytorch:latest -o cyclonedx-json=bom.json"
  },

  "OSV-Scanner": {
    name: "OSV-Scanner",
    description: "Scan dependencies using Google's OSV vulnerability database.",
    url: "https://github.com/google/osv-scanner",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Google Open Source Security Team",
    license: "Apache-2.0",
    ecosystem: ["Go", "OSV", "Pip", "Npm", "Go Modules"],
    longDescription: "OSV-Scanner is a vulnerability scanner that uses the Open Source Vulnerabilities (OSV) database to find dependencies with known security vulnerabilities across language ecosystems and lockfiles.",
    typicalUseCase: "Scanning lockfiles (`requirements.txt`, `poetry.lock`, `Pipfile.lock`) in machine learning repositories for open-source CVEs.",
    keyFeatures: [
      "Directly queries Google's distributed Open Source Vulnerabilities (OSV) database",
      "Scans lockfiles, directories, git repositories, and container images",
      "Provides precise commit-level vulnerability matching",
      "Zero-config fast CLI with JSON and table outputs"
    ],
    installationOrQuickstart: "go install github.com/google/osv-scanner/cmd/osv-scanner@latest\nosv-scanner -r ."
  },

  "Renovate": {
    name: "Renovate",
    description: "Automated dependency updates with policy controls.",
    url: "https://github.com/renovatebot/renovate",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Mend / Renovate Community",
    license: "AGPL-3.0",
    ecosystem: ["Node.js", "Docker", "GitLab", "GitHub", "Bitbucket"],
    longDescription: "Renovate is an automated dependency update tool that monitors repositories for outdated dependencies across 90+ package managers, opening automated pull requests with granular configuration options.",
    typicalUseCase: "Automating security patch updates for PyTorch, LangChain, Transformers, and CUDA container base images in engineering repositories.",
    keyFeatures: [
      "Automated pull requests with changelogs and release notes",
      "Configurable scheduling, automerge rules, and package grouping",
      "Supports Python (pip, poetry), Node.js, Docker, Helm, and GitHub Actions",
      "Self-hosted runner with full control over repository access"
    ],
    installationOrQuickstart: "npx -y renovate"
  },

  "Dependabot": {
    name: "Dependabot",
    description: "Automated dependency updates and security alerts.",
    url: "https://github.com/dependabot",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "GitHub / Microsoft",
    license: "Core Open Source / GitHub Native",
    ecosystem: ["GitHub", "Pip", "Npm", "Docker", "Actions"],
    longDescription: "Dependabot creates automated pull requests to keep dependencies secure and up-to-date by parsing repository manifest files and alerting on newly disclosed vulnerabilities.",
    typicalUseCase: "Automatically detecting vulnerable Python packages in machine learning repositories and opening pull requests with minimal version bumps.",
    keyFeatures: [
      "Integrated directly into GitHub repository security settings",
      "Automated security pull requests for vulnerable packages",
      "Version update PRs keeping dependencies current",
      "Configurable via `.github/dependabot.yml`"
    ],
    installationOrQuickstart: "Add .github/dependabot.yml configured for 'pip' and 'docker' package ecosystems"
  },

  "Permit.io": {
    name: "Permit.io",
    description: "Authorization platform for least-privilege access.",
    url: "https://www.permit.io/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Permit.io Inc.",
    license: "Commercial / Free Tier",
    ecosystem: ["OPA", "Cedar", "REST API", "Python", "Node.js"],
    longDescription: "Permit.io is a full-stack authorization platform that provides Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), and Relationship-Based Access Control (ReBAC) built on Open Policy Agent and Cedar.",
    typicalUseCase: "Enforcing least-privilege authorization rules on AI agent tool calls and data access permissions based on user role and context attributes.",
    keyFeatures: [
      "Low-code authorization UI with RBAC, ABAC, and ReBAC support",
      "Powered by local Policy Decision Points (PDPs) for sub-millisecond latency",
      "Real-time audit log streams recording every authorization decision",
      "SDKs for Python, Node.js, Go, Java, and REST APIs"
    ],
    installationOrQuickstart: "pip install permit\nfrom permit import Permit\npermit = Permit(token='...')"
  },

  "Auth0": {
    name: "Auth0",
    description: "Managed authentication for tools and agents.",
    url: "https://auth0.com/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Okta / Auth0",
    license: "Commercial / SaaS",
    ecosystem: ["OAuth2", "OIDC", "SAML", "MFA", "SaaS"],
    longDescription: "Auth0 by Okta is an enterprise-grade Identity-as-a-Service (IDaaS) platform providing universal authentication, Single Sign-On (SSO), Multi-Factor Authentication (MFA), and token management.",
    typicalUseCase: "Authenticating human users and external API clients before allowing interactions with enterprise LLM assistants and Model Context Protocol servers.",
    keyFeatures: [
      "Universal login with social and enterprise identity federation",
      "Machine-to-Machine (M2M) token issuance for AI service authentication",
      "Adaptive Multi-Factor Authentication and anomaly detection",
      "Extensive SDKs covering every modern web and backend framework"
    ],
    installationOrQuickstart: "Configure Auth0 Application -> Ingest JWT Bearer tokens in API gateway"
  },

  "Zitadel": {
    name: "Zitadel",
    description: "Open-source IAM and identity management.",
    url: "https://github.com/zitadel/zitadel",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Zitadel / CAOS AG",
    license: "Apache-2.0",
    ecosystem: ["Go", "OAuth2", "OIDC", "Passkeys", "Kubernetes"],
    longDescription: "ZITADEL is an open-source, cloud-native identity management platform designed for multi-tenancy, providing turnkey authentication, authorization, and audit logging using OAuth2, OIDC, and FIDO2 passkeys.",
    typicalUseCase: "Providing self-hosted, privacy-first identity management and scoped API token delegation for on-premises AI deployments.",
    keyFeatures: [
      "Native multi-tenancy and organization hierarchy support",
      "Passkey and FIDO2 passwordless authentication",
      "Fine-grained role assignment and user metadata claims",
      "Audit trail capturing all identity lifecycle events"
    ],
    installationOrQuickstart: "docker compose up -d\n# Open Zitadel admin console at http://localhost:8080"
  },

  "Linkerd": {
    name: "Linkerd",
    description: "Service mesh with mutual TLS by default.",
    url: "https://linkerd.io/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "CNCF / Buoyant",
    license: "Apache-2.0",
    ecosystem: ["Rust", "Go", "Kubernetes"],
    longDescription: "Linkerd is an ultralight, security-first service mesh for Kubernetes written in Rust that automatically provides mutual TLS, zero-config telemetry, and traffic reliability without complexity.",
    typicalUseCase: "Enforcing automatic mutual TLS encryption and traffic authorization between AI inference services, vector databases, and agent pods.",
    keyFeatures: [
      "Automatic zero-configuration mutual TLS encryption for all meshed traffic",
      "Micro-proxy written in Rust with minimal memory and CPU overhead",
      "ServerAuthorization policies restricting inter-service traffic",
      "Real-time Golden Signals metrics (success rate, latency, throughput)"
    ],
    installationOrQuickstart: "linkerd install --crds | kubectl apply -f -\nlinkerd install | kubectl apply -f -"
  },

  "Helicone": {
    name: "Helicone",
    description: "LLM telemetry and monitoring for incidents.",
    url: "https://www.helicone.ai/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Helicone AI",
    license: "Commercial / Open-source core",
    ecosystem: ["Python", "TypeScript", "OpenAI", "Anthropic", "Cloudflare"],
    longDescription: "Helicone is an open-source LLM observability platform that operates as a lightweight proxy, logging requests, costs, latency, prompt versions, and user sessions with a single line of code.",
    typicalUseCase: "Proxying enterprise LLM traffic to track cost per user, log prompt-response pairs for security auditing, and enforce caching to reduce API spend.",
    keyFeatures: [
      "One-line integration via base URL proxy redirection",
      "Real-time threat and anomaly detection on prompt traffic",
      "Semantic caching to reduce API latency and cost",
      "User session tracking and token usage rate limiting"
    ],
    installationOrQuickstart: "from openai import OpenAI\nclient = OpenAI(base_url='https://oai.helicone.ai/v1', default_headers={'Helicone-Auth': 'Bearer $HELICONE_API_KEY'})"
  },

  "OneTrust": {
    name: "OneTrust",
    description: "Consent and data governance for AI pipelines.",
    url: "https://www.onetrust.com/",
    cost: "€€€",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "OneTrust LLC",
    license: "Commercial / Enterprise SaaS",
    ecosystem: ["Enterprise", "SaaS", "Data Governance", "GDPR/CCPA"],
    longDescription: "OneTrust is an enterprise trust intelligence and privacy platform that automates data governance, consent management, regulatory compliance, and AI risk assessments across corporate systems.",
    typicalUseCase: "Conducting Algorithmic Impact Assessments (AIAs) and tracking data subject consent across training corpora for GDPR and EU AI Act compliance.",
    keyFeatures: [
      "AI Governance module for inventorying models and conducting risk assessments",
      "Automated consent tracking linked to training data sources",
      "Regulatory mapping for EU AI Act, NIST AI RMF, and ISO 42001",
      "Third-party AI vendor risk management and assessment workflows"
    ],
    installationOrQuickstart: "Access enterprise OneTrust tenant -> Configure AI Model Registry & Assessment Templates"
  },

  "BigID": {
    name: "BigID",
    description: "Sensitive data discovery and classification.",
    url: "https://bigid.com/",
    cost: "€€€",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "BigID Inc.",
    license: "Commercial / Enterprise",
    ecosystem: ["Enterprise", "Cloud", "SaaS", "Databases", "S3"],
    longDescription: "BigID is an enterprise data intelligence platform for privacy, security, and governance that uses deep learning to discover, classify, and protect sensitive, personal, and regulated data everywhere.",
    typicalUseCase: "Scanning multi-cloud object storage, data lakes, and vector stores to map sensitive customer data and enforce automated DSPM policies.",
    keyFeatures: [
      "Deep ML-based correlation and discovery of structured and unstructured PII",
      "DSPM (Data Security Posture Management) for AI training pipelines",
      "Data lineage and access risk visualization across enterprise repositories",
      "Automated remediation workflows for privacy and compliance violations"
    ],
    installationOrQuickstart: "Deploy BigID scanner appliance connected to enterprise data stores"
  },

  "Privacera": {
    name: "Privacera",
    description: "Data access governance and policy enforcement.",
    url: "https://www.privacera.com/",
    cost: "€€€",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Privacera",
    license: "Commercial / Enterprise",
    ecosystem: ["Apache Ranger", "Databricks", "Snowflake", "AWS", "Azure"],
    longDescription: "Privacera is a unified data access governance and security platform built by the creators of Apache Ranger that automates fine-grained access control, encryption, and masking across hybrid-cloud data platforms.",
    typicalUseCase: "Enforcing row-level, column-level, and tag-based access control policies on data lakehouse tables feeding LLM fine-tuning pipelines.",
    keyFeatures: [
      "Unified access policies enforced across Databricks, Snowflake, and S3",
      "Dynamic data masking and encryption for sensitive columns and attributes",
      "Centralized audit logging of all data queries and access attempts",
      "Privacera AI Governance module managing LLM data access permissions"
    ],
    installationOrQuickstart: "Deploy Privacera Manager to configure data access policies across data platforms"
  },

  "AFL++": {
    name: "AFL++",
    description: "Coverage-guided fuzzing for parsers and adapters.",
    url: "https://github.com/AFLplusplus/AFLplusplus",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "AFLplusplus Team",
    license: "Apache-2.0",
    ecosystem: ["C/C++", "LLVM", "Linux"],
    longDescription: "AFL++ is a superior, state-of-the-art coverage-guided fuzzer incorporating leading research advancements in mutation engines, scheduling algorithms, and hardware-accelerated instrumentation.",
    typicalUseCase: "Fuzzing native C/C++ parsers, tokenizers, and serialization libraries used in AI inference runtimes (e.g. ggml, llama.cpp, safetensors) to discover memory corruption bugs.",
    keyFeatures: [
      "Fast LLVM-mode compiler instrumentation with custom mutators",
      "Multiple mutation strategies (MOPT, custom dictionary mutators)",
      "QEMU and Unicorn modes for black-box binary fuzzing without source code",
      "Collision-free coverage maps and persistent execution modes"
    ],
    installationOrQuickstart: "git clone https://github.com/AFLplusplus/AFLplusplus && make\nafl-clang-fast++ -fsanitize=address parser.cpp -o parser_fuzz\nafl-fuzz -i in_dir -o out_dir -- ./parser_fuzz"
  },

  "libFuzzer": {
    name: "libFuzzer",
    description: "LLVM fuzzing engine for unsafe parsing paths.",
    url: "https://llvm.org/docs/LibFuzzer.html",
    cost: "Free",
    type: "Third-party",
    category: "Offensive",
    authorOrMaintainer: "LLVM Project",
    license: "Apache-2.0 with LLVM Exception",
    ecosystem: ["C/C++", "Clang", "LLVM"],
    longDescription: "libFuzzer is an in-process, coverage-guided, evolutionary fuzzing engine that is part of the LLVM compiler toolchain, designed to fuzz single target functions with high execution speed.",
    typicalUseCase: "Testing native tensor deserialization routines and custom tokenizer parsers for buffer overflows and use-after-free vulnerabilities.",
    keyFeatures: [
      "In-process fuzzing achieving tens of thousands of executions per second",
      "Deep integration with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer",
      "Built directly into modern Clang compilers",
      "Corpus minimization and automated crash reproduction"
    ],
    installationOrQuickstart: "clang++ -fsanitize=fuzzer,address target.cpp -o target_fuzzer\n./target_fuzzer corpus_dir/"
  },

  "SELinux": {
    name: "SELinux",
    description: "Mandatory access control to confine processes.",
    url: "https://github.com/SELinuxProject/selinux",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "SELinux Project / Red Hat / NSA",
    license: "GPL-2.0",
    ecosystem: ["Linux", "RHEL", "CentOS", "Fedora"],
    longDescription: "Security-Enhanced Linux (SELinux) is a Linux kernel security module that provides a mechanism for supporting access control security policies, including Mandatory Access Control (MAC) and Type Enforcement.",
    typicalUseCase: "Confining local AI inference worker processes to strictly defined file domains and preventing compromised model runners from touching host system resources.",
    keyFeatures: [
      "Kernel-level Mandatory Access Control enforcing strict Type Enforcement rules",
      "Multi-Category Security (MCS) isolating container instances on the same host",
      "Detailed audit logging for policy denial events via auditd",
      "Immutable access rules that root users cannot bypass in enforcing mode"
    ],
    installationOrQuickstart: "sestatus\n# Apply custom SELinux policy module confining model processes"
  },

  "AppArmor": {
    name: "AppArmor",
    description: "Linux MAC profiles to constrain execution.",
    url: "https://apparmor.net/",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "AppArmor Project / Canonical",
    license: "GPL-2.0",
    ecosystem: ["Linux", "Ubuntu", "Debian", "Docker"],
    longDescription: "AppArmor is a Linux kernel security module that allows system administrators to restrict programs' capabilities with per-program profiles, enforcing file access restrictions and network limits.",
    typicalUseCase: "Creating sandbox execution profiles for Model Context Protocol servers to restrict filesystem access strictly to approved workspaces.",
    keyFeatures: [
      "Path-based access control profiles for straightforward configuration",
      "Enforces file read/write restrictions, raw socket limits, and capability caps",
      "Integrated with Docker via `--security-opt apparmor=profile_name`",
      "Complain and Enforce execution modes for safe profile authoring"
    ],
    installationOrQuickstart: "apparmor_parser -r -W /etc/apparmor.d/ai_sandbox_profile\ndocker run --security-opt apparmor=ai_sandbox_profile my-tool-server"
  },

  "Nightfall AI": {
    name: "Nightfall AI",
    description: "AI-native data loss prevention and PII/secrets detection API.",
    url: "https://www.nightfall.ai/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Nightfall AI Inc.",
    license: "Commercial / SaaS API",
    ecosystem: ["Python", "JavaScript", "AWS", "Slack", "Jira", "REST API"],
    longDescription: "Nightfall AI is a cloud-based data security and DLP platform that uses machine learning to detect and classify over 150+ sensitive data types (PII, PHI, PCI, secrets, credentials) across SaaS applications and GenAI prompts in real time.",
    typicalUseCase: "Inline scanning of prompts and completions in enterprise AI workflows to prevent employees from leaking API credentials, patient records, or financial data into LLMs.",
    keyFeatures: [
      "150+ pre-trained ML detectors for sensitive tokens and personal data",
      "Real-time API latency (<50ms) for inline gateway integration",
      "Automated webhook alerts and compliance audit logs",
      "Native SaaS integrations with Slack, GitHub, Confluence, and Google Drive"
    ],
    installationOrQuickstart: "pip install nightfall\nfrom nightfall import Nightfall\nnf = Nightfall(key='$NIGHTFALL_API_KEY')\nres = nf.scan_text('Patient SSN: 000-12-3456')"
  },

  "AWS Macie": {
    name: "AWS Macie",
    description: "Managed data security service that uses ML to discover sensitive data in S3.",
    url: "https://aws.amazon.com/macie/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Amazon Web Services",
    license: "Commercial / AWS Cloud",
    ecosystem: ["AWS", "S3", "CloudWatch", "IAM", "EventBridge"],
    longDescription: "Amazon Macie is a fully managed data security and privacy service that uses machine learning and pattern matching to discover, monitor, and protect sensitive data stored in Amazon S3 buckets.",
    typicalUseCase: "Scanning training datasets, model weights, and fine-tuning caches in AWS S3 buckets to identify unencrypted PII, credentials, or unprotected customer data.",
    keyFeatures: [
      "Automated sensitive data discovery across S3 buckets",
      "Custom regex and keyword identifiers for proprietary enterprise data",
      "Risk scoring of storage access permissions and public bucket alerts",
      "Integrated with AWS Security Hub and Amazon EventBridge"
    ],
    installationOrQuickstart: "aws macie2 create-classification-job --job-type ONE_OFF --name s3-ai-data-scan --s3-job-definition '{\"bucketDefinitions\":[{\"accountId\":\"123456789012\",\"buckets\":[\"ai-training-data\"]}]}'"
  },

  "Microsoft Purview DLP": {
    name: "Microsoft Purview DLP",
    description: "Enterprise data loss prevention for Microsoft Copilot and cloud apps.",
    url: "https://www.microsoft.com/en-us/security/business/information-protection/microsoft-purview-data-loss-prevention",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Microsoft",
    license: "Commercial / Microsoft 365 Enterprise",
    ecosystem: ["Microsoft 365", "Azure", "Windows", "macOS", "REST API"],
    longDescription: "Microsoft Purview Data Loss Prevention (DLP) helps prevent the unauthorized sharing, transfer, or leakage of sensitive data across endpoints, Microsoft Copilot, cloud apps, and on-premises repositories.",
    typicalUseCase: "Enforcing sensitivity labels and blocking users from copying confidential financial or engineering data into public generative AI tools or internal Copilots.",
    keyFeatures: [
      "Native integration with Microsoft 365 Copilot and Teams",
      "OCR sensitive data inspection inside images and documents",
      "Adaptive protection based on user risk levels",
      "Unified compliance auditing and policy simulation testing"
    ],
    installationOrQuickstart: "Configure DLP Policy in Microsoft Purview Compliance Portal -> Select Generative AI & Copilot locations"
  },

  "Privacy Meter": {
    name: "Privacy Meter",
    description: "Membership inference attack tool to quantify model privacy leakage.",
    url: "https://github.com/privacytrustlab/ml_privacy_meter",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Privacy Trust Lab (NUS / SUTD)",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "TensorFlow", "Scikit-learn"],
    longDescription: "ML Privacy Meter is an open-source Python tool developed by academic privacy researchers to rigorously audit and quantify data privacy risks in machine learning models via Membership Inference Attacks (MIA).",
    typicalUseCase: "Auditing a trained or fine-tuned model checkpoint before release to mathematically verify that proprietary training records cannot be reconstructed by adversaries.",
    keyFeatures: [
      "Population and Shadow model attack algorithms",
      "ROC curve generation for empirical privacy leakage (epsilon bounds)",
      "Support for PyTorch and TensorFlow computational graphs",
      "Automated privacy scorecard and audit report generation"
    ],
    installationOrQuickstart: "pip install ml-privacy-meter\n# Initialize audit metric with target model and dataset splits"
  },

  "ML Privacy Meter": {
    name: "ML Privacy Meter",
    description: "Auditing tool for data privacy risks in machine learning models.",
    url: "https://github.com/privacytrustlab/ml_privacy_meter",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Privacy Trust Lab",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "TensorFlow"],
    longDescription: "ML Privacy Meter provides standardized mathematical auditing for membership inference attacks and empirical privacy leakage metrics in deep neural networks.",
    typicalUseCase: "Benchmarking the empirical privacy budget of fine-tuned language and vision models against black-box membership inference probes.",
    keyFeatures: [
      "Empirical differential privacy quantification",
      "Shadow model attack simulations",
      "Detailed ROC curve and false positive rate profiling",
      "Integrates with standard deep learning training loops"
    ],
    installationOrQuickstart: "pip install ml-privacy-meter\n# Run privacy audit on PyTorch checkpoint"
  },

  "PrivacyRaven": {
    name: "PrivacyRaven",
    description: "Privacy testing framework for deep learning systems.",
    url: "https://github.com/trailofbits/PrivacyRaven",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Trail of Bits",
    license: "Apache-2.0",
    ecosystem: ["Python", "PyTorch", "NumPy"],
    longDescription: "PrivacyRaven is a privacy testing framework developed by Trail of Bits for deep learning systems, enabling researchers to perform membership inference, model extraction, and model inversion attacks.",
    typicalUseCase: "Red-teaming neural network APIs to measure how accurately an attacker can steal model weights or extract private training samples.",
    keyFeatures: [
      "Modular attack pipeline (Membership Inference, Model Extraction, Model Inversion)",
      "Automated target querying and query budget optimization",
      "Detailed privacy risk reporting and metric visualizations",
      "Designed specifically for security researchers and red teams"
    ],
    installationOrQuickstart: "pip install privacyraven\n# Execute PrivacyRaven attack module against model target"
  },

  "Sonatype Nexus IQ": {
    name: "Sonatype Nexus IQ",
    description: "Software supply chain intelligence and open-source governance platform.",
    url: "https://www.sonatype.com/products/nexus-platform",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Sonatype",
    license: "Commercial / Enterprise",
    ecosystem: ["Java", "Python", "Node.js", "Jenkins", "GitLab", "GitHub"],
    longDescription: "Sonatype Nexus IQ provides deep binary and dependency analysis to enforce software supply chain policies, block vulnerable packages, and detect malicious open-source packages in automated pipelines.",
    typicalUseCase: "Scanning Python ML dependencies and PyTorch libraries in CI/CD pipelines to block packages with malicious install scripts or critical CVEs.",
    keyFeatures: [
      "Nexus Intelligence vulnerability and license compliance database",
      "Automated policy enforcement blocking risky builds",
      "IDE and CI/CD plugins for continuous developer feedback",
      "Component lifecycle and architectural risk management"
    ],
    installationOrQuickstart: "nexus-iq-cli -i my-ai-app -s http://nexus-iq:8070 -a admin:admin ./requirements.txt"
  },

  "OWASP AIBOM Generator": {
    name: "OWASP AIBOM Generator",
    description: "Standardized AI Bill of Materials generation for models and training data.",
    url: "https://github.com/OWASP/www-project-ai-security-and-privacy-guide",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "OWASP AI Exchange & GenAI Project",
    license: "Creative Commons / Apache-2.0",
    ecosystem: ["JSON", "YAML", "CycloneDX", "Python"],
    longDescription: "The OWASP AIBOM Generator produces structured AI Bills of Materials detailing model architectures, base models, training dataset hashes, licensing constraints, and ethical assessments.",
    typicalUseCase: "Creating auditable compliance documentation for generative AI and LLM applications to comply with the EU AI Act and enterprise procurement security standards.",
    keyFeatures: [
      "Captures dataset provenance, model lineage, and fine-tuning history",
      "Exports to standard CycloneDX AIBOM format",
      "Maps to OWASP Top 10 for LLMs and ISO/IEC 42001 requirements",
      "Lightweight CLI and library for automated build integration"
    ],
    installationOrQuickstart: "npm install -g @owasp/aibom-generator\naibom generate --config aibom-config.yaml"
  },

  "BackdoorBench": {
    name: "BackdoorBench",
    description: "Comprehensive benchmark for backdoor poisoning attacks and defenses.",
    url: "https://github.com/SCLBD/BackdoorBench",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "SCLBD Lab / Academic Research",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "CUDA"],
    longDescription: "BackdoorBench is an open-source benchmarking framework for machine learning backdoor attacks and defense algorithms, implementing over 20+ poison injection techniques and 15+ defense mechanisms.",
    typicalUseCase: "Evaluating computer vision and NLP model resilience against targeted trigger poisoning and clean-label backdoor injections.",
    keyFeatures: [
      "Standardized implementations of BadNets, Blended, WaNet, and Clean-Label backdoor attacks",
      "Defense algorithms including Neural Cleanse, STRIP, and Fine-Pruning",
      "Automated benchmark scoring across accuracy and attack success rate (ASR)",
      "Extensive dataset support across CIFAR, ImageNet, and Tiny-ImageNet"
    ],
    installationOrQuickstart: "git clone https://github.com/SCLBD/BackdoorBench && cd BackdoorBench\npython attack/badnet.py --dataset cifar10"
  },

  "TensorFlow Data Validation": {
    name: "TensorFlow Data Validation",
    description: "Scalable dataset validation and schema anomaly detection.",
    url: "https://github.com/tensorflow/data-validation",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Google / TensorFlow Extended (TFX)",
    license: "Apache-2.0",
    ecosystem: ["Python", "Apache Beam", "TensorFlow", "PySpark"],
    longDescription: "TFDV is part of TensorFlow Extended (TFX) for analyzing and validating machine learning data, calculating descriptive statistics, inferring schemas, and detecting data anomalies and drift.",
    typicalUseCase: "Detecting data distribution skew, missing features, and anomalous tokens in streaming training and inference pipelines.",
    keyFeatures: [
      "Computes summary statistics over multi-gigabyte datasets via Apache Beam",
      "Infers feature schemas with automated validation rules",
      "Generates interactive Facets visualizations for anomaly inspection",
      "Detects training-serving skew and dataset drift"
    ],
    installationOrQuickstart: "pip install tensorflow-data-validation\nimport tensorflow_data_validation as tfdv\nstats = tfdv.generate_statistics_from_dataframe(df)"
  },

  "Amazon Deequ": {
    name: "Amazon Deequ",
    description: "Unit tests for data on top of Apache Spark.",
    url: "https://github.com/awslabs/deequ",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "AWS Labs",
    license: "Apache-2.0",
    ecosystem: ["Scala", "Java", "Python (pydeequ)", "Apache Spark"],
    longDescription: "Amazon Deequ is an open-source library built on Apache Spark for defining 'unit tests for data', measuring data quality metrics on large datasets and verifying data integrity constraints.",
    typicalUseCase: "Verifying that large-scale data lakes and token repositories ingested for model pre-training satisfy non-null, uniqueness, and value range constraints.",
    keyFeatures: [
      "Declarative VerificationSuite with checks for completeness, uniqueness, and correlations",
      "Automated constraint suggestion based on historical distributions",
      "Anomaly detection over incremental dataset updates",
      "Native execution on petabyte-scale Apache Spark clusters"
    ],
    installationOrQuickstart: "pip install pydeequ\nfrom pydeequ.checks import Check, CheckLevel\ncheck = Check(spark, CheckLevel.Error, 'Integrity Check')"
  },

  "OpenLineage": {
    name: "OpenLineage",
    description: "Open standard for metadata and data lineage collection.",
    url: "https://openlineage.io/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Linux Foundation / OpenLineage",
    license: "Apache-2.0",
    ecosystem: ["Python", "Java", "Apache Spark", "Airflow", "dbt"],
    longDescription: "OpenLineage defines an open standard for observing dataset dependencies, ETL transformations, and pipeline runs, mapping end-to-end data lineage across disparate processing systems.",
    typicalUseCase: "Tracking the exact origin, transformation steps, and intermediate storage locations of datasets that feed LLM fine-tuning pipelines to guarantee auditability.",
    keyFeatures: [
      "Standard JSON specification for dataset and job metadata",
      "Automated lineage extractors for Apache Spark, Airflow, and dbt",
      "Integration with Marquez, DataHub, and Amundsen catalog backends",
      "Fine-grained column-level lineage tracking"
    ],
    installationOrQuickstart: "pip install openlineage-python openlineage-airflow\n# Configure OPENLINEAGE_URL in Airflow or Spark environment"
  },

  "DataHub": {
    name: "DataHub",
    description: "Metadata platform for modern data stack discovery and governance.",
    url: "https://datahubproject.io/",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "LinkedIn / DataHub Project",
    license: "Apache-2.0",
    ecosystem: ["Python", "React", "Kafka", "Elasticsearch", "Docker"],
    longDescription: "DataHub is an extensible metadata platform for data discovery, data observability, and federated governance across data warehouses, ML features, and AI model registries.",
    typicalUseCase: "Mapping enterprise data catalogs to AI training pipelines to enforce access restrictions, verify data ownership, and track regulatory compliance.",
    keyFeatures: [
      "Real-time search and discovery for datasets, pipelines, and ML models",
      "Automated data lineage graphs and dependency visualization",
      "Policy-based access governance and metadata tagging",
      "GraphQL and OpenAPI programmatic interfaces"
    ],
    installationOrQuickstart: "pip install acryl-datahub\ndatahub docker quickstart"
  },

  "CodeQL": {
    name: "CodeQL",
    description: "Semantic code analysis engine for discovering security vulnerabilities.",
    url: "https://codeql.github.com/",
    cost: "Free+Paid",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "GitHub / Microsoft",
    license: "Free for Open Source / GitHub Advanced Security",
    ecosystem: ["Python", "TypeScript", "Java", "C/C++", "Go", "GitHub Actions"],
    longDescription: "CodeQL treats code as data, compiling codebases into relational databases and allowing security engineers to write declarative queries that discover complex taint-tracking vulnerabilities.",
    typicalUseCase: "Finding untrusted data flow from LLM model completions to SQL execution engines, command shells, or dynamic deserialization routines in backend code.",
    keyFeatures: [
      "Powerful object-oriented query language (QL) for code analysis",
      "Deep taint-tracking across complex function call graphs and microservices",
      "Comprehensive library of pre-built queries for OWASP and CWE vulnerabilities",
      "Integrated into GitHub Actions and pull request security checks"
    ],
    installationOrQuickstart: "codeql database create my-db --language=python\ncodeql query run --database=my-db ./queries/llm-rce.ql"
  },

  "AgentOps SDK": {
    name: "AgentOps SDK",
    description: "Observability and guardrails for agent behavior.",
    url: "https://www.agentops.ai/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "AgentOps Inc.",
    license: "Commercial / Free Tier",
    ecosystem: ["Python", "CrewAI", "AutoGen", "LangChain"],
    longDescription: "AgentOps SDK provides specialized observability, monitoring, and compliance guardrails for autonomous AI agent workflows, tracking multi-agent tool execution, goal deviation, and recursive loop traps.",
    typicalUseCase: "Monitoring production autonomous agent sessions to detect rogue loops, excessive tool invocation costs, and unintended external actions.",
    keyFeatures: [
      "Session replay and step-by-step visual trace of agent reasoning chains",
      "Detection of recursive infinite loops and goal deviation",
      "Multi-agent communication topology mapping",
      "Cost and latency tracking per tool execution"
    ],
    installationOrQuickstart: "pip install agentops\nimport agentops\nagentops.init(api_key='...')"
  },

  "LlamaIndex Evaluations": {
    name: "LlamaIndex Evaluations",
    description: "Evaluation modules for RAG retrieval and response generation.",
    url: "https://docs.llamaindex.ai/en/stable/module_guides/evaluating/",
    cost: "Free",
    type: "Local",
    category: "Both",
    authorOrMaintainer: "LlamaIndex Inc.",
    license: "MIT",
    ecosystem: ["Python", "TypeScript", "OpenAI", "Hugging Face"],
    longDescription: "LlamaIndex Evaluations is a suite of evaluation modules specifically designed to test the correctness, relevancy, faithfulness, and semantic retrieval accuracy of RAG query engines.",
    typicalUseCase: "Evaluating retrieval quality and answer groundedness across enterprise document collections to detect hallucination and context poisoning.",
    keyFeatures: [
      "FaithfulnessEvaluator and RelevancyEvaluator metrics",
      "Pairwise LLM comparison and response grading",
      "Batch evaluation runners for CI/CD integration",
      "Seamless integration with LlamaIndex vector indices"
    ],
    installationOrQuickstart: "pip install llama-index\nfrom llama_index.core.evaluation import FaithfulnessEvaluator\nevaluator = FaithfulnessEvaluator()"
  },

  "Pinecone Security Scans": {
    name: "Pinecone Security Scans",
    description: "Managed vector database access controls and data isolation.",
    url: "https://www.pinecone.io/security/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Pinecone Systems",
    license: "Commercial / SaaS",
    ecosystem: ["Python", "Node.js", "Go", "AWS", "GCP", "Azure"],
    longDescription: "Pinecone provides managed vector search with enterprise security features, including namespace-level data isolation, private VPC endpoints, metadata filtering, and encryption at rest.",
    typicalUseCase: "Restricting vector embeddings access in multi-tenant RAG applications using namespace isolation and metadata-based authorization filters.",
    keyFeatures: [
      "Multi-tenant namespace isolation for vector indexes",
      "AWS and GCP PrivateLink dedicated network endpoints",
      "SOC 2 Type II, HIPAA, and GDPR compliance certifications",
      "Vector-level role-based access control policies"
    ],
    installationOrQuickstart: "pip install pinecone-client\nfrom pinecone import Pinecone\npc = Pinecone(api_key='...')"
  },

  "Galileo": {
    name: "Galileo",
    description: "GenAI evaluation, guardrails, and observability platform.",
    url: "https://www.rungalileo.io/",
    cost: "Paid",
    type: "Third-party",
    category: "Both",
    authorOrMaintainer: "Galileo Technologies",
    license: "Commercial / Enterprise",
    ecosystem: ["Python", "LangChain", "LlamaIndex", "SaaS"],
    longDescription: "Galileo is an enterprise GenAI evaluation and observability platform that helps teams evaluate, protect, and observe LLMs and RAG systems from development to production.",
    typicalUseCase: "Real-time hallucination scoring and prompt injection interception on high-volume enterprise generative AI endpoints.",
    keyFeatures: [
      "Galileo Guard for sub-50ms runtime firewalls",
      "Fine-grained RAG metrics including ChainPoll and Chunk Attribution",
      "Automated prompt evaluation benchmarks and drift tracking",
      "Custom metric authoring and human-in-the-loop annotations"
    ],
    installationOrQuickstart: "pip install dataquality\nimport dataquality as dq\ndq.init(project_name='ai-security-audit')"
  },

  "Locust": {
    name: "Locust",
    description: "Python-based load testing tool for scalable user simulation.",
    url: "https://github.com/locustio/locust",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Locust.io Community",
    license: "MIT",
    ecosystem: ["Python", "HTTP", "WebSocket", "CLI"],
    longDescription: "Locust is an open-source load testing tool where user behavior is defined completely in regular Python code, allowing distributed swarms of concurrent users to stress-test APIs.",
    typicalUseCase: "Simulating thousands of concurrent streaming users against LLM endpoints to benchmark rate limiters, token throttlers, and GPU memory saturation.",
    keyFeatures: [
      "Test scenarios written in clean, idiomatic Python code",
      "Distributed master-worker architecture supporting millions of simulated users",
      "Real-time web UI dashboard displaying latency percentiles and error rates",
      "Extensible protocol support for HTTP, REST, and WebSockets"
    ],
    installationOrQuickstart: "pip install locust\nlocust -f locustfile.py --headless -u 100 -r 10 -t 1m"
  },

  "Apache JMeter": {
    name: "Apache JMeter",
    description: "Java application designed to load test functional behavior and measure performance.",
    url: "https://jmeter.apache.org/",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Apache Software Foundation",
    license: "Apache-2.0",
    ecosystem: ["Java", "XML", "Cross-platform"],
    longDescription: "Apache JMeter is a battle-tested, Java-based load testing tool designed to test performance, simulate heavy loads on servers, and analyze overall performance under different load types.",
    typicalUseCase: "Stress-testing AI API gateways and microservices with high concurrency to identify Denial-of-Wallet vulnerabilities and GPU timeout thresholds.",
    keyFeatures: [
      "Comprehensive protocol support (HTTP, HTTPS, REST, SOAP, JDBC, JMS)",
      "Multithreaded framework for simulating high concurrent user loads",
      "Extensive charting, reporting, and statistical plugins",
      "Headless CLI execution for CI/CD pipeline automation"
    ],
    installationOrQuickstart: "jmeter -n -t llm_load_test.jmx -l results.jtl -e -o ./report"
  },

  "Upstash Rate Limit": {
    name: "Upstash Rate Limit",
    description: "Serverless rate limiting SDK built on Serverless Redis.",
    url: "https://github.com/upstash/ratelimit",
    cost: "Free+Paid",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Upstash Inc.",
    license: "MIT",
    ecosystem: ["TypeScript", "JavaScript", "Node.js", "Next.js", "Cloudflare Workers"],
    longDescription: "Upstash Rate Limit is an open-source, ultra-fast rate limiting SDK designed for serverless architectures (Next.js, Cloudflare Workers, AWS Lambda) using sliding window and token bucket algorithms over Redis.",
    typicalUseCase: "Enforcing per-user and per-IP rate limits in frontend and Edge serverless functions to stop bot scraping and denial-of-wallet attacks against LLM APIs.",
    keyFeatures: [
      "Sliding window, fixed window, and token bucket rate limiting algorithms",
      "Sub-millisecond latency over globally replicated Redis",
      "Zero-infrastructure serverless deployment model",
      "Native Edge runtime compatibility (Cloudflare Workers, Vercel Edge)"
    ],
    installationOrQuickstart: "npm install @upstash/ratelimit @upstash/redis\nimport { Ratelimit } from '@upstash/ratelimit';"
  },

  "Azure API Management": {
    name: "Azure API Management",
    description: "Hybrid, multi-cloud API management platform with AI gateway capabilities.",
    url: "https://azure.microsoft.com/en-us/products/api-management",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Microsoft Azure",
    license: "Commercial / Azure Cloud",
    ecosystem: ["Azure", "REST", "OpenAPI", "Entra ID"],
    longDescription: "Azure API Management provides a scalable, multi-cloud API gateway with specialized GenAI policies for OpenAI and model endpoints, including token rate limiting, multi-model load balancing, and semantic caching.",
    typicalUseCase: "Managing enterprise access to Azure OpenAI models with per-team token quotas, circuit breaking, and centralized security telemetry.",
    keyFeatures: [
      "GenAI policy toolkit (llm-token-limit, llm-emit-token-metric, llm-semantic-cache)",
      "OAuth 2.0 and Microsoft Entra ID token validation",
      "Comprehensive Azure Monitor logging and diagnostic tracing",
      "Multi-model load balancing and automated failover"
    ],
    installationOrQuickstart: "az apim create --name my-ai-gateway --resource-group my-rg --location eastus --sku-name Consumption"
  },

  "RobustBench": {
    name: "RobustBench",
    description: "Standardized benchmark for adversarial robustness evaluation.",
    url: "https://github.com/RobustBench/robustbench",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "RobustBench Team (Univ. of Tübingen)",
    license: "MIT",
    ecosystem: ["Python", "PyTorch", "AutoAttack"],
    longDescription: "RobustBench is a community-driven benchmark for adversarial robustness evaluation in computer vision, maintaining an official leaderboard across multiple perturbation norms (Linf, L2, Common Corruptions).",
    typicalUseCase: "Evaluating and tracking model robustness against standardized adversarial perturbation attacks to prevent evasion exploits.",
    keyFeatures: [
      "Standardized AutoAttack evaluation harness",
      "Unified model zoo with 100+ pre-trained robust model weights",
      "Clean, reproducible PyTorch evaluation API",
      "Official leaderboard rankings across CIFAR-10, CIFAR-100, and ImageNet"
    ],
    installationOrQuickstart: "pip install git+https://github.com/RobustBench/robustbench.git\nfrom robustbench.eval import benchmark\nclean_acc, robust_acc = benchmark(model, dataset='cifar10', threat_model='Linf')"
  },

  "WhyLabs": {
    name: "WhyLabs",
    description: "AI observability and continuous monitoring platform.",
    url: "https://whylabs.ai/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "WhyLabs Inc.",
    license: "Commercial / Free Community Tier",
    ecosystem: ["Python", "whylogs", "Cloud", "SaaS"],
    longDescription: "WhyLabs provides continuous observability and guardrails for machine learning models and LLM applications, tracking statistical data drift, anomalies, and safety violations in real time.",
    typicalUseCase: "Monitoring production LLM embeddings, user query distributions, and output toxicity scores with automated Slack/PagerDuty alerts on drift detection.",
    keyFeatures: [
      "Privacy-preserving profiling using whylogs (zero raw data retention)",
      "Real-time statistical anomaly and drift detection",
      "Customizable guardrail rules and hallucination metrics",
      "Historical trend dashboards and compliance reporting"
    ],
    installationOrQuickstart: "pip install whylabs-client whylogs\n# Upload statistical profiles to WhyLabs observability hub"
  },

  "River": {
    name: "River",
    description: "Online machine learning library for streaming data and concept drift detection.",
    url: "https://github.com/online-ml/river",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "River Online ML Team",
    license: "BSD-3-Clause",
    ecosystem: ["Python", "Streaming", "NumPy", "Scikit-learn"],
    longDescription: "River is a Python library for dynamic online machine learning on streaming data, featuring algorithms for continuous learning, streaming classification, and statistical concept drift detection (ADWIN, PageHinkley).",
    typicalUseCase: "Monitoring streaming inference traffic in real time to detect statistical distribution shifts and adversarial evasion attempts on a per-sample basis.",
    keyFeatures: [
      "Online incremental learning algorithms designed for one-instance-at-a-time data",
      "Dedicated drift detection algorithms (ADWIN, DDM, EDDM, Page-Hinkley)",
      "High-throughput streaming pipeline execution",
      "Extensive evaluation metrics for streaming data"
    ],
    installationOrQuickstart: "pip install river\nfrom river import drift\ndrift_detector = drift.ADWIN()"
  },

  "AWS Config": {
    name: "AWS Config",
    description: "Continual assessment, audit, and evaluation of AWS resource configurations.",
    url: "https://aws.amazon.com/config/",
    cost: "Paid",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "Amazon Web Services",
    license: "Commercial / AWS Cloud",
    ecosystem: ["AWS Cloud", "CloudTrail", "IAM", "Systems Manager"],
    longDescription: "AWS Config continuously monitors and records AWS resource configurations, evaluating recorded configurations against desired secure configurations and compliance rules.",
    typicalUseCase: "Auditing Amazon Bedrock, SageMaker notebooks, and S3 vector data stores to ensure encryption-at-rest is enabled and public access is strictly blocked.",
    keyFeatures: [
      "Continuous configuration tracking and resource relationship mapping",
      "Pre-built conformance packs for CIS and NIST AI benchmarks",
      "Automated remediation workflows via AWS Systems Manager",
      "Immutable configuration history timeline for security forensics"
    ],
    installationOrQuickstart: "aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::..."
  },

  "git-secrets": {
    name: "git-secrets",
    description: "Prevents committing secrets and credentials into git repositories.",
    url: "https://github.com/awslabs/git-secrets",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "AWS Labs",
    license: "Apache-2.0",
    ecosystem: ["Shell", "Git", "AWS"],
    longDescription: "git-secrets is a CLI tool developed by AWS Labs that scans commits, commit messages, and diffs to prevent secrets and sensitive credentials from entering Git repositories.",
    typicalUseCase: "Installing pre-commit hooks on developer workstations to prevent accidentally committing AWS access keys or OpenAI API tokens into source code.",
    keyFeatures: [
      "Fast pre-commit hook integration preventing accidental commits",
      "Customizable regex patterns for proprietary keys and tokens",
      "AWS provider pattern presets covering AWS Access Keys and Secrets",
      "Scans commit histories and unstaged files"
    ],
    installationOrQuickstart: "brew install git-secrets\ngit secrets --register-aws --install"
  },

  "detect-secrets": {
    name: "detect-secrets",
    description: "Enterprise tool for detecting secrets in codebase with baseline support.",
    url: "https://github.com/Yelp/detect-secrets",
    cost: "Free",
    type: "Local",
    category: "Offensive",
    authorOrMaintainer: "Yelp",
    license: "Apache-2.0",
    ecosystem: ["Python", "Git", "Pre-commit", "CI/CD"],
    longDescription: "detect-secrets is an open-source secret scanning framework created by Yelp that uses heuristics, regex patterns, and Shannon entropy analysis to identify credentials without noise.",
    typicalUseCase: "Generating a version-controlled `.secrets.baseline` file in machine learning repositories to prevent new API keys from being introduced in PRs while managing existing legacy secrets.",
    keyFeatures: [
      "Heuristic and Shannon entropy plugins for high precision detection",
      "Baseline file support for gradual codebase remediation",
      "Pre-commit framework integration and CI/CD audit mode",
      "Custom plugin architecture for proprietary API tokens"
    ],
    installationOrQuickstart: "pip install detect-secrets\ndetect-secrets scan > .secrets.baseline"
  },

  "NIST AI RMF": {
    name: "NIST AI RMF",
    description: "NIST Artificial Intelligence Risk Management Framework (NIST AI 100-1).",
    url: "https://www.nist.gov/itl/ai-risk-management-framework",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "National Institute of Standards and Technology (NIST)",
    license: "Public Domain / US Federal Standard",
    ecosystem: ["Framework", "Governance", "ISO 42001", "Compliance"],
    longDescription: "The NIST AI RMF is a voluntary guidance framework designed to improve the ability to incorporate trustworthiness considerations into the design, development, use, and evaluation of AI products, services, and systems.",
    typicalUseCase: "Structuring enterprise AI governance programs, establishing risk tolerance thresholds, and conducting formal AI risk assessments across Govern, Map, Measure, and Manage functions.",
    keyFeatures: [
      "Four core functions: Govern, Map, Measure, and Manage",
      "Comprehensive Playbook with actionable risk mitigation tasks",
      "Cross-mappings to ISO/IEC 42001 and EU AI Act requirements",
      "Standardized AI risk taxonomy covering validity, safety, and security"
    ],
    installationOrQuickstart: "Review NIST AI RMF Playbook -> Align internal model validation checklists with Measure & Manage categories"
  },

  "OWASP ASVS": {
    name: "OWASP ASVS",
    description: "OWASP Application Security Verification Standard.",
    url: "https://owasp.org/www-project-application-security-verification-standard/",
    cost: "Free",
    type: "Third-party",
    category: "Defensive",
    authorOrMaintainer: "OWASP Foundation",
    license: "Creative Commons Attribution-ShareAlike 4.0",
    ecosystem: ["Framework", "AppSec", "OWASP", "Compliance"],
    longDescription: "The OWASP Application Security Verification Standard (ASVS) provides a basis for testing web application technical security controls and also provides developers with a list of requirements for secure development.",
    typicalUseCase: "Establishing baseline security requirements for web applications, APIs, and microservices that wrap LLM models and Model Context Protocol servers.",
    keyFeatures: [
      "Three verification levels: Level 1 (Basic), Level 2 (Standard), Level 3 (Advanced)",
      "Comprehensive coverage of authentication, access control, input validation, and cryptography",
      "Industry-standard penetration testing and security review benchmark",
      "Actionable security controls for secure software architectures"
    ],
    installationOrQuickstart: "Download OWASP ASVS v4.0.3 checklist -> Audit API gateway and authentication architecture"
  }
};

/**
 * Retrieves the enriched metadata for a given tool name, with fallbacks.
 */
export function getEnrichedTool(tool: SecurityTool): SecurityTool {
  const normalizedKey = tool.name.trim().toLowerCase();
  
  for (const [key, meta] of Object.entries(TOOL_DATABASE)) {
    if (key.toLowerCase() === normalizedKey || meta.name.toLowerCase() === normalizedKey) {
      return {
        ...tool,
        ...meta,
        // Preserve any category or cost passed in original object
        category: tool.category || meta.category,
        cost: tool.cost || meta.cost,
        type: tool.type || meta.type,
      };
    }
  }

  // Fallback: Generate reasonable default metadata if not found in database
  return {
    ...tool,
    authorOrMaintainer: tool.type === 'Local' ? 'Open Source Community' : 'Enterprise Provider',
    license: tool.cost === 'Free' ? 'Open Source (Permissive)' : 'Commercial License',
    ecosystem: tool.type === 'Local' ? ['Python', 'Docker', 'CLI'] : ['Cloud Platform', 'REST API'],
    longDescription: tool.description + ' This tool is referenced throughout the AI Security Nexus catalog to evaluate, test, or mitigate vulnerabilities across AI systems.',
    typicalUseCase: `Security practitioners deploy ${tool.name} during testing or production operations to strengthen security posture and mitigate AI vulnerabilities.`,
    keyFeatures: [
      'Specialized capability mapped to AI vulnerability frameworks',
      'Integrates into modern development and security workflows',
      'Supports automated verification and compliance checks'
    ],
    installationOrQuickstart: tool.type === 'Local' ? `# Install and run ${tool.name}\nSee official documentation at: ${tool.url}` : `# Access ${tool.name}\nExplore setup and API documentation at: ${tool.url}`
  };
}
