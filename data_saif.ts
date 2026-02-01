
import { OwaspTop10Entry } from './types';

export const OWASP_SAIF_THREATS_DATA: OwaspTop10Entry[] = [
  {
    id: "SAIF-R01",
    title: "Data Poisoning",
    description: "Attackers inject malicious or misleading data into the model's training data, compromising performance or creating backdoors that activate under specific conditions.",
    commonRisks: [
      "Compromised model integrity and overall performance decay.",
      "Hidden backdoors triggered by specific input patterns or 'trigger' tokens.",
      "Degraded trust in automated decision-making systems.",
      "Systemic bias introduction targeting specific subgroups."
    ],
    preventionStrategies: [
      "Input Validation and Sanitization: Detect and block malicious samples during data ingestion.",
      "Continuous Training Monitoring: Use statistical checks to detect distribution shifts during the training process.",
      "Data Provenance: Ensure training data comes from trusted, verified sources and maintain audit trails.",
      "Robust Aggregation: Use techniques like trimmed means to mitigate individual poisoned records."
    ],
    attackScenarios: [
      { title: "Sentiment Analysis Poisoning", description: "Attacker injects thousands of reviews where specific positive keywords are paired with negative sentiments to bias a brand's score." },
      { title: "IDS Threshold Shift", description: "Attacker slowly injects malicious traffic labeled as 'safe' to gradually shift the AI's detection boundary until real attacks pass through." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Cleanlab", description: "Automatically detect and clean label noise and outliers in training data.", url: "https://github.com/cleanlab/cleanlab", cost: "Free", type: "Local" },
      { name: "Hugging Face Model Hub Scanners", description: "Check datasets for known poisoning patterns before download.", url: "https://huggingface.co/", cost: "Free", type: "Third-party" }
    ]
  },
  {
    id: "SAIF-R02",
    title: "Unauthorized Training Data",
    description: "The model is trained on unauthorized data (unlicensed, non-consensual, or PII), resulting in severe legal, ethical, or regulatory compliance issues.",
    commonRisks: [
      "Copyright infringement and massive legal liabilities.",
      "Reputational damage due to unethical data sourcing practices.",
      "Regulatory non-compliance (e.g., GDPR 'Right to be Forgotten' violations).",
      "Disclosure of trade secrets or proprietary code accidentally ingested."
    ],
    preventionStrategies: [
      "Data Governance Frameworks: Implement strict auditing and approval processes for all training datasets.",
      "Privacy-Preserving Sourcing: Use anonymized or synthetic data where possible.",
      "Legal Review: Ensure all data used for fine-tuning or training is properly licensed and consented.",
      "Sensitive Data Discovery: Automatically scan datasets for PII before ingestion."
    ],
    attackScenarios: [
      { title: "Proprietary Code Leakage", description: "An internal model is trained on a developer's private codebase without consent, causing it to reveal snippet of private code to other users." },
      { title: "Medical Record Ingestion", description: "A health bot is fine-tuned on un-anonymized doctor notes, leading to the bot repeating patient names and diagnoses." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "OneTrust Data Governance", description: "Manage data consent and usage rights for model training.", url: "https://www.onetrust.com/", cost: "€€€", type: "Third-party" }
    ]
  },
  {
    id: "SAIF-R03",
    title: "Model Source Tampering",
    description: "Attackers manipulate the model's source code, serving framework, or weights file, compromising performance or creating persistent backdoors in the inference engine.",
    commonRisks: [
      "Total loss of model reliability and predictable behavior.",
      "Introduction of persistent backdoors into the inference pipeline.",
      "Execution of malicious code via tampered framework libraries (e.g., pickle exploits).",
      "Unauthorized changes to model safety filters or guardrails."
    ],
    preventionStrategies: [
      "Artifact Integrity: Use cryptographic hashes and signatures for all model weight files.",
      "Secure CI/CD: Protect the training and deployment environment from unauthorized access with MFA.",
      "Code Scanning: Regularly scan model implementation code and dependencies for vulnerabilities.",
      "Immutable Infrastructure: Deploy models in signed, read-only containers."
    ],
    attackScenarios: [
      { title: "Weights Manipulation", description: "An attacker with access to a storage bucket modifies a few bits of a weight file to ensure a specific facial accessory always grants access." },
      { title: "Library Hijack", description: "An attacker replaces the 'torch' library in the serving image with a version that intercepts and exfiltrates every user prompt." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Checkmarx AI", description: "Scan model code and framework dependencies for tampered logic.", url: "https://checkmarx.com/", cost: "€€€", type: "Third-party" },
      { name: "ModelScan", description: "Detect unsafe code hidden in model weight files.", url: "https://github.com/protectai/modelscan", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "SAIF-R04",
    title: "Excessive Data Handling",
    description: "Data collection or retention goes beyond what is allowed in corresponding privacy policies, resulting in legal risk and increased attack surface for data breaches.",
    commonRisks: [
      "Privacy violations and massive regulatory fines (GDPR, CCPA).",
      "Increased attack surface due to unnecessary long-term data storage.",
      "Loss of user trust and brand damage.",
      "Inadvertent disclosure of PII in future model fine-tuning cycles."
    ],
    preventionStrategies: [
      "Data Minimization: Only collect the specific data needed for the immediate AI task.",
      "Automated Deletion: Implement strict retention policies and automated purging mechanisms.",
      "Privacy Audits: Regularly verify that stored data matches public-facing privacy policies.",
      "Differential Privacy: Use techniques that allow learning without storing raw individual records."
    ],
    attackScenarios: [
      { title: "PII Hoarding", description: "An AI support agent retains full chat transcripts including credit card numbers for 5 years despite a 30-day retention policy." },
      { title: "Ghost Data Disclosure", description: "A model is fine-tuned on data that should have been deleted, causing it to 'memorize' and later reveal the deleted secrets." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Privacera", description: "Data access governance and policy enforcement for data lakes.", url: "https://www.privacera.com/", cost: "€€€", type: "Third-party" }
    ]
  },
  {
    id: "SAIF-R05",
    title: "Model Exfiltration",
    description: "Attackers gain unauthorized access to the model weights or architecture, stealing intellectual property and enabling 'white-box' local attacks.",
    commonRisks: [
      "Loss of proprietary IP and significant competitive advantage.",
      "Enabling attackers to perform perfect 'white-box' adversarial attacks locally.",
      "Financial loss from R&D theft and counterfeit AI service creation.",
      "Reputational damage due to security negligence."
    ],
    preventionStrategies: [
      "Secure Storage: Encrypt model weights at rest with strict IAM and MFA controls.",
      "Exfiltration Detection: Monitor for abnormal data movement from model registries and buckets.",
      "VPC Service Controls: Isolate model artifacts in secured network perimeters.",
      "Watermarking: Embed identifiable signals in weights to trace the source of any leak."
    ],
    attackScenarios: [
      { title: "Bucket Misconfiguration", description: "An internal model repository is accidentally set to public, allowing an attacker to download the multi-billion parameter weights." },
      { title: "CI/CD Leak", description: "An attacker compromises a Jenkins server and uses a script to upload the latest model checkpoint to an external server." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Datadog Cloud SIEM", description: "Monitor for abnormal data exfiltration patterns in storage buckets.", url: "https://www.datadoghq.com/", cost: "€€", type: "Third-party" },
      { name: "HashiCorp Vault", description: "Secrets management for controlling access to weight storage.", url: "https://www.vaultproject.io/", cost: "€€", type: "Local" }
    ]
  },
  {
    id: "SAIF-R06",
    title: "Model Deployment Tampering",
    description: "Attackers manipulate components used for model deployment (API gateways, load balancers, serving images), compromising performance or creating backdoors.",
    commonRisks: [
      "Inference-time manipulation of results to achieve attacker goals.",
      "System unavailability or instability (Denial of Service).",
      "Bypassing runtime guardrails and safety filters.",
      "Theft of user prompts and model responses at the network layer."
    ],
    preventionStrategies: [
      "Secure Deployment Pipelines: Use signed container images and immutable infrastructure.",
      "Runtime Monitoring: Detect anomalies in inference latency or output distribution shifts.",
      "Hardware Root of Trust: Use secure enclaves (e.g., Confidential Computing) for model serving.",
      "Zero Trust Networking: Authenticate every connection between the app and the model."
    ],
    attackScenarios: [
      { title: "Container Hijack", description: "Attacker replaces a serving container with a version that intercepts all user prompts and logs them to an external server." },
      { title: "API Proxy Injection", description: "Attacker compromises a load balancer and injects a script that subtly changes 'Fraud: False' to 'Fraud: True' for a competitor's requests." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Sysdig Secure", description: "Runtime security for model containers with anomaly detection.", url: "https://sysdig.com/", cost: "€€", type: "Third-party" }
    ]
  },
  {
    id: "SAIF-R07",
    title: "Denial of ML Service",
    description: "Attackers feed inputs to the model that result in excessively high resource consumption, causing disruptions or high costs for the ML service.",
    commonRisks: [
      "Financial 'denial of wallet' via high token/GPU usage charges.",
      "Model unavailability for legitimate users during an attack.",
      "System-wide crashes due to resource exhaustion in the inference engine.",
      "Degradation of downstream application performance."
    ],
    preventionStrategies: [
      "Rate Limiting and Quotas: Enforce strict per-user and per-app token and request limits.",
      "Input Size Constraints: Block excessively long or semantically recursive prompts early.",
      "Resource Monitoring: Auto-scale and implement circuit breakers when GPU usage spikes.",
      "Semantic Caching: Reuse responses for repeated queries to save computation."
    ],
    attackScenarios: [
      { title: "Token Exhaustion", description: "Attacker floods an LLM endpoint with recursive prompts designed to maximize internal reasoning loops and cost." },
      { title: "High-Latency Queries", description: "Attacker submits complex images designed to take 10x longer to process than normal images, clogging the inference queue." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Cloudflare WAF", description: "L7 protection with specific rate-limiting and bot detection.", url: "https://www.cloudflare.com/waf/", cost: "€€", type: "Third-party" }
    ]
  },
  {
    id: "SAIF-R08",
    title: "Model Reverse Engineering",
    description: "Attackers gain unauthorized insights into the model by analyzing systematically collected inputs and outputs, stealing Intellectual Property.",
    commonRisks: [
      "Creation of surrogate models that mimic the proprietary model's logic.",
      "Discovery of sensitive logic patterns or training data secrets.",
      "Bypassing 'security through obscurity' measures built into the prompt.",
      "Commercial loss to competitors who clone the service functionality."
    ],
    preventionStrategies: [
      "Output Obfuscation: Add subtle noise to outputs (Differential Privacy) or round confidence scores.",
      "Query Throttling: Prevent the high-velocity systematic probing required for extraction.",
      "Confidence Masking: Only return the predicted label, not the full probability distribution.",
      "Monitoring: Detect patterns indicative of a systematic extraction attempt."
    ],
    attackScenarios: [
      { title: "Surrogate Model Training", description: "An attacker queries a proprietary pricing model 1 million times to train a local model that replicates its logic for free." },
      { title: "Feature Extraction", description: "Attacker probes a loan model to find exactly which keywords in a resume lead to higher approval ratings." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "PrivacyRaven", description: "Test your models locally against reverse-engineering and extraction attacks.", url: "https://github.com/trailofbits/PrivacyRaven", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "SAIF-R09",
    title: "Insecure Integrated Component",
    description: "Attackers exploit security vulnerabilities in third-party software interacting with the model, such as plugins, agents, or orchestration frameworks.",
    commonRisks: [
      "Remote Code Execution (RCE) via vulnerable third-party plugins.",
      "Unauthorized tool access (e.g., file system or network) via the AI agent.",
      "Confidentiality breaches via tool manipulation.",
      "Privilege escalation by exploiting over-privileged integration points."
    ],
    preventionStrategies: [
      "Component Scanning: Regularly audit third-party plugins and libraries for CVEs.",
      "Sandboxing: Run all integrated tools in isolated, low-privilege container environments.",
      "Least Privilege Agency: Restrict exactly what APIs and data a plugin can call.",
      "AIBOM: Maintain a manifest of all integrated AI components."
    ],
    attackScenarios: [
      { title: "Vulnerable Retrieval Plugin", description: "An attacker exploits a path traversal vulnerability in a PDF-reading plugin used by an AI agent to read local system secrets." },
      { title: "Shell Command Injection", description: "An agent with a 'Python REPL' tool is tricked into running `import os; os.system('ls')` by a clever user prompt." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Snyk", description: "Automated vulnerability scanning for plugins and integrated frameworks.", url: "https://snyk.io/", cost: "€€", type: "Third-party" }
    ]
  },
  {
    id: "SAIF-R10",
    title: "Prompt Injection",
    description: "Attackers manipulate the model's input directly or indirectly to cause malicious, illegal, or unintended behavior in the AI application.",
    commonRisks: [
      "Bypassing system guardrails and safety filters (Jailbreaking).",
      "Unauthorized execution of agentic actions (e.g., mass deletions).",
      "Redirection of model goals to exfiltrate data or spread misinformation.",
      "Loss of control over the AI persona and instructions."
    ],
    preventionStrategies: [
      "Input Validation and Sanitization: Implement semantic filters to detect override attempts.",
      "Output Validation: Check that the model's response matches the intended persona and rules.",
      "Adversarial Testing: Stress test the model with known injection patterns (e.g., 'DAN').",
      "Context Isolation: Clearly mark where user input ends and system instructions begin."
    ],
    attackScenarios: [
      { title: "Goal Redirection", description: "User tricks a support bot into writing code for a malware script by framing it as a 'fictional cyber-thriller scenario'." },
      { title: "Indirect Exfiltration", description: "Attacker places a hidden instruction on a webpage to send the summarized text to their server; the model obeys." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Lakera Guard", description: "Real-time prompt protection and filtering.", url: "https://www.lakera.ai/", cost: "€€€", type: "Third-party" },
      { name: "Garak", description: "Local tool to probe models for prompt injection susceptibility.", url: "https://github.com/leondz/garak", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "SAIF-R11",
    title: "Model Evasion",
    description: "Attackers manipulate the model's input by applying slight perturbations to cause incorrect inference results while appearing normal to humans.",
    commonRisks: [
      "Bypassing fraud or malware detection filters in automated systems.",
      "Misclassification of safety-critical inputs (e.g., medical images).",
      "Security bypasses in automated authentication or biometric systems.",
      "Integrity failure of content moderation filters."
    ],
    preventionStrategies: [
      "Adversarial Training: Train the model on perturbed examples to improve its noise robustness.",
      "Input Pre-processing: Use techniques like blurring or bit-depth reduction to disrupt noise.",
      "Model Ensembling: Use multiple different models to verify predictions before action.",
      "Confidence Thresholding: Reject low-confidence predictions in safety-critical tasks."
    ],
    attackScenarios: [
      { title: "Malware Filter Bypass", description: "An attacker adds a few bytes of 'junk data' to a virus file so an AI scanner classifies it as a benign document." },
      { title: "ID Verification Spoof", description: "Attacker uses a printed mask with a subtle adversarial pattern to trick a biometric login system into seeing a different user." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "ART (Adversarial Robustness Toolbox)", description: "Generate and test robustness against model evasion perturbations.", url: "https://github.com/Trusted-AI/adversarial-robustness-toolbox", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "SAIF-R12",
    title: "Sensitive Data Disclosure",
    description: "Attackers trick the model into revealing sensitive information (PII, secrets, or context) in its response that it should have kept confidential.",
    commonRisks: [
      "PII leaks in generated content (e.g., names, SSNs, emails).",
      "Exposure of secret keys or internal system details from the prompt.",
      "Privacy breaches leading to legal penalties and loss of trust.",
      "Discovery of private training data through memorization attacks."
    ],
    preventionStrategies: [
      "Output Sanitization: Scan model responses for patterns like SSNs or API keys before delivery.",
      "Fine-Tuning Sanitization: Remove sensitive data from the dataset before training.",
      "Adversarial Testing: Use red teaming to find prompts that elicit sensitive data.",
      "Differential Privacy: Limit the model's ability to memorize specific data points."
    ],
    attackScenarios: [
      { title: "Credential Leak", description: "A user asks 'What are the environment variables for this server?' and the model outputs a list containing the DB password." },
      { title: "PII Recall", description: "Attacker queries: 'Who lives at 123 Maple St?' and the model reveals the name and phone number from its training set." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "Presidio", description: "Redact PII from model responses locally before user delivery.", url: "https://github.com/microsoft/presidio", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "SAIF-R13",
    title: "Inferred Sensitive Data",
    description: "The model provides sensitive information that it did not have access to by inferring it from training data patterns or user prompts.",
    commonRisks: [
      "Unintended discovery of private user attributes (e.g., health status, location).",
      "Disclosure of sensitive information that was never explicitly collected.",
      "Sophisticated privacy breaches that bypass traditional redaction.",
      "Reputational damage due to invasive 'creepy' model predictions."
    ],
    preventionStrategies: [
      "Adversarial Training: Specifically train the model to refuse inferring sensitive attributes.",
      "Output Validation: Detect and block responses that contain inferred private facts.",
      "Differential Privacy: Limit the model's ability to learn specific patterns from individuals.",
      "Context Masking: Provide only the necessary context to the model to limit inference scope."
    ],
    attackScenarios: [
      { title: "Health Inference", description: "An AI travel bot infers a user has a specific medical condition based on diet preferences and offers unsolicited medical advice." },
      { title: "Political Alignment Prediction", description: "A hiring bot infers a candidate's political views based on their university and hobby, using it as a hidden rejection factor." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "ML Privacy Meter", description: "Quantify how much sensitive info is leaking via model inference.", url: "https://github.com/privacytrustlab/ml_privacy_meter", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "SAIF-R14",
    title: "Insecure Model Output",
    description: "Model output is handled insecurely by the application, resulting in vulnerabilities like Cross-Site Scripting (XSS) or SQL Injection.",
    commonRisks: [
      "Cross-Site Scripting (XSS) in UI components that render model text.",
      "SQL Injection if output is used directly in raw database queries.",
      "Unauthorized system commands if output is passed to a shell.",
      "CSRF if model-generated links are followed without validation."
    ],
    preventionStrategies: [
      "Output Validation: Treat all model output as untrusted user input.",
      "Context-Aware Encoding: Escape HTML, SQL, or shell characters properly before use.",
      "Adversarial Testing: Attempt to make the model generate destructive strings.",
      "Framework Safeguards: Use libraries like DOMPurify to clean all rendered content."
    ],
    attackScenarios: [
      { title: "Chat XSS", description: "Attacker tricks an LLM into generating a `<script>` tag that executes in the browser of the admin viewing the logs." },
      { title: "Prompt-driven SQLi", description: "A user tricks a bot into outputting `' OR 1=1 --` which is then used by a legacy backend to bypass authentication." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "DOMPurify", description: "Standard client-side sanitizer for LLM text before rendering.", url: "https://github.com/cure53/dompurify", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "SAIF-R15",
    title: "Rogue Actions",
    description: "Attackers exploit insufficiently restricted model access to cause autonomous harm in the real or digital world.",
    commonRisks: [
      "Unauthorized autonomous operations (e.g., mass database deletions).",
      "Financial fraud via autonomous agent tools (unintended refunds).",
      "Physical world safety risks in robotics, IoT, or industrial control.",
      "Brand destruction via autonomous offensive social media posting."
    ],
    preventionStrategies: [
      "Output Validation: Intercept and block unauthorized tool calls generated by the model.",
      "Human-in-the-Loop: Require manual approval for all high-impact actions.",
      "Least Agency: Only give the model the minimal tools needed for its task.",
      "Behavioral Monitoring: Detect and stop agentic loops that deviate from norms."
    ],
    attackScenarios: [
      { title: "Email Broadcast Abuse", description: "An agent with 'Send Email' access is tricked into sending a phishing link to the entire client list." },
      { title: "Infrastructure Destruction", description: "An SRE bot is tricked into thinking the production environment is 'staging' and runs a mass teardown command." }
    ],
    references: [{ title: "SAIF Risks", url: "https://saif.google/secure-ai-framework/risks" }],
    suggestedTools: [
      { name: "AgentOps", description: "Audit trail and safety checks for autonomous agent tool usage.", url: "https://www.agentops.ai/", cost: "€€", type: "Third-party" }
    ]
  }
];
