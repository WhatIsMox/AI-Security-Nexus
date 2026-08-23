
import { OwaspTop10Entry } from './types';

export const OWASP_MCP_TOP_10_DATA: OwaspTop10Entry[] = [
  {
    id: "MCP1:2025",
    title: "Token Mismanagement & Secret Exposure",
    description: "Hard-coded credentials, long-lived tokens, and secrets stored in model memory or MCP logs can expose sensitive environments to unauthorized access and lateral movement.",
    commonRisks: [
      "Secrets embedded in prompts, tools, or configuration files that leak via logs or telemetry.",
      "Long-lived or overly broad tokens reused across tools and sessions.",
      "Debug traces exposing API keys, service accounts, or internal endpoints.",
      "Prompt-injection-driven exfiltration of cached credentials or system context.",
      "Client tokens forwarded directly to downstream APIs, breaking audit trails and creating confused deputy paths.",
      "Secrets stored in environment variables, plain text code, or logs where the LLM or verbose tooling can reach them."
    ],
    preventionStrategies: [
      "Use short-lived, scoped tokens with automatic rotation and revocation.",
      "Centralize secret storage in a vault and inject at runtime (never in prompts).",
      "Redact sensitive values from logs, traces, and prompt history.",
      "Continuously scan repos and artifacts for secrets before deployment.",
      "Keep secrets management in transparent middleware that is inaccessible to the LLM.",
      "Prohibit token passthrough; use tokens explicitly issued to the MCP server or validated On-Behalf-Of flows."
    ],
    attackScenarios: [
      { title: "Prompt-Injected Secret Dump", description: "An attacker hides instructions in retrieved context that cause the agent to print cached API keys in its next response." },
      { title: "Token Reuse Lateral Move", description: "A long-lived token embedded in a tool config is stolen and reused to access unrelated MCP servers and data sources." },
      { title: "Log Scrape Leak", description: "Debug logs capture bearer tokens and are later queried by the model, leaking secrets." },
      { title: "Hard-Coded Tool Secret", description: "A tool ships with embedded credentials that are exposed through prompts or logs." },
      { title: "Memory Cache Exposure", description: "Secrets stored in model memory are surfaced in unrelated conversations." },
      { title: "Confused Deputy Passthrough", description: "An MCP server forwards a user's client token to a downstream API and is tricked into using that user's privileges outside the server's intended policy." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Gitleaks", description: "Secret-scanning for repositories and CI pipelines to prevent credential leaks.", url: "https://github.com/gitleaks/gitleaks", cost: "Free tier / $49/mo", type: "Local" },
      { name: "TruffleHog", description: "Detects secrets in code, history, and cloud storage with verified checks.", url: "https://github.com/trufflesecurity/trufflehog", cost: "Free OSS / $25/user/mo", type: "Local" },
      { name: "HashiCorp Vault", description: "Centralized secrets management with leasing, rotation, and access policies.", url: "https://www.vaultproject.io/", cost: "Free OSS / ~$25/mo (Cloud)", type: "Third-party" }
    ]
  },
  {
    id: "MCP2:2025",
    title: "Privilege Escalation via Scope Creep",
    description: "Temporary or loosely defined permissions within MCP servers often expand over time, allowing agents or tools to gain unintended capabilities and perform unauthorized actions.",
    commonRisks: [
      "Tokens granted wider scopes than necessary for a single task.",
      "Accumulated permissions across chained tools and agents.",
      "Lack of expiry for temporary privileges or session-based access.",
      "Inconsistent enforcement of scopes across tool boundaries.",
      "MCP servers relying on session IDs alone instead of re-checking validated user and client identity.",
      "Permission mismatches where the LLM can drive tools with broader access than the user should have."
    ],
    preventionStrategies: [
      "Enforce least-privilege scopes per tool call and task.",
      "Adopt just-in-time access with strict expiry and re-authorization.",
      "Review and audit scope policies regularly for drift.",
      "Use policy-as-code to centrally validate permissions at runtime.",
      "Use OAuth token delegation to pass user context while preserving distinct MCP server non-human identity.",
      "Centralize policy enforcement for authentication, authorization, consent, tool filtering, and audit logging."
    ],
    attackScenarios: [
      { title: "Scope Drift Exploit", description: "A token issued for read-only access silently accumulates write permissions over time, enabling repository modification by an attacker." },
      { title: "Agent Chain Escalation", description: "An agent chains two tools—each safe alone—to obtain admin-level access that neither tool should allow." },
      { title: "Temporary Scope Becomes Permanent", description: "Short-lived elevated access is never revoked and becomes the default scope." },
      { title: "Wildcard Permission Abuse", description: "An overly broad scope grants access to unrelated resources." },
      { title: "Expired Token Still Valid", description: "A supposedly expired token remains accepted by an MCP server." },
      { title: "Session ID Treated as Identity", description: "An attacker obtains a session identifier and performs sensitive actions because the MCP server does not re-check OAuth identity and authorization." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Open Policy Agent (OPA)", description: "Policy engine for enforcing least-privilege and runtime authorization decisions.", url: "https://www.openpolicyagent.org/", cost: "Free", type: "Local" },
      { name: "Permit.io", description: "Authorization service for fine-grained, time-bound access control.", url: "https://www.permit.io/", cost: "Free tier / $249/mo", type: "Third-party" }
    ]
  },
  {
    id: "MCP3:2025",
    title: "Tool Poisoning",
    description: "Attackers compromise tools, plugins, schemas, or their outputs to inject malicious or misleading context, steering model behavior through trusted interfaces.",
    commonRisks: [
      "Malicious tool updates (rug pulls) that alter behavior after installation.",
      "Schema poisoning that tricks models into unsafe or privileged tool calls.",
      "Tool shadowing with lookalike services that intercept requests.",
      "Injected or manipulated tool outputs that override system intent.",
      "Unsigned tool manifests that allow descriptions, schemas, versions, or required permissions to change without integrity checks.",
      "Tool descriptions that advertise safe behavior while runtime code performs undeclared actions such as network writes."
    ],
    preventionStrategies: [
      "Pin tool versions and verify integrity with cryptographic signatures.",
      "Validate tool schemas and outputs against strict, allowlisted formats.",
      "Use provenance and attestation for all tool artifacts.",
      "Monitor tool behavior for drift and unexpected output patterns.",
      "Require signed tool manifests containing description, schema, version, and required permissions; verify hash and signature at load time.",
      "Compare tool descriptions against runtime behavior and expose only minimal fields needed by the model."
    ],
    attackScenarios: [
      { title: "Rug-Pull Plugin Update", description: "A trusted MCP tool updates and begins injecting hidden instructions that exfiltrate data on every call." },
      { title: "Schema Trap", description: "A poisoned tool schema mislabels parameters, causing the model to send secrets to a public endpoint." },
      { title: "Tool Shadowing", description: "A lookalike tool intercepts requests and alters responses." },
      { title: "Output Poisoning", description: "A compromised tool returns malicious content that overrides system intent." },
      { title: "Schema Version Swap", description: "An attacker swaps a schema version to change parameter meanings." },
      { title: "Description-Behavior Mismatch", description: "A tool description claims read-only lookup behavior, but the tool code performs external network writes when invoked by the model." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Sigstore Cosign", description: "Sign and verify tool artifacts to ensure integrity and provenance.", url: "https://github.com/sigstore/cosign", cost: "Free", type: "Local" },
      { name: "in-toto", description: "Supply chain attestation framework for verifying tool build and release steps.", url: "https://github.com/in-toto/in-toto", cost: "Free", type: "Local" },
      { name: "OpenSSF Scorecard", description: "Evaluates security posture of open-source tool dependencies.", url: "https://github.com/ossf/scorecard", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "MCP4:2025",
    title: "Software Supply Chain Attacks & Dependency Tampering",
    description: "MCP ecosystems rely on open-source packages, connectors, and plugins. Compromised dependencies can alter agent behavior or introduce execution-level backdoors.",
    commonRisks: [
      "Typosquatting or dependency confusion in MCP tool registries.",
      "Malicious code in transitive dependencies.",
      "Unsigned plugins or connectors replaced in build pipelines.",
      "Outdated packages with known vulnerabilities used in tool runtimes.",
      "Builds without AIBOMs or provenance metadata, making tampering and dependency drift hard to detect.",
      "CI/CD pipelines that allow unapproved dependencies, failed policy checks, or vulnerable code to ship."
    ],
    preventionStrategies: [
      "Maintain an SBOM for all MCP tools, connectors, and libraries.",
      "Pin versions and verify checksums for tool artifacts.",
      "Continuously scan dependencies for CVEs and license issues.",
      "Adopt provenance tracking and signed releases for all MCP modules.",
      "Use SAST, dynamic testing, SCA, and manual security review as gates for new or updated tools.",
      "Use signed container images, monitor OSV/CVE sources, and maintain AIBOMs for every build."
    ],
    attackScenarios: [
      { title: "Dependency Confusion", description: "An attacker publishes a higher-version package to a public registry that gets pulled into the MCP build." },
      { title: "Compromised Connector", description: "A third-party MCP connector update introduces a hidden remote shell during initialization." },
      { title: "Registry Hijack", description: "A tool registry is compromised and serves tampered packages to agents." },
      { title: "Malicious Container Image", description: "A poisoned MCP runtime image exfiltrates prompts and tokens." },
      { title: "Build Pipeline Tampering", description: "Artifacts are modified in CI before being deployed to MCP servers." },
      { title: "Policy Gate Bypass", description: "A connector with a vulnerable dependency is released because the build pipeline does not fail on SCA or policy-as-code findings." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Syft / Grype", description: "Generate SBOMs and scan MCP dependencies for vulnerabilities.", url: "https://github.com/anchore/syft", cost: "Free", type: "Local" },
      { name: "Snyk", description: "Dependency scanning and prioritization for vulnerable MCP components.", url: "https://snyk.io/", cost: "Free tier / $25/dev/mo", type: "Third-party" }
    ]
  },
  {
    id: "MCP5:2025",
    title: "Command Injection & Execution",
    description: "Agents that construct and execute system commands or API calls from untrusted input can be coerced into running arbitrary code or destructive actions.",
    commonRisks: [
      "Shell command injection through concatenated prompts or tool parameters.",
      "Unsafe execution of model-generated code without validation.",
      "Abuse of high-privilege tool access for lateral movement.",
      "RCE via unsafe deserialization or eval-style runtimes.",
      "Tool inputs or outputs that skip JSON Schema validation and pass malformed data into commands, APIs, or queries.",
      "Unbounded execution time, CPU, memory, or filesystem use allowing runaway tools and DoS conditions."
    ],
    preventionStrategies: [
      "Never pass raw user or context input directly into command execution.",
      "Use allowlisted commands and strict parameter schemas.",
      "Run tools in isolated sandboxes with restricted networking.",
      "Validate and lint model outputs before execution.",
      "Define JSON Schemas for every tool input and output; reject malformed or unrecognized data before execution.",
      "Apply timeouts, resource quotas, output size limits, and sanitization/encoding for XSS, SQL injection, and RCE primitives."
    ],
    attackScenarios: [
      { title: "Shell Injection", description: "A tool uses `cmd = \"grep \" + user_input` and executes it, enabling `; rm -rf /` injection." },
      { title: "Autonomous Script Run", description: "An agent retrieves a script from a URL and runs it without verification, installing a backdoor." },
      { title: "Template Injection", description: "Untrusted input is used to build shell templates, enabling command execution." },
      { title: "Parameter Smuggling", description: "An attacker injects extra flags into tool parameters to bypass allowlists." },
      { title: "Eval-Style Execution", description: "Model output is passed into an eval-like runtime and executes arbitrary code." },
      { title: "Malformed JSON-RPC Execution", description: "A malformed tool call bypasses validation and reaches a command wrapper that treats attacker-controlled fields as executable arguments." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Semgrep", description: "Static analysis to detect unsafe command execution patterns in tool code.", url: "https://github.com/semgrep/semgrep", cost: "Free OSS / $40/dev/mo", type: "Local" },
      { name: "ShellCheck", description: "Linting for shell scripts to catch injection and quoting issues.", url: "https://github.com/koalaman/shellcheck", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "MCP6:2025",
    title: "Prompt Injection via Contextual Payloads",
    description: "Attackers hide instructions in retrieved documents, logs, or OCR text. The model treats these payloads as authoritative context and follows them.",
    commonRisks: [
      "Hidden instructions embedded in RAG sources or external files.",
      "Context mixing of untrusted content with system instructions.",
      "Injected payloads that override tool call constraints.",
      "Exfiltration or policy bypass via indirect prompt injection.",
      "Free-form text commands that allow the model to turn untrusted context into executable intent.",
      "Long-lived sessions where hidden instructions persist after the agent changes task or context."
    ],
    preventionStrategies: [
      "Treat external context as untrusted and clearly separate it from system prompts.",
      "Use content filtering and instruction-stripping on retrieved data.",
      "Require explicit user confirmation for high-impact actions.",
      "Constrain tool calls with schema validation and intent checks.",
      "Favor structured JSON tool invocation over free-form text commands.",
      "For high-risk actions, use human-in-the-loop approval or a separate LLM-as-a-judge policy check in a distinct context."
    ],
    attackScenarios: [
      { title: "Poisoned PDF Retrieval", description: "A model retrieves a PDF with hidden instructions that tell it to email sensitive context to an attacker." },
      { title: "OCR Injection", description: "An image contains microtext that instructs the model to disable safety checks before acting." },
      { title: "Email Thread Injection", description: "A malicious email reply includes instructions that the agent treats as authoritative." },
      { title: "Log File Injection", description: "Poisoned logs are retrieved and interpreted as instructions for tool calls." },
      { title: "Contextual Payload in Notes", description: "Hidden instructions in meeting notes cause the agent to exfiltrate data." },
      { title: "Persistent Task Switch Injection", description: "A hidden instruction survives in a long MCP session and affects a later, unrelated high-risk tool call." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Garak", description: "LLM vulnerability scanner with prompt-injection probes.", url: "https://github.com/leondz/garak", cost: "Free", type: "Local" },
      { name: "Promptfoo", description: "Regression testing for prompts and tool interactions against adversarial inputs.", url: "https://github.com/promptfoo/promptfoo", cost: "Free", type: "Local" }
    ]
  },
  {
    id: "MCP7:2025",
    title: "Insufficient Authentication & Authorization",
    description: "MCP servers, tools, or agents that do not properly verify identities or enforce access controls expose high-impact attack paths across the ecosystem.",
    commonRisks: [
      "Unauthenticated MCP endpoints accessible on internal networks.",
      "Weak token validation or missing audience and scope checks.",
      "Cross-tenant data access due to missing authorization boundaries.",
      "Impersonation of tools or agents in multi-agent workflows.",
      "Remote MCP servers that do not validate OAuth iss, aud, exp, and token signatures on every request.",
      "Local HTTP MCP servers bound too broadly or accepting requests without Origin validation."
    ],
    preventionStrategies: [
      "Require strong authentication (mTLS, OAuth2/OIDC) for all MCP traffic.",
      "Enforce fine-grained authorization on every tool call.",
      "Bind tokens to specific audiences, scopes, and lifetimes.",
      "Isolate tenants and agent identities with strict RBAC/ABAC.",
      "Treat authentication as mandatory for remote MCP servers and enforce TLS 1.2+ for all remote connections.",
      "For local HTTP, bind only to 127.0.0.1, require explicit auth, and validate the Origin header; prefer STDIO or Unix sockets where possible."
    ],
    attackScenarios: [
      { title: "Unauthenticated Tool Call", description: "A public-facing MCP endpoint accepts unauthenticated requests and performs privileged file access." },
      { title: "Token Replay", description: "An attacker replays a captured bearer token to impersonate a trusted agent." },
      { title: "Weak API Key Reuse", description: "A shared API key is reused across tools, allowing lateral access." },
      { title: "Missing Per-Tool Auth", description: "Tools assume upstream authentication and skip their own checks." },
      { title: "Cross-Tenant Access", description: "Authorization gaps allow one tenant to access another tenant's data." },
      { title: "Localhost Trust Abuse", description: "A local HTTP MCP server accepts browser-originated requests because it binds broadly and does not validate Origin or require explicit authentication." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Keycloak", description: "Open-source identity and access management for MCP services.", url: "https://www.keycloak.org/", cost: "Free", type: "Local" },
      { name: "Auth0", description: "Managed identity platform for secure authentication flows.", url: "https://auth0.com/", cost: "Free tier / $35 - $240/mo", type: "Third-party" }
    ]
  },
  {
    id: "MCP8:2025",
    title: "Lack of Audit and Telemetry",
    description: "Without comprehensive activity logging and alerting, unauthorized actions or data access can go undetected, undermining incident response.",
    commonRisks: [
      "Missing logs for tool invocations or context mutations.",
      "No correlation across agents, tools, and user actions.",
      "Inability to trace data exfiltration paths or policy violations.",
      "Delayed detection of anomalous or abusive behavior.",
      "Authentication, authorization, and configuration changes not logged with enough context for forensics.",
      "Verbose logs that capture sensitive fields because no field-level allowlist, redaction, or hashing is applied."
    ],
    preventionStrategies: [
      "Instrument all MCP interactions with structured, immutable audit logs.",
      "Centralize telemetry and correlate across agents and tools.",
      "Set real-time alerts for high-risk actions and data access.",
      "Retain logs with tamper-evident storage and access controls.",
      "Log tool invocations with parameters, resource access, auth events, and configuration changes including old and new values where safe.",
      "Feed logs into a SIEM and alert on suspicious patterns such as validation spikes, high-frequency tool calls, or unusual file access."
    ],
    attackScenarios: [
      { title: "Silent Data Exfiltration", description: "An attacker repeatedly pulls sensitive documents through a tool without triggering any alerts." },
      { title: "Undetected Policy Bypass", description: "An agent performs privileged actions with no traceability, delaying incident response." },
      { title: "Missing Tool Call Trace", description: "Critical tool calls are not logged, preventing forensic reconstruction." },
      { title: "Log Tampering", description: "Attackers modify or delete logs to hide their actions." },
      { title: "No Alerting on Anomalies", description: "High-risk actions occur without any automated notifications." },
      { title: "Sensitive Audit Spill", description: "A verbose audit trail captures tokens and filesystem paths, then exposes them during incident investigation or model-assisted log review." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "OpenTelemetry", description: "Standardized tracing and metrics for end-to-end MCP observability.", url: "https://opentelemetry.io/", cost: "Free", type: "Local" },
      { name: "Datadog", description: "Managed observability platform for alerting and audit analysis.", url: "https://www.datadoghq.com/", cost: "~$15 - $23/host/mo", type: "Third-party" }
    ]
  },
  {
    id: "MCP9:2025",
    title: "Shadow MCP Servers",
    description: "Unapproved or unsupervised MCP deployments outside formal governance often use default credentials or permissive configs, creating hidden attack surfaces.",
    commonRisks: [
      "Rogue MCP servers deployed without security review.",
      "Default credentials or open endpoints in internal networks.",
      "Data leakage through unsanctioned tool integrations.",
      "Inconsistent patching and configuration hardening.",
      "Servers deployed outside hardened containers or restricted network segments.",
      "Unregistered servers bypassing centralized policy enforcement, tool filtering, and approval workflows."
    ],
    preventionStrategies: [
      "Maintain an authoritative inventory of approved MCP servers.",
      "Enforce network segmentation and zero-trust access for MCP services.",
      "Scan for unknown endpoints and block unregistered MCP instances.",
      "Require centralized registration and policy enforcement for deployments.",
      "Deploy MCP servers in minimal, hardened, non-root containers with unnecessary packages and Linux capabilities removed.",
      "Use firewall rules or Kubernetes NetworkPolicies to deny inbound and outbound traffic except what is explicitly required."
    ],
    attackScenarios: [
      { title: "Shadow Lab Server", description: "A developer spins up an MCP server with default settings; an attacker discovers it and extracts test data." },
      { title: "Rogue Integration", description: "A team connects a personal MCP instance to production tools, leaking customer data." },
      { title: "Default Credentials", description: "A shadow MCP server ships with default passwords that are never changed." },
      { title: "Public IP Exposure", description: "An internal MCP instance is accidentally exposed on a public IP." },
      { title: "Unpatched Dev Instance", description: "A dev MCP server misses security updates and is compromised." },
      { title: "Unrestricted Shadow Egress", description: "An unapproved MCP server runs outside network policy and can call arbitrary external endpoints after prompt injection." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Cloud Custodian", description: "Policy-as-code for discovering and enforcing approved cloud resources.", url: "https://github.com/cloud-custodian/cloud-custodian", cost: "Free", type: "Local" },
      { name: "Wiz", description: "Cloud security platform for asset discovery and misconfiguration detection.", url: "https://www.wiz.io/", cost: "~$15k - $60k/yr (Enterprise)", type: "Third-party" }
    ]
  },
  {
    id: "MCP10:2025",
    title: "Context Injection & Over-Sharing",
    description: "Shared or persistent context windows can leak sensitive information across users, tasks, or agents, turning convenience into a data exposure risk.",
    commonRisks: [
      "Cross-tenant leakage from shared context buffers.",
      "Overly permissive context retention beyond task scope.",
      "Sensitive data echoed into subsequent sessions or tools.",
      "Context mixing that reveals private data to unauthorized users.",
      "User-specific data stored in global variables, class-level attributes, or shared singleton instances.",
      "MCP sessions that leave temporary files, in-memory context, file handles, or cached tokens behind after disconnect or timeout."
    ],
    preventionStrategies: [
      "Scope context to the minimum task and user boundary required.",
      "Expire or redact context buffers after each session.",
      "Apply DLP and PII redaction before context persistence.",
      "Segregate context across agents with strict access controls.",
      "Instantiate separate objects per session or use a strictly session-keyed state store such as Redis with session_id namespaces.",
      "Implement deterministic cleanup and per-session quotas for memory, CPU, filesystem usage, and API rate limits."
    ],
    attackScenarios: [
      { title: "Cross-Session Leakage", description: "A later user receives sensitive notes stored in a shared context window from a prior session." },
      { title: "Over-Shared Tool Context", description: "An agent passes full conversation logs to a third-party tool that only required a short summary." },
      { title: "Cross-Tenant Memory", description: "Shared context buffers leak information between tenants." },
      { title: "Overly Persistent Context", description: "Context persists beyond the task scope and resurfaces later." },
      { title: "Context Mixing", description: "Multiple tasks share context, causing sensitive data to be revealed to the wrong user." },
      { title: "Residual Session State", description: "A timed-out MCP session leaves cached tokens and temporary files behind, allowing the next session on the same host to access prior user context." }
    ],
    references: [
      { title: "OWASP MCP Top 10 (v0.1)", url: "https://owasp.org/www-project-mcp-top-10/" },
      { title: "OWASP Practical Guide for Secure MCP Server Development", url: "https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/" }
    ],
    suggestedTools: [
      { name: "Presidio", description: "Detect and redact PII before storing or sharing context.", url: "https://github.com/microsoft/presidio", cost: "Free", type: "Local" },
      { name: "Nightfall AI", description: "Cloud DLP for identifying and masking sensitive content in logs and prompts.", url: "https://www.nightfall.ai/", cost: "Free tier / $49/mo", type: "Third-party" }
    ]
  }
];
