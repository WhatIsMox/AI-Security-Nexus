# Data Dictionary & Security Taxonomy Reference

> **Project**: AI Security Nexus (OWASP-AI-Testing-Bible)  
> **Purpose**: Definitive taxonomy, identifier format specifications, and cross-framework relationship mapping.

---

## 1. Security Framework Catalogs

### 1.1 OWASP Top 10 for LLM Applications (2026 Edition)
- **Data File**: [`data_llm.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/data_llm.ts)
- **ID Format**: `LLM01:2026` through `LLM10:2026`
- **Scope**:
  - `LLM01:2026`: Prompt Injection (Direct, Indirect, Multimodal, RAG, MCP)
  - `LLM02:2026`: Sensitive Information Disclosure
  - `LLM03:2026`: Supply Chain Vulnerabilities
  - `LLM04:2026`: Data and Model Poisoning
  - `LLM05:2026`: Improper Output Handling
  - `LLM06:2026`: Excessive Agency
  - `LLM07:2026`: System Prompt Leakage
  - `LLM08:2026`: Vector and Embedding Weaknesses
  - `LLM09:2026`: Misinformation and Hallucination
  - `LLM10:2026`: Unbounded Consumption and Denial of Service

### 1.2 OWASP Agentic Applications Top 10 (2026)
- **Data File**: [`data_agentic_applications.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/data_agentic_applications.ts)
- **ID Format**: `ASI01` through `ASI10`
- **Scope**: System-wide autonomous agent risks:
  - `ASI01`: Agent Goal Hijack
  - `ASI02`: Tool Misuse & Excessive Scope
  - `ASI03`: Identity, Delegation & Authorization Abuse
  - `ASI04`: Agentic Supply Chain & Dependency Compromise
  - `ASI05`: Remote Code Execution & Unsafe Execution
  - `ASI06`: Memory Poisoning & Context Corruption
  - `ASI07`: Insecure Inter-Agent Communication
  - `ASI08`: Cascading Failures & Autonomous Amplification
  - `ASI09`: Human Trust & Social Engineering Exploitation
  - `ASI10`: Rogue Agents & Governance Loss

### 1.3 OWASP Agentic Skills Top 10 (August 2026)
- **Data File**: [`data_agentic.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/data_agentic.ts)
- **ID Format**: `AST01` through `AST10`
- **Scope**: Skill package and discovery boundary risks:
  - `AST01`: Malicious Skills
  - `AST02`: Supply Chain Compromise
  - `AST03`: Excessive Permissions & Missing Least Privilege
  - `AST04`: Insecure Metadata & Deceptive Frontmatter
  - `AST05`: Untrusted External Instructions & Rug Pulls
  - `AST06`: Missing Isolation & Sandbox Escape
  - `AST07`: Insecure Updates & Hot-Reload Drift
  - `AST08`: Inadequate Scanning & Obfuscation Bypass
  - `AST09`: Missing Inventory & Governance Gaps
  - `AST10`: Cross-Platform Reuse & Security Property Loss

### 1.4 OWASP MCP Top 10 (v0.1) & Secure MCP Guide (v1.0)
- **Data Files**: [`data_mcp.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/data_mcp.ts), [`data_secure_mcp_guide.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/data_secure_mcp_guide.ts)
- **ID Format**: `MCP1:2025` through `MCP10:2025`
- **Scope**: Model Context Protocol security risks (token mismanagement, tool poisoning, injection, authorization).

### 1.5 OWASP GenAI Data Security (2026)
- **Data File**: [`data_genai_data_security.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/data_genai_data_security.ts)
- **ID Format**: `DSGAI01` through `DSGAI21`
- **Capabilities**: `ai-dspm-01` through `ai-dspm-13`

### 1.6 OWASP Machine Learning Security Top 10
- **Data File**: [`data_ml.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/data_ml.ts)
- **ID Format**: `ML01:2023` through `ML10:2023`

### 1.7 Google Secure AI Framework (SAIF)
- **Data File**: [`data_saif.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/data_saif.ts)
- **ID Format**: `SAIF-R01` through `SAIF-R15`

---

## 2. Test Catalog Taxonomy

Tests are partitioned across the 4 Pillars defined in `types.ts`:

| Pillar Enum | Prefix | Target Domain | Example Test ID |
| :--- | :--- | :--- | :--- |
| `Pillar.APP` | `AITG-APP-*` / `AGT-*` | Prompt boundaries, UI, agent reasoning, API gateways | `AITG-APP-01`, `AGT-01` |
| `Pillar.MODEL` | `AITG-MOD-*` | Adversarial weights, inversion, extraction, poisoning | `AITG-MOD-01` |
| `Pillar.INFRA` | `AITG-INFRA-*` / `AGT-*` | Sandboxes, MCP hosts, pipelines, registries, CI/CD | `AITG-INFRA-01`, `AGT-02` |
| `Pillar.DATA` | `AITG-DATA-*` | RAG corpora, vector stores, PII leakage, embeddings | `AITG-DATA-01` |

---

## 3. Tooling & Incident Taxonomy

- **Tooling Catalog** ([`tools_catalog.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/tools_catalog.ts)):
  - Categories: `Offensive`, `Defensive`, `Both`
  - Types: `Local`, `Third-party`
  - Cost: `Free`, `Free+Paid`, `Paid`, `€`, `€€`, `€€€`, `€€€€`
- **Incidents Catalog** ([`incidents_catalog.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/incidents_catalog.ts)):
  - Real-world disclosures (OpenAI ChatGPT leak, Samsung leak, ClawHavoc campaign, Bing Chat prompt injections).
