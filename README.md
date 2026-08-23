<p align="center">
  <img src="./public/icon.png" width="128" height="128" alt="AI Security Nexus Logo" style="border-radius: 24px; box-shadow: 0 0 30px rgba(6, 182, 212, 0.4);" />
</p>

<h1 align="center">AI Security Nexus</h1>
<p align="center"><b>Interactive AI Security Framework Navigator, Threat Modeling & Red-Teaming Test Bible</b></p>

The **AI Security Nexus** is an interactive, graphical exploration of global AI security frameworks. It serves as a dynamic "Security Bible" for AI systems, transforming static documentation from OWASP and Google into a functional navigator for security professionals, auditors, and developers.

## 🌟 Key Features

### 1. Multi-Framework Intelligence
Navigate the most influential AI security standards through specialized, color-coded interfaces:
- **🧠 OWASP Top 10 for LLM Applications (2026)**: The updated OWASP GenAI/LLM risk list covering Prompt Injection, Sensitive Information Disclosure, Excessive Agency, Supply Chain, Data and Model Poisoning, Unbounded Consumption, Misinformation, Hidden Context Exposure, Vector and Embedding Weaknesses, and Improper Output Handling.
- **⚙️ OWASP Machine Learning Security Top 10**: Critical risks for traditional ML systems including Adversarial Evasion and Data Poisoning.
- **🤖 OWASP Agentic Top 10 — Applications and Skills**: Two coordinated views keep the frameworks distinct and complete. **ASI01-ASI10** covers application-wide risks such as goal hijack, tool misuse, identity abuse, agentic supply chains, RCE, poisoned memory, inter-agent communication, cascading failures, human trust, and rogue agents. **AST01-AST10** covers the reusable skill layer: malicious skills, supply-chain compromise, excessive permissions, metadata, external instructions, isolation, updates, scanning, governance, and cross-platform reuse.
- **🔗 OWASP MCP Top 10 (v0.1)**: Security risks for Model Context Protocol ecosystems, including tool poisoning and context injection.
- **🗄️ OWASP GenAI Data Security Risks and Mitigations 2026**: A detailed, searchable navigator for DSGAI01-DSGAI21 covering GenAI data leakage, agent credentials, shadow AI, poisoning, lifecycle governance, compliance, multimodal leakage, unsafe data gateways, vector stores, telemetry, context over-sharing, endpoint assistants, resilience, inference, labeler exposure, model exfiltration, and disinformation.
- **📘 Secure MCP Server Development Guide (v1.0)**: An interactive MCP hardening workspace with expandable control families, search, concept drill-downs, and an implementation readiness checklist.
- **🛡️ Google SAIF (Secure AI Framework) Risks**: A holistic mapping of 15+ risks across the entire AI lifecycle.

### 2. Interactive Architecture & Threat Modelling
- **Visual Pipeline**: Explore the AI system layers (Application, Model, Data, Infrastructure) through an interactive dashboard.
- **SAIF Risk Flow Map**: A complex, SVG-based diagram that visualizes where specific threats are **Introduced**, **Exposed**, and **Mitigated** across the architectural components.
- **Business Impact Matrix**: Align technical vulnerabilities with high-level business consequences and ownership responsibilities.

### 3. Comprehensive Security Test Library
Access a curated database of **30+ specific AI security test cases**, each including:
- **Objectives**: Clear goals for what to verify.
- **Payloads & Test Vectors**: Actual attack strings, "DAN" prompts, and adversarial code snippets.
- **Indicators of Vulnerability**: What "success" looks like for an attacker.
- **Remediation & Mitigation**: Concrete architectural fixes and defensive strategies.

### 4. OWASP GenAI Data Security Navigator
Explore **OWASP GenAI Data Security Risks and Mitigations 2026** as an interactive working reference:
- **AI-DSPM Capability Map**: 13 posture-management capabilities covering discovery, classification, lineage, access governance, DLP, vector security, integrity, telemetry, third parties, lifecycle, training governance, resilience, and shadow AI.
- **DSGAI Risk Navigator**: 21 expandable risk entries with attack flow, attacker capabilities, illustrative scenarios, impacts, CVEs/exploits, references, and cross-references.
- **Tiered Controls**: Foundational, hardening, and advanced mitigations with Buy / Build / Buy and Build scope labels for planning implementation work.
- **Search & Filtering**: Filter by risk theme, mitigation tier, CVE, keyword, and control text.

### 5. Security Tooling Database
Each threat and test case is mapped to recommended security tools. The database includes:
- **Metadata**: Classification by **Cost** (Free to Premium) and **Deployment Type** (Local vs. Third-party).
- **Tool Categories**: Scanners (Garak, Promptfoo), Sanitizers (DOMPurify, Presidio), and Robustness libraries (ART, Foolbox).

## 📚 Data Sources & References

This application is built upon the following authoritative sources:
1. **OWASP AI Exchange & AI Testing Guide v1.0**
2. **Google Secure AI Framework (SAIF)**
3. **OWASP Top 10 for Large Language Model Applications (2026), Version 2026**, OWASP GenAI Security Project: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
4. **OWASP Machine Learning Security Top 10**
5. **OWASP Top 10 for Agentic Applications for 2026 (ASI01-ASI10)**: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
6. **OWASP Agentic Skills Top 10 (AST01-AST10), August 2026**: https://owasp.org/www-project-agentic-skills-top-10/
7. **OWASP MCP Top 10 (v0.1)**
8. **OWASP GenAI Data Security Risks and Mitigations 2026, Version 1.0 (March 2026)**, OWASP GenAI Security Project: https://genai.owasp.org/resource/owasp-genai-data-security-risks-mitigations-2026/
9. **Secure MCP Server Development, Version 1.0 (February 2026)**, OWASP GenAI Security Project: https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
10. **EU AI Act & NIST AI RMF**

### Attribution for OWASP GenAI Data Security Risks and Mitigations 2026

The separate **OWASP GenAI Data Security** application section adapts content from **OWASP GenAI Data Security Risks and Mitigations 2026, Version 1.0, March 2026**, published by the OWASP GenAI Security Project at https://genai.owasp.org/resource/owasp-genai-data-security-risks-mitigations-2026/.

Referenced asset named in the source license notice: **OWASP Top 10 for LLMs - GenAI Red Teaming Guide**.

Changes made: the original document content has been transformed into structured application data and rendered as an interactive guide and risk navigator with search, theme filters, tier filters, scoped mitigation labels, source links, and acknowledgements for navigation and readability.

### Attribution for Secure MCP Server Development

The separate **Secure MCP Guide** application section adapts content from **Secure MCP Server Development, Version 1.0, February 2026**, published by the OWASP GenAI Security Project at https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/.

Referenced asset named in the source license notice: **OWASP Top 10 for LLMs - GenAI Red Teaming Guide**.

Changes made: the original document content has been transformed into structured application data and rendered as an interactive MCP hardening workspace with expandable sections, concept cards, search, and a readiness checklist.

## 🚀 Getting Started (Local Development)

### Prerequisites
- Node.js (v18 or higher)
- npm or yarn

### Installation
1. Clone the repository.
2. Install dependencies (including devDependencies required by Vite):
   ```bash
   rm -rf node_modules package-lock.json
   npm install --include=dev
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```

> If you encounter `sh: vite: command not found`, it means devDependencies were not installed correctly.  
> Re-run the commands above, or verify Vite is present with:
> ```bash
> npx vite --version
> ```

## 🌐 GitHub Pages Deployment

This project must be **built** before it will work on GitHub Pages. Serving the repo root directly will load `index.tsx` and fail in the browser.

Two supported options:
1. **GitHub Actions (recommended)**: Set Settings → Pages → Source to **GitHub Actions**. The `Deploy to GitHub Pages` workflow will build and publish `dist`.
2. **gh-pages branch**: Set Settings → Pages → Source to **gh-pages / (root)**. The `Deploy to gh-pages branch` workflow will build and publish `dist` to that branch.

## 🛠 Tech Stack
- **Framework**: React 18 with TypeScript
- **Bundler**: Vite
- **Styling**: Tailwind CSS (via PostCSS build)
- **Icons**: Lucide React
- **Visualization**: Custom Interactive SVG Components

---

**License**: Content adapted from open-source OWASP and Google documentation. Provided for educational and security testing purposes.

## 🧩 Troubleshooting

### vite: command not found
This project relies on Vite as a devDependency. If you see:

sh: vite: command not found

Run:

```bash
rm -rf node_modules package-lock.json
npm install --include=dev
npm run dev
```

Ensure you are using Node.js v18+ and that you did not install with `--omit=dev` or `--production`.

### Using other package managers
If you prefer yarn or pnpm:

```bash
yarn install
yarn dev
```

or

```bash
pnpm install
pnpm dev
```
