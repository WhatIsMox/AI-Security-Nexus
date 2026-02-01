# AI Security Nexus

The **AI Security Nexus** is an interactive, graphical exploration of global AI security frameworks. It serves as a dynamic "Security Bible" for AI systems, transforming static documentation from OWASP and Google into a functional navigator for security professionals, auditors, and developers.

## 🌟 Key Features

### 1. Multi-Framework Intelligence
Navigate the most influential AI security standards through specialized, color-coded interfaces:
- **🧠 OWASP Top 10 for LLM Applications (2025)**: The definitive guide to LLM-specific risks like Prompt Injection and Sensitive Information Disclosure.
- **⚙️ OWASP Machine Learning Security Top 10**: Critical risks for traditional ML systems including Adversarial Evasion and Data Poisoning.
- **🤖 OWASP Agentic AI Threats**: Emerging risks for autonomous agents, such as Goal Hijacking and Tool Misuse.
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

### 4. Security Tooling Database
Each threat and test case is mapped to recommended security tools. The database includes:
- **Metadata**: Classification by **Cost** (Free to Premium) and **Deployment Type** (Local vs. Third-party).
- **Tool Categories**: Scanners (Garak, Promptfoo), Sanitizers (DOMPurify, Presidio), and Robustness libraries (ART, Foolbox).

## 📚 Data Sources & References

This application is built upon the following authoritative sources:
1. **OWASP AI Exchange & AI Testing Guide v1.0**
2. **Google Secure AI Framework (SAIF)**
3. **OWASP Top 10 for Large Language Model Applications (2025)**
4. **OWASP Machine Learning Security Top 10**
5. **OWASP Agentic AI Threats (ASI)**
6. **EU AI Act & NIST AI RMF**

## 🚀 Getting Started (Local Development)

### Prerequisites
- Node.js (v18 or higher)
- npm or yarn

### Installation
1. Clone the repository.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```

## 🛠 Tech Stack
- **Framework**: React 18 with TypeScript
- **Bundler**: Vite
- **Styling**: Tailwind CSS (via CDN for portability)
- **Icons**: Lucide React
- **Visualization**: Custom Interactive SVG Components

---

**License**: Content adapted from open-source OWASP and Google documentation. Provided for educational and security testing purposes.