
# OWASP AI Security Bible

The **OWASP AI Security Bible** is an interactive, graphical cyber-range and knowledge base designed for AI security professionals, auditors, and developers. It transforms static security documentation into a dynamic exploration tool, visualizing the complex landscape of AI threats, vulnerabilities, and testing methodologies.

## 🌟 Key Features

### 1. Interactive Architecture Dashboard
- **Visual Pipeline**: Explore the complete AI system lifecycle from User input to Data storage.
- **Layered Decomposition**: Clickable architectural components (Application, Model, Infrastructure, Data) that drill down into specific testing pillars.
- **Compliance Tracking**: Quick access to regulatory frameworks like the **EU AI Act**.

### 2. Advanced Threat Modelling
- **SAIF-Based Diagram**: An interactive, drag-and-pan diagram based on the **Secure AI Framework (SAIF)**.
- **Component Analysis**: Click on any architectural component (e.g., Vector DB, Model Serving) to see mapped threats specific to that asset.
- **Business Impact Analysis (BIA)**: A sortable view aligning technical vulnerabilities with business consequences.
- **Threat-to-Test Matrix**: Direct mapping between high-level threats (e.g., "Prompt Injection") and actionable test cases (e.g., "AITG-APP-01").
- **Dynamic Sorting**: Filter threats by Risk Level (Critical, High, Medium) or Attack Category.

### 3. Comprehensive Test Library
Access a curated database of **20+ specific AI security tests**, categorized by architectural pillar:
- **Application Testing**: Prompt Injection, Excessive Agency, SSRF via Plugins.
- **Model Testing**: Evasion Attacks, Model Inversion, Membership Inference, Poisoning.
- **Infrastructure Testing**: Supply Chain Tampering, Model Theft, Resource Exhaustion.
- **Data Testing**: Training Data Exposure, Poisoning, Consent Violations.

### 4. Dedicated Standards Views
Navigate the industry's leading security standards with specialized, color-coded interfaces:
- **🧠 OWASP Top 10 for LLM Applications 2025**: The definitive guide to LLM risks like Jailbreaking and Prompt Leaks.
- **⚙️ OWASP Machine Learning Security Top 10**: Critical risks for traditional ML systems including Adversarial Attacks and Data Poisoning.
- **🤖 OWASP Agentic AI Threats**: Emerging risks for autonomous agents, such as Memory Poisoning and Tool Misuse.

### 5. Deep-Dive Test Details
Each test case provides actionable intelligence:
- **Objectives**: What to verify.
- **Payloads & Code**: Actual attack vectors and prompt examples (e.g., DAN, base64 obfuscation, adversarial perturbations).
- **Mitigation Strategies**: Remediation advice and architectural fixes.
- **Tools**: Links to testing tools like Garak, TextAttack, and Adversarial Robustness Toolbox (ART).

---

## 📚 Data Sources & References

This application is built upon and references the following authoritative documents and frameworks:

1.  **OWASP AI Exchange & AI Testing Guide v1.0**: The core foundation for the testing methodology and architectural pillars.
2.  **Google Secure AI Framework (SAIF)**: Used for the threat modelling architectural decomposition.
3.  **OWASP Top 10 for Large Language Model Applications (2025 Version)**: Source for LLM-specific risks and mitigations.
4.  **OWASP Machine Learning Security Top 10**: Source for traditional ML vulnerabilities.
5.  **OWASP Agentic AI Threats**: Source for autonomous agent specific attack vectors (Memory Poisoning, Tool Misuse).
6.  **EU AI Act**: Referenced for compliance and regulatory context.
7.  **MITRE ATLAS**: Referenced within specific test cases for attack tactics and techniques.
8.  **NIST AI Risk Management Framework (AI RMF)**: Referenced for risk management strategies.

---

## 🚀 Getting Started (Local Development)

### Prerequisites
- Node.js (v16 or higher)
- npm or yarn

### Installation Steps

1.  **Download the source code** to your local machine.
2.  **Install dependencies**:
    ```bash
    npm install
    ```
3.  **Run the App**:
    ```bash
    npm run dev
    ```
4.  **Open in Browser**:
    Navigate to `http://localhost:5173` (or the URL shown in your terminal).

## 🛠 Tech Stack
- **Frontend**: React 18, TypeScript, Vite
- **Styling**: Tailwind CSS
- **Icons**: Lucide React
- **Visualization**: Custom SVG interactive diagrams

---

**License**: Content adapted from open-source OWASP documentation. Provided for educational and testing purposes.
