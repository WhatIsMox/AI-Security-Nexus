# AI Security Nexus — System Project Map & Taxonomy Index

> **Auto-Generated Reference Document**  
> **Last Synchronized**: `2026-08-27T17:24:03.858Z`  
> *Do not edit manually. Re-generate via `npm run docs:sync`.*

---

## 📊 Live System Metrics

| Security Catalog / Asset | Identifier Prefix | Entry Count | Source Data File |
| :--- | :--- | :---: | :--- |
| **OWASP Top 10 for LLMs (2026)** | `LLM01:2026` - `LLM10:2026` | **10** | [`data_llm.ts`](../src/data/data_llm.ts) |
| **OWASP ML Security Top 10** | `ML01:2023` - `ML10:2023` | **10** | [`data_ml.ts`](../src/data/data_ml.ts) |
| **OWASP Agentic Applications Top 10** | `ASI01` - `ASI10` | **10** | [`data_agentic_applications.ts`](../src/data/data_agentic_applications.ts) |
| **OWASP Agentic Skills Top 10** | `AST01` - `AST10` | **10** | [`data_agentic.ts`](../src/data/data_agentic.ts) |
| **OWASP MCP Top 10 (v0.1)** | `MCP1:2025` - `MCP10:2025` | **10** | [`data_mcp.ts`](../src/data/data_mcp.ts) |
| **Google SAIF Threat Model** | `SAIF-R01` - `SAIF-R15` | **15** | [`data_saif.ts`](../src/data/data_saif.ts) |
| **OWASP GenAI Data Security (2026)** | `DSGAI01` - `DSGAI21` | **21** | [`data_genai_data_security.ts`](../src/data/data_genai_data_security.ts) |
| **AI-DSPM Posture Capabilities** | `ai-dspm-01` - `ai-dspm-13` | **13** | [`data_genai_data_security.ts`](../src/data/data_genai_data_security.ts) |
| **Security Test Cases (Total)** | `AITG-*`, `AGT-*` | **62** | [`data_tests.ts`](../src/data/data_tests.ts) & [`data_agentic.ts`](../src/data/data_agentic.ts) |
| **Tooling Registry Entries** | Security Tools | **241** | [`tools_catalog.ts`](../src/data/tools_catalog.ts) |
| **Real-World Incident Citations** | CVEs / Papers / Outages | **156** | [`incidents_catalog.ts`](../src/data/incidents_catalog.ts) |

### Test Case Pillar Distribution
- **AI Application Pillar (`Pillar.APP`)**: 17 tests
- **AI Model Pillar (`Pillar.MODEL`)**: 7 tests
- **AI Infrastructure Pillar (`Pillar.INFRA`)**: 6 tests
- **AI Data Pillar (`Pillar.DATA`)**: 25 tests

---

## 🗺️ Component Hierarchy & View Routing

`src/App.tsx` acts as the central state router coordinating 11 primary views:

```mermaid
graph TD
    App[src/App.tsx (State: currentView, activePillar, selectedTest)]
    App --> Sidebar[src/components/Sidebar.tsx]
    App --> Dashboard[src/components/Dashboard.tsx]
    App --> ThreatModelling[src/components/ThreatModelling.tsx]
    App --> OwaspTop10View[src/components/OwaspTop10View.tsx]
    App --> AgenticTop10View[src/components/AgenticTop10View.tsx]
    App --> SecureMcpGuideView[src/components/SecureMcpGuideView.tsx]
    App --> GenAiDataSecurityView[src/components/GenAiDataSecurityView.tsx]
    App --> TestList[src/components/TestList.tsx]
    App --> TestDetail[src/components/TestDetail.tsx]

    OwaspTop10View -->|Renders| LLM[OWASP LLM Top 10]
    OwaspTop10View -->|Renders| ML[OWASP ML Top 10]
    OwaspTop10View -->|Renders| SAIF[Google SAIF Threats]
    OwaspTop10View -->|Renders| MCP[OWASP MCP Top 10]
```

---

## 📁 Key File Index for Agents

- **Application Entry**: [`index.tsx`](../src/index.tsx), [`App.tsx`](../src/App.tsx), [`index.html`](../index.html)
- **Data Models & Types**: [`types.ts`](../src/types.ts), [`data.ts`](../src/data/data.ts)
- **Security Catalogs**:
  - [`data_llm.ts`](../src/data/data_llm.ts)
  - [`data_agentic.ts`](../src/data/data_agentic.ts)
  - [`data_agentic_applications.ts`](../src/data/data_agentic_applications.ts)
  - [`data_mcp.ts`](../src/data/data_mcp.ts)
  - [`data_secure_mcp_guide.ts`](../src/data/data_secure_mcp_guide.ts)
  - [`data_genai_data_security.ts`](../src/data/data_genai_data_security.ts)
  - [`data_ml.ts`](../src/data/data_ml.ts)
  - [`data_saif.ts`](../src/data/data_saif.ts)
  - [`data_tests.ts`](../src/data/data_tests.ts)
  - [`tools_catalog.ts`](../src/data/tools_catalog.ts)
  - [`incidents_catalog.ts`](../src/data/incidents_catalog.ts)
- **UI Components**:
  - [`components/Sidebar.tsx`](../src/components/Sidebar.tsx)
  - [`components/Dashboard.tsx`](../src/components/Dashboard.tsx)
  - [`components/ThreatModelling.tsx`](../src/components/ThreatModelling.tsx)
  - [`components/OwaspTop10View.tsx`](../src/components/OwaspTop10View.tsx)
  - [`components/AgenticTop10View.tsx`](../src/components/AgenticTop10View.tsx)
  - [`components/SecureMcpGuideView.tsx`](../src/components/SecureMcpGuideView.tsx)
  - [`components/GenAiDataSecurityView.tsx`](../src/components/GenAiDataSecurityView.tsx)
  - [`components/TestList.tsx`](../src/components/TestList.tsx)
  - [`components/TestDetail.tsx`](../src/components/TestDetail.tsx)
- **Build & Config**: [`vite.config.ts`](../vite.config.ts), [`tailwind.config.js`](../tailwind.config.js), [`tsconfig.json`](../tsconfig.json)
