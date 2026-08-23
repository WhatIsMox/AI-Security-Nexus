# Antigravity & Gemini Agent Operations Manual

> **Workspace**: `WhatIsMox/AI-Security-Nexus` (`/Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible`)  
> **Agent Engine**: Antigravity / Gemini 3.7+  
> **Purpose**: Antigravity specialized directives, quick-navigation indexes, subagent delegation patterns, and UI state routing.

---

## 🧭 Fast Reference Navigation

### State Management & Primary Views in [`App.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/App.tsx)
The UI is a state-driven single page application. Navigation is controlled via `currentView` and `activePillar`:

| `currentView` | `activePillar` | Component Rendered | Description |
| :--- | :--- | :--- | :--- |
| `'dashboard'` | `'ALL'` | [`Dashboard.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/Dashboard.tsx) | Executive metrics, framework cards, recent tests |
| `'threat-model'` | Any | [`ThreatModelling.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/ThreatModelling.tsx) | Interactive SVG architecture pipeline & SAIF threat flow |
| `'owasp-top10'` | `'TOP10'` | [`OwaspTop10View.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/OwaspTop10View.tsx) | OWASP LLM Applications Top 10 (2026 Edition) |
| `'owasp-ml-top10'` | `'MLTOP10'` | [`OwaspTop10View.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/OwaspTop10View.tsx) | OWASP Machine Learning Top 10 |
| `'owasp-agent-top10'`| `'AGENTTOP10'`| [`AgenticTop10View.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/AgenticTop10View.tsx) | Dual view: ASI01-ASI10 & AST01-AST10 |
| `'owasp-saif-top10'` | `'SAIFTOP10'` | [`OwaspTop10View.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/OwaspTop10View.tsx) | Google SAIF Threat Matrix |
| `'owasp-mcp-top10'` | `'MCPTOP10'` | [`OwaspTop10View.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/OwaspTop10View.tsx) | OWASP MCP Top 10 (v0.1) |
| `'secure-mcp-guide'` | `'SECUREMCPGUIDE'` | [`SecureMcpGuideView.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/SecureMcpGuideView.tsx) | Secure MCP Server Hardening Guide v1.0 |
| `'genai-data-security'`| `'GENAIDATASECURITY'`| [`GenAiDataSecurityView.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/GenAiDataSecurityView.tsx) | DSGAI01-DSGAI21 & AI-DSPM capabilities |
| `'audit-checklist'` | Any | [`AuditChecklistView.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/AuditChecklistView.tsx) | Interactive audit tracking, scoring & JSON/MD report export |
| `'tools'` | Any | [`ToolsDirectoryView.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/ToolsDirectoryView.tsx) | Consolidated security tools directory & posture filtering |
| `'incidents'` | Any | [`IncidentsDirectoryView.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/IncidentsDirectoryView.tsx) | Real-world AI security incidents & CVE explorer |
| `'tests'` | `Pillar \| 'ALL'` | [`TestList.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/TestList.tsx) | Filterable security test catalog (42+ tests) with keyword search |
| `'detail'` | `Pillar` | [`TestDetail.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/components/TestDetail.tsx) | Test drill-down with payloads, copy button, and remediations |

---

## ⚡ Antigravity Subagent Directives

When delegating tasks to subagents:
1. **Data Curation Agent**:
   - Focus: Updating `data_*.ts`, verifying taxonomy references, adding test cases, managing incident/tool citations.
   - Requirement: Must run `npm run test:data`, `npm run test:links`, and `npm run docs:sync` upon completion.
2. **Frontend UI/UX Agent**:
   - Focus: Styling components, updating SVG diagrams, enhancing micro-interactions, maintaining dark mode aesthetics.
   - Requirement: Keep bundle size in check; ensure `npm run build` succeeds with zero TypeScript errors.
3. **Security Reviewer Agent**:
   - Focus: Verifying CSP compliance in `vite.config.ts`, ensuring payloads in test cases are safely handled without XSS risks, validating `target="_blank"` and `rel="noopener noreferrer"` on all external links.

---

## 🛠️ Automated Operations & Knowledge Hooks

- **Automated Validation**: Whenever modifying data catalogs, run `npm run test:data`.
- **Live Link Verification**: Whenever modifying or adding external URLs, run `npm run test:links` to ensure 100% resolution with HTTP 200 OK.
- **Dynamic Stats & Project Map**: Auto-generated into `docs/PROJECT_MAP.md` and `docs/AUTO_GENERATED_STATS.json`.
- **Pre-commit / CI**: `.github/workflows/agent-docs-sync.yml` guarantees documentation freshness on every push and weekly cron.
- **GitHub Pages Continuous Deployment**: Verified via `.github/workflows/deploy.yml`. Ensure all asset references, static bundle outputs (`npm run build`), and CSP rules stay compatible with GitHub Pages hosting under subdirectory paths.
- **Process & Shell Lifecycle**: When spawning test environments, dev servers, or debugging shells, always terminate them cleanly upon test completion to avoid lingering background processes that waste system resources.


