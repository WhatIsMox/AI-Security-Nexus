# Agent Operating Guidelines & Workspace Directives

> **Project**: AI Security Nexus (OWASP-AI-Testing-Bible)  
> **Domain**: Interactive AI Security Framework Navigator, Threat Modeling & Red-Teaming Test Bible  
> **Target Audience**: AI Agents (Antigravity, Cursor, Claude Code, Copilot, Codex), Security Researchers, Frontend Engineers  
> **Primary Rule**: Maintain strict schema typing, preserve exact framework citations, enforce strict Content Security Policy (CSP), require that EVERY new implementation or addition includes automated tests in `tests/` verifying its correctness, and run automated data integrity checks after any catalog modification.

---

## 1. Project Overview & Architectural Mission

The **AI Security Nexus** is a state-of-the-art interactive graphical exploration of global AI security standards, bridging static security guidance into an actionable vulnerability navigator and red-team test suite.

### Key Frameworks Implemented
1. **OWASP Top 10 for LLM Applications (2026 Edition)**: `LLM01:2026` - `LLM10:2026` (`data_llm.ts`)
2. **OWASP Agentic Applications Top 10 (2026)**: `ASI01` - `ASI10` (`data_agentic_applications.ts`)
3. **OWASP Agentic Skills Top 10 (August 2026)**: `AST01` - `AST10` (`data_agentic.ts`)
4. **OWASP MCP Top 10 (v0.1)**: `MCP1:2025` - `MCP10:2025` (`data_mcp.ts`)
5. **Secure MCP Server Development Guide (v1.0)**: Hardening controls & readiness checklist (`data_secure_mcp_guide.ts`)
6. **OWASP GenAI Data Security Risks & Mitigations (2026)**: `DSGAI01` - `DSGAI21` & AI-DSPM capabilities (`data_genai_data_security.ts`)
7. **OWASP Machine Learning Security Top 10**: `ML01:2023` - `ML10:2023` (`data_ml.ts`)
8. **Google Secure AI Framework (SAIF)**: 15 Lifecycle Threats & interactive SVG threat model (`data_saif.ts`)
9. **Curated Security Test Suite**: 42+ structured tests across 4 Pillars (`data_tests.ts` & `data_agentic.ts`)
10. **Security Tools & Real-World Incident Catalogs**: Tool classifications and CVE/research citations (`tools_catalog.ts`, `incidents_catalog.ts`)

---

## 2. Technology Stack & Coding Standards

### Core Technologies
- **Runtime & Language**: TypeScript 5.2+ (strict mode enabled), React 18
- **Build System & Dev Server**: Vite 6, PostCSS, Tailwind CSS 3.4
- **Layout & Icons**: Bootstrap Grid SCSS (for fluid row/col grid systems), Lucide React
- **Hosting & Bundling**: GitHub Pages static bundle (`dist/`) via GitHub Actions

### Strict TypeScript Guidelines
- **Zero `any` policy**: Every entity must adhere to interfaces in [`types.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/types.ts).
- **Pillar Enum**: Always use `Pillar.APP`, `Pillar.MODEL`, `Pillar.INFRA`, or `Pillar.DATA` from `types.ts`.
- **Framework IDs**: Maintain standardized ID formats:
  - LLM: `LLM01:2026` ... `LLM10:2026`
  - ML: `ML01:2023` ... `ML10:2023`
  - Agentic Applications: `ASI01` ... `ASI10`
  - Agentic Skills: `AST01` ... `AST10`
  - MCP Top 10: `MCP1:2025` ... `MCP10:2025`
  - SAIF: `SAIF-R01` ... `SAIF-R15`
  - GenAI Data Security: `DSGAI01` ... `DSGAI21`
  - AI-DSPM: `ai-dspm-01` ... `ai-dspm-13`
  - Tests: `AITG-APP-*`, `AITG-MOD-*`, `AITG-INFRA-*`, `AITG-DATA-*`, `AGT-*`

---

## 3. UI/UX Design System & Styling Rules

1. **Aesthetic Baseline**:
   - Background: Dark slate aesthetic (`bg-slate-950`, `bg-slate-900/50`, `border-slate-800`).
   - Text Hierarchy: Primary `text-slate-100`, secondary `text-slate-400`, muted `text-slate-500`.
   - Brand Accents:
     - LLM / Agentic: Cyan (`cyan-400`, `cyan-500/20`) and Pink (`pink-400`, `pink-500/20`).
     - ML: Emerald (`emerald-400`, `emerald-500/20`).
     - SAIF / MCP: Blue / Indigo / Purple (`blue-400`, `purple-400`).
2. **Glassmorphism & Micro-interactions**:
   - Use `backdrop-blur-md`, subtle translucent borders (`border-slate-700/50`), and hover transitions (`transition-all duration-200 hover:border-cyan-500/50`).
3. **Responsive Grid & Mobile Compatibility**:
   - Use Tailwind responsive prefixes (`hidden md:flex`, `grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3`).
   - Use `bootstrap-grid.scss` classes (`container-fluid`, `row`, `col-*`) where applicable for fluid layouts.
   - Support mobile header drawer toggling via `isSidebarOpen` state in [`App.tsx`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/App.tsx).

---

## 4. Content Security Policy (CSP) & Security Constraints

The build injects strict CSP and Referrer headers via [`vite.config.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/vite.config.ts):
- `default-src 'self'`
- `script-src 'self' https://stats.byreference.net`
- `connect-src 'self' https://stats.byreference.net`
- `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`
- `font-src 'self' https://fonts.gstatic.com`
- `img-src 'self' data:`
- `object-src 'none'`

**Agent Rules for CSP**:
- ❌ **NEVER** use inline `javascript:` URLs or dynamic `eval()`.
- ❌ **NEVER** insert external scripts from unapproved CDNs.
- ✅ Always use standard React `onClick` event listeners and React state.
- ✅ Attack payloads in test items (`TestItem.payloads[].code`) must be rendered as raw text inside `<pre><code>` blocks, never rendered directly as active HTML.

---

## 5. Verification & Maintenance Commands

Every change made by an agent MUST be verified before concluding:

```bash
# 1. Run complete automated test suite (Unit, Functional, Security, Build)
npm test

# 2. Run data catalog schema & referential integrity validator
npm run test:data

# 3. Verify live HTTP resolution of all external links (incidents, tools, references)
npm run test:links

# 4. Synchronize auto-generated documentation and project statistics
npm run docs:sync

# 5. Verify documentation is in sync (CI check mode)
npm run docs:check

# 6. Compile TypeScript and build production bundle
npm run build

# 7. Run local development preview
npm run dev
```

---

## 6. How to Add or Modify Security Data & Features

> 🧪 **MANDATORY TESTING DIRECTIVE**: Every new implementation, UI feature, framework addition, or security test case **MUST be accompanied by an automated test** in [`tests/`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/tests/) verifying that it functions as expected and preserves data integrity.

### Adding a Security Test
1. Edit [`data_tests.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/data_tests.ts) (or [`data_agentic.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/data_agentic.ts) for agentic skill tests).
2. Ensure the test object provides:
   - `id`: unique ID matching pattern `AITG-[APP|MOD|INF|DAT|INFRA|DATA]-NN` or `AGT-NN`.
   - `pillar`: correct `Pillar` enum.
   - `riskLevel`: `'Critical' | 'High' | 'Medium' | 'Low'`.
   - `objectives`: non-empty string array.
   - `payloads`: list of `{ name, description, code }`.
   - `mitigationStrategies`: list of `{ type: 'Remediation' | 'Mitigation', content }`.
   - Framework references (`owaspTop10Ref`, `owaspAgenticRef`, `owaspSaifRef`, etc.).
3. Update or add corresponding tests in `tests/unit/data-schema.test.mjs` or `tests/unit/taxonomies-and-links.test.mjs`.
4. Run `npm test` and `npm run docs:sync`.

### Adding a Framework Threat Entry
1. Edit the corresponding data file (e.g. `data_llm.ts`, `data_agentic_applications.ts`).
2. Provide complete fields: `id`, `title`, `description`, `commonRisks`, `preventionStrategies`, `attackScenarios`, `references`, `suggestedTools`.
3. Add a test in `tests/unit/data-schema.test.mjs` asserting the new entry's existence, structure, and non-empty properties.
4. Run `npm test` and `npm run docs:sync`.

### Adding or Modifying Security Tools & Metadata (MANDATORY DIRECTIVE)
1. Whenever adding or referencing a security tool in [`tools_catalog.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/tools_catalog.ts):
   - You MUST define the base tool with `name`, `description`, `url`, `cost` (`'Free' | 'Free+Paid' | 'Paid'`), `type` (`'Local' | 'Third-party'`), and `category` (`'Offensive' | 'Defensive' | 'Both'`).
   - You **MUST ALWAYS** add a corresponding verified metadata entry in [`tool_details_catalog.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/tool_details_catalog.ts) (`TOOL_DATABASE`) supplying ALL mandatory fields:
     - `authorOrMaintainer`: Engineering team, foundation, or company (e.g. `NVIDIA / Leon Derczynski`, `Microsoft AI Red Team`, `CNCF`, `Aqua Security`).
     - `license`: Verified software license (e.g. `Apache-2.0`, `MIT`, `Commercial / SaaS API`).
     - `longDescription`: Detailed technical architecture and inner mechanics (minimum 30 characters).
     - `typicalUseCase`: Concrete real-world offensive or defensive security workflow (minimum 20 characters).
     - `keyFeatures`: Array of at least 3 concrete technical capabilities.
     - `installationOrQuickstart`: Exact, copyable shell installation command or quickstart code snippet.
     - `ecosystem`: Supported language runtimes and platforms (e.g. `['Python', 'PyTorch', 'Docker']`).
2. Run automated validation and link checks:
   ```bash
   npm test && npm run test:data && npm run test:links
   ```
   *(The CI data integrity validator `validate-data-integrity.mjs` will strictly fail if any tool lacks verified metadata!)*

### Adding or Modifying External Incident / Tool Links
1. When adding or updating incident citations (`incidents_catalog.ts`), security tools (`tools_catalog.ts`), or framework references (`data_*.ts`):
   - **Mandatory Live Verification**: Run `npm run test:links` to execute live HTTP `GET` requests against all external endpoints and confirm `HTTP 200 OK`.
   - **No Bot-Challenged Paywalls / Broken 404s**: Never use paywalled news links or anti-bot portals that return 401/403/404. Prefer permanent, open-access scholarly/official records (arXiv.org, NVD/NIST, CISA advisories, US DOJ, FTC, EDPB, US Copyright Office, verified Wikipedia).
   - **Security Attributes**: External links rendered in React components must strictly specify `target="_blank"` and `rel="noopener noreferrer"`.
   - Run `npm test && npm run test:data && npm run test:links` before concluding.

---

## 7. Automated Synchronization & CI/CD Pipeline

The project includes an automated GitHub Actions workflow ([`.github/workflows/agent-docs-sync.yml`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/.github/workflows/agent-docs-sync.yml)) that:
- Runs data integrity assertions on every push and PR.
- Runs a scheduled scan every Monday at 03:00 UTC.
- Automatically commits updated documentation stats if any data changes were made.

---

## 8. GitHub Pages Deployment & Continuous Operability Mandate

> ⚠️ **CRITICAL DIRECTIVE**: This application is deployed as a **GitHub Pages** static website via [`.github/workflows/deploy.yml`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/.github/workflows/deploy.yml). It **MUST CONTINUE TO DEPLOY AND RUN WITHOUT DEFECTS AFTER EVERY CHANGE**.

### Mandatory GitHub Pages Rules:
1. **Pure Static Bundling**:
   - The application is an entirely client-side Single Page Application (SPA).
   - Never introduce dependencies that require a persistent Node.js/Python backend runtime in production.
2. **Base Path Resilience**:
   - GitHub Pages serves the repository under a subdirectory path (e.g. `/<repo-name>/`).
   - Dynamic base configuration is handled in [`vite.config.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/vite.config.ts) via `process.env.BASE_PATH` and repository name extraction.
   - **Never hardcode absolute root paths** (e.g. `/assets/image.png` or `/detail/`) in HTML, CSS, or React routing components; always use relative assets or Vite asset imports (`import img from './assets/...'`).
3. **Build Output Verification**:
   - Every code change must produce a clean, valid `dist/` directory via `npm run build`.
   - Never commit broken TypeScript types or invalid imports that cause `tsc` or `vite build` to fail.
4. **Verification with Static Preview**:
   - Verify that the production static bundle runs correctly using `npm run preview` prior to finalizing changes.

---

## 9. Process Lifecycle, Debugging Shells & Resource Cleanup Mandate

> 🧹 **PROCESS LIFECYCLE DIRECTIVE**: If testing, debugging, or verification requires spawning background processes, dev servers, local test environments, child processes, or debugging shells, **they MUST be cleanly terminated and shut down upon completion** to prevent zombie processes from lingering and consuming system resources (CPU, RAM, or occupied ports).

### Mandatory Process Hygiene Rules:
1. **Explicit Termination**:
   - Always terminate background tasks, dev servers (`npm run dev`), preview servers (`npm run preview`), or spawned subprocesses when testing concludes.
   - For agent task runners, always issue kill / cleanup commands for background task IDs before completing turns.
2. **No Orphan Background Jobs**:
   - Do not leave detached background `node`, `vite`, or shell processes running after automated verification.
   - In test scripts and test fixtures, ensure `beforeEach` / `afterEach` and `after` hooks cleanly close all streams, servers, and child processes.
3. **Port Hygiene**:
   - Ensure default ports (e.g., `5173`, `4173`) are released immediately after test execution.


