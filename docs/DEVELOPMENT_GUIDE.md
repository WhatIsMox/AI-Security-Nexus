# Developer & Agent Operations Guide

> **Project**: AI Security Nexus (OWASP-AI-Testing-Bible)  
> **Target**: Human Developers, CI Systems & Autonomous AI Agents

---

## 1. Prerequisites & Environment Setup

- **Node.js**: `v18+` or `v20.x` (see [`.nvmrc`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/.nvmrc))
- **Package Manager**: `npm` (v10+)

### Clean Installation
To install dependencies (including Vite and TypeScript devDependencies):
```bash
npm install --include=dev
```

---

## 2. Available Scripts & Workflows

| Command | Purpose |
| :--- | :--- |
| `npm run dev` | Starts Vite local development server on `http://127.0.0.1:5173` |
| `npm test` | Runs the complete automated test suite (Unit, Functional, Security, Build) |
| `npm run test:unit` | Runs unit & schema tests (`tests/unit/`) |
| `npm run test:functional` | Runs functional and routing tests (`tests/functional/`) |
| `npm run test:security` | Runs CSP and payload security tests (`tests/security/`) |
| `npm run test:build` | Runs build & GitHub Pages compatibility tests (`tests/build/`) |
| `npm run test:data` | Executes data schema & referential integrity validation |
| `npm run docs:sync` | Updates `docs/PROJECT_MAP.md` and `docs/AUTO_GENERATED_STATS.json` |
| `npm run docs:check`| CI verification that dynamic documentation matches data catalogs |
| `npm run build` | Compiles TypeScript (`tsc`) and builds production SPA to `dist/` |
| `npm run preview` | Previews the production build locally |

---

## 3. Application Architecture & Global Domain Filtering

The AI Security Nexus acts as a consolidated browser for multiple distinct AI frameworks (LLM, ML, Agentic, MCP, etc.). 
To provide a focused user experience, the application implements a **Global Domain Filtering** pattern.

- **State Management**: The central state `globalDomain` of type `GlobalDomain` (defined in `types.ts`) is maintained in `App.tsx`.
- **Prop Drilling Contract**: Any view component that renders aggregated cross-domain data (e.g., `Dashboard`, `ToolsDirectoryView`, `ThreatModelling`) MUST accept the `globalDomain: GlobalDomain` prop.
- **Local Filtering**: View components MUST use `useMemo` hooks to filter their respective data structures based on the `globalDomain` (e.g., `if (globalDomain === 'LLM') return ...`).
- **Testing Requirement**: New cross-domain views MUST be added to the assertions in `tests/functional/global-domain-filtering.test.mjs` to ensure the filter propagates without regression.

---

## 4. Mandatory Testing Policy for New Code & Implementations

> 🧪 **DEVELOPMENT MANDATE**: Every new component, route, framework threat entry, or security test case **must include a corresponding automated test** in `tests/` before being finalized.

1. **Feature Verification**: Verify that the new code behaves as intended through unit or functional tests.
2. **Schema & Integrity**: Ensure any new data item passes validation checks (`npm run test:unit` and `npm run test:data`).
3. **Continuous Regression Prevention**: Run `npm test` prior to submitting changes to guarantee zero regressions across the codebase.

---

## 5. Local Development & Live Reloading

1. Run `npm run dev`.
2. Open `http://127.0.0.1:5173` in a modern browser.
3. Fast-Refresh / HMR will automatically reload React components and SCSS/Tailwind styling changes.

---

## 6. GitHub Pages Deployment & Continuous Operability

The application is deployed as a **GitHub Pages** static website:
- **Primary CI/CD Workflow**: [`.github/workflows/deploy.yml`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/.github/workflows/deploy.yml)
- **Secondary Deployment Workflow**: [`.github/workflows/deploy-gh-pages.yml`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/.github/workflows/deploy-gh-pages.yml)
- **Deployment Trigger**: Any push to `main` or `master`.
- **Target Output Directory**: `dist/`

### 6.1 Maintaining Continuous GitHub Pages Compatibility

Every update made to the codebase must preserve full compatibility with GitHub Pages:

1. **Subdirectory Base Path Awareness**:
   GitHub Pages serves static sites under `https://<username>.github.io/<repository-name>/`.
   - In [`vite.config.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/vite.config.ts), `base` is automatically resolved from `process.env.BASE_PATH` (provided by GitHub Actions `configure-pages` action) or parsed from `process.env.GITHUB_REPOSITORY`.
   - **Do not hardcode absolute root links** (e.g. `<a href="/dashboard">` or `<img src="/logo.svg">`).
   - Use React component state navigation or relative asset imports (`import logo from './assets/logo.svg'`).

2. **No Server-Side Dependencies**:
   - The entire application runs client-side in the browser.
   - Never introduce backend API routes or server-side rendering (SSR) dependencies that fail on static hosts.

3. **Strict Content Security Policy (CSP)**:
   - Security meta tags are injected into `index.html` at build time by `vite.config.ts`.
   - All assets, scripts, styles, and font resources must comply with the CSP header defined in `vite.config.ts`.

4. **Pre-commit & PR Verification**:
   Before merging or finalizing changes, execute:
   ```bash
   npm run build && npm run preview
   ```
   Ensure the production bundle initializes cleanly and all views render properly without console errors.

---

## 7. Process Lifecycle, Debugging Shells & Resource Cleanup

> 🧹 **PROCESS HYGIENE DIRECTIVE**: When spawning background test environments, dev servers, preview servers, child processes, or debugging subshells, **they must be explicitly and cleanly shut down after testing concludes**.

### Guidelines for Developers & Agents:
1. **Never Leave Orphan Daemons**:
   Always kill dev servers (`npm run dev`) and preview servers (`npm run preview`) after verifying changes.
2. **Release Network Ports**:
   Ensure ports (`5173`, `4173`) are freed immediately to avoid conflicts with subsequent test runs.
3. **Agent Task Cleanup**:
   When using agentic tools to execute background commands, always cancel or kill background tasks upon task completion.


