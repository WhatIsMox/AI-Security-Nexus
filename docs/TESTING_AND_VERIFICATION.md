# Testing & Verification Guide

> **Project**: AI Security Nexus (OWASP-AI-Testing-Bible)  
> **Target**: Quality Assurance, Security Test Authors & CI Automation

---

## 1. Multi-Tier Automated Testing Strategy

The project implements a zero-dependency, comprehensive test architecture built on native Node.js test infrastructure (`node:test` & `node:assert`):

### 1.1 Test Suite Hierarchy

| Test Suite | Path | Description | Execution Command |
| :--- | :--- | :--- | :--- |
| **Master Suite** | `scripts/run-all-tests.mjs` | Runs all test suites in sequence with formatted metrics | `npm test` |
| **Unit & Schema** | `tests/unit/*.test.mjs` | Strict schema assertions across all 8 frameworks and 42+ test items | `npm run test:unit` |
| **Functional & Logic**| `tests/functional/*.test.mjs` | View routing transitions, active pillar filtering, and search logic | `npm run test:functional` |
| **Security & CSP** | `tests/security/*.test.mjs` | CSP header compliance, raw payload rendering safety, and citation scheme validation | `npm run test:security` |
| **Build & GitHub Pages** | `tests/build/*.test.mjs` | Static output validation, base path support (`/<repo>/`), and pure SPA checks | `npm run test:build` |
| **Data Integrity** | `scripts/validate-data-integrity.mjs` | Deep cross-reference analysis & orphan detector | `npm run test:data` |

### 1.2 Mandatory Testing Policy for New Implementations & Additions

> ⚠️ **STRICT POLICY**: Every newly implemented feature, component, route, framework dataset, or security test case **must be accompanied by an automated test** to prove and continuously verify that it works properly.

- **For New Framework Threats / Risks**:
  Add an assertion in `tests/unit/data-schema.test.mjs` verifying the item ID, title, description, attack scenarios, and remediation fields.
- **For New Security Test Cases**:
  Add/verify the test item structure and ID formatting in `tests/unit/data-schema.test.mjs` and `tests/unit/taxonomies-and-links.test.mjs`.
- **For New UI Components & Views**:
  Add a functional test in `tests/functional/view-routing-and-filtering.test.mjs` asserting navigation state transitions, rendering conditions, and interaction handlers.
- **For External Tool or Citation Additions**:
  Verify the URL schema and protocol in `tests/security/external-resources-integrity.test.mjs`.

---

## 2. Running Automated Tests

```bash
# Run the complete test suite
npm test

# Run individual test suites
npm run test:unit
npm run test:functional
npm run test:security
npm run test:build
npm run test:data
```

---

## 3. Documentation Freshness Check

Verify that documentation and metrics match the current data catalogs:
```bash
npm run docs:check
```
If data files were updated without running `npm run docs:sync`, this check alerts contributors and exits with code 1.

---

## 4. Compilation & Production Build Verification

Run TypeScript compilation and Vite build to guarantee static bundle integrity:
```bash
npm run build
```

---

## 5. Manual Verification Checklist for UI & Pre-Deployment

Before submitting PRs or finalizing agent tasks:
- [ ] **Automated Tests**: All test suites pass cleanly (`npm test`).
- [ ] **Mobile Responsiveness**: Viewport resizing (< 768px) displays the hamburger drawer and navigation cleanly.
- [ ] **Search & Filtering**: Search inputs in `TestList`, `OwaspTop10View`, and `GenAiDataSecurityView` filter items accurately.
- [ ] **Code Copy Interaction**: Clicking "Copy" on payloads in `TestDetail` copies raw text to clipboard.
- [ ] **Deep Linking**: Clicking a framework risk link in `Dashboard` or `ThreatModelling` opens the corresponding view with the entry expanded.
- [ ] **Dark Mode Styling**: High contrast and visual coherence across all cards and modals.
- [ ] **GitHub Pages Static Preview**: Run `npm run preview` on the built `dist/` bundle to confirm static asset resolution, subpath routing, and CSP compliance for GitHub Pages hosting.
- [ ] **Process Cleanup**: Ensure all background debugging shells, test servers, and child processes spawned during testing have been properly terminated.

---

## 6. Process Lifecycle & Resource Cleanup

> 🧹 **PROCESS HYGIENE DIRECTIVE**: When executing interactive test suites, end-to-end testing, local dev servers, or debugging shells, **always cleanly terminate processes upon test completion**.

1. **Prevent Resource Leaks**:
   - Zombie or detached background processes (e.g. running `vite`, `node`, or shell daemons) waste CPU/RAM and can lock ports (`5173`, `4173`).
2. **Deterministic Test Teardown**:
   - In automated test scripts, ensure all streams, subprocesses, and test servers register clean teardown handlers (`after()`, `process.on('exit')`).
3. **Agent & CLI Workflows**:
   - When AI agents or CLI runners launch background commands or debugging subshells, explicitly terminate background task IDs before concluding the task.

