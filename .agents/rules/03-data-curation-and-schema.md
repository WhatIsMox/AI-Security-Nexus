# Rule: Data Curation & Schema Integrity

## Context
Data files contain authoritative AI security frameworks and test cases that must adhere strictly to TypeScript interfaces and citation standards.

## Directives
1. **Schema Adherence**:
   - `OwaspTop10Entry`: Requires `id`, `title`, `description`, `commonRisks`, `preventionStrategies`, `attackScenarios`, `references`.
   - `TestItem`: Requires `id`, `title`, `pillar`, `summary`, `objectives`, `payloads`, `mitigationStrategies`, `riskLevel`.
   - `GenAiDataSecurityRisk`: Requires `id` (`DSGAI01`-`DSGAI21`), `title`, `theme`, `summary`, `howItUnfolds`, `scenarios`, `impacts`, `mitigations` (tiered by 1, 2, 3), `references`.
2. **Citation Truthfulness**:
   - Every framework entry must point to its official OWASP or Google SAIF publication URL.
   - Real-world incident citations in `incidents_catalog.ts` must use valid URLs to CVEs, research papers, or reputable advisories.
3. **Mandatory Automated Test Accompaniment**:
   - Every newly authored test item or framework risk MUST be accompanied by an assertion in `tests/unit/data-schema.test.mjs` or `tests/unit/taxonomies-and-links.test.mjs` confirming that it resolves correctly and conforms to schema requirements.
4. **Mandatory Post-Curation Verification**:
   - Any modification to `data_*.ts`, `tools_catalog.ts`, or `incidents_catalog.ts` must be followed by executing:
     ```bash
     npm test && npm run docs:sync
     ```

