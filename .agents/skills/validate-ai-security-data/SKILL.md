---
name: validate-ai-security-data
description: Validate data consistency, taxonomy IDs, payload code blocks, and cross-references across all security frameworks in the project.
---

# Validate AI Security Data Skill

Use this workflow whenever modifying or adding data to `data_*.ts`, `tools_catalog.ts`, or `incidents_catalog.ts`.

## Step-by-Step Workflow

1. **Run Data Integrity & Schema Check**:
   Execute the automated integrity validator:
   ```bash
   npm run test:data
   ```

2. **Verify Live Link Resolution**:
   Validate that all incident citations, tool links, and framework URLs resolve with HTTP 200:
   ```bash
   npm run test:links
   ```

3. **Run Complete Automated Test Suite**:
   ```bash
   npm test
   ```

4. **Verify Output**:
   Ensure all security frameworks pass:
   - OWASP Top 10 for LLMs (2026): 10 entries (`LLM01:2026`-`LLM10:2026`)
   - OWASP Machine Learning Top 10: 10 entries (`ML01:2023`-`ML10:2023`)
   - OWASP Agentic Applications Top 10: 10 entries (`ASI01`-`ASI10`)
   - OWASP Agentic Skills Top 10: 10 entries (`AST01`-`AST10`)
   - OWASP MCP Top 10 (v0.1): 10 entries (`MCP1:2025`-`MCP10:2025`)
   - Google SAIF Threats: 15 entries (`SAIF-R01`-`SAIF-R15`)
   - OWASP GenAI Data Security (2026): 21 entries (`DSGAI01`-`DSGAI21`)
   - AI-DSPM Capabilities: 13 entries (`ai-dspm-01`-`ai-dspm-13`)
   - Test Matrix: 42+ unique tests (`AITG-*`, `AGT-*`)

5. **Synchronize Documentation**:
   Update dynamic project stats and maps:
   ```bash
   npm run docs:sync
   ```

6. **Verify TypeScript & Production Build**:
   ```bash
   npm run build
   ```
