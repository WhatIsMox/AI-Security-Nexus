---
name: add-new-security-test
description: Author and index a new AI security test item with attack payloads, expected outputs, remediation strategies, and framework cross-references.
---

# Add New Security Test Skill

Follow this standardized protocol when creating a new AI security test case for the testing library.

## Step-by-Step Instructions

1. **Determine Pillar & ID Format**:
   - Application Layer: `Pillar.APP` -> `AITG-APP-NN`
   - Model Layer: `Pillar.MODEL` -> `AITG-MOD-NN`
   - Infrastructure Layer: `Pillar.INFRA` -> `AITG-INFRA-NN`
   - Data Layer: `Pillar.DATA` -> `AITG-DATA-NN`
   - Agentic Skill: `Pillar.APP` / `Pillar.INFRA` -> `AGT-NN`

2. **Construct Test Item Object in `data_tests.ts` or `data_agentic.ts`**:
   ```typescript
   {
     id: "AITG-APP-XX",
     title: "Testing for <Vulnerability Name>",
     pillar: Pillar.APP,
     riskLevel: "Critical" | "High" | "Medium" | "Low",
     owaspTop10Ref: "LLM01:2026", // If applicable
     owaspAgenticRef: "ASI01",    // If applicable
     owaspSaifRef: "SAIF-R10",    // If applicable
     summary: "Detailed executive summary of what this test verifies...",
     objectives: [
       "Objective 1: ...",
       "Objective 2: ..."
     ],
     payloads: [
       {
         name: "Attack Vector / Prompt / Exploit Name",
         description: "How this payload functions and what it tests.",
         code: "Adversarial prompt or exploit snippet"
       }
     ],
     expectedOutput: [
       "Vulnerable response indicator: ...",
       "Secure response indicator: ..."
     ],
     mitigationStrategies: [
       {
         type: "Remediation",
         content: "Architectural or operational remediation step..."
       },
       {
         type: "Mitigation",
         content: "Defensive guardrail or monitoring mitigation..."
       }
     ],
     suggestedTools: [
       { name: "garak", description: "...", url: "https://github.com/NVIDIA/garak" }
     ]
   }
   ```

3. **Add / Update Automated Tests**:
   - Ensure the new test ID and schema are verified in `tests/unit/data-schema.test.mjs` and `tests/unit/taxonomies-and-links.test.mjs`.

4. **Verify Integrity & Synchronize**:
   ```bash
   # Run full test suite
   npm test

   # Synchronize documentation and project map
   npm run docs:sync

   # Verify static production build
   npm run build
   ```

