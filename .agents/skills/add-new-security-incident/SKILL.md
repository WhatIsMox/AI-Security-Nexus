---
name: add-new-security-incident
description: Author and index a real-world AI security incident or CVE case study with verified attack vectors, impact breakdowns, recovery timelines, legal repercussions, and defensive remediation.
---

# Adding a Real-World AI Incident to AI Security Nexus

Follow this exact procedure whenever adding or modifying an AI security incident or CVE case study in the repository.

---

## 1. Step-by-Step Incident Authoring Workflow

### Step 1: Add Incident Citation in `incidents_catalog.ts`
1. Locate or create the category array (e.g. `PROMPT_INJECTION_INCIDENTS`, `DATA_POISONING_INCIDENTS`, `SERVING_INFRASTRUCTURE_INCIDENTS`) in [`incidents_catalog.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/incidents_catalog.ts).
2. Define the incident citation adhering to `ExternalResource` in [`types.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/types.ts):
   ```typescript
   {
     title: 'CVE-2024-XXXX: Concise descriptive summary of the exploit',
     url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX' // Must resolve HTTP 200 OK
   }
   ```
3. Map the incident to relevant framework threat IDs in `INCIDENTS_BY_THREAT_ID`.

---

### Step 2: Add Verified Intelligence in `incident_details_catalog.ts`
Every incident in `incidents_catalog.ts` **MUST** have a corresponding entry in `INCIDENT_DATABASE` in [`incident_details_catalog.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/incident_details_catalog.ts):

```typescript
  "CVE-2024-XXXX: Concise descriptive summary of the exploit": {
    title: "CVE-2024-XXXX: Concise descriptive summary of the exploit",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX",
    year: "2024",
    targetOrVictim: "Organization / Framework Name",
    cveOrAdvisoryId: "CVE-2024-XXXX",
    severity: "Critical", // 'Critical' | 'High' | 'Medium' | 'Low'
    attackVector: "Detailed technical breakdown explaining the vulnerability, trigger conditions, and execution chain.",
    impact: "Concrete data, financial, or system impact (e.g. root shell takeover, source code leak, unauthorized financial transactions).",
    recoveryTime: "48 hours (emergency hotfix release & advisory)",
    repercussions: "Legal, regulatory, compliance, or corporate fallout (e.g. FTC investigation, CVE disclosure, GDPR inquiry).",
    remediation: "Specific defensive architectural controls and engineering safeguards to eliminate the risk.",
    lessonsLearned: "Actionable strategic security takeaway for AI architects and red teams."
  }
```

---

## 2. Mandatory Verification Pipeline

Before concluding any incident addition, execute the complete validation pipeline:

```bash
# 1. Run data integrity & schema check (strictly enforces 100% incident metadata coverage)
npm run test:data

# 2. Verify all external URLs resolve HTTP 200 OK
npm run test:links

# 3. Run full automated test suite
npm test

# 4. Sync documentation statistics
npm run docs:sync

# 5. Build production bundle
npm run build
```
