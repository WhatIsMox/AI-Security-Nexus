---
name: add-new-security-tool
description: Author and index a new AI security tool with rich practitioner metadata, typical use cases, installation commands, ecosystem tags, and framework cross-mappings.
---

# Adding a New AI Security Tool to AI Security Nexus

Follow this exact procedure whenever adding or modifying a security tool in the repository.

---

## 1. Step-by-Step Tool Authoring Workflow

### Step 1: Add Tool Reference in `tools_catalog.ts`
1. Locate or create the category array (e.g. `PROMPT_INJECTION_TOOLS`, `SUPPLY_CHAIN_TOOLS`, `AGENT_MONITORING_TOOLS`) in [`tools_catalog.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/tools_catalog.ts).
2. Define the tool object adhering to `SecurityTool` in [`types.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/types.ts):
   ```typescript
   {
     name: 'MyTool',
     description: '1-line concise summary of tool capability.',
     url: 'https://github.com/org/mytool', // Must resolve HTTP 200 OK
     cost: 'Free' | 'Free+Paid' | 'Paid',
     type: 'Local' | 'Third-party',
     category: 'Offensive' | 'Defensive' | 'Both'
   }
   ```
3. Ensure the tool is mapped to relevant threats in `TOOLS_BY_THREAT_ID`.

---

### Step 2: Add Complete Verified Metadata in `tool_details_catalog.ts`
Every tool in `tools_catalog.ts` **MUST** have an entry in `TOOL_DATABASE` in [`tool_details_catalog.ts`](file:///Users/gabrielemossino/Documents/GitHub/OWASP-AI-Testing-Bible/src/data/tool_details_catalog.ts):

```typescript
  "MyTool": {
    name: "MyTool",
    description: "1-line concise summary of tool capability.",
    url: "https://github.com/org/mytool",
    cost: "Free",
    type: "Local",
    category: "Defensive",
    authorOrMaintainer: "Organization / Maintainer Name",
    license: "Apache-2.0", // MIT, BSD, AGPL, Commercial, etc.
    ecosystem: ["Python", "PyTorch", "Docker"],
    longDescription: "Detailed multi-paragraph technical overview explaining architecture, internal probe mechanisms, or runtime gateway filtering.",
    typicalUseCase: "Concrete operational security workflow describing how red-teams or SecOps engineers deploy this tool in practice.",
    keyFeatures: [
      "Feature 1 with technical detail",
      "Feature 2 with technical detail",
      "Feature 3 with technical detail"
    ],
    installationOrQuickstart: "pip install mytool\nmytool scan --target model.pt"
  }
```

---

## 2. Mandatory Verification Commands

Before concluding any tool addition, execute the full validation pipeline:

```bash
# 1. Run data integrity checks (strictly enforces 100% metadata coverage)
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
