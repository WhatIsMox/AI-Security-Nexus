#!/usr/bin/env node

/**
 * AI Security Nexus - Agent Documentation & Knowledge Sync Engine
 * 
 * Automatically scans all security framework catalogs, test cases, and application
 * metadata to extract live metrics and generate/update machine-readable and 
 * human-readable project reference maps.
 * 
 * Usage:
 *   node scripts/sync-agent-docs.mjs          # Generates and updates docs
 *   node scripts/sync-agent-docs.mjs --check  # Verifies docs are up to date (CI mode)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const docsDir = path.join(rootDir, 'docs');

const isCheckMode = process.argv.includes('--check');

function readFileContent(relativePath) {
  let fullPath = path.join(rootDir, relativePath);
  if (!fs.existsSync(fullPath)) {
    if (fs.existsSync(path.join(rootDir, 'src/data', relativePath))) {
      fullPath = path.join(rootDir, 'src/data', relativePath);
    } else if (fs.existsSync(path.join(rootDir, 'src', relativePath))) {
      fullPath = path.join(rootDir, 'src', relativePath);
    } else {
      return '';
    }
  }
  return fs.readFileSync(fullPath, 'utf8');
}

function extractFrameworkStats() {
  const llmContent = readFileContent('src/data/data_llm.ts');
  const mlContent = readFileContent('src/data/data_ml.ts');
  const agenticSkillsContent = readFileContent('src/data/data_agentic.ts');
  const agenticAppsContent = readFileContent('src/data/data_agentic_applications.ts');
  const mcpContent = readFileContent('src/data/data_mcp.ts');
  const secureMcpContent = readFileContent('src/data/data_secure_mcp_guide.ts');
  const saifContent = readFileContent('src/data/data_saif.ts');
  const dsgaiContent = readFileContent('src/data/data_genai_data_security.ts');
  const testsContent = readFileContent('src/data/data_tests.ts');
  const toolsContent = readFileContent('src/data/tools_catalog.ts');
  const incidentsContent = readFileContent('src/data/incidents_catalog.ts');

  const llmMatches = [...llmContent.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]);
  const mlMatches = [...mlContent.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]);
  const astMatches = [...new Set([...agenticSkillsContent.matchAll(/id:\s*["'](AST\d{2})["']/g)].map(m => m[1]))];
  const asiMatches = [...new Set([...agenticAppsContent.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]))];
  const mcpMatches = [...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1]);
  const saifMatches = [...saifContent.matchAll(/id:\s*["'](SAIF-R\d+)["']/g)].map(m => m[1]);
  const dsgaiMatches = [...dsgaiContent.matchAll(/id:\s*["'](DSGAI\d{2})["']/g)].map(m => m[1]);
  const dspmMatches = [...dsgaiContent.matchAll(/id:\s*["'](ai-dspm-\d{2})["']/g)].map(m => m[1]);

  const standardTestMatches = [...testsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]);
  const agenticTestMatches = [...agenticSkillsContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)].map(m => m[1]);

  const toolMatches = [...toolsContent.matchAll(/name:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const incidentMatches = [...incidentsContent.matchAll(/title:\s*["']([^"']+)["']/g)].map(m => m[1]);

  // Pillar counts
  const appTests = (testsContent.match(/pillar:\s*Pillar\.APP/g) || []).length + 
                   (agenticSkillsContent.match(/pillar:\s*Pillar\.APP/g) || []).length;
  const modelTests = (testsContent.match(/pillar:\s*Pillar\.MODEL/g) || []).length;
  const infraTests = (testsContent.match(/pillar:\s*Pillar\.INFRA/g) || []).length;
  const dataTests = (testsContent.match(/pillar:\s*Pillar\.DATA/g) || []).length;

  return {
    timestamp: new Date().toISOString(),
    frameworks: {
      owaspLlmTop10_2026: { count: llmMatches.length, ids: llmMatches },
      owaspMlTop10: { count: mlMatches.length, ids: mlMatches },
      owaspAgenticSkillsTop10: { count: astMatches.length, ids: astMatches },
      owaspAgenticAppsTop10: { count: asiMatches.length, ids: asiMatches },
      owaspMcpTop10: { count: mcpMatches.length, ids: mcpMatches },
      googleSaifThreats: { count: saifMatches.length, ids: saifMatches },
      owaspGenAiDataSecurity: { count: dsgaiMatches.length, ids: dsgaiMatches },
      aiDspmCapabilities: { count: dspmMatches.length, ids: dspmMatches }
    },
    tests: {
      standard: standardTestMatches.length,
      agentic: agenticTestMatches.length,
      total: standardTestMatches.length + agenticTestMatches.length,
      byPillar: {
        application: appTests,
        model: modelTests,
        infrastructure: infraTests,
        data: dataTests
      }
    },
    catalogs: {
      toolsCount: toolMatches.length,
      incidentsCount: incidentMatches.length
    }
  };
}

function generateProjectMap(stats) {
  return `# AI Security Nexus — System Project Map & Taxonomy Index

> **Auto-Generated Reference Document**  
> **Last Synchronized**: \`${stats.timestamp}\`  
> *Do not edit manually. Re-generate via \`npm run docs:sync\`.*

---

## 📊 Live System Metrics

| Security Catalog / Asset | Identifier Prefix | Entry Count | Source Data File |
| :--- | :--- | :---: | :--- |
| **OWASP Top 10 for LLMs (2026)** | \`LLM01:2026\` - \`LLM10:2026\` | **${stats.frameworks.owaspLlmTop10_2026.count}** | [\`data_llm.ts\`](../src/data/data_llm.ts) |
| **OWASP ML Security Top 10** | \`ML01:2023\` - \`ML10:2023\` | **${stats.frameworks.owaspMlTop10.count}** | [\`data_ml.ts\`](../src/data/data_ml.ts) |
| **OWASP Agentic Applications Top 10** | \`ASI01\` - \`ASI10\` | **${stats.frameworks.owaspAgenticAppsTop10.count}** | [\`data_agentic_applications.ts\`](../src/data/data_agentic_applications.ts) |
| **OWASP Agentic Skills Top 10** | \`AST01\` - \`AST10\` | **${stats.frameworks.owaspAgenticSkillsTop10.count}** | [\`data_agentic.ts\`](../src/data/data_agentic.ts) |
| **OWASP MCP Top 10 (v0.1)** | \`MCP1:2025\` - \`MCP10:2025\` | **${stats.frameworks.owaspMcpTop10.count}** | [\`data_mcp.ts\`](../src/data/data_mcp.ts) |
| **Google SAIF Threat Model** | \`SAIF-R01\` - \`SAIF-R15\` | **${stats.frameworks.googleSaifThreats.count}** | [\`data_saif.ts\`](../src/data/data_saif.ts) |
| **OWASP GenAI Data Security (2026)** | \`DSGAI01\` - \`DSGAI21\` | **${stats.frameworks.owaspGenAiDataSecurity.count}** | [\`data_genai_data_security.ts\`](../src/data/data_genai_data_security.ts) |
| **AI-DSPM Posture Capabilities** | \`ai-dspm-01\` - \`ai-dspm-13\` | **${stats.frameworks.aiDspmCapabilities.count}** | [\`data_genai_data_security.ts\`](../src/data/data_genai_data_security.ts) |
| **Security Test Cases (Total)** | \`AITG-*\`, \`AGT-*\` | **${stats.tests.total}** | [\`data_tests.ts\`](../src/data/data_tests.ts) & [\`data_agentic.ts\`](../src/data/data_agentic.ts) |
| **Tooling Registry Entries** | Security Tools | **${stats.catalogs.toolsCount}** | [\`tools_catalog.ts\`](../src/data/tools_catalog.ts) |
| **Real-World Incident Citations** | CVEs / Papers / Outages | **${stats.catalogs.incidentsCount}** | [\`incidents_catalog.ts\`](../src/data/incidents_catalog.ts) |

### Test Case Pillar Distribution
- **AI Application Pillar (\`Pillar.APP\`)**: ${stats.tests.byPillar.application} tests
- **AI Model Pillar (\`Pillar.MODEL\`)**: ${stats.tests.byPillar.model} tests
- **AI Infrastructure Pillar (\`Pillar.INFRA\`)**: ${stats.tests.byPillar.infrastructure} tests
- **AI Data Pillar (\`Pillar.DATA\`)**: ${stats.tests.byPillar.data} tests

---

## 🗺️ Component Hierarchy & View Routing

\`src/App.tsx\` acts as the central state router coordinating 11 primary views:

\`\`\`mermaid
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
\`\`\`

---

## 📁 Key File Index for Agents

- **Application Entry**: [\`index.tsx\`](../src/index.tsx), [\`App.tsx\`](../src/App.tsx), [\`index.html\`](../index.html)
- **Data Models & Types**: [\`types.ts\`](../src/types.ts), [\`data.ts\`](../src/data/data.ts)
- **Security Catalogs**:
  - [\`data_llm.ts\`](../src/data/data_llm.ts)
  - [\`data_agentic.ts\`](../src/data/data_agentic.ts)
  - [\`data_agentic_applications.ts\`](../src/data/data_agentic_applications.ts)
  - [\`data_mcp.ts\`](../src/data/data_mcp.ts)
  - [\`data_secure_mcp_guide.ts\`](../src/data/data_secure_mcp_guide.ts)
  - [\`data_genai_data_security.ts\`](../src/data/data_genai_data_security.ts)
  - [\`data_ml.ts\`](../src/data/data_ml.ts)
  - [\`data_saif.ts\`](../src/data/data_saif.ts)
  - [\`data_tests.ts\`](../src/data/data_tests.ts)
  - [\`tools_catalog.ts\`](../src/data/tools_catalog.ts)
  - [\`incidents_catalog.ts\`](../src/data/incidents_catalog.ts)
- **UI Components**:
  - [\`components/Sidebar.tsx\`](../src/components/Sidebar.tsx)
  - [\`components/Dashboard.tsx\`](../src/components/Dashboard.tsx)
  - [\`components/ThreatModelling.tsx\`](../src/components/ThreatModelling.tsx)
  - [\`components/OwaspTop10View.tsx\`](../src/components/OwaspTop10View.tsx)
  - [\`components/AgenticTop10View.tsx\`](../src/components/AgenticTop10View.tsx)
  - [\`components/SecureMcpGuideView.tsx\`](../src/components/SecureMcpGuideView.tsx)
  - [\`components/GenAiDataSecurityView.tsx\`](../src/components/GenAiDataSecurityView.tsx)
  - [\`components/TestList.tsx\`](../src/components/TestList.tsx)
  - [\`components/TestDetail.tsx\`](../src/components/TestDetail.tsx)
- **Build & Config**: [\`vite.config.ts\`](../vite.config.ts), [\`tailwind.config.js\`](../tailwind.config.js), [\`tsconfig.json\`](../tsconfig.json)
`;
}

function syncDocs() {
  if (!fs.existsSync(docsDir)) {
    fs.mkdirSync(docsDir, { recursive: true });
  }

  const stats = extractFrameworkStats();
  const statsPath = path.join(docsDir, 'AUTO_GENERATED_STATS.json');
  const projectMapPath = path.join(docsDir, 'PROJECT_MAP.md');

  const statsJson = JSON.stringify(stats, null, 2);
  const projectMapMd = generateProjectMap(stats);

  if (isCheckMode) {
    let hasDrift = false;
    if (fs.existsSync(statsPath)) {
      const existing = fs.readFileSync(statsPath, 'utf8');
      // compare without timestamp
      const existingObj = JSON.parse(existing);
      const newObj = JSON.parse(statsJson);
      delete existingObj.timestamp;
      delete newObj.timestamp;
      if (JSON.stringify(existingObj) !== JSON.stringify(newObj)) {
        hasDrift = true;
      }
    } else {
      hasDrift = true;
    }

    if (hasDrift) {
      console.error('\x1b[31m✖ Documentation drift detected! Run `npm run docs:sync` to update.\x1b[0m');
      process.exit(1);
    } else {
      console.log('\x1b[32m✔ Documentation is fully up to date with data catalogs.\x1b[0m');
      process.exit(0);
    }
  }

  fs.writeFileSync(statsPath, statsJson + '\n', 'utf8');
  fs.writeFileSync(projectMapPath, projectMapMd, 'utf8');

  console.log(`\x1b[32m✔ Successfully synchronized agent documentation:\x1b[0m`);
  console.log(`  - ${path.relative(rootDir, statsPath)}`);
  console.log(`  - ${path.relative(rootDir, projectMapPath)}`);
}

syncDocs();
