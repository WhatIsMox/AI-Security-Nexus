#!/usr/bin/env node

/**
 * AI Security Nexus - Data Integrity Validator
 * 
 * Validates the syntactic and referential integrity of all security data catalogs:
 * - OWASP Top 10 for LLM Applications (2026)
 * - OWASP Machine Learning Security Top 10
 * - OWASP Agentic Applications Top 10 (ASI01-ASI10)
 * - OWASP Agentic Skills Top 10 (AST01-AST10)
 * - OWASP MCP Top 10 (v0.1)
 * - Secure MCP Server Development Guide (v1.0)
 * - OWASP GenAI Data Security Risks (DSGAI01-DSGAI21)
 * - Google SAIF Threats
 * - Security Test Catalog (AITG-*)
 * - Tooling Catalog & Incidents Catalog
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const errors = [];
const warnings = [];

function logPass(msg) {
  console.log(`\x1b[32m✔\x1b[0m ${msg}`);
}

function logWarn(msg) {
  warnings.push(msg);
  console.log(`\x1b[33m⚠\x1b[0m ${msg}`);
}

function logFail(msg) {
  errors.push(msg);
  console.log(`\x1b[31m✖\x1b[0m ${msg}`);
}

function readFileContent(relativePath) {
  const fullPath = path.join(rootDir, relativePath);
  if (!fs.existsSync(fullPath)) {
    logFail(`Required file missing: ${relativePath}`);
    return '';
  }
  return fs.readFileSync(fullPath, 'utf8');
}

// 1. Validate data_llm.ts
function validateLlmData() {
  const content = readFileContent('data_llm.ts');
  if (!content) return;

  const idMatches = [...content.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]);
  if (idMatches.length !== 10) {
    logFail(`data_llm.ts: Expected 10 LLM Top 10 entries (LLM01:2026-LLM10:2026), found ${idMatches.length}`);
  } else {
    logPass(`data_llm.ts: 10 LLM Top 10 (2026) entries correctly formatted (${idMatches[0]} to ${idMatches[idMatches.length - 1]})`);
  }
}

// 2. Validate data_ml.ts
function validateMlData() {
  const content = readFileContent('data_ml.ts');
  if (!content) return;

  const idMatches = [...content.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]);
  if (idMatches.length !== 10) {
    logFail(`data_ml.ts: Expected 10 ML Top 10 entries, found ${idMatches.length}`);
  } else {
    logPass(`data_ml.ts: 10 ML Top 10 entries correctly formatted (${idMatches[0]} to ${idMatches[idMatches.length - 1]})`);
  }
}

// 3. Validate data_agentic.ts & data_agentic_applications.ts
function validateAgenticData() {
  const skillsContent = readFileContent('data_agentic.ts');
  const appsContent = readFileContent('data_agentic_applications.ts');
  
  if (skillsContent) {
    const astMatches = [...skillsContent.matchAll(/id:\s*["'](AST0?[1-9]|AST10)["']/g)].map(m => m[1]);
    // Extract unique AST IDs
    const uniqueAst = [...new Set(astMatches.filter(id => /^AST\d{2}$/.test(id)))];
    if (uniqueAst.length !== 10) {
      logFail(`data_agentic.ts: Expected 10 unique AST entries (AST01-AST10), found ${uniqueAst.length}`);
    } else {
      logPass(`data_agentic.ts: 10 Agentic Skills Top 10 entries (AST01-AST10) verified`);
    }
  }

  if (appsContent) {
    const asiMatches = [...appsContent.matchAll(/id:\s*["'](ASI0?[1-9]|ASI10)["']/g)].map(m => m[1]);
    const uniqueAsi = [...new Set(asiMatches.filter(id => /^ASI\d{2}$/.test(id)))];
    if (uniqueAsi.length !== 10) {
      logFail(`data_agentic_applications.ts: Expected 10 unique ASI entries (ASI01-ASI10), found ${uniqueAsi.length}`);
    } else {
      logPass(`data_agentic_applications.ts: 10 Agentic Applications Top 10 entries (ASI01-ASI10) verified`);
    }
  }
}

// 4. Validate data_mcp.ts & data_secure_mcp_guide.ts
function validateMcpData() {
  const mcpContent = readFileContent('data_mcp.ts');
  const guideContent = readFileContent('data_secure_mcp_guide.ts');

  if (mcpContent) {
    const mcpMatches = [...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1]);
    if (mcpMatches.length !== 10) {
      logFail(`data_mcp.ts: Expected 10 MCP Top 10 entries (MCP1:2025-MCP10:2025), found ${mcpMatches.length}`);
    } else {
      logPass(`data_mcp.ts: 10 MCP Top 10 entries (MCP1:2025-MCP10:2025) verified`);
    }
  }

  if (guideContent) {
    const sectionMatches = [...guideContent.matchAll(/id:\s*["']([a-z0-9\-]+)["']/g)].map(m => m[1]);
    if (sectionMatches.length < 5) {
      logFail(`data_secure_mcp_guide.ts: Expected guide sections, found ${sectionMatches.length}`);
    } else {
      logPass(`data_secure_mcp_guide.ts: ${sectionMatches.length} Secure MCP guide sections verified`);
    }
  }
}

// 5. Validate data_saif.ts
function validateSaifData() {
  const content = readFileContent('data_saif.ts');
  if (!content) return;

  const saifMatches = [...content.matchAll(/id:\s*["'](SAIF-R\d+)["']/g)].map(m => m[1]);
  if (saifMatches.length < 10) {
    logFail(`data_saif.ts: Expected at least 10 SAIF risk entries, found ${saifMatches.length}`);
  } else {
    logPass(`data_saif.ts: ${saifMatches.length} Google SAIF Threat entries verified`);
  }
}

// 6. Validate data_genai_data_security.ts
function validateGenAiDataSecurity() {
  const content = readFileContent('data_genai_data_security.ts');
  if (!content) return;

  const dsgaiMatches = [...content.matchAll(/id:\s*["'](DSGAI\d{2})["']/g)].map(m => m[1]);
  if (dsgaiMatches.length !== 21) {
    logFail(`data_genai_data_security.ts: Expected 21 DSGAI entries (DSGAI01-DSGAI21), found ${dsgaiMatches.length}`);
  } else {
    logPass(`data_genai_data_security.ts: 21 OWASP GenAI Data Security entries (DSGAI01-DSGAI21) verified`);
  }

  const dspmMatches = [...content.matchAll(/id:\s*["'](ai-dspm-\d{2})["']/g)].map(m => m[1]);
  if (dspmMatches.length !== 13) {
    logFail(`data_genai_data_security.ts: Expected 13 AI-DSPM capability entries, found ${dspmMatches.length}`);
  } else {
    logPass(`data_genai_data_security.ts: 13 AI-DSPM capability entries verified`);
  }
}

// 7. Validate data_tests.ts & agentic tests
function validateTestData() {
  const standardTestsContent = readFileContent('data_tests.ts');
  const agenticTestsContent = readFileContent('data_agentic.ts');

  const allTestIds = new Set();
  const duplicateIds = [];

  const standardMatches = [...standardTestsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]);
  const agenticMatches = [...agenticTestsContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)].map(m => m[1]);

  const combined = [...standardMatches, ...agenticMatches];

  for (const id of combined) {
    if (allTestIds.has(id)) {
      duplicateIds.push(id);
    }
    allTestIds.add(id);
  }

  if (duplicateIds.length > 0) {
    logFail(`Duplicate Test IDs found: ${duplicateIds.join(', ')}`);
  } else {
    logPass(`Verified ${allTestIds.size} unique security test cases (Standard AITG: ${standardMatches.length}, Agentic AGT: ${agenticMatches.length})`);
  }

  // Check that test cases have non-empty payloads and mitigation strategies
  const standardPayloadCount = (standardTestsContent.match(/payloads:\s*\[/g) || []).length;
  const standardMitigationCount = (standardTestsContent.match(/mitigationStrategies:\s*\[/g) || []).length;

  if (standardPayloadCount !== standardMatches.length) {
    logWarn(`data_tests.ts: Some tests might be missing 'payloads' array (${standardPayloadCount} vs ${standardMatches.length})`);
  }
  if (standardMitigationCount !== standardMatches.length) {
    logWarn(`data_tests.ts: Some tests might be missing 'mitigationStrategies' array (${standardMitigationCount} vs ${standardMatches.length})`);
  }
}

// 8. Validate Tools & Incidents catalogs & external link health
function validateCatalogs() {
  const toolsContent = readFileContent('tools_catalog.ts');
  const incidentsContent = readFileContent('incidents_catalog.ts');

  if (toolsContent) {
    const toolUrls = [...toolsContent.matchAll(/url:\s*["']([^"']+)["']/g)].map(m => m[1]);
    let malformedCount = 0;
    for (const u of toolUrls) {
      if (!u.startsWith('https://') && !u.startsWith('http://')) malformedCount++;
      try { new URL(u); } catch { malformedCount++; }
    }
    if (malformedCount > 0) {
      logFail(`tools_catalog.ts: Found ${malformedCount} malformed or invalid URLs`);
    } else {
      logPass(`tools_catalog.ts: Verified ${toolUrls.length} security tool references with valid URLs`);
    }

    // Validate coverage in tool_details_catalog.ts
    const detailsContent = readFileContent('tool_details_catalog.ts');
    if (detailsContent) {
      const toolNames = [...new Set([...toolsContent.matchAll(/name:\s*["\x27]([^"\x27]+)["\x27]/g)].map(m => m[1]))];
      const dbNames = new Set([...detailsContent.matchAll(/"([^"]+)":\s*\{/g)].map(m => m[1].toLowerCase()));
      const missing = toolNames.filter(n => !dbNames.has(n.toLowerCase()));
      if (missing.length > 0) {
        logFail(`tool_details_catalog.ts: Missing ${missing.length} tool entries in TOOL_DATABASE: ${missing.join(', ')}`);
      } else {
        logPass(`tool_details_catalog.ts: 100% metadata coverage verified across all ${toolNames.length} unique security tools`);
      }
    }
  }

  if (incidentsContent) {
    const incidentUrls = [...incidentsContent.matchAll(/url:\s*["']([^"']+)["']/g)].map(m => m[1]);
    let malformedCount = 0;
    for (const u of incidentUrls) {
      if (!u.startsWith('https://') && !u.startsWith('http://')) malformedCount++;
      try { new URL(u); } catch { malformedCount++; }
    }
    if (malformedCount > 0) {
      logFail(`incidents_catalog.ts: Found ${malformedCount} malformed or invalid URLs`);
    } else {
      logPass(`incidents_catalog.ts: Verified ${incidentUrls.length} real-world incident citations`);
    }
  }
}

console.log('------------------------------------------------------------');
console.log('🔍 AI Security Nexus - Data Integrity & Schema Validation');
console.log('------------------------------------------------------------');

validateLlmData();
validateMlData();
validateAgenticData();
validateMcpData();
validateSaifData();
validateGenAiDataSecurity();
validateTestData();
validateCatalogs();

console.log('------------------------------------------------------------');
if (errors.length > 0) {
  console.error(`\x1b[31mValidation Failed with ${errors.length} error(s) and ${warnings.length} warning(s).\x1b[0m`);
  process.exit(1);
} else {
  console.log(`\x1b[32mAll Data Integrity & Schema Validations Passed Successfully! (${warnings.length} warnings)\x1b[0m`);
  process.exit(0);
}
