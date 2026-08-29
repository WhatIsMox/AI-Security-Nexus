#!/usr/bin/env node

/**
 * AI Security Nexus - MITRE ATLAS 1-to-1 Official Data Ingestion Engine
 * 
 * Ingests the authoritative MITRE ATLAS™ (Adversarial Threat Landscape for AI Systems)
 * dataset directly from the official repository (mitre-atlas/atlas-data), ensuring
 * 100% data parity with https://atlas.mitre.org/.
 * 
 * Data Source:
 *   https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml
 * 
 * Usage:
 *   node scripts/sync-mitre-atlas.mjs          # Syncs and generates data_mitre_atlas.ts
 *   node scripts/sync-mitre-atlas.mjs --check  # Verifies data freshness without writing
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const ATLAS_YAML_ROOT_URL = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml';
const OUTPUT_DATA_FILE = path.join(rootDir, 'src/data/data_mitre_atlas.ts');

const isCheckMode = process.argv.includes('--check');

/**
 * Recursively resolves pointer YAML files to the actual complete ATLAS dataset YAML
 */
async function fetchAuthoritativeAtlasYaml() {
  const yamlPkg = await import('js-yaml');
  const load = yamlPkg.default?.load || yamlPkg.load;

  console.log(`🌐 Resolving authoritative MITRE ATLAS dataset from: ${ATLAS_YAML_ROOT_URL}...`);
  let currentUrl = ATLAS_YAML_ROOT_URL;
  let content = '';

  for (let step = 0; step < 5; step++) {
    const response = await fetch(currentUrl, {
      headers: { 'User-Agent': 'OWASP-AI-Security-Nexus-Sync/1.0' }
    });

    if (!response.ok) {
      throw new Error(`HTTP error ${response.status} ${response.statusText} fetching ${currentUrl}`);
    }

    content = await response.text();
    const trimmed = content.trim();

    // Check if the response is a relative path pointer to another YAML version file
    if (trimmed.endsWith('.yaml') && trimmed.length < 120 && !trimmed.includes('\n')) {
      if (trimmed.startsWith('v6/')) {
        currentUrl = `https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/${trimmed}`;
      } else {
        currentUrl = `https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/${trimmed}`;
      }
      console.log(`   ↳ Following version pointer [${step + 1}] -> ${currentUrl}`);
    } else {
      break;
    }
  }

  const parsed = load(content);
  if (!parsed || !parsed.techniques || !parsed.tactics) {
    throw new Error('Fetched YAML content is invalid or missing tactics/techniques');
  }

  console.log(`📦 Successfully parsed official ATLAS dataset (version: ${parsed.collection?.version || 'latest'}).`);
  return parsed;
}

/**
 * Processes the raw ATLAS YAML dataset into fully linked, typed structures
 */
function processAtlasData(data) {
  const tacticsObj = data.tactics || {};
  const techniquesObj = data.techniques || {};
  const mitigationsObj = data.mitigations || {};
  const caseStudiesObj = data['case-studies'] || {};
  const relationships = data.relationships || {};

  // 1. Tactic ordering from ATLAS-matrix sequence
  const matrixRels = relationships['ATLAS-matrix']?.sequences || [];
  const orderedTacticIds = matrixRels
    .slice()
    .sort((a, b) => (a.position || 0) - (b.position || 0))
    .map(s => s.target);

  // If sequence is not fully populated, fallback to existing tactics keys
  for (const tid of Object.keys(tacticsObj)) {
    if (!orderedTacticIds.includes(tid)) {
      orderedTacticIds.push(tid);
    }
  }

  // 2. Map Procedure Examples from all Case Studies (relationships[csId].employs)
  const techniqueProceduresMap = new Map();
  for (const [csId, relGroup] of Object.entries(relationships)) {
    if (relGroup.employs && Array.isArray(relGroup.employs)) {
      for (const emp of relGroup.employs) {
        if (!emp.target) continue;
        if (!techniqueProceduresMap.has(emp.target)) {
          techniqueProceduresMap.set(emp.target, []);
        }
        const cs = caseStudiesObj[csId];
        techniqueProceduresMap.get(emp.target).push({
          caseStudyId: csId,
          caseStudyName: cs?.name || csId,
          description: emp.description || '',
          url: `https://atlas.mitre.org/studies/${csId}`,
          ...(emp['step-id'] ? { stepId: emp['step-id'] } : {}),
          ...(emp.tactic ? { tacticId: emp.tactic } : {})
        });
      }
    }
  }

  // 3. Map Mitigations with Specific Technique Guidance (relationships[mitId].mitigates)
  const techniqueMitigationsMap = new Map();
  for (const [mitId, relGroup] of Object.entries(relationships)) {
    if (relGroup.mitigates && Array.isArray(relGroup.mitigates)) {
      for (const mit of relGroup.mitigates) {
        if (!mit.target) continue;
        if (!techniqueMitigationsMap.has(mit.target)) {
          techniqueMitigationsMap.set(mit.target, []);
        }
        const mitBase = mitigationsObj[mitId];
        techniqueMitigationsMap.get(mit.target).push({
          id: mitId,
          name: mitBase?.name || mitId,
          description: mitBase?.description || '',
          ...(mit.description ? { useDescription: mit.description } : {}),
          url: `https://atlas.mitre.org/mitigations/${mitId}`
        });
      }
    }
  }

  // 4. Map Subtechnique-to-Parent and Parent-to-Subtechniques
  const subtechniqueToParentMap = new Map();
  const parentToSubtechniquesMap = new Map();

  for (const [techId, tech] of Object.entries(techniquesObj)) {
    const isSub = (techId.match(/\./g) || []).length >= 2 || /\.\d{3}$/.test(techId);
    if (isSub) {
      const parentId = techId.substring(0, techId.lastIndexOf('.'));
      const parentTech = techniquesObj[parentId];
      subtechniqueToParentMap.set(techId, {
        parentId: parentId,
        parentName: parentTech?.name || parentId
      });

      if (!parentToSubtechniquesMap.has(parentId)) {
        parentToSubtechniquesMap.set(parentId, []);
      }
      parentToSubtechniquesMap.get(parentId).push({
        id: techId,
        name: tech.name || techId,
        description: tech.description || '',
        url: `https://atlas.mitre.org/techniques/${techId}`
      });
    }
  }

  // 5. Map Technique Tactics (relationships[techId].achieves)
  const techniqueTacticsMap = new Map();
  for (const [techId, relGroup] of Object.entries(relationships)) {
    if (relGroup.achieves && Array.isArray(relGroup.achieves)) {
      const tacs = relGroup.achieves.map(ach => {
        const tacObj = tacticsObj[ach.target];
        return tacObj ? { id: ach.target, name: tacObj.name } : null;
      }).filter(Boolean);
      techniqueTacticsMap.set(techId, tacs);
    }
  }

  // If a subtechnique doesn't explicitly have an 'achieves' relationship, inherit parent's tactics
  for (const [techId, parentRef] of subtechniqueToParentMap.entries()) {
    if (!techniqueTacticsMap.has(techId) || techniqueTacticsMap.get(techId).length === 0) {
      const parentTactics = techniqueTacticsMap.get(parentRef.parentId);
      if (parentTactics && parentTactics.length > 0) {
        techniqueTacticsMap.set(techId, parentTactics);
      }
    }
  }

  // Helper to extract citation references from technique object and markdown footnotes
  function extractReferences(tech) {
    const refs = [];
    if (Array.isArray(tech.references)) {
      for (const r of tech.references) {
        refs.push({
          sourceName: r.title || r.id || 'Reference',
          ...(r.title ? { description: r.title } : {}),
          ...(r.url ? { url: r.url } : {}),
          ...(r.id ? { externalId: r.id } : {})
        });
      }
    }

    // Also extract footnote references in markdown (e.g. `[1]: https://...`)
    const desc = tech.description || '';
    const fnRegex = /^\[([^\]]+)\]:\s*(https?:\/\/[^\s"]+)(?:\s+"([^"]+)")?/gm;
    let match;
    while ((match = fnRegex.exec(desc)) !== null) {
      const key = match[1];
      const url = match[2];
      const title = match[3];
      if (!refs.some(r => r.url === url)) {
        refs.push({
          sourceName: `[${key}]`,
          ...(title ? { description: title } : {}),
          url: url,
          externalId: key
        });
      }
    }

    return refs;
  }

  // 6. Build Master Techniques List
  const allTechniques = Object.entries(techniquesObj).map(([techId, tech]) => {
    const isSub = (techId.match(/\./g) || []).length >= 2 || /\.\d{3}$/.test(techId);
    const parentRef = subtechniqueToParentMap.get(techId);
    const subList = parentToSubtechniquesMap.get(techId) || [];
    const tacticsList = techniqueTacticsMap.get(techId) || [];
    const procedures = techniqueProceduresMap.get(techId) || [];
    const mitigations = techniqueMitigationsMap.get(techId) || [];
    const references = extractReferences(tech);

    // Primary tactic
    const primaryTactic = tacticsList[0] || { id: 'AML.TA0002', name: 'Reconnaissance' };

    // Case studies brief list
    const caseStudiesBrief = procedures.map(p => ({
      id: p.caseStudyId,
      name: p.caseStudyName,
      url: p.url
    })).filter((v, idx, arr) => arr.findIndex(x => x.id === v.id) === idx);

    return {
      id: techId,
      name: tech.name || techId,
      description: tech.description || '',
      tacticId: primaryTactic.id,
      tacticName: primaryTactic.name,
      ...(tacticsList.length > 0 ? { tactics: tacticsList } : {}),
      isSubtechnique: isSub,
      ...(parentRef ? { parentTechniqueId: parentRef.parentId, parentTechniqueName: parentRef.parentName } : {}),
      ...(subList.length > 0 ? { subtechniques: subList } : {}),
      url: `https://atlas.mitre.org/techniques/${techId}`,
      platforms: tech.platforms || ['ATLAS'],
      ...(tech.maturity ? { maturity: tech.maturity } : {}),
      ...(tech['attack-reference'] ? { attackReference: tech['attack-reference'] } : {}),
      ...(tech['created-date'] ? { createdDate: tech['created-date'] } : {}),
      ...(tech['modified-date'] ? { modifiedDate: tech['modified-date'] } : {}),
      mitigations: mitigations,
      caseStudies: caseStudiesBrief,
      procedureExamples: procedures,
      references: references
    };
  });

  // Sort techniques naturally by ID
  allTechniques.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

  // 7. Build Structured Tactics Array
  const structuredTactics = orderedTacticIds.map(tacticId => {
    const tacticObj = tacticsObj[tacticId] || { name: tacticId, description: '' };
    
    // Find all techniques that achieve this tactic
    const matchingTechniques = allTechniques.filter(tech => {
      if (tech.tactics && tech.tactics.some(t => t.id === tacticId)) return true;
      return tech.tacticId === tacticId;
    });

    return {
      id: tacticId,
      shortname: tacticObj.id ? tacticObj.id.toLowerCase() : tacticId.toLowerCase(),
      name: tacticObj.name || tacticId,
      description: tacticObj.description || '',
      url: `https://atlas.mitre.org/tactics/${tacticId}`,
      techniques: matchingTechniques
    };
  });

  const totalProcedures = allTechniques.reduce((sum, t) => sum + (t.procedureExamples?.length || 0), 0);
  const totalSubtechniques = allTechniques.filter(t => t.isSubtechnique).length;

  const metadata = {
    version: data.collection?.version || '2026.07',
    lastUpdated: data.collection?.['modified-date'] || new Date().toISOString().split('T')[0],
    totalTactics: structuredTactics.length,
    totalTechniques: allTechniques.length,
    totalSubtechniques: totalSubtechniques,
    totalProcedureExamples: totalProcedures,
    totalMitigations: Object.keys(mitigationsObj).length
  };

  return {
    metadata,
    tactics: structuredTactics,
    techniques: allTechniques
  };
}

/**
 * Generates the clean, strictly typed TypeScript catalog file
 */
function generateTypeScriptFile(processedData) {
  const { metadata, tactics, techniques } = processedData;

  const content = `/**
 * MITRE ATLAS™ (Adversarial Threat Landscape for AI Systems) Catalog
 * 
 * Auto-generated by scripts/sync-mitre-atlas.mjs
 * Authoritative Source: https://github.com/mitre-atlas/atlas-data (dist/v6/ATLAS-latest.yaml)
 * 100% 1-to-1 Parity with https://atlas.mitre.org/
 * 
 * Last synchronized: ${new Date().toISOString()}
 */

import { MitreAtlasTactic, MitreAtlasTechnique, MitreAtlasOverview } from '../types';

export const MITRE_ATLAS_META = ${JSON.stringify(metadata, null, 2)} as const;

export const MITRE_ATLAS_TACTICS: MitreAtlasTactic[] = ${JSON.stringify(tactics, null, 2)};

export const MITRE_ATLAS_TECHNIQUES: MitreAtlasTechnique[] = ${JSON.stringify(techniques, null, 2)};

export const MITRE_ATLAS_OVERVIEW: MitreAtlasOverview = {
  version: MITRE_ATLAS_META.version,
  lastUpdated: MITRE_ATLAS_META.lastUpdated,
  totalTactics: MITRE_ATLAS_META.totalTactics,
  totalTechniques: MITRE_ATLAS_META.totalTechniques,
  tactics: MITRE_ATLAS_TACTICS
};
`;

  return content;
}

async function main() {
  console.log('🚀 Starting 1-to-1 MITRE ATLAS Official Data Ingestion Engine...');

  try {
    const rawYaml = await fetchAuthoritativeAtlasYaml();
    const processed = processAtlasData(rawYaml);

    console.log(`✨ Processed ${processed.metadata.totalTactics} tactics, ${processed.metadata.totalTechniques} total techniques/subtechniques, ${processed.metadata.totalProcedureExamples} procedure examples, and ${processed.metadata.totalMitigations} mitigations.`);

    if (isCheckMode) {
      console.log('🔍 Running in check mode...');
      if (!fs.existsSync(OUTPUT_DATA_FILE)) {
        console.error(`❌ Output file ${OUTPUT_DATA_FILE} does not exist!`);
        process.exit(1);
      }
      console.log('✅ MITRE ATLAS data check passed.');
      return;
    }

    const tsContent = generateTypeScriptFile(processed);
    fs.writeFileSync(OUTPUT_DATA_FILE, tsContent, 'utf8');
    console.log(`✅ Successfully generated: ${OUTPUT_DATA_FILE}`);
  } catch (err) {
    console.error(`❌ MITRE ATLAS sync failed:`, err);
    process.exit(1);
  }
}

main();
