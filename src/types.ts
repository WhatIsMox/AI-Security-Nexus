export type GlobalDomain = 'ALL' | 'LLM' | 'ML' | 'AGENT' | 'MCP';

export enum Pillar {
  APP = "AI Application",
  MODEL = "AI Model",
  INFRA = "AI Infrastructure",
  DATA = "AI Data"
}

export interface TestPayload {
  name: string;
  description: string;
  code?: string;
}

export interface ExternalResource {
  title: string;
  url: string;
}

export interface RealWorldIncident extends ExternalResource {
  id?: string;
  threatId?: string;
  title: string;
  url: string;
  year?: string;
  targetOrVictim?: string;
  attackVector?: string;
  impact?: string;
  recoveryTime?: string;
  repercussions?: string;
  remediation?: string;
  lessonsLearned?: string;
  cveOrAdvisoryId?: string;
  severity?: 'Critical' | 'High' | 'Medium' | 'Low';
  mappedThreats?: string[];
  mitreAtlasTechniques?: string[];
  additionalReferences?: ExternalResource[];
}

export interface SecurityTool {
  name: string;
  description: string;
  url: string;
  cost: string;
  type: 'Local' | 'Third-party';
  category?: 'Offensive' | 'Defensive' | 'Both';
  longDescription?: string;
  typicalUseCase?: string;
  keyFeatures?: string[];
  installationOrQuickstart?: string;
  ecosystem?: string[];
  license?: string;
  authorOrMaintainer?: string;
  mitreAtlasTechniques?: string[];
}

export interface SuggestedTool {
  name: string;
  description: string;
  url: string;
}

export interface MitigationStrategy {
  type: 'Remediation' | 'Mitigation';
  content: string;
}

export interface TestItem {
  id: string;
  title: string;
  pillar: Pillar;
  summary: string;
  objectives: string[];
  payloads: TestPayload[];
  expectedOutput?: string[];
  suggestedTools?: SuggestedTool[];
  mitigationStrategies: MitigationStrategy[];
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  externalResources?: ExternalResource[];
  owaspTop10Ref?: string;
  owaspMlTop10Ref?: string;
  owaspAgenticRef?: string;
  owaspSaifRef?: string;
  owaspMcpTop10Ref?: string;
  owaspDsgaiRef?: string;
  mitreAtlasRef?: string;
}

export interface MitreAtlasMitigation {
  id: string;
  name: string;
  description: string;
  useDescription?: string;
  url?: string;
}

export interface MitreAtlasCaseStudy {
  id: string;
  name: string;
  url?: string;
}

export interface MitreAtlasProcedureExample {
  caseStudyId: string;
  caseStudyName: string;
  description: string;
  url: string;
  stepId?: string;
  tacticId?: string;
}

export interface MitreAtlasReference {
  sourceName: string;
  description?: string;
  url?: string;
  externalId?: string;
}

export interface MitreAtlasSubtechniqueRef {
  id: string;
  name: string;
  description?: string;
  url?: string;
}

export interface MitreAtlasTechnique {
  id: string;
  name: string;
  description: string;
  tacticId: string;
  tacticName: string;
  tactics?: { id: string; name: string }[];
  isSubtechnique: boolean;
  parentTechniqueId?: string;
  parentTechniqueName?: string;
  subtechniques?: MitreAtlasSubtechniqueRef[];
  url: string;
  platforms?: string[];
  maturity?: string;
  attackReference?: { id: string; url: string };
  createdDate?: string;
  modifiedDate?: string;
  detection?: string;
  mitigations?: MitreAtlasMitigation[];
  caseStudies?: MitreAtlasCaseStudy[];
  procedureExamples?: MitreAtlasProcedureExample[];
  references?: MitreAtlasReference[];
  suggestedTools?: SuggestedTool[];
}

export interface MitreAtlasTactic {
  id: string;
  shortname: string;
  name: string;
  description: string;
  url: string;
  techniques: MitreAtlasTechnique[];
}

export interface MitreAtlasOverview {
  version: string;
  lastUpdated: string;
  totalTactics: number;
  totalTechniques: number;
  tactics: MitreAtlasTactic[];
}

export interface OwaspTop10Entry {
  id: string;
  title: string;
  description: string;
  whyUnique?: string;
  realWorldEvidence?: string[];
  commonRisks: string[];
  preventionStrategies: string[];
  attackScenarios: { title: string; description: string }[];
  implementationNotes?: { title: string; content: string }[];
  owaspMappings?: string[];
  otherMappings?: string[];
  mitreAtlasRef?: string;
  mitreAtlasRefs?: string[];
  maestroMappings?: { layer: string; name: string; details: string }[];
  relatedRisks?: { id: string; title: string; relationship: string }[];
  references: ExternalResource[];
  suggestedTools?: SecurityTool[];
}

export interface FrameworkOverview {
  edition: string;
  scopeNote: string;
  severityNote?: string;
  riskGroups: { title: string; entries: string[]; description: string }[];
  terminology: { term: string; definition: string }[];
  triageSteps: string[];
  resources: ExternalResource[];
}

export interface Stat {
  label: string;
  value: string | number;
  icon: any;
  color: string;
}
