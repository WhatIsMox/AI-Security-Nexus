
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
  additionalReferences?: ExternalResource[];
}

export interface SecurityTool {
  name: string;
  description: string;
  url: string;
  cost: 'Free' | 'Free+Paid' | 'Paid' | '€' | '€€' | '€€€' | '€€€€';
  type: 'Local' | 'Third-party';
  category?: 'Offensive' | 'Defensive' | 'Both';
  longDescription?: string;
  typicalUseCase?: string;
  keyFeatures?: string[];
  installationOrQuickstart?: string;
  ecosystem?: string[];
  license?: string;
  authorOrMaintainer?: string;
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
