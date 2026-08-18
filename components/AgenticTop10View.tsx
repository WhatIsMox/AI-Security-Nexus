import React, { useEffect, useState } from 'react';
import { Blocks, Bot, ExternalLink } from 'lucide-react';
import {
  AGENTIC_APPLICATIONS_OVERVIEW,
  AGENTIC_SKILLS_OVERVIEW,
  OWASP_AGENTIC_APPLICATIONS_DATA,
  OWASP_AGENTIC_THREATS_DATA,
} from '../data';
import OwaspTop10View from './OwaspTop10View';

type AgenticFramework = 'applications' | 'skills';

interface AgenticTop10ViewProps {
  initialExpandedId?: string | null;
}

const AgenticTop10View: React.FC<AgenticTop10ViewProps> = ({ initialExpandedId }) => {
  const [framework, setFramework] = useState<AgenticFramework>(
    initialExpandedId?.startsWith('AST') ? 'skills' : 'applications',
  );

  useEffect(() => {
    if (initialExpandedId?.startsWith('AST')) setFramework('skills');
    if (initialExpandedId?.startsWith('ASI')) setFramework('applications');
  }, [initialExpandedId]);

  const selectFramework = (next: AgenticFramework) => {
    setFramework(next);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const currentSource = framework === 'applications'
    ? {
        label: 'Official ASI publication',
        url: 'https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/',
        className: 'text-orange-300 hover:text-orange-200',
      }
    : {
        label: 'Official AST project',
        url: 'https://owasp.org/www-project-agentic-skills-top-10/',
        className: 'text-cyan-300 hover:text-cyan-200',
      };

  return (
    <div>
      <section className="px-4 md:px-8 pt-5 max-w-6xl mx-auto" aria-label="Agentic security framework selector">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-3">
          <div className="flex items-center gap-3 min-w-0">
            <span className="hidden md:block pl-1 text-[11px] font-bold uppercase tracking-[0.18em] text-slate-500 whitespace-nowrap">Agentic framework</span>
            <div className="inline-flex w-full sm:w-auto rounded-lg border border-slate-700 bg-slate-950/80 p-1" role="tablist" aria-label="Agentic Top 10 framework">
              <button
                id="agentic-applications-tab"
                type="button"
                role="tab"
                aria-selected={framework === 'applications'}
                aria-controls="agentic-applications-panel"
                onClick={() => selectFramework('applications')}
                className={`flex flex-1 sm:flex-none items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition-all ${framework === 'applications' ? 'bg-orange-500/15 text-orange-200 shadow-sm ring-1 ring-orange-500/30' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'}`}
              >
                <Bot className="w-4 h-4" />Applications <span className="font-mono text-[10px] opacity-75">ASI</span>
              </button>
              <button
                id="agentic-skills-tab"
                type="button"
                role="tab"
                aria-selected={framework === 'skills'}
                aria-controls="agentic-skills-panel"
                onClick={() => selectFramework('skills')}
                className={`flex flex-1 sm:flex-none items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition-all ${framework === 'skills' ? 'bg-cyan-500/15 text-cyan-200 shadow-sm ring-1 ring-cyan-500/30' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'}`}
              >
                <Blocks className="w-4 h-4" />Skills <span className="font-mono text-[10px] opacity-75">AST</span>
              </button>
            </div>
          </div>
          <a href={currentSource.url} target="_blank" rel="noopener noreferrer" className={`inline-flex items-center gap-1.5 px-2 text-xs font-medium whitespace-nowrap ${currentSource.className}`}>
            {currentSource.label}<ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </section>

      {framework === 'applications' ? (
        <div id="agentic-applications-panel" role="tabpanel" aria-labelledby="agentic-applications-tab">
          <OwaspTop10View
            key="agentic-applications"
            initialExpandedId={initialExpandedId?.startsWith('ASI') ? initialExpandedId : null}
            data={OWASP_AGENTIC_APPLICATIONS_DATA}
            title="OWASP Top 10 for Agentic Applications 2026"
            description="Application-level risks across agent goals, tools, identities, supply chains, execution, memory, inter-agent coordination, systemic propagation, human trust, and behavioral integrity."
            colorTheme="orange"
            frameworkOverview={AGENTIC_APPLICATIONS_OVERVIEW}
          />
        </div>
      ) : (
        <div id="agentic-skills-panel" role="tabpanel" aria-labelledby="agentic-skills-tab">
          <OwaspTop10View
            key="agentic-skills"
            initialExpandedId={initialExpandedId?.startsWith('AST') ? initialExpandedId : null}
            data={OWASP_AGENTIC_THREATS_DATA}
            title="OWASP Agentic Skills Top 10"
            description="Skill-layer risks for reusable agent instructions, code, metadata, registries, runtime permissions, lifecycle controls, and cross-platform reuse."
            colorTheme="cyan"
            frameworkOverview={AGENTIC_SKILLS_OVERVIEW}
          />
        </div>
      )}
    </div>
  );
};

export default AgenticTop10View;
