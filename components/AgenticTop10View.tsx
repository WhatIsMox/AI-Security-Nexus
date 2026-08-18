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

  return (
    <div>
      <section className="px-4 md:px-8 pt-4 max-w-6xl mx-auto" aria-label="Agentic security framework selector">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4 md:p-5 shadow-xl shadow-black/10">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
              <p className="text-xs font-bold uppercase tracking-[0.2em] text-orange-400 mb-1">OWASP agentic security</p>
              <h1 className="text-xl font-bold text-white">Two complementary Top 10 frameworks</h1>
              <p className="text-sm text-slate-400 mt-1 max-w-2xl">Choose the system-wide application risks (ASI) or the reusable skill-layer risks (AST). Both lists remain complete, independently sourced, and connected to the rest of the testing guide.</p>
            </div>
            <div className="grid sm:grid-cols-2 gap-2 lg:w-[520px]" role="tablist" aria-label="Agentic Top 10 framework">
              <button
                type="button"
                role="tab"
                aria-selected={framework === 'applications'}
                onClick={() => selectFramework('applications')}
                className={`text-left rounded-xl border p-3 transition-colors ${framework === 'applications' ? 'border-orange-500/50 bg-orange-500/15 text-white' : 'border-slate-700 bg-slate-950/60 text-slate-400 hover:border-slate-600 hover:text-white'}`}
              >
                <span className="flex items-center gap-2 font-bold text-sm"><Bot className="w-4 h-4 text-orange-400" />Agentic Applications</span>
                <span className="block text-[11px] mt-1 font-mono text-orange-300">ASI01-ASI10 · 2026</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={framework === 'skills'}
                onClick={() => selectFramework('skills')}
                className={`text-left rounded-xl border p-3 transition-colors ${framework === 'skills' ? 'border-cyan-500/50 bg-cyan-500/10 text-white' : 'border-slate-700 bg-slate-950/60 text-slate-400 hover:border-slate-600 hover:text-white'}`}
              >
                <span className="flex items-center gap-2 font-bold text-sm"><Blocks className="w-4 h-4 text-cyan-400" />Agentic Skills</span>
                <span className="block text-[11px] mt-1 font-mono text-cyan-300">AST01-AST10 · August 2026</span>
              </button>
            </div>
          </div>
          <div className="flex flex-wrap gap-3 mt-4 pt-4 border-t border-slate-800 text-xs">
            <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-orange-300 hover:text-orange-200">Official ASI publication <ExternalLink className="w-3 h-3" /></a>
            <a href="https://owasp.org/www-project-agentic-skills-top-10/" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-cyan-300 hover:text-cyan-200">Official AST project <ExternalLink className="w-3 h-3" /></a>
          </div>
        </div>
      </section>

      {framework === 'applications' ? (
        <OwaspTop10View
          key="agentic-applications"
          initialExpandedId={initialExpandedId?.startsWith('ASI') ? initialExpandedId : null}
          data={OWASP_AGENTIC_APPLICATIONS_DATA}
          title="OWASP Top 10 for Agentic Applications 2026"
          description="Application-level risks across agent goals, tools, identities, supply chains, execution, memory, inter-agent coordination, systemic propagation, human trust, and behavioral integrity."
          colorTheme="orange"
          frameworkOverview={AGENTIC_APPLICATIONS_OVERVIEW}
        />
      ) : (
        <OwaspTop10View
          key="agentic-skills"
          initialExpandedId={initialExpandedId?.startsWith('AST') ? initialExpandedId : null}
          data={OWASP_AGENTIC_THREATS_DATA}
          title="OWASP Agentic Skills Top 10"
          description="Skill-layer risks for reusable agent instructions, code, metadata, registries, runtime permissions, lifecycle controls, and cross-platform reuse."
          colorTheme="cyan"
          frameworkOverview={AGENTIC_SKILLS_OVERVIEW}
        />
      )}
    </div>
  );
};

export default AgenticTop10View;
