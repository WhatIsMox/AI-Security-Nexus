
import React, { useState } from 'react';
import { TestItem, SecurityTool } from '../types';
import { getEnrichedTool } from '../tool_details_catalog';
import ToolDetailModal from './ToolDetailModal';
import { 
  ArrowLeft, Target, Code, ShieldCheck, ExternalLink, BookOpen, 
  Wrench, Shield, Brain, Terminal, Eye, Link as LinkIcon, Cpu, 
  Bot, AlertCircle, Gavel, Network, Copy, Check, Lock, Globe, Info
} from 'lucide-react';

interface TestDetailProps {
  test: TestItem;
  onBack: () => void;
  onNavigateToOwasp: (id: string) => void;
}

const TestDetail: React.FC<TestDetailProps> = ({ test, onBack, onNavigateToOwasp }) => {
  const [copiedPayloadIndex, setCopiedPayloadIndex] = useState<number | null>(null);
  const [selectedTool, setSelectedTool] = useState<SecurityTool | null>(null);
  const isAgentic = test.id.startsWith('AGT') || !!test.owaspAgenticRef;

  const handleToolClick = (tool: SecurityTool) => {
    setSelectedTool(tool);
  };

  const handleCopyPayload = (code: string, index: number) => {
    navigator.clipboard.writeText(code).then(() => {
      setCopiedPayloadIndex(index);
      setTimeout(() => {
        setCopiedPayloadIndex(null);
      }, 2000);
    });
  };

  return (
    <div className="container-fluid p-3 sm:p-5 md:p-8 max-w-5xl mx-auto animate-in slide-in-from-right-4 duration-300">
      <button 
        onClick={onBack}
        className="flex items-center text-sm text-slate-400 hover:text-cyan-400 mb-6 transition-colors"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to list
      </button>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="p-3.5 sm:p-6 md:p-8 border-b border-slate-800 bg-slate-950">
          <div className="flex flex-col gap-3 sm:gap-4">
            
            <div className="flex flex-col items-start justify-between gap-3 sm:flex-row">
               {/* Identifiers */}
               <div className="flex flex-wrap items-center gap-1.5 sm:gap-3">
                  <span className="font-mono text-xs sm:text-sm text-cyan-500 bg-cyan-950/30 px-2.5 py-1 sm:px-3 sm:py-1.5 rounded border border-cyan-900">
                    {test.id}
                  </span>
                  {test.owaspTop10Ref && (
                    <button 
                      onClick={() => onNavigateToOwasp(test.owaspTop10Ref!)}
                      className="flex items-center gap-1.5 font-mono text-xs sm:text-sm text-pink-400 bg-pink-500/10 px-2.5 py-1 sm:px-3 sm:py-1.5 rounded border border-pink-500/20 hover:bg-pink-500/20 hover:border-pink-500/40 transition-all cursor-pointer"
                      title="Go to OWASP LLM Top 10 Entry"
                    >
                      <Brain className="w-3.5 h-3.5" /> {test.owaspTop10Ref}
                    </button>
                  )}
                  {test.owaspMlTop10Ref && (
                    <button 
                      onClick={() => onNavigateToOwasp(test.owaspMlTop10Ref!)}
                      className="flex items-center gap-1.5 font-mono text-xs sm:text-sm text-emerald-400 bg-emerald-500/10 px-2.5 py-1 sm:px-3 sm:py-1.5 rounded border border-emerald-500/20 hover:bg-emerald-500/20 hover:border-emerald-500/40 transition-all cursor-pointer"
                      title="Go to OWASP ML Top 10 Entry"
                    >
                      <Cpu className="w-3.5 h-3.5" /> {test.owaspMlTop10Ref}
                    </button>
                  )}
                  {test.owaspAgenticRef && (
                    <button 
                      onClick={() => onNavigateToOwasp(test.owaspAgenticRef!)}
                      className="flex items-center gap-1.5 font-mono text-xs sm:text-sm text-orange-400 bg-orange-500/10 px-2.5 py-1 sm:px-3 sm:py-1.5 rounded border border-orange-500/20 hover:bg-orange-500/20 hover:border-orange-500/40 transition-all cursor-pointer"
                      title="Go to OWASP Agentic Top 10 entry"
                    >
                      <Bot className="w-3.5 h-3.5" /> {test.owaspAgenticRef}
                    </button>
                  )}
                  {test.owaspSaifRef && (
                    <button 
                      onClick={() => onNavigateToOwasp(test.owaspSaifRef!)}
                      className="flex items-center gap-1.5 font-mono text-xs sm:text-sm text-blue-400 bg-blue-500/10 px-2.5 py-1 sm:px-3 sm:py-1.5 rounded border border-blue-500/20 hover:bg-blue-500/20 hover:border-blue-500/40 transition-all cursor-pointer"
                      title="Go to Google SAIF Risk Entry"
                    >
                      <Gavel className="w-3.5 h-3.5" /> {test.owaspSaifRef}
                    </button>
                  )}
                  {test.owaspMcpTop10Ref && (
                    <button 
                      onClick={() => onNavigateToOwasp(test.owaspMcpTop10Ref!)}
                      className="flex items-center gap-1.5 font-mono text-xs sm:text-sm text-cyan-400 bg-cyan-500/10 px-2.5 py-1 sm:px-3 sm:py-1.5 rounded border border-cyan-500/20 hover:bg-cyan-500/20 hover:border-cyan-500/40 transition-all cursor-pointer"
                      title="Go to OWASP MCP Top 10 Entry"
                    >
                      <Network className="w-3.5 h-3.5" /> {test.owaspMcpTop10Ref}
                    </button>
                  )}
                  <span className="text-slate-400 text-xs sm:text-sm font-medium border-l border-slate-800 pl-2 sm:pl-3">
                    {test.pillar}
                  </span>
               </div>

               <span className={`px-3 py-1 sm:px-4 sm:py-1.5 rounded-full text-xs sm:text-sm font-bold border shrink-0 ${
                 test.riskLevel === 'Critical' ? 'text-red-400 bg-red-950/30 border-red-900' :
                 test.riskLevel === 'High' ? 'text-orange-400 bg-orange-950/30 border-orange-900' :
                 test.riskLevel === 'Medium' ? 'text-yellow-400 bg-yellow-950/30 border-yellow-900' :
                 'text-green-400 bg-green-950/30 border-green-900'
               }`}>
                 {test.riskLevel} Risk
               </span>
            </div>

            <div>
              <h1 className="text-xl sm:text-2xl md:text-3xl font-bold text-slate-100 tracking-tight break-words">
                {test.title}
              </h1>
              <p className="text-slate-400 text-xs sm:text-sm md:text-base mt-2 leading-relaxed">
                {test.summary}
              </p>
            </div>

          </div>
        </div>

        {/* Content Body */}
        <div className="p-3.5 sm:p-6 md:p-8 space-y-6 sm:space-y-8">
          
          {/* Objectives */}
          <section>
            <div className="flex items-center gap-2 mb-3 sm:mb-4 text-slate-100">
              <Target className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400 shrink-0" />
              <h3 className="text-lg sm:text-xl font-bold">Testing Objectives</h3>
            </div>
            <ul className="space-y-2">
              {test.objectives.map((obj, i) => (
                <li key={i} className="flex items-start gap-2.5 sm:gap-3 text-slate-300 bg-slate-950 p-3 sm:p-4 rounded-lg border border-slate-800/80">
                  <span className="font-mono text-cyan-500 font-bold text-xs sm:text-sm">{i + 1}.</span>
                  <span className="text-xs sm:text-sm leading-relaxed">{obj}</span>
                </li>
              ))}
            </ul>
          </section>

          {/* Payloads / Test Vectors */}
          <section>
            <div className="flex items-center gap-2 mb-3 sm:mb-4 text-slate-100">
              <Code className="w-4 h-4 sm:w-5 sm:h-5 text-purple-400 shrink-0" />
              <h3 className="text-lg sm:text-xl font-bold">How to Test / Payloads</h3>
            </div>
            <div className="grid gap-3 sm:gap-4">
              {test.payloads.map((payload, i) => (
                <div key={i} className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
                  <div className="px-3.5 py-2.5 sm:px-4 sm:py-2 bg-slate-900 border-b border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                    <span className="font-semibold text-xs sm:text-sm text-slate-200 break-words">{payload.name}</span>
                    {payload.code && (
                      <button
                        onClick={() => handleCopyPayload(payload.code!, i)}
                        type="button"
                        className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono transition-all self-end sm:self-auto ${
                          copiedPayloadIndex === i
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'bg-slate-800/80 text-slate-400 hover:text-white hover:bg-slate-700 border border-slate-700'
                        }`}
                        title="Copy attack payload"
                      >
                        {copiedPayloadIndex === i ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span>Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy Payload</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>
                  <div className="p-3.5 sm:p-4">
                    <p className="text-slate-400 text-xs sm:text-sm mb-3 whitespace-pre-line leading-relaxed">{payload.description}</p>
                    {payload.code && (
                      <div className="relative group mt-2">
                        <div className="absolute top-0 right-0 px-2 py-0.5 text-[9px] sm:text-[10px] text-slate-500 font-mono">PAYLOAD / CODE</div>
                        <pre className="bg-black/50 text-green-400 p-3 pt-5 sm:p-4 sm:pt-6 rounded-lg font-mono text-xs sm:text-sm whitespace-pre-wrap break-words border border-slate-800 overflow-x-auto">
                          <code>{payload.code}</code>
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Expected Output */}
          {test.expectedOutput && test.expectedOutput.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-4 text-slate-100">
                <Eye className="w-5 h-5 text-amber-400" />
                <h3 className="text-xl font-bold">Expected Output / Indicators of Vulnerability</h3>
              </div>
              <ul className="space-y-2">
                {test.expectedOutput.map((out, i) => (
                  <li key={i} className="flex items-start gap-3 text-slate-300 bg-amber-500/5 p-4 rounded-lg border border-amber-500/20">
                    <div className="w-1.5 h-1.5 rounded-full bg-amber-500 mt-2 shrink-0" />
                    <span className="text-sm">{out}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Remediation */}
          <section>
            <div className="flex items-center gap-2 mb-4 text-slate-100">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h3 className="text-xl font-bold">Remediation & Mitigation</h3>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              {test.mitigationStrategies.map((item, i) => (
                <div key={i} className={`p-4 border-b last:border-0 border-slate-800 flex gap-4 ${item.type === 'Remediation' ? 'bg-emerald-500/5' : 'bg-blue-500/5'}`}>
                  <div className="shrink-0 mt-1">
                    {item.type === 'Remediation' ? (
                      <div className="p-1.5 rounded-md bg-emerald-500/20 text-emerald-400" title="Remediation: Fixes the root cause">
                         <Wrench className="w-4 h-4" />
                      </div>
                    ) : (
                      <div className="p-1.5 rounded-md bg-blue-500/20 text-blue-400" title="Mitigation: Reduces impact">
                         <Shield className="w-4 h-4" />
                      </div>
                    )}
                  </div>
                  <div>
                    <span className={`text-xs font-bold uppercase tracking-wider mb-1 block ${item.type === 'Remediation' ? 'text-emerald-500' : 'text-blue-500'}`}>
                      {item.type}
                    </span>
                    <p className="text-slate-300 text-sm leading-relaxed">
                      {item.content}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Suggested Tools */}
          {test.suggestedTools && test.suggestedTools.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-4 text-slate-100">
                <Terminal className="w-5 h-5 text-pink-400" />
                <h3 className="text-xl font-bold">Suggested Tools ({test.suggestedTools.length})</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {test.suggestedTools.map((rawTool, i) => {
                  const tool = getEnrichedTool(rawTool);
                  return (
                    <div 
                      key={i} 
                      onClick={() => handleToolClick(tool)}
                      className="bg-slate-950 border border-slate-800 hover:border-pink-500/50 rounded-xl p-4 transition-all hover:bg-slate-900/60 cursor-pointer group shadow-sm flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-sm text-slate-200 group-hover:text-pink-300 transition-colors">
                              {tool.name}
                            </span>
                            <Info className="w-3.5 h-3.5 text-slate-500 group-hover:text-pink-400 transition-colors" />
                          </div>
                          <div className="flex gap-1.5 flex-wrap justify-end">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider flex items-center gap-1 ${
                              tool.type === 'Local' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                            }`}>
                              {tool.type === 'Local' ? <Lock className="w-2 h-2" /> : <Globe className="w-2 h-2" />}
                              {tool.type}
                            </span>
                            {(() => {
                              const isFreeOnly = tool.cost.trim().toLowerCase() === 'free';
                              const hasFreeTier = tool.cost.toLowerCase().includes('free');
                              const costStyle = isFreeOnly
                                ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                                : hasFreeTier
                                ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20'
                                : 'text-amber-400 bg-amber-500/10 border-amber-500/20';
                              return (
                                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border font-mono ${costStyle}`}>
                                  {tool.cost}
                                </span>
                              );
                            })()}
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
                              (tool.category || 'Offensive') === 'Offensive'
                                ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                                : (tool.category || 'Offensive') === 'Both'
                                  ? 'bg-purple-500/15 text-purple-300 border border-purple-500/30'
                                  : 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20'
                            }`}>
                              {tool.category || 'Offensive'}
                            </span>
                          </div>
                        </div>
                        <p className="text-xs text-slate-400 leading-relaxed line-clamp-2">
                          {tool.description}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* External Resources */}
          {test.externalResources && test.externalResources.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-4 text-slate-100">
                <BookOpen className="w-5 h-5 text-blue-400" />
                <h3 className="text-xl font-bold">References & Deep Dives</h3>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {test.externalResources.map((res, i) => (
                  <a 
                    key={i} 
                    href={res.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="flex items-center justify-between p-4 bg-slate-800/50 hover:bg-slate-800 border border-slate-700 hover:border-blue-400/50 rounded-lg transition-all group"
                  >
                    <span className="text-slate-300 font-medium group-hover:text-blue-300 text-sm">{res.title}</span>
                    <LinkIcon className="w-4 h-4 text-slate-500 group-hover:text-blue-400 shrink-0 ml-3" />
                  </a>
                ))}
              </div>
            </section>
          )}

        </div>
      </div>

      {/* Tool Detail Inspection Modal */}
      <ToolDetailModal
        tool={selectedTool}
        onClose={() => setSelectedTool(null)}
        onNavigateToOwasp={onNavigateToOwasp}
      />
    </div>
  );
};

export default TestDetail;
