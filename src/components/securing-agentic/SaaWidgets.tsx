import React, { useMemo, useState } from 'react';
import {
  ArrowRight, ArrowDown, Check, X, AlertTriangle, ShieldCheck, ShieldAlert, Lock, Unlock,
  Database, Globe, Inbox, RotateCcw, Zap, Power, Eye, Ban, PauseCircle, Pencil, UserCheck,
  Clock, Hash, CheckCircle2, XCircle, Link2, Bot, User,
} from 'lucide-react';
import {
  SAA_KEY_COMPONENTS,
  SAA_THREATS,
  SAA_MEMORY_SCOPES,
  SAA_ARCHITECTURE_PATTERNS,
  SAA_CONTROL_PLANE_INPUTS,
  SAA_HOOKS,
  SAA_HOOK_DISPOSITIONS,
  SAA_HOOK_CONTROL_MAP,
  SAA_CIRCUIT_BREAKER_TIERS,
  SAA_CIRCUIT_BREAKER_SCHEMA,
  SAA_CIRCUIT_BREAKER_EXAMPLES,
  SAA_CAPABILITIES,
  SAA_ASSURANCE_CHAIN,
  SAA_TOOL_LIFECYCLE,
  SaaWidgetId,
  SaaTrustLevel,
  SaaSubcomponent,
} from '../../data/data_securing_agentic_apps';

// ─── Shared styling ──────────────────────────────────────────────────────────

/** Literal (JIT-safe) class sets per key component, mirroring the guide's color coding. */
export const KC_STYLES: Record<string, { text: string; bg: string; border: string; solid: string; bar: string }> = {
  KC1: { text: 'text-slate-200', bg: 'bg-slate-400/10', border: 'border-slate-400/40', solid: 'bg-slate-300', bar: 'bg-slate-300/80' },
  KC2: { text: 'text-indigo-300', bg: 'bg-indigo-500/10', border: 'border-indigo-400/40', solid: 'bg-indigo-400', bar: 'bg-indigo-400/80' },
  KC3: { text: 'text-sky-300', bg: 'bg-sky-500/10', border: 'border-sky-400/40', solid: 'bg-sky-400', bar: 'bg-sky-400/80' },
  KC4: { text: 'text-cyan-200', bg: 'bg-cyan-400/10', border: 'border-cyan-300/40', solid: 'bg-cyan-300', bar: 'bg-cyan-300/80' },
  KC5: { text: 'text-amber-300', bg: 'bg-amber-500/10', border: 'border-amber-400/40', solid: 'bg-amber-400', bar: 'bg-amber-400/80' },
  KC6: { text: 'text-orange-300', bg: 'bg-orange-700/15', border: 'border-orange-500/40', solid: 'bg-orange-600', bar: 'bg-orange-600/80' },
};

const TRUST_STYLES: Record<SaaTrustLevel, string> = {
  System: 'bg-violet-500/20 text-violet-200 border-violet-400/50',
  Vetted: 'bg-sky-500/15 text-sky-200 border-sky-400/40',
  User: 'bg-slate-700/60 text-slate-200 border-slate-500/50',
  Untrusted: 'bg-transparent text-amber-300 border-amber-400/60 border-dashed',
};

const panel = 'rounded-xl border border-slate-800 bg-slate-950/60 p-4';
const chipBtn = (active: boolean) =>
  `px-2.5 py-1 rounded-lg text-xs font-medium border transition-all duration-200 ${
    active
      ? 'bg-violet-500/20 text-violet-200 border-violet-400/60'
      : 'bg-slate-900/70 text-slate-400 border-slate-800 hover:border-violet-500/40 hover:text-slate-200'
  }`;

export interface SaaWidgetProps {
  onNavigateToOwasp?: (id: string) => void;
  onJumpToSection?: (sectionId: string) => void;
  focusThreat?: string | null;
}

const threatName = (id: string) => SAA_THREATS.find((t) => t.id === id)?.name ?? id;

const ThreatChip: React.FC<{ id: string; onClick?: () => void; active?: boolean }> = ({ id, onClick, active }) => (
  <button
    type="button"
    onClick={onClick}
    title={threatName(id)}
    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono border transition-colors ${
      active ? 'bg-rose-500/25 text-rose-200 border-rose-400/60' : 'bg-rose-500/10 text-rose-300 border-rose-500/30 hover:border-rose-400/60'
    }`}
  >
    {id}
    <span className="font-sans text-slate-300 hidden sm:inline">{threatName(id)}</span>
  </button>
);

const AsiLink: React.FC<{ asi?: string; onNavigateToOwasp?: (id: string) => void }> = ({ asi, onNavigateToOwasp }) => {
  if (!asi || !onNavigateToOwasp) return null;
  return (
    <button
      type="button"
      onClick={() => onNavigateToOwasp(asi)}
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400/70 transition-colors"
    >
      Related {asi} <ArrowRight className="w-3 h-3" />
    </button>
  );
};

// ─── 1. Key component explorer ──────────────────────────────────────────────

const SubcomponentCard: React.FC<{ sc: SaaSubcomponent; kc: string }> = ({ sc, kc }) => (
  <div className={`rounded-lg border ${KC_STYLES[kc].border} bg-slate-950/70 p-3 space-y-1.5`}>
    <div className="flex items-baseline gap-2">
      <span className={`font-mono text-[11px] font-bold ${KC_STYLES[kc].text}`}>{sc.id}</span>
      <span className="text-sm font-semibold text-slate-100">{sc.name}</span>
    </div>
    <p className="text-xs text-slate-400 leading-relaxed">{sc.description}</p>
    {sc.children && (
      <ul className="space-y-1.5 pt-1">
        {sc.children.map((c) => (
          <li key={c.id} className="text-xs text-slate-300 leading-relaxed pl-3 border-l border-slate-700">
            {!c.id.includes('-') && <span className={`font-mono font-bold ${KC_STYLES[kc].text} mr-1.5`}>{c.id}</span>}
            <span className="font-semibold text-slate-200">{c.name}:</span> {c.description}
          </li>
        ))}
      </ul>
    )}
  </div>
);

const KcExplorer: React.FC<SaaWidgetProps> = ({ onNavigateToOwasp }) => {
  const [selected, setSelected] = useState('KC1');
  const kc = SAA_KEY_COMPONENTS.find((k) => k.id === selected) ?? SAA_KEY_COMPONENTS[0];
  const st = KC_STYLES[kc.id];
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2" role="group" aria-label="Key components">
        {SAA_KEY_COMPONENTS.map((k) => {
          const s = KC_STYLES[k.id];
          const active = k.id === selected;
          return (
            <button
              key={k.id}
              type="button"
              aria-pressed={active}
              onClick={() => setSelected(k.id)}
              className={`text-left rounded-xl border p-3 transition-all duration-200 ${
                active ? `${s.bg} ${s.border} shadow-lg` : 'bg-slate-900/60 border-slate-800 hover:border-slate-600'
              }`}
            >
              <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-mono font-bold text-slate-950 ${s.solid}`}>{k.id}</span>
              <div className={`mt-1.5 text-xs font-semibold leading-snug ${active ? s.text : 'text-slate-300'}`}>{k.name}</div>
              <div className="text-[10px] text-slate-500 font-mono mt-1">{k.subcomponents.length} sub-components · {k.threats.length} threats</div>
            </button>
          );
        })}
      </div>

      <div className={`rounded-xl border ${st.border} bg-slate-900/50 p-4 sm:p-5 space-y-4`}>
        <div>
          <h4 className={`text-base font-bold ${st.text}`}>{kc.id} · {kc.name}</h4>
          <p className="text-sm text-slate-300 leading-relaxed mt-1.5">{kc.definition}</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          {kc.subcomponents.map((sc) => <SubcomponentCard key={sc.id} sc={sc} kc={kc.id} />)}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className={panel}>
            <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-rose-300 mb-2 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5" /> Attack surface (2.2)
            </div>
            <p className="text-xs text-slate-400 italic mb-2">{kc.riskSummary}</p>
            <ul className="space-y-2">
              {kc.threats.map((t) => {
                const th = SAA_THREATS.find((x) => x.id === t.id);
                return (
                  <li key={t.id} className="text-xs text-slate-300 leading-relaxed">
                    <div className="flex flex-wrap items-center gap-1.5 mb-0.5">
                      <ThreatChip id={t.id} />
                      <AsiLink asi={th?.relatedAsi} onNavigateToOwasp={onNavigateToOwasp} />
                    </div>
                    {t.text}
                  </li>
                );
              })}
            </ul>
          </div>
          <div className={panel}>
            <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-violet-300 mb-2 flex items-center gap-1.5">
              <Power className="w-3.5 h-3.5" /> Circuit breaker (3.3.8)
            </div>
            <div className="space-y-2.5 text-xs leading-relaxed">
              <div><span className="font-semibold text-slate-200">Watch: </span><span className="text-slate-300">{kc.breaker.detect}</span></div>
              <div><span className="font-semibold text-slate-200">Kill-switch actions: </span><span className="text-slate-300">{kc.breaker.actions}</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── 2. Memory scope matrix ─────────────────────────────────────────────────

const MemoryMatrix: React.FC = () => {
  const cols: ('Session' | 'Cross-session' | 'Cross-user')[] = ['Session', 'Cross-session', 'Cross-user'];
  const rows: ('In agent' | 'Cross-agent')[] = ['In agent', 'Cross-agent'];
  const intensity = ['', 'bg-cyan-500/5', 'bg-cyan-500/10', 'bg-amber-500/10', 'bg-amber-500/15', 'bg-rose-500/15', 'bg-rose-500/20'];
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40">
      <div className="min-w-[640px] grid grid-cols-[110px_repeat(3,1fr)] gap-2 p-3">
        <div />
        {cols.map((c) => (
          <div key={c} className="text-center text-[11px] font-mono uppercase tracking-wider text-slate-400 py-1">{c}</div>
        ))}
        {rows.map((r) => (
          <React.Fragment key={r}>
            <div className="flex flex-col justify-center text-xs text-slate-300 font-semibold">
              {r}
              <span className="text-[10px] font-normal text-slate-500">{r === 'In agent' ? 'single agent' : 'shared across agents'}</span>
            </div>
            {cols.map((c) => {
              const m = SAA_MEMORY_SCOPES.find((x) => x.sharing === r && x.persistence === c);
              if (!m) return <div key={c} />;
              return (
                <div key={c} className={`rounded-lg border border-slate-800 p-3 ${intensity[m.blastRadius]}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-300 text-slate-950">{m.id}</span>
                    <span className="text-xs font-semibold text-slate-100 leading-tight">{m.name}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">{m.compromise}</p>
                  <div className="flex gap-0.5 mt-2" aria-label={`Relative blast radius ${m.blastRadius} of 6`}>
                    {[1, 2, 3, 4, 5, 6].map((i) => (
                      <span key={i} className={`h-1.5 flex-1 rounded-full ${i <= m.blastRadius ? (m.blastRadius >= 5 ? 'bg-rose-400' : m.blastRadius >= 3 ? 'bg-amber-400' : 'bg-cyan-400') : 'bg-slate-800'}`} />
                    ))}
                  </div>
                </div>
              );
            })}
          </React.Fragment>
        ))}
      </div>
      <p className="px-3 pb-3 text-[11px] text-slate-500">Bars show the relative blast radius implied by each definition (editorial visual aid, not a score from the guide).</p>
    </div>
  );
};

// ─── 3. Threat × component heatmap ─────────────────────────────────────────

const ThreatHeatmap: React.FC<SaaWidgetProps> = ({ onNavigateToOwasp, focusThreat }) => {
  const [threat, setThreat] = useState<string | null>(focusThreat ?? null);
  const [kcSel, setKcSel] = useState<string | null>(null);
  const lookup = (kcId: string, tId: string) => SAA_KEY_COMPONENTS.find((k) => k.id === kcId)?.threats.find((t) => t.id === tId)?.text;
  const th = threat ? SAA_THREATS.find((t) => t.id === threat) : null;
  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40">
        <table className="min-w-[620px] w-full text-xs border-separate border-spacing-1 p-2">
          <thead>
            <tr>
              <th className="text-left font-mono text-[10px] uppercase text-slate-500 px-2">Threat</th>
              {SAA_KEY_COMPONENTS.map((k) => (
                <th key={k.id} scope="col">
                  <button
                    type="button"
                    aria-pressed={kcSel === k.id}
                    onClick={() => setKcSel(kcSel === k.id ? null : k.id)}
                    className={`w-full px-1.5 py-1 rounded text-[10px] font-mono font-bold text-slate-950 ${KC_STYLES[k.id].solid} ${kcSel && kcSel !== k.id ? 'opacity-30' : ''}`}
                  >
                    {k.id}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {SAA_THREATS.map((t) => {
              const rowActive = threat === t.id;
              return (
                <tr key={t.id} className={threat && !rowActive ? 'opacity-40' : ''}>
                  <th scope="row" className="text-left font-normal">
                    <button
                      type="button"
                      aria-pressed={rowActive}
                      onClick={() => setThreat(rowActive ? null : t.id)}
                      className={`w-full text-left px-2 py-1 rounded transition-colors ${rowActive ? 'bg-rose-500/15 text-rose-200' : 'text-slate-300 hover:bg-slate-800/70'}`}
                    >
                      <span className="font-mono text-rose-300 mr-1.5">{t.id}</span>{t.name}
                    </button>
                  </th>
                  {SAA_KEY_COMPONENTS.map((k) => {
                    const txt = lookup(k.id, t.id);
                    const dim = kcSel && kcSel !== k.id;
                    return (
                      <td key={k.id} className={`h-7 rounded ${txt ? KC_STYLES[k.id].bar : 'bg-slate-900/60'} ${dim ? 'opacity-25' : ''}`} title={txt ? `${k.id} · ${t.id}: ${txt}` : undefined}>
                        <span className="sr-only">{txt ? `${t.id} affects ${k.id}` : `${t.id} not listed for ${k.id}`}</span>
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {(th || kcSel) && (
        <div className={`${panel} space-y-2`}>
          {th && (
            <div className="flex flex-wrap items-center gap-2">
              <ThreatChip id={th.id} active />
              <AsiLink asi={th.relatedAsi} onNavigateToOwasp={onNavigateToOwasp} />
              <span className="text-xs text-slate-400">{th.summary}</span>
            </div>
          )}
          <ul className="space-y-1.5">
            {SAA_KEY_COMPONENTS.filter((k) => !kcSel || k.id === kcSel).flatMap((k) =>
              k.threats
                .filter((t) => !threat || t.id === threat)
                .map((t) => (
                  <li key={`${k.id}-${t.id}`} className="text-xs text-slate-300 leading-relaxed flex gap-2">
                    <span className={`shrink-0 px-1.5 py-0.5 h-fit rounded text-[10px] font-mono font-bold text-slate-950 ${KC_STYLES[k.id].solid}`}>{k.id}</span>
                    <span><span className="font-mono text-rose-300">{t.id}</span> — {t.text}</span>
                  </li>
                )),
            )}
          </ul>
        </div>
      )}
      <p className="text-[11px] text-slate-500">Click a threat or a component to focus it. Cells follow the detailed lists in 2.2.1–2.2.6.</p>
    </div>
  );
};

// ─── 4. Architecture patterns ───────────────────────────────────────────────

const Topology: React.FC<{ id: string }> = ({ id }) => {
  const node = 'px-2 py-1 rounded-md border border-violet-400/40 bg-violet-500/10 text-[11px] text-violet-100 whitespace-nowrap';
  if (id === 'sequential' || id === 'reactive' || id === 'knowledge') {
    const steps = id === 'sequential' ? ['User input', 'Single LLM agent', 'Tool execution', 'Output'] : id === 'reactive' ? ['Input', 'Reason', 'Act (tool)', 'Observe ↺'] : ['Query', 'Retrieve', 'Augment', 'Generate'];
    return (
      <div className="flex flex-wrap items-center gap-1.5">
        {steps.map((s, i) => (
          <React.Fragment key={s}>
            <span className={node}>{s}</span>
            {i < steps.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-slate-500" />}
          </React.Fragment>
        ))}
      </div>
    );
  }
  if (id === 'hierarchical') {
    return (
      <div className="flex flex-col items-center gap-1.5">
        <span className={node}>User input</span>
        <ArrowDown className="w-3.5 h-3.5 text-slate-500" />
        <span className={`${node} border-violet-300`}>Orchestrator agent</span>
        <ArrowDown className="w-3.5 h-3.5 text-slate-500" />
        <div className="flex flex-wrap justify-center gap-1.5">
          {['Calendar', 'Email', 'Drive'].map((s) => <span key={s} className={node}>{s} sub-agent</span>)}
        </div>
      </div>
    );
  }
  return (
    <svg viewBox="0 0 200 110" className="w-full max-w-[260px] h-auto mx-auto" role="img" aria-label="Peer agents fully connected in a mesh">
      {[[30, 25], [170, 25], [30, 85], [170, 85], [100, 55]].map(([x1, y1], i, arr) =>
        arr.slice(i + 1).map(([x2, y2], j) => <line key={`${i}-${j}`} x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgb(167 139 250 / 0.35)" strokeWidth="1.5" />),
      )}
      {[[30, 25], [170, 25], [30, 85], [170, 85], [100, 55]].map(([x, y], i) => (
        <g key={i}>
          <circle cx={x} cy={y} r="13" fill="rgb(15 23 42)" stroke="rgb(167 139 250)" strokeWidth="1.5" />
          <text x={x} y={y + 3.5} textAnchor="middle" fontSize="9" fill="rgb(221 214 254)">P{i + 1}</text>
        </g>
      ))}
    </svg>
  );
};

const ArchitecturePatterns: React.FC = () => {
  const [sel, setSel] = useState('sequential');
  const [view, setView] = useState<'profile' | 'table'>('profile');
  const pat = SAA_ARCHITECTURE_PATTERNS.find((x) => x.id === sel) ?? SAA_ARCHITECTURE_PATTERNS[0];
  const rows: [string, keyof typeof pat.profile, string][] = [
    ['Brain', 'brain', 'KC1'], ['Control', 'control', 'KC2'], ['Reasoning', 'reasoning', 'KC3'],
    ['Memory', 'memory', 'KC4'], ['Tools', 'tools', 'KC5'], ['Environment', 'environment', 'KC6'],
  ];
  const source = view === 'profile' ? pat.profile : pat.comprehensive;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Architecture patterns">
        {SAA_ARCHITECTURE_PATTERNS.map((x) => (
          <button key={x.id} type="button" aria-pressed={sel === x.id} onClick={() => setSel(x.id)} className={chipBtn(sel === x.id)}>{x.name}</button>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
        <div className={`${panel} lg:col-span-2 space-y-3`}>
          <Topology id={pat.id} />
          <p className="text-xs text-slate-300 leading-relaxed">{pat.summary}</p>
          {pat.trustModel && (
            <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-2.5 text-xs text-violet-100 leading-relaxed">
              <span className="font-semibold">Trust model: </span>{pat.trustModel}
            </div>
          )}
          <div className="flex flex-wrap gap-1.5">
            {pat.frameworks.map((f) => <span key={f} className="px-2 py-0.5 rounded-md text-[11px] bg-slate-800 text-slate-300 border border-slate-700">{f}</span>)}
          </div>
        </div>
        <div className={`${panel} lg:col-span-3`}>
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Component profile</span>
            <div className="flex gap-1">
              <button type="button" aria-pressed={view === 'profile'} onClick={() => setView('profile')} className={chipBtn(view === 'profile')}>2.3 profile</button>
              <button type="button" aria-pressed={view === 'table'} onClick={() => setView('table')} className={chipBtn(view === 'table')}>2.5 table</button>
            </div>
          </div>
          <dl className="divide-y divide-slate-800/80">
            {rows.map(([label, key, kc]) => (
              <div key={key} className="flex items-start gap-3 py-2">
                <dt className="w-24 shrink-0 flex items-center gap-1.5 text-xs text-slate-400">
                  <span className={`px-1 rounded text-[9px] font-mono font-bold text-slate-950 ${KC_STYLES[kc].solid}`}>{kc}</span>{label}
                </dt>
                <dd className="text-xs text-slate-200 leading-relaxed">{source[key]}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </div>
  );
};

// ─── 5. Control plane ───────────────────────────────────────────────────────

const ControlPlane: React.FC = () => (
  <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
    <div className="flex flex-wrap gap-1.5 items-center text-[11px] text-slate-400">
      Trust level recorded with each input:
      {(['System', 'Vetted', 'User', 'Untrusted'] as SaaTrustLevel[]).map((t) => (
        <span key={t} className={`px-2 py-0.5 rounded border ${TRUST_STYLES[t]}`}>{t}</span>
      ))}
    </div>
    <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto_1fr] gap-3 items-center">
      <ul className="space-y-1.5">
        {SAA_CONTROL_PLANE_INPUTS.map((i) => (
          <li key={i.input} className="rounded-lg border border-slate-800 bg-slate-900/60 p-2.5">
            <div className="flex items-start justify-between gap-2">
              <span className="text-xs text-slate-200 leading-snug">{i.input}</span>
              <span className={`shrink-0 px-1.5 py-0.5 rounded border text-[10px] font-mono ${TRUST_STYLES[i.trust]}`}>{i.trust}</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">{i.path}</div>
          </li>
        ))}
      </ul>
      <div className="flex lg:flex-col items-center justify-center gap-2 text-center">
        <ArrowRight className="w-4 h-4 text-slate-500 hidden lg:block" />
        <div className="rounded-lg border-2 border-slate-400/50 bg-slate-900 px-3 py-2">
          <div className="text-[10px] font-mono font-bold text-slate-950 bg-slate-300 rounded px-1 mb-1">KC1</div>
          <div className="text-xs text-slate-200 font-semibold">Model</div>
          <div className="text-[10px] text-slate-500 max-w-[110px]">roles & delimiters are provenance cues, not boundaries</div>
        </div>
        <ArrowRight className="w-4 h-4 text-slate-500" />
      </div>
      <div className="space-y-2">
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-100">
          <ShieldCheck className="w-4 h-4 inline mr-1.5" />
          <span className="font-semibold">Deterministic policy & authorization at the action sink</span>
          <div className="text-[11px] text-emerald-200/80 mt-1">Receives the <em>proposed</em> action; only authorized actions continue.</div>
        </div>
        <div className="flex justify-center"><ArrowDown className="w-4 h-4 text-slate-500" /></div>
        <div className="rounded-lg border border-dashed border-slate-600 p-2.5 text-xs text-slate-300 text-center">Outside systems</div>
      </div>
    </div>
    <p className="text-[11px] text-slate-500 flex items-center gap-1.5"><Hash className="w-3 h-3" /> System prompts and tool definitions are verified against approved hashes at session start and at checkpoints.</p>
  </div>
);

// ─── 6. Effective scope calculator ──────────────────────────────────────────

const SCOPE_PERMS = ['calendar:read', 'calendar:write', 'email:read', 'email:send', 'drive:read', 'drive:share', 'drive:delete', 'payments:transfer'];
type ScopeSet = 'user' | 'agent' | 'intent' | 'consent';
const SCOPE_LABELS: Record<ScopeSet, string> = { user: 'User permission', agent: 'Agent capability', intent: 'Bound intent', consent: 'Consented scope' };
const INITIAL_SCOPES: Record<ScopeSet, string[]> = {
  user: ['calendar:read', 'calendar:write', 'email:read', 'email:send', 'drive:read', 'drive:share', 'drive:delete'],
  agent: ['calendar:read', 'calendar:write', 'email:read', 'email:send', 'drive:read', 'drive:share', 'payments:transfer'],
  intent: ['calendar:read', 'calendar:write', 'email:send'],
  consent: ['calendar:read', 'calendar:write', 'email:read', 'email:send'],
};

const EffectiveScope: React.FC = () => {
  const [sets, setSets] = useState<Record<ScopeSet, string[]>>(INITIAL_SCOPES);
  const [userPresent, setUserPresent] = useState(true);
  const active: ScopeSet[] = userPresent ? ['user', 'agent', 'intent', 'consent'] : ['user', 'agent', 'intent'];
  const toggle = (s: ScopeSet, p: string) =>
    setSets((prev) => ({ ...prev, [s]: prev[s].includes(p) ? prev[s].filter((x) => x !== p) : [...prev[s], p] }));
  const effective = SCOPE_PERMS.filter((p) => active.every((s) => sets[s].includes(p)));
  const ambient = SCOPE_PERMS.filter((p) => sets.user.includes(p) || sets.agent.includes(p));
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-slate-400">Illustrative scenario: a copilot asked to <span className="text-slate-200">“schedule a meeting and send the invite”</span>. Toggle cells to see the intersection change.</p>
        <div className="flex gap-1.5">
          <button type="button" aria-pressed={userPresent} onClick={() => setUserPresent(!userPresent)} className={chipBtn(userPresent)}>
            {userPresent ? 'User present (Auth Code + PKCE)' : 'No user (Client Credentials)'}
          </button>
          <button type="button" onClick={() => setSets(INITIAL_SCOPES)} className={chipBtn(false)} aria-label="Reset scopes"><RotateCcw className="w-3.5 h-3.5" /></button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-[560px] w-full text-xs">
          <thead>
            <tr className="text-[10px] font-mono uppercase text-slate-500">
              <th className="text-left py-1.5 pr-2">Permission</th>
              {active.map((s) => <th key={s} className="px-1.5">{SCOPE_LABELS[s]}</th>)}
              <th className="px-1.5 text-violet-300">Effective</th>
            </tr>
          </thead>
          <tbody>
            {SCOPE_PERMS.map((p) => {
              const eff = effective.includes(p);
              return (
                <tr key={p} className="border-t border-slate-800/70">
                  <td className="py-1.5 pr-2 font-mono text-slate-300">{p}</td>
                  {active.map((s) => {
                    const on = sets[s].includes(p);
                    return (
                      <td key={s} className="px-1.5 text-center">
                        <button
                          type="button"
                          aria-pressed={on}
                          aria-label={`${SCOPE_LABELS[s]} includes ${p}`}
                          onClick={() => toggle(s, p)}
                          className={`w-7 h-7 rounded-md border inline-flex items-center justify-center transition-colors ${on ? 'bg-slate-700/70 border-slate-500 text-slate-100' : 'bg-slate-950 border-slate-800 text-slate-700 hover:border-slate-600'}`}
                        >
                          {on ? <Check className="w-3.5 h-3.5" /> : <X className="w-3 h-3" />}
                        </button>
                      </td>
                    );
                  })}
                  <td className="px-1.5 text-center">
                    {eff ? <CheckCircle2 className="w-4 h-4 text-violet-300 inline" aria-label="allowed" /> : <XCircle className="w-4 h-4 text-slate-700 inline" aria-label="denied" />}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <div className="rounded-lg border border-violet-400/40 bg-violet-500/10 p-2.5">
          <div className="text-[11px] font-mono uppercase text-violet-300 mb-1">Effective scope ({effective.length})</div>
          <div className="text-xs text-violet-100 font-mono break-words">{effective.length ? effective.join(', ') : '∅ — nothing may run'}</div>
        </div>
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-2.5">
          <div className="text-[11px] font-mono uppercase text-rose-300 mb-1">Ambient authority — what NOT to do ({ambient.length})</div>
          <div className="text-xs text-rose-100/80 font-mono break-words">{ambient.join(', ')}</div>
        </div>
      </div>
    </div>
  );
};

// ─── 7. Rule of Two / Lethal Trifecta ───────────────────────────────────────

const LEGS = [
  { id: 'sensitive', label: 'Accesses private or sensitive data/systems', icon: Database },
  { id: 'untrusted', label: 'Processes untrusted content', icon: Inbox },
  { id: 'external', label: 'Communicates externally or changes state', icon: Globe },
] as const;
type LegId = typeof LEGS[number]['id'];
const PRESETS: { name: string; legs: LegId[]; note: string }[] = [
  { name: 'Coding / computer-use agent', legs: ['sensitive', 'untrusted', 'external'], note: 'A Lethal Trifecta by definition (5.5.1).' },
  { name: 'Inbox assistant that can send mail', legs: ['sensitive', 'untrusted', 'external'], note: 'Reads attacker-controllable email, holds private data, and can send.' },
  { name: 'Internal RAG Q&A without egress', legs: ['sensitive', 'untrusted'], note: 'Retrieved documents are untrusted; no external channel or state change.' },
  { name: 'Public web research summarizer', legs: ['untrusted', 'external'], note: 'No private data in reach.' },
];

const RuleOfTwo: React.FC = () => {
  const [legs, setLegs] = useState<LegId[]>(['sensitive', 'untrusted']);
  const count = legs.length;
  const toggle = (id: LegId) => setLegs((l) => (l.includes(id) ? l.filter((x) => x !== id) : [...l, id]));
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
      <div className="flex flex-wrap gap-1.5">
        <span className="text-[11px] text-slate-500 self-center mr-1">Presets:</span>
        {PRESETS.map((pr) => (
          <button key={pr.name} type="button" onClick={() => setLegs(pr.legs)} className={chipBtn(false)} title={pr.note}>{pr.name}</button>
        ))}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        {LEGS.map((l) => {
          const on = legs.includes(l.id);
          const Icon = l.icon;
          return (
            <button
              key={l.id}
              type="button"
              aria-pressed={on}
              onClick={() => toggle(l.id)}
              className={`text-left rounded-xl border p-3 transition-all duration-200 ${on ? (count === 3 ? 'border-rose-400/70 bg-rose-500/15' : 'border-violet-400/60 bg-violet-500/10') : 'border-slate-800 bg-slate-900/50 hover:border-slate-600'}`}
            >
              <div className="flex items-center justify-between">
                <Icon className={`w-4 h-4 ${on ? 'text-slate-100' : 'text-slate-500'}`} />
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${on ? 'bg-slate-100 text-slate-900' : 'bg-slate-800 text-slate-500'}`}>{on ? 'HELD' : 'OFF'}</span>
              </div>
              <div className={`text-xs mt-2 leading-snug ${on ? 'text-slate-100 font-semibold' : 'text-slate-400'}`}>{l.label}</div>
            </button>
          );
        })}
      </div>
      <div
        role="status"
        aria-live="polite"
        className={`rounded-xl border p-3 text-xs leading-relaxed ${count === 3 ? 'border-rose-500/50 bg-rose-500/10 text-rose-100' : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-100'}`}
      >
        {count === 3 ? (
          <>
            <div className="flex items-center gap-1.5 font-bold text-sm mb-1"><AlertTriangle className="w-4 h-4" /> Lethal Trifecta — 3 of 3 legs</div>
            This agent can be manipulated into exfiltrating data. Default: remove one capability, or split the legs across independently authorized components with hard information-flow and egress boundaries. Any exception needs layered deterministic enforcement, tested information-flow/egress controls, documented residual-risk ownership, and HITL or monitoring only as a supporting control.
          </>
        ) : (
          <>
            <div className="flex items-center gap-1.5 font-bold text-sm mb-1"><ShieldCheck className="w-4 h-4" /> Within the Rule of Two — {count} of 3 legs</div>
            {count === 2
              ? 'Acceptable composition, but every newly acquired capability must be re-checked: adding the third leg at runtime would create the trifecta.'
              : 'Low composition risk. Still apply the per-capability controls from Section 5.'}
          </>
        )}
      </div>
    </div>
  );
};

// ─── 8. Two validation gates ───────────────────────────────────────────────

const ValidationGates: React.FC = () => {
  const [gate, setGate] = useState<'admission' | 'execution'>('admission');
  const box = 'rounded-lg border border-dashed border-slate-600 p-2.5 text-[11px] text-slate-400 leading-relaxed';
  const gateBtn = (id: 'admission' | 'execution', title: string, sub: string) => (
    <button
      type="button"
      aria-pressed={gate === id}
      onClick={() => setGate(id)}
      className={`rounded-lg border-2 p-2.5 text-center transition-all ${gate === id ? 'border-violet-400 bg-violet-500/15 text-violet-100' : 'border-slate-600 bg-slate-900 text-slate-300 hover:border-violet-500/60'}`}
    >
      <div className="text-xs font-bold">{title}</div>
      <div className="text-[10px] text-slate-400">{sub}</div>
    </button>
  );
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto_1fr_auto_auto_auto_1fr_auto_1fr] items-center gap-2">
        <div className={box}><span className="text-slate-200 font-semibold">Untrusted content</span><br />user input · web pages · RAG results · tool/API outputs · MCP tool descriptions · agent messages · non-text media</div>
        <ArrowRight className="w-4 h-4 text-slate-500 hidden lg:block" />
        {gateBtn('admission', 'Context admission validation', 'before content enters the model context')}
        <ArrowRight className="w-4 h-4 text-slate-500 hidden lg:block" />
        <div className="rounded-lg border-2 border-slate-400/50 bg-slate-900 px-3 py-2 text-center"><span className="text-[10px] font-mono font-bold bg-slate-300 text-slate-950 rounded px-1">KC1</span><div className="text-xs text-slate-200">Model context</div></div>
        <ArrowRight className="w-4 h-4 text-slate-500 hidden lg:block" />
        {gateBtn('execution', 'Action execution validation', 'before anything affects the world')}
        <ArrowRight className="w-4 h-4 text-slate-500 hidden lg:block" />
        <div className={box}><span className="text-slate-200 font-semibold">Outside world</span><br />API calls · code execution · DB writes · email/send · file writes · browser actions · OS commands</div>
      </div>
      <p className="text-[11px] text-slate-500 flex items-center gap-1.5"><RotateCcw className="w-3 h-3" /> Tool/API outputs and other results return as untrusted content — back through gate 1.</p>
      <div className={`${panel} text-xs text-slate-300 leading-relaxed`}>
        {gate === 'admission'
          ? 'Keeps instruction-like or malicious content from being admitted as trusted instruction. Fragmented multi-layer payloads evade content filters, so schema enforcement and runtime isolation come before content sanitization. Media goes through the same trust policy: OCR or speech-to-text output is still untrusted.'
          : 'Confirms the action is authorized, in scope, and matches the agent’s declared intent before it executes. Parse once into a canonical typed structure, then authorize every operation against actor, intent, target, resource, and current policy — schema conformance is not authorization.'}
      </div>
    </div>
  );
};

// ─── 9. Guardrail placement ────────────────────────────────────────────────

const GUARDRAILS = [
  { name: 'API Gateway (input layer)', what: 'Deterministic controls on inputs and access: only valid, authorized, safe queries come in.', visibility: 1, note: 'Network-based: may lack the session history needed to catch multi-turn prompt injection.' },
  { name: 'LLM (model)', what: 'Model alignment and behavior rules: system prompt & policies, fine-tuning / RLHF.', visibility: 2, note: 'Probabilistic — a best-effort layer.' },
  { name: 'Agent (reasoning & tools)', what: 'Orchestration and tool-use guardrails: tool permissions, step-wise validation, memory controls.', visibility: 3, note: 'In the application/agent code space: full visibility and context.' },
  { name: 'Output (post-process)', what: 'Final output filtering and correction: safe for the user, correct, compliant, and on-objective.', visibility: 3, note: 'In the application code space; sees the full response.' },
];

const GuardrailPlacement: React.FC = () => (
  <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
    <div className="text-[11px] font-mono uppercase tracking-wider text-slate-500 flex items-center gap-1.5">Request path <ArrowRight className="w-3 h-3" /></div>
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
      {GUARDRAILS.map((g) => (
        <div key={g.name} className={`rounded-lg border p-3 space-y-2 ${g.visibility === 1 ? 'border-dashed border-slate-600 bg-slate-900/40' : 'border-slate-700 bg-slate-900/70'}`}>
          <div className="text-xs font-bold text-slate-100">{g.name}</div>
          <p className="text-[11px] text-slate-400 leading-relaxed">{g.what}</p>
          <div>
            <div className="text-[10px] font-mono text-slate-500 mb-1 flex items-center gap-1"><Eye className="w-3 h-3" /> Session visibility</div>
            <div className="flex gap-0.5">{[1, 2, 3].map((i) => <span key={i} className={`h-1.5 flex-1 rounded-full ${i <= g.visibility ? 'bg-violet-400' : 'bg-slate-800'}`} />)}</div>
          </div>
          <p className="text-[11px] text-slate-500 italic">{g.note}</p>
        </div>
      ))}
    </div>
    <p className="text-[11px] text-slate-500">In a multi-agent workflow, weight placement by each agent’s influence on the output — in a sequential architecture the last agent influences it most.</p>
  </div>
);

// ─── 10. Hook explorer ─────────────────────────────────────────────────────

const DISP_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  Allow: Check, Deny: Ban, Modify: Pencil, Escalate: UserCheck, Defer: PauseCircle,
};

const HookExplorer: React.FC = () => {
  const [disp, setDisp] = useState<string>('ALL');
  const [sel, setSel] = useState('toolCallRequest');
  const [failure, setFailure] = useState(false);
  const matches = (h: typeof SAA_HOOKS[number]) =>
    disp === 'ALL' || (disp === 'Audit' ? h.dispositions.some((d) => d.startsWith('Audit')) : h.dispositions.includes(disp));
  const hook = SAA_HOOKS.find((h) => h.id === sel) ?? SAA_HOOKS[0];
  const related = SAA_HOOK_CONTROL_MAP.filter((m) => hook.id.split(' / ').some((part) => m.hooks.includes(part)));
  const canEscalate = hook.dispositions.includes('Escalate');
  const scopes: ('Session' | 'Turn' | 'Inner')[] = ['Session', 'Turn', 'Inner'];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter hooks by disposition">
        <span className="text-[11px] text-slate-500 mr-1">Returns:</span>
        {['ALL', 'Allow', 'Deny', 'Modify', 'Escalate', 'Defer', 'Audit'].map((d) => (
          <button key={d} type="button" aria-pressed={disp === d} onClick={() => setDisp(d)} className={chipBtn(disp === d)}>{d === 'ALL' ? 'All 18 hooks' : d}</button>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
        <div className="lg:col-span-3 space-y-2">
          {scopes.map((sc) => (
            <div key={sc} className="rounded-xl border border-slate-800 bg-slate-950/40 p-2.5">
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1.5">{sc === 'Inner' ? 'Inner (not strictly sequential)' : sc}</div>
              <div className="flex flex-wrap gap-1.5">
                {SAA_HOOKS.filter((h) => h.scope === sc).map((h) => {
                  const on = matches(h);
                  const active = sel === h.id;
                  return (
                    <button
                      key={h.id}
                      type="button"
                      aria-pressed={active}
                      onClick={() => setSel(h.id)}
                      className={`px-2 py-1 rounded-md text-[11px] font-mono border transition-all ${
                        active ? 'bg-violet-500/25 border-violet-300 text-violet-100'
                          : h.priority === 'first' ? 'border-violet-400/70 text-slate-200 bg-slate-900'
                          : h.priority === 'next' ? 'border-dashed border-violet-400/60 text-slate-200 bg-slate-900'
                          : 'border-slate-700 text-slate-300 bg-slate-900'
                      } ${on ? '' : 'opacity-25'}`}
                    >
                      {h.id}
                      {h.dispositions.every((d) => d.startsWith('Audit')) && <span className="ml-1 text-[9px] text-slate-500">audit</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
          <p className="text-[11px] text-slate-500">Solid violet border: wire first (near-universally available). Dashed: wire next.</p>
        </div>
        <div className={`${panel} lg:col-span-2 space-y-3`}>
          <div>
            <div className="text-[10px] font-mono uppercase text-slate-500">{hook.scope} hook</div>
            <div className="text-sm font-bold font-mono text-violet-200 break-words">{hook.id}</div>
            {hook.priority && <div className="text-[11px] text-violet-300 mt-0.5">{hook.priority === 'first' ? '★ Wire this first' : '☆ Wire this next'}</div>}
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{hook.controls}</p>
          <div className="flex flex-wrap gap-1.5">
            {hook.dispositions.map((d) => {
              const Icon = DISP_ICONS[d] ?? Eye;
              return <span key={d} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] bg-slate-800 text-slate-200 border border-slate-700"><Icon className="w-3 h-3" />{d}</span>;
            })}
          </div>
          {related.length > 0 && (
            <ul className="space-y-1">
              {related.map((r) => <li key={r.control} className="text-[11px] text-slate-400"><span className="text-slate-200 font-semibold">{r.control}</span> ({r.ref}): {r.hooks}</li>)}
            </ul>
          )}
          <div className="border-t border-slate-800 pt-2.5 space-y-2">
            <button type="button" aria-pressed={failure} onClick={() => setFailure(!failure)} className={chipBtn(failure)}>
              <Zap className="w-3 h-3 inline mr-1" />Simulate enforcement timeout
            </button>
            {failure && (
              <div role="status" className="text-[11px] rounded-lg border border-rose-500/40 bg-rose-500/10 text-rose-100 p-2 leading-relaxed">
                Hook cannot decide → <span className="font-bold">fail closed: {canEscalate ? 'Deny or Escalate' : hook.dispositions.includes('Deny') ? 'Deny' : 'halt and alert (audit-only hook must not silently pass)'}</span>. Never Allow by default — a hook that fails open can be bypassed by anyone able to make it fail.
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
        {SAA_HOOK_DISPOSITIONS.map((d) => {
          const Icon = DISP_ICONS[d.id] ?? Eye;
          return (
            <div key={d.id} className="rounded-lg border border-slate-800 bg-slate-900/50 p-2.5">
              <div className="text-xs font-bold text-slate-100 flex items-center gap-1.5"><Icon className="w-3.5 h-3.5 text-violet-300" />{d.id}</div>
              <p className="text-[11px] text-slate-400 leading-relaxed mt-1">{d.description}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// ─── 11. Circuit breaker designer ──────────────────────────────────────────

const CircuitBreaker: React.FC = () => {
  const [tier, setTier] = useState(0);
  const [kc, setKc] = useState('KC5');
  const comp = SAA_KEY_COMPONENTS.find((k) => k.id === kc) ?? SAA_KEY_COMPONENTS[0];
  const tierColors = ['bg-sky-400', 'bg-amber-400', 'bg-orange-500', 'bg-rose-500'];
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
        <div className="text-[11px] font-mono uppercase tracking-wider text-slate-500">Graduated tiers — click to escalate</div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {SAA_CIRCUIT_BREAKER_TIERS.map((t, i) => (
            <button key={t.id} type="button" aria-pressed={tier === i} onClick={() => setTier(i)} className={`rounded-lg border p-2.5 text-left transition-all ${i <= tier ? 'border-slate-500 bg-slate-800/70' : 'border-slate-800 bg-slate-900/40'}`}>
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${i <= tier ? tierColors[i] : 'bg-slate-700'}`} />
                <span className="text-xs font-bold text-slate-100">{i + 1}. {t.id}</span>
              </div>
            </button>
          ))}
        </div>
        <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden"><div className={`h-full transition-all duration-300 ${tierColors[tier]}`} style={{ width: `${((tier + 1) / 4) * 100}%` }} /></div>
        <p className="text-xs text-slate-300">{SAA_CIRCUIT_BREAKER_TIERS[tier].description}</p>
        {tier === 3 && <p className="text-[11px] text-rose-200 flex items-center gap-1.5"><Clock className="w-3 h-3" /> Capture the incident snapshot (frozen context window + tamper-evident provenance chain) before kill or rollback.</p>}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {SAA_CIRCUIT_BREAKER_SCHEMA.map((s) => (
          <div key={s.id} className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <div className="text-xs font-bold text-violet-200 mb-1">{s.id}</div>
            <p className="text-[11px] text-slate-400 leading-relaxed">{s.text}</p>
          </div>
        ))}
      </div>
      <div className={`${panel} space-y-2.5`}>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] text-slate-500 mr-1">Per-component matrix:</span>
          {SAA_KEY_COMPONENTS.map((k) => (
            <button key={k.id} type="button" aria-pressed={kc === k.id} onClick={() => setKc(k.id)} className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold text-slate-950 ${KC_STYLES[k.id].solid} ${kc === k.id ? 'ring-2 ring-white/70' : 'opacity-50 hover:opacity-80'}`}>{k.id}</button>
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs leading-relaxed">
          <div className="rounded-lg bg-slate-900/70 border border-slate-800 p-2.5"><div className="text-[10px] font-mono uppercase text-slate-500 mb-1">Detection space · {comp.name}</div><span className="text-slate-300">{comp.breaker.detect}</span></div>
          <div className="rounded-lg bg-slate-900/70 border border-slate-800 p-2.5"><div className="text-[10px] font-mono uppercase text-slate-500 mb-1">Kill-switch actions</div><span className="text-slate-300">{comp.breaker.actions}</span></div>
        </div>
      </div>
      <details className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 group">
        <summary className="cursor-pointer text-xs font-semibold text-slate-200">Worked trigger examples ({SAA_CIRCUIT_BREAKER_EXAMPLES.length})</summary>
        <ul className="mt-2 space-y-1.5">
          {SAA_CIRCUIT_BREAKER_EXAMPLES.map((e) => <li key={e} className="text-xs text-slate-300 leading-relaxed pl-3 border-l-2 border-violet-500/40">{e}</li>)}
        </ul>
      </details>
    </div>
  );
};

// ─── 12. Capability matrix with composition check ──────────────────────────

const legTone = (v: string) => (/^(yes|often)/i.test(v) ? 'text-rose-300' : /^(possibly|via|bounded)/i.test(v) ? 'text-amber-300' : 'text-slate-400');

const CapabilityMatrix: React.FC<SaaWidgetProps> = ({ onJumpToSection }) => {
  const [held, setHeld] = useState<string[]>(['CAP-DB']);
  const [strict, setStrict] = useState(false);
  const toggle = (id: string) => setHeld((h) => (h.includes(id) ? h.filter((x) => x !== id) : [...h, id]));
  const combined = useMemo(() => {
    const caps = SAA_CAPABILITIES.filter((c) => held.includes(c.id));
    return {
      sensitive: caps.some((c) => c.legs.sensitive),
      untrusted: caps.some((c) => c.legs.untrusted),
      external: caps.some((c) => (strict ? c.externalComms === 'Yes' : c.legs.external || c.externalComms === 'Bounded')),
    };
  }, [held, strict]);
  const legCount = Number(combined.sensitive) + Number(combined.untrusted) + Number(combined.external);
  return (
    <div className="space-y-3">
      <div className="space-y-2">
        {SAA_CAPABILITIES.map((c) => {
          const on = held.includes(c.id);
          return (
            <div key={c.id} className={`rounded-xl border p-3 transition-all ${on ? 'border-violet-400/50 bg-violet-500/5' : 'border-slate-800 bg-slate-950/40'}`}>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <button type="button" aria-pressed={on} aria-label={`Agent holds ${c.name}`} onClick={() => toggle(c.id)} className={`w-6 h-6 shrink-0 rounded-md border flex items-center justify-center ${on ? 'bg-violet-500 border-violet-400 text-white' : 'border-slate-600 text-transparent hover:border-violet-400'}`}>
                    <Check className="w-3.5 h-3.5" />
                  </button>
                  <div>
                    <div className="text-sm font-semibold text-slate-100">{c.name} <span className="font-mono text-[11px] text-orange-300">{c.kc}</span></div>
                    <div className="text-[11px] text-slate-500 font-mono">{c.capabilityClass}</div>
                  </div>
                </div>
                {onJumpToSection && (
                  <button type="button" onClick={() => onJumpToSection(c.sectionId)} className="text-[11px] text-violet-300 hover:text-violet-100 inline-flex items-center gap-1">
                    Controls in {c.sectionId.replace('SAA-', '§')} <ArrowRight className="w-3 h-3" />
                  </button>
                )}
              </div>
              <div className="grid grid-cols-3 gap-2 mt-2.5 text-[11px]">
                <div><div className="text-slate-500">Sensitive data?</div><div className={`font-semibold ${legTone(c.sensitiveData)}`}>{c.sensitiveData}</div></div>
                <div><div className="text-slate-500">Untrusted input?</div><div className={`font-semibold ${legTone(c.untrustedInput)}`}>{c.untrustedInput}</div></div>
                <div><div className="text-slate-500">External / state change?</div><div className={`font-semibold ${legTone(c.externalComms)}`}>{c.externalComms}</div></div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2 text-[11px] leading-relaxed">
                <div><span className="text-slate-500">Required controls: </span><span className="text-slate-300">{c.requiredControls}</span></div>
                <div><span className="text-slate-500">Escalation trigger: </span><span className="text-amber-200">{c.escalationTrigger}</span></div>
              </div>
            </div>
          );
        })}
      </div>
      <div role="status" aria-live="polite" className={`rounded-xl border p-3 ${legCount === 3 ? 'border-rose-500/50 bg-rose-500/10' : 'border-emerald-500/40 bg-emerald-500/10'}`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className={`text-sm font-bold flex items-center gap-1.5 ${legCount === 3 ? 'text-rose-100' : 'text-emerald-100'}`}>
            {legCount === 3 ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
            Composed agent ({held.length} capabilities): {legCount}/3 trifecta legs
          </div>
          <button type="button" aria-pressed={strict} onClick={() => setStrict(!strict)} className={chipBtn(strict)}>{strict ? 'Bounded egress ≠ external' : 'Count bounded egress as external'}</button>
        </div>
        <div className="flex flex-wrap gap-1.5 mt-2 text-[11px]">
          {(['sensitive', 'untrusted', 'external'] as const).map((k) => (
            <span key={k} className={`px-2 py-0.5 rounded border ${combined[k] ? 'border-slate-300 text-slate-100' : 'border-slate-700 text-slate-500'}`}>{k === 'sensitive' ? 'Sensitive data' : k === 'untrusted' ? 'Untrusted input' : 'External / state change'}</span>
          ))}
        </div>
        <p className="text-xs text-slate-300 mt-2 leading-relaxed">
          {legCount === 3
            ? 'The combination covers all three legs: add sandboxing, HITL, runtime monitoring, or architectural separation — or remove a leg (2.7.3).'
            : 'Below the trifecta. Re-run this check whenever the agent acquires a capability dynamically.'}
        </p>
      </div>
    </div>
  );
};

// ─── 13. On-Behalf-Of delegation chain ─────────────────────────────────────

const OboChain: React.FC = () => {
  const [revokedAt, setRevokedAt] = useState<number | null>(null);
  const [depthLimit, setDepthLimit] = useState(3);
  const hops = [
    { name: 'User', icon: User, scope: 100, ttl: '—' },
    { name: 'Orchestrator agent', icon: Bot, scope: 70, ttl: '15 min' },
    { name: 'Sub-agent', icon: Bot, scope: 45, ttl: '5 min' },
    { name: 'Sub-agent (next hop)', icon: Bot, scope: 25, ttl: '2 min' },
  ];
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="rounded-lg border border-violet-400/40 bg-violet-500/10 px-2.5 py-1.5 text-[11px] text-violet-100 flex items-center gap-1.5">
          <Link2 className="w-3.5 h-3.5" /> Signed, immutable, intent-locked task descriptor travels unchanged
        </div>
        <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
          Depth limit:
          {[1, 2, 3].map((d) => <button key={d} type="button" aria-pressed={depthLimit === d} onClick={() => setDepthLimit(d)} className={chipBtn(depthLimit === d)}>{d}</button>)}
          <button type="button" onClick={() => setRevokedAt(null)} className={chipBtn(false)} aria-label="Reset revocation"><RotateCcw className="w-3.5 h-3.5" /></button>
        </div>
      </div>
      <div className="space-y-1.5">
        {hops.map((h, i) => {
          const blockedByDepth = i > depthLimit;
          const revoked = revokedAt !== null && i >= revokedAt && i > 0;
          const Icon = h.icon;
          return (
            <div key={h.name} className={`grid grid-cols-[150px_1fr_auto] sm:grid-cols-[190px_1fr_auto] items-center gap-2 ${blockedByDepth || revoked ? 'opacity-40' : ''}`}>
              <div className="flex items-center gap-1.5 text-xs text-slate-200 min-w-0">
                <Icon className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                <span className="truncate">{h.name}</span>
              </div>
              <div className="h-5 rounded bg-slate-900 border border-slate-800 relative overflow-hidden">
                <div className={`h-full ${i === 0 ? 'bg-slate-500/50' : 'bg-violet-500/50'} transition-all`} style={{ width: `${h.scope}%` }} />
                <span className="absolute inset-0 flex items-center px-2 text-[10px] font-mono text-slate-200">
                  {i === 0 ? 'user permission' : blockedByDepth ? 'exchange refused: depth limit' : revoked ? 'revoked (cascade)' : `token ⊂ parent · TTL ${h.ttl}`}
                </span>
              </div>
              {i > 0 ? (
                <button type="button" disabled={blockedByDepth} onClick={() => setRevokedAt(i)} className="text-[10px] px-2 py-1 rounded border border-rose-500/40 text-rose-300 hover:bg-rose-500/10 disabled:opacity-40">Revoke</button>
              ) : <span />}
            </div>
          );
        })}
      </div>
      <p className="text-[11px] text-slate-500">Each hop performs its own OAuth 2.0 Token Exchange (RFC 8693) and receives a short-lived, task-bound, audience-bound token that is a proper subset of its parent. Revoking a hop cascades downstream. Bar widths and TTLs are illustrative.</p>
    </div>
  );
};

// ─── 14. Tool lifecycle ────────────────────────────────────────────────────

const ToolLifecycle: React.FC = () => {
  const [changed, setChanged] = useState(false);
  const [ttlExpired, setTtlExpired] = useState(false);
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
      <div className="text-[11px] font-mono uppercase tracking-wider text-slate-500">Onboard</div>
      <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
        {SAA_TOOL_LIFECYCLE.onboard.map((s, i) => (
          <li key={s.id} className="rounded-lg border border-slate-700 bg-slate-900/60 p-2.5">
            <div className="text-[10px] font-mono text-violet-300">Step {i + 1}</div>
            <div className="text-xs font-semibold text-slate-100">{s.id}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">{s.detail}</div>
          </li>
        ))}
      </ol>
      <div className="text-[11px] font-mono uppercase tracking-wider text-slate-500 pt-1">Run — every session</div>
      <div className="flex flex-wrap gap-1.5">
        <button type="button" aria-pressed={changed} onClick={() => setChanged(!changed)} className={chipBtn(changed)}>Live definition changed since approval</button>
        <button type="button" aria-pressed={ttlExpired} onClick={() => setTtlExpired(!ttlExpired)} className={chipBtn(ttlExpired)}>Approval TTL expired</button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr_auto_1fr] items-center gap-2">
        {SAA_TOOL_LIFECYCLE.run.map((s, i) => (
          <React.Fragment key={s.id}>
            <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-2.5">
              <div className="text-xs font-semibold text-slate-100">{s.id}</div>
              <div className="text-[11px] text-slate-400 mt-0.5">{s.detail}</div>
            </div>
            {i < SAA_TOOL_LIFECYCLE.run.length && <ArrowRight className="w-4 h-4 text-slate-500 hidden md:block" />}
          </React.Fragment>
        ))}
        <div role="status" aria-live="polite" className={`rounded-lg border-2 p-2.5 text-xs leading-relaxed ${changed ? 'border-rose-500/60 bg-rose-500/10 text-rose-100' : 'border-emerald-500/50 bg-emerald-500/10 text-emerald-100'}`}>
          <div className="font-bold mb-0.5">{changed ? 'Digest mismatch' : 'Digest matches'}</div>
          {changed ? SAA_TOOL_LIFECYCLE.mismatch : SAA_TOOL_LIFECYCLE.match}
          {ttlExpired && <div className="mt-1 text-amber-200">TTL expired → automatic re-validation first; never silent re-approval.</div>}
        </div>
      </div>
    </div>
  );
};

// ─── 15. Assurance chain ───────────────────────────────────────────────────

const AssuranceChain: React.FC = () => {
  const [sel, setSel] = useState(0);
  const step = SAA_ASSURANCE_CHAIN[sel];
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4 space-y-3">
      <ol className="flex flex-wrap items-center gap-1.5">
        {SAA_ASSURANCE_CHAIN.map((s, i) => (
          <li key={s.id} className="flex items-center gap-1.5">
            <button type="button" aria-pressed={sel === i} onClick={() => setSel(i)} className={chipBtn(sel === i)}>
              <span className="font-mono text-[10px] mr-1 opacity-70">{i + 1}</span>{s.label}
            </button>
            {i < SAA_ASSURANCE_CHAIN.length - 1 && <ArrowRight className="w-3 h-3 text-slate-600" />}
          </li>
        ))}
      </ol>
      <div className={`${panel} text-xs text-slate-300 leading-relaxed`}>
        <span className="font-semibold text-violet-200">{step.label}: </span>{step.detail}
      </div>
      <p className="text-[11px] text-slate-500 flex items-start gap-1.5"><RotateCcw className="w-3 h-3 mt-0.5 shrink-0" /> A regression trigger loops back to the design scope: partial replay of the affected design checks, red-team scenarios, and behavioral cases. An undocumented decision to skip revalidation is itself an assurance gap.</p>
    </div>
  );
};

// ─── Registry ──────────────────────────────────────────────────────────────

export const SAA_WIDGET_LABELS: Record<SaaWidgetId, string> = {
  'kc-explorer': 'Key Component Explorer',
  'memory-matrix': 'Memory Scope Matrix',
  'threat-heatmap': 'Threat × Component Heatmap',
  'architecture-patterns': 'Architecture Pattern Comparator',
  'control-plane': 'Control-Plane Trust Map',
  'effective-scope': 'Effective Scope Calculator',
  'rule-of-two': 'Rule of Two Checker',
  'validation-gates': 'Two Validation Gates',
  'guardrail-placement': 'Guardrail Placement',
  'hooks': 'Hook Explorer',
  'circuit-breaker': 'Circuit Breaker Designer',
  'capability-matrix': 'Capability Composition Matrix',
  'obo-chain': 'OBO Delegation Chain',
  'tool-lifecycle': 'Tool Lifecycle & Rug-Pull Check',
  'assurance-chain': 'Assurance Chain',
};

export const SaaWidget: React.FC<SaaWidgetProps & { id: SaaWidgetId }> = ({ id, ...props }) => {
  switch (id) {
    case 'kc-explorer': return <KcExplorer {...props} />;
    case 'memory-matrix': return <MemoryMatrix />;
    case 'threat-heatmap': return <ThreatHeatmap key={props.focusThreat ?? 'none'} {...props} />;
    case 'architecture-patterns': return <ArchitecturePatterns />;
    case 'control-plane': return <ControlPlane />;
    case 'effective-scope': return <EffectiveScope />;
    case 'rule-of-two': return <RuleOfTwo />;
    case 'validation-gates': return <ValidationGates />;
    case 'guardrail-placement': return <GuardrailPlacement />;
    case 'hooks': return <HookExplorer />;
    case 'circuit-breaker': return <CircuitBreaker />;
    case 'capability-matrix': return <CapabilityMatrix {...props} />;
    case 'obo-chain': return <OboChain />;
    case 'tool-lifecycle': return <ToolLifecycle />;
    case 'assurance-chain': return <AssuranceChain />;
  }
};

