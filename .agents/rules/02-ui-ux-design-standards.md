# Rule: UI/UX Design and Aesthetic Standards

## Context
AI Security Nexus delivers a cybersecurity command-center experience with high visual fidelity, modern typography, glassmorphism, and responsive interactive SVG diagrams.

## Directives
1. **Dark Mode Palette**:
   - Canvas: `bg-slate-950` with subtle background glow orbs (`bg-cyan-500/5`, `bg-purple-500/5` with `blur-[100px]`).
   - Cards/Containers: `bg-slate-900/60` with `border border-slate-800/80` and `backdrop-blur-md`.
   - Badges & Highlights:
     - Critical: `bg-red-500/10 text-red-400 border-red-500/20`
     - High: `bg-orange-500/10 text-orange-400 border-orange-500/20`
     - Medium: `bg-amber-500/10 text-amber-400 border-amber-500/20`
     - Low: `bg-blue-500/10 text-blue-400 border-blue-500/20`
2. **Interactive Elements & Hover Feedback**:
   - All interactive cards must have hover feedback (`transition-all duration-200 hover:border-cyan-500/50 hover:bg-slate-900/90`).
   - Copyable code blocks in `TestDetail` must offer visual copy confirmation.
3. **Accessibility & Responsive Layout**:
   - Mobile navigation: Sidebar must support collapse/drawer mode toggled via `isSidebarOpen` and close on `Escape` key.
   - Contrast: Ensure all text maintains WCAG AA contrast against dark backgrounds.
   - SVG components in `ThreatModelling.tsx` must maintain responsive viewBox properties.
