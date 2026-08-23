# Rule: Architecture and Data Model Standards

## Context
AI Security Nexus is a data-driven React application designed to render complex security frameworks and test matrices with zero backend latency.

## Directives
1. **Unidirectional State Flow**:
   - Navigation and active selection state are centrally managed in `App.tsx`.
   - Child components must receive callbacks (`onSelectTest`, `onNavigateToOwasp`, `onSelectPillar`) rather than attempting side-effect routing.
2. **Data Layer Decoupling**:
   - All security frameworks and test matrices reside in static TypeScript files (`data_*.ts`).
   - `data.ts` serves as the centralized re-export hub for all data modules.
   - Do NOT embed large static data directly inside React component files.
3. **Pillar Taxonomy**:
   - Security tests must belong to one of the 4 Pillars defined in `Pillar` enum (`types.ts`):
     - `Pillar.APP` ("AI Application")
     - `Pillar.MODEL` ("AI Model")
     - `Pillar.INFRA` ("AI Infrastructure")
     - `Pillar.DATA` ("AI Data")
4. **Referential Consistency**:
   - Every test item should link to applicable framework risks (`owaspTop10Ref`, `owaspAgenticRef`, `owaspSaifRef`, `owaspMlTop10Ref`, `owaspMcpTop10Ref`).
   - IDs referenced in tests must exist in the corresponding framework catalog.
5. **GitHub Pages Deployment Compatibility**:
   - The application must compile to a completely static bundle (`dist/`) that runs on GitHub Pages without server-side compute.
   - All asset links and routing must support GitHub Pages subfolder paths (`/<repository-name>/`).
   - Run `npm run build` to confirm production static bundle integrity after every change.

