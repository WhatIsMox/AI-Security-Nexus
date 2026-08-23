# Rule: Security & Content Security Policy (CSP)

## Context
As a cybersecurity documentation tool, this application enforces strict Content Security Policy (CSP) and secure coding standards.

## Directives
1. **CSP Strictness in Vite Build**:
   - `default-src 'self'`
   - `script-src 'self' https://stats.byreference.net`
   - `connect-src 'self' https://stats.byreference.net`
   - `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`
   - `font-src 'self' https://fonts.gstatic.com`
   - `img-src 'self' data:`
   - `object-src 'none'`
2. **Payload Safety**:
   - Attack vectors and prompt injection payloads in `data_tests.ts` must be treated as untrusted strings.
   - Always display payloads inside standard React code containers (`<pre><code>{payload.code}</code></pre>`).
   - Never use `dangerouslySetInnerHTML` to render test payloads or external resources.
3. **No Unvetted External Resources**:
   - Do not load fonts, scripts, or stylesheets from unapproved domains outside the CSP definition in `vite.config.ts`.
