export function renderLandingHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clauth: Encrypted Credential Proxy + Firewall for Agents</title>
  <meta name="description" content="Clauth brokers agent API calls so skills never see raw tokens. Encrypted vault, per-skill scopes, host allowlists, anomaly detection, and a tamper-evident audit trail." />
  <link rel="canonical" href="https://cl-auth.com/" />
  <meta name="theme-color" content="#0a0e17" />
  <link rel="icon" type="image/png" href="/favicon.png" />
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
  <meta property="og:site_name" content="Clauth" />
  <meta property="og:url" content="https://cl-auth.com/" />
  <meta property="og:title" content="Clauth: Encrypted Credential Proxy + Firewall for Agents" />
  <meta property="og:description" content="Secure agent API calls without exposing credentials. Encrypted vault, scoped grants, endpoint policies, anomaly detection, and a tamper-evident audit trail." />
  <meta property="og:image" content="https://cl-auth.com/og.png" />
  <meta property="og:image:alt" content="Clauth. Encrypted credential proxy + firewall for agents. Get started at cl-auth.com." />
  <meta property="og:type" content="website" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Clauth: Encrypted Credential Proxy + Firewall for Agents" />
  <meta name="twitter:description" content="Store credentials once. Agents get scoped handles, never raw tokens. Encrypted vault, endpoint policies, anomaly detection, tamper-evident audit." />
  <meta name="twitter:image" content="https://cl-auth.com/og.png" />
  <meta name="twitter:image:alt" content="Clauth. Encrypted credential proxy + firewall for agents. Get started at cl-auth.com." />
  <style>
    :root {
      --bg: #0a0e17;
      --bg-card: #111827;
      --bg-card-hover: #1a2332;
      --border: #1e293b;
      --border-active: #f97316;
      --text: #e2e8f0;
      --text-muted: #64748b;
      --text-dim: #475569;
      --accent: #f97316;
      --accent-glow: rgba(249, 115, 22, 0.16);
      --green: #22c55e;
      --green-glow: rgba(34, 197, 94, 0.12);
      --red: #ef4444;
      --red-glow: rgba(239, 68, 68, 0.12);
      --blue: #3b82f6;
      --blue-glow: rgba(59, 130, 246, 0.12);
      --purple: #a855f7;
      --purple-glow: rgba(168, 85, 247, 0.12);
      --yellow: #eab308;
      --mono: "JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace;
      --sans: "Space Grotesk", "Segoe UI", "Avenir Next", sans-serif;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    html { scroll-behavior: smooth; }

    body {
      min-height: 100vh;
      background:
        radial-gradient(1200px 600px at 5% -20%, rgba(59, 130, 246, 0.14), rgba(59, 130, 246, 0)),
        radial-gradient(1000px 520px at 96% -15%, rgba(249, 115, 22, 0.14), rgba(249, 115, 22, 0)),
        var(--bg);
      color: var(--text);
      font-family: var(--sans);
      padding: 30px 22px 48px;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    .shell {
      max-width: 1040px;
      margin: 0 auto;
    }

    .hero {
      margin-bottom: 40px;
      text-align: center;
      padding: 20px 0 36px;
      animation: fade-in 420ms ease-out both;
    }

    .hero-logo {
      width: 88px;
      height: 88px;
      margin: 0 auto 20px;
      filter: drop-shadow(0 12px 32px rgba(249, 115, 22, 0.35));
    }

    .hero h1 {
      font-family: var(--sans);
      font-size: clamp(32px, 5.5vw, 56px);
      font-weight: 800;
      letter-spacing: -0.03em;
      line-height: 1.08;
      margin-bottom: 18px;
    }

    .hero h1 .highlight {
      background: linear-gradient(135deg, #fdba74, #f97316);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .hero-sub {
      font-size: clamp(17px, 2.2vw, 22px);
      color: #94a3b8;
      max-width: 680px;
      margin: 0 auto 28px;
      line-height: 1.55;
    }

    .hero-props {
      display: flex;
      justify-content: center;
      flex-wrap: wrap;
      gap: 12px 24px;
      margin-bottom: 32px;
    }

    .hero-prop {
      display: flex;
      align-items: center;
      gap: 8px;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 600;
      color: #c7d2e3;
    }

    .hero-prop .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      flex: 0 0 auto;
    }

    .hero-actions {
      display: flex;
      justify-content: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 36px;
    }

    .hero-divider {
      width: 100%;
      max-width: 600px;
      margin: 0 auto;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(249, 115, 22, 0.3), transparent);
    }

    .btn {
      border-radius: 10px;
      border: 1px solid var(--border);
      padding: 9px 14px;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 700;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 160ms ease;
    }

    .btn.primary {
      color: #fef3e8;
      border-color: #d9631f;
      background: linear-gradient(160deg, #f97316, #d45516);
      box-shadow: 0 8px 20px rgba(249, 115, 22, 0.24);
    }

    .btn.primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 24px rgba(249, 115, 22, 0.3);
    }

    .btn.subtle {
      color: #c8d7ea;
      background: rgba(17, 24, 39, 0.7);
    }

    .btn.subtle:hover {
      border-color: #324155;
      color: #e9f1fb;
    }

    .tabs {
      display: flex;
      gap: 6px;
      margin-bottom: 18px;
      flex-wrap: wrap;
      scroll-margin-top: 24px;
    }

    .deep-dive-fallback {
      display: block;
      margin-top: 14px;
    }

    .js .deep-dive-fallback {
      display: none;
    }

    .tab {
      border-radius: 9px;
      border: 1px solid var(--border);
      background: rgba(17, 24, 39, 0.64);
      color: var(--text-muted);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 700;
      padding: 8px 13px;
      transition: all 150ms ease;
    }

    .tab.active {
      color: var(--accent);
      border-color: var(--accent);
      background: var(--accent-glow);
    }

    .view {
      animation: fade-in 260ms ease-out both;
    }

    .muted-note {
      font-size: 11px;
      color: var(--text-dim);
      margin: 0 0 14px;
      font-family: var(--mono);
      text-align: center;
    }

    .stack {
      display: grid;
      gap: 10px;
    }

    .flow-arrow {
      display: flex;
      justify-content: center;
      margin: 2px 0;
    }

    .flow-arrow svg {
      width: 20px;
      height: 28px;
      color: var(--text-dim);
      opacity: 0.75;
      animation: pulse 2s ease-in-out infinite;
    }

    .layer-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 22px;
      transition: all 220ms ease;
      cursor: pointer;
    }

    .layer-card:hover {
      border-color: #314258;
      background: var(--bg-card-hover);
    }

    .layer-card.active {
      transform: scale(1.01);
      box-shadow: 0 0 28px rgba(249, 115, 22, 0.14);
    }

    .layer-head {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 5px;
    }

    .layer-head svg {
      width: 18px;
      height: 18px;
      flex: 0 0 auto;
    }

    .layer-label {
      font-family: var(--mono);
      font-size: 15px;
      font-weight: 700;
      letter-spacing: 0.02em;
    }

    .layer-subtitle {
      font-family: var(--mono);
      font-size: 11px;
      color: var(--text-muted);
      margin-bottom: 12px;
    }

    .layer-items {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }

    .layer-item {
      border-radius: 9px;
      border: 1px solid rgba(255, 255, 255, 0.05);
      background: rgba(255, 255, 255, 0.02);
      padding: 10px 11px;
    }

    .layer-item h4 {
      font-size: 12px;
      margin-bottom: 3px;
    }

    .layer-item p {
      font-size: 10px;
      color: var(--text-muted);
      line-height: 1.45;
    }

    .principle {
      margin-top: 20px;
      border: 1px solid rgba(249, 115, 22, 0.25);
      background: rgba(249, 115, 22, 0.08);
      border-radius: 11px;
      padding: 15px 18px;
    }

    .principle h3 {
      font-family: var(--mono);
      font-size: 12px;
      margin-bottom: 7px;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 0.07em;
      display: flex;
      gap: 8px;
      align-items: center;
    }

    .principle h3 svg {
      width: 14px;
      height: 14px;
    }

    .principle p {
      font-size: 12px;
      color: #d8e2ef;
      line-height: 1.62;
    }

    .flow-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 15px;
    }

    .flow-step {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 15px;
      cursor: pointer;
      transition: all 180ms ease;
    }

    .flow-step.active {
      border-color: var(--accent);
      background: rgba(249, 115, 22, 0.12);
      box-shadow: 0 0 20px rgba(249, 115, 22, 0.14);
    }

    .flow-step h4 {
      font-family: var(--mono);
      font-size: 12px;
      margin-bottom: 5px;
    }

    .flow-step p {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.5;
    }

    .play-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 13px;
    }

    .play-row .note {
      font-size: 11px;
      font-family: var(--mono);
      color: var(--text-dim);
    }

    .play-btn {
      border-radius: 8px;
      border: 1px solid var(--accent);
      background: var(--accent-glow);
      color: var(--accent);
      font-family: var(--mono);
      font-size: 11px;
      padding: 6px 12px;
      cursor: pointer;
    }

    .compare-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 15px;
    }

    .compare-card {
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid var(--border);
      background: var(--bg-card);
    }

    .compare-card header {
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
    }

    .compare-card header svg {
      width: 14px;
      height: 14px;
    }

    .compare-body {
      padding: 13px 15px;
      display: grid;
      gap: 9px;
    }

    .compare-row {
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      padding-bottom: 8px;
    }

    .compare-row:last-child {
      border-bottom: 0;
      padding-bottom: 0;
    }

    .compare-row h5 {
      font-size: 10px;
      color: var(--text-dim);
      font-family: var(--mono);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-bottom: 3px;
    }

    .compare-row p {
      font-size: 12px;
      line-height: 1.42;
    }

    .verify-list {
      display: grid;
      gap: 8px;
    }

    .verify-item {
      display: grid;
      grid-template-columns: 38px 1fr 126px 116px;
      gap: 12px;
      align-items: center;
      padding: 13px 14px;
      border-radius: 10px;
      background: var(--bg-card);
      border: 1px solid var(--border);
    }

    .verify-item.legacy {
      background: rgba(239, 68, 68, 0.07);
      border-color: rgba(239, 68, 68, 0.36);
    }

    .verify-item.coming {
      background: rgba(148, 163, 184, 0.06);
      border-color: rgba(148, 163, 184, 0.28);
      opacity: 0.78;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 7px;
      border-radius: 999px;
      margin-left: 8px;
      font-family: var(--mono);
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.02em;
      color: var(--text-dim);
      border: 1px solid rgba(148, 163, 184, 0.28);
      background: rgba(148, 163, 184, 0.08);
    }

    .verify-item .icon-wrap {
      width: 34px;
      height: 34px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      background: rgba(255, 255, 255, 0.03);
      display: grid;
      place-items: center;
    }

    .verify-item .icon-wrap svg {
      width: 17px;
      height: 17px;
      color: #9db1ca;
    }

    .verify-item h4 {
      font-size: 13px;
      margin-bottom: 3px;
    }

    .verify-item p {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.5;
    }

    .mini-label {
      font-size: 10px;
      color: var(--text-dim);
      margin-bottom: 5px;
      font-family: var(--mono);
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }

    .bar {
      display: flex;
      gap: 3px;
      align-items: center;
    }

    .bar span {
      width: 14px;
      height: 5px;
      border-radius: 2px;
      background: rgba(255, 255, 255, 0.09);
    }

    .bar em {
      margin-left: 5px;
      font-style: normal;
      font-size: 10px;
      font-family: var(--mono);
    }

    .attack {
      margin-top: 18px;
      padding: 16px 18px;
      border-radius: 11px;
      border: 1px solid var(--border);
      background: var(--bg-card);
    }

    .attack h3 {
      font-family: var(--mono);
      font-size: 12px;
      margin-bottom: 10px;
      color: var(--accent);
      display: flex;
      gap: 8px;
      align-items: center;
      text-transform: uppercase;
      letter-spacing: 0.07em;
    }

    .attack h3 svg {
      width: 14px;
      height: 14px;
    }

    .attack-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }

    .attack-grid h4 {
      font-size: 11px;
      margin-bottom: 5px;
      font-family: var(--mono);
    }

    .attack-grid p {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.6;
    }

    .callout {
      margin-bottom: 14px;
      border-radius: 10px;
      border: 1px solid rgba(59, 130, 246, 0.32);
      background: var(--blue-glow);
      padding: 12px 15px;
      color: #d6e6ff;
      font-size: 12px;
      line-height: 1.56;
    }

    .callout strong {
      color: var(--blue);
    }

    .icon-btn {
      width: 14px;
      height: 14px;
      flex: 0 0 auto;
    }

    @keyframes pulse {
      0%, 100% { opacity: 0.38; }
      50% { opacity: 1; }
    }

    @keyframes fade-in {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Content sections */
    .content-section {
      margin: 56px 0 0;
      animation: fade-in 420ms ease-out both;
      scroll-margin-top: 24px;
    }

    .section-title {
      font-family: var(--sans);
      font-size: clamp(24px, 3.5vw, 36px);
      font-weight: 800;
      letter-spacing: -0.02em;
      text-align: center;
      margin-bottom: 10px;
    }

    .section-sub {
      text-align: center;
      color: #94a3b8;
      font-size: clamp(15px, 2vw, 18px);
      max-width: 600px;
      margin: 0 auto 32px;
      line-height: 1.55;
    }

    /* Steps */
    .steps-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
    }

    .step-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 22px 20px;
      transition: border-color 200ms ease;
      min-width: 0;
    }

    .step-card:hover {
      border-color: #314258;
    }

    .step-num {
      width: 32px;
      height: 32px;
      border-radius: 9px;
      background: linear-gradient(135deg, var(--accent), #d45516);
      color: #fff;
      font-family: var(--mono);
      font-weight: 800;
      font-size: 15px;
      display: grid;
      place-items: center;
      margin-bottom: 14px;
    }

    .step-card h3 {
      font-size: 15px;
      font-weight: 700;
      margin-bottom: 12px;
    }

    .step-desc {
      font-size: 13px;
      color: var(--text-muted);
      line-height: 1.55;
      margin-top: 12px;
    }

    .code-block {
      margin: 0;
      border-radius: 9px;
      border: 1px solid var(--border);
      background: rgba(0, 0, 0, 0.4);
      padding: 12px 14px;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.6;
      color: var(--text);
      overflow-x: auto;
      position: relative;
    }

    .code-block .dim { color: var(--text-dim); }
    .code-block .kw { color: var(--accent); }
    .code-block .str { color: var(--green); }
    .code-block .cmt { color: var(--text-dim); font-style: italic; }

    .copy-btn {
      position: absolute;
      top: 8px;
      right: 8px;
      border-radius: 9px;
      border: 1px solid rgba(255, 255, 255, 0.12);
      background: rgba(17, 24, 39, 0.72);
      color: var(--text-muted);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 800;
      padding: 6px 10px;
      cursor: pointer;
      transition: all 160ms ease;
      backdrop-filter: blur(10px);
    }

    .copy-btn:hover {
      border-color: rgba(249, 115, 22, 0.55);
      background: rgba(249, 115, 22, 0.12);
      color: var(--text);
    }

    .copy-btn:active {
      transform: translateY(1px);
    }

    /* SDK section */
    .sdk-grid {
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 24px;
      align-items: start;
    }

    .sdk-code {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      overflow: hidden;
    }

    .code-header {
      display: flex;
      align-items: center;
      gap: 7px;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      background: rgba(0, 0, 0, 0.15);
    }

    .code-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }

    .code-dot.red { background: #ef4444; }
    .code-dot.yellow { background: #eab308; }
    .code-dot.green { background: #22c55e; }

    .code-filename {
      margin-left: 8px;
      font-family: var(--mono);
      font-size: 11px;
      color: var(--text-dim);
    }

    .code-block.large {
      border: 0;
      border-radius: 0;
      padding: 18px 20px;
      font-size: 13px;
      background: transparent;
    }

    .sdk-features {
      display: grid;
      gap: 16px;
    }

    .sdk-feature {
      display: flex;
      gap: 14px;
      align-items: start;
    }

    .sf-icon {
      width: 36px;
      height: 36px;
      flex: 0 0 36px;
      display: grid;
      place-items: center;
    }

    .sf-icon svg {
      width: 22px;
      height: 22px;
    }

    .sdk-feature h4 {
      font-size: 14px;
      font-weight: 700;
      margin-bottom: 4px;
    }

    .sdk-feature p {
      font-size: 13px;
      color: var(--text-muted);
      line-height: 1.5;
    }

    /* Trust grid */
    .trust-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
    }

    .trust-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 24px 20px;
      transition: border-color 200ms ease, transform 200ms ease;
    }

    .trust-card:hover {
      border-color: #314258;
      transform: translateY(-2px);
    }

    .trust-icon {
      width: 42px;
      height: 42px;
      border-radius: 10px;
      border: 1px solid;
      display: grid;
      place-items: center;
      margin-bottom: 14px;
    }

    .trust-icon svg {
      width: 20px;
      height: 20px;
    }

    .trust-card h3 {
      font-size: 15px;
      font-weight: 700;
      margin-bottom: 8px;
    }

    .trust-card p {
      font-size: 13px;
      color: var(--text-muted);
      line-height: 1.55;
    }

    /* Docs grid */
    .docs-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
    }

    .doc-card {
      display: block;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px 18px;
      transition: all 180ms ease;
      cursor: pointer;
    }

    .doc-card:hover {
      border-color: var(--accent);
      background: rgba(249, 115, 22, 0.06);
      transform: translateY(-2px);
    }

    .doc-icon {
      width: 36px;
      height: 36px;
      border-radius: 9px;
      background: var(--accent-glow);
      border: 1px solid rgba(249, 115, 22, 0.25);
      display: grid;
      place-items: center;
      margin-bottom: 12px;
      color: var(--accent);
    }

    .doc-icon svg {
      width: 18px;
      height: 18px;
    }

    .doc-card h3 {
      font-size: 14px;
      font-weight: 700;
      margin-bottom: 6px;
    }

    .doc-card p {
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.5;
    }

    /* Footer */
    .site-footer {
      margin-top: 64px;
      padding: 32px 0;
      border-top: 1px solid var(--border);
      text-align: center;
    }

    .footer-inner {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 10px;
    }

    .footer-brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-family: var(--mono);
      font-weight: 800;
      font-size: 16px;
    }

    .footer-brand img {
      border-radius: 6px;
    }

    .footer-tagline {
      color: var(--text-muted);
      font-size: 13px;
    }

    .footer-links {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      color: var(--text-dim);
      font-family: var(--mono);
    }

    .footer-sep { opacity: 0.4; }

    @media (max-width: 920px) {
      .flow-grid,
      .compare-grid,
      .attack-grid {
        grid-template-columns: 1fr;
      }

      .verify-item {
        grid-template-columns: 34px 1fr;
      }

      .verify-item .meta {
        grid-column: 1 / -1;
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
      }

      .layer-items {
        grid-template-columns: 1fr;
      }

      .steps-grid,
      .trust-grid,
      .docs-grid {
        grid-template-columns: 1fr;
      }

      .sdk-grid {
        grid-template-columns: 1fr;
      }
    }

    @media (min-width: 921px) and (max-width: 1100px) {
      .trust-grid,
      .docs-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <img class="hero-logo" src="/logo.png" alt="Clauth" width="88" height="88" />

      <h1>Your agents make API calls.<br/><span class="highlight">They should never see your keys.</span></h1>

      <p class="hero-sub">
        Clauth is a local daemon that sits between your AI agents and the APIs they call.
        It holds your credentials in an encrypted vault and injects them at request time &mdash;
        so agents get the job done without ever touching a secret.
      </p>

      <div class="hero-props">
        <span class="hero-prop"><span class="dot" style="background:var(--green);"></span>Encrypted vault (AES-256-GCM)</span>
        <span class="hero-prop"><span class="dot" style="background:var(--accent);"></span>Per-agent scope enforcement</span>
        <span class="hero-prop"><span class="dot" style="background:var(--blue);"></span>Behavioral anomaly detection</span>
        <span class="hero-prop"><span class="dot" style="background:var(--purple);"></span>Tamper-evident audit log</span>
      </div>

      <div class="hero-actions">
        <a class="btn primary" href="#how-it-works">
          <svg class="icon-btn" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 5l7 7-7 7"/></svg>
          Get Started
        </a>
        <a class="btn subtle" href="#docs">
          <svg class="icon-btn" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
          Documentation
        </a>
      </div>

      <div class="hero-divider"></div>
    </section>

    <!-- How It Works -->
    <section class="content-section" id="how-it-works">
      <h2 class="section-title">Up and running in 60 seconds</h2>
      <p class="section-sub">Install, store your credentials once, and every agent you run is automatically protected.</p>
      <div class="steps-grid">
        <article class="step-card">
          <div class="step-num">1</div>
          <h3>Install &amp; start the daemon</h3>
          <pre class="code-block"><span class="dim">$</span> npm install -g clauth-ai
<span class="dim">$</span> clauth init
<span class="dim">$</span> export CLAUTH_ADMIN_TOKEN='set-admin-token'
<span class="dim">$</span> clauth daemon</pre>
          <p class="step-desc">One-time setup. Runs locally on your machine — nothing leaves your network.</p>
        </article>
        <article class="step-card">
          <div class="step-num">2</div>
          <h3>Store your credentials</h3>
          <pre class="code-block"><span class="dim">$</span> export GITHUB_PAT='ghp_xxx'
<span class="dim">$</span> export OPENAI_API_KEY='sk-xxx'
<span class="dim">$</span> clauth store --handle github-main --provider github --secret-env GITHUB_PAT
<span class="dim">$</span> clauth store --handle openai-main --provider openai --secret-env OPENAI_API_KEY</pre>
          <p class="step-desc">Encrypted at rest with AES-256-GCM. You set the passphrase, nobody else.</p>
        </article>
        <article class="step-card">
          <div class="step-num">3</div>
          <h3>Grant scoped access to skills</h3>
          <pre class="code-block"><span class="dim">$</span> clauth grant --skill my-agent --provider github --scope github:read --rpm 60
<span class="dim">$</span> clauth grant --skill my-agent --provider openai --scope openai:chat --rpm 60
<span class="dim">$</span> clauth grant --skill my-agent --provider stripe --scope stripe:charges --rpm 30</pre>
          <p class="step-desc">Each agent gets only the permissions it needs. Nothing more.</p>
        </article>
      </div>
    </section>

    <!-- Operator Quick Start -->
    <section class="content-section" id="operator">
      <h2 class="section-title">Operator quick start</h2>
      <p class="section-sub">Copy/paste runbook to provision a skill and validate a real brokered call.</p>
      <pre class="code-block"><span class="dim">$</span> export CLAUTH_PASSPHRASE='your-long-passphrase-here'
<span class="dim">$</span> export CLAUTH_ADMIN_TOKEN='set-admin-token'
<span class="dim">$</span> clauth init
<span class="dim">$</span> clauth daemon

<span class="dim">#</span> in another terminal
<span class="dim">$</span> export CLAUTH_PASSPHRASE='your-long-passphrase-here'
<span class="dim">$</span> export GITHUB_PAT='ghp_xxx'
<span class="dim">$</span> clauth store --handle github-main --provider github --secret-env GITHUB_PAT
<span class="dim">$</span> clauth grant --skill my-agent --provider github --scope github:read --rpm 60
<span class="dim">$</span> clauth skill-token issue --skill my-agent
<span class="dim">$</span> export CLAUTH_SKILL_TOKEN='&lt;issued-token&gt;'

<span class="dim">$</span> curl -sS -X POST http://127.0.0.1:4317/clauth/v1/proxy \\
  -H "content-type: application/json" \\
  -H "x-clauth-skill-token: $CLAUTH_SKILL_TOKEN" \\
  -d '{ "provider":"github","credentialHandle":"github-main","scope":"github:read","method":"GET","endpoint":"https://api.github.com/user" }'

<span class="dim">$</span> curl -sS http://127.0.0.1:4317/clauth/v1/status</pre>
      <p class="step-desc">Expected: proxy returns a 200 wrapper with upstream payload; status shows <code>auditIntegrity.valid</code> true; audit log contains <code>proxy.allow</code>.</p>
    </section>

    <!-- For Skill Developers -->
    <section class="content-section" id="sdk">
      <h2 class="section-title">For skill developers</h2>
      <p class="section-sub">Your skill never sees a credential. Just tell Clauth what you need — it handles the rest.</p>
      <div class="sdk-grid">
        <div class="sdk-code">
          <div class="code-header">
            <span class="code-dot red"></span>
            <span class="code-dot yellow"></span>
            <span class="code-dot green"></span>
            <span class="code-filename">my-skill.ts</span>
          </div>
          <pre class="code-block large"><span class="kw">import</span> { ClauthClient } <span class="kw">from</span> <span class="str">"clauth-ai/client"</span>;

<span class="kw">const</span> clauth = <span class="kw">new</span> ClauthClient({
  skillId: <span class="str">"my-agent"</span>,
  skillToken: process.env.CLAUTH_SKILL_TOKEN
});

<span class="cmt">// Make an API call — Clauth injects credentials</span>
<span class="kw">const</span> repos = <span class="kw">await</span> clauth.fetch(
  <span class="str">"github"</span>,
  <span class="str">"github-main"</span>,
  <span class="str">"github:read"</span>,
  <span class="str">"https://api.github.com/user/repos"</span>
);

console.log(repos.body); <span class="cmt">// Your repos. No token in sight.</span></pre>
        </div>
        <div class="sdk-features">
          <div class="sdk-feature">
            <div class="sf-icon" style="color:var(--green);">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 5-3.5 8.5-7 9-3.5-.5-7-4-7-9V6z"/></svg>
            </div>
            <div>
              <h4>Zero credential exposure</h4>
              <p>Your code never handles secrets. Clauth injects auth headers at the network boundary.</p>
            </div>
          </div>
          <div class="sdk-feature">
            <div class="sf-icon" style="color:var(--accent);">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
            </div>
            <div>
              <h4>Scoped by default</h4>
              <p>Request only what you need. Clauth enforces least-privilege — unauthorized calls are blocked and logged.</p>
            </div>
          </div>
          <div class="sdk-feature">
            <div class="sf-icon" style="color:var(--blue);">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>
            </div>
            <div>
              <h4>One line integration</h4>
              <p>Drop in the SDK. Built-in policies for popular providers; custom providers work with operator-defined allowlists.</p>
            </div>
          </div>
          <div class="sdk-feature">
            <div class="sf-icon" style="color:var(--purple);">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2m10-10h-2M4 12H2"/></svg>
            </div>
            <div>
              <h4>Behavioral protection</h4>
              <p>Clauth watches for anomalies — unusual endpoints, rate spikes, off-hours activity — and blocks them automatically.</p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Built for Trust -->
    <section class="content-section" id="trust">
      <h2 class="section-title">Built for trust</h2>
      <p class="section-sub">Clauth is designed so you don't have to trust Clauth. Everything is local, auditable, and under your control.</p>
      <div class="trust-grid">
        <article class="trust-card">
          <div class="trust-icon" style="background:var(--green-glow);border-color:rgba(34,197,94,0.3);">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 5-3.5 8.5-7 9-3.5-.5-7-4-7-9V6z"/></svg>
          </div>
          <h3>Runs on your machine</h3>
          <p>No cloud service, no SaaS, no third-party credential storage. Clauth is a local daemon — your secrets stay encrypted on disk and are only sent to the provider APIs you call.</p>
        </article>
        <article class="trust-card">
          <div class="trust-icon" style="background:var(--accent-glow);border-color:rgba(249,115,22,0.3);">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
          </div>
          <h3>Zero runtime deps</h3>
          <p>No third-party runtime packages. Clauth runs on Node.js built-in modules; dev deps are TypeScript tooling only.</p>
        </article>
        <article class="trust-card">
          <div class="trust-icon" style="background:var(--blue-glow);border-color:rgba(59,130,246,0.3);">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
          </div>
          <h3>Tamper-evident audit log</h3>
          <p>Every request, every grant, every anomaly — hash-chained and append-only. If someone edits history, integrity verification fails.</p>
        </article>
        <article class="trust-card">
          <div class="trust-icon" style="background:var(--purple-glow);border-color:rgba(168,85,247,0.3);">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2m10-10h-2M4 12H2m15.07-5.07l-1.41 1.41M8.34 15.66l-1.41 1.41m0-11.31l1.41 1.41m7.32 7.32l1.41 1.41"/></svg>
          </div>
          <h3>Open source</h3>
          <p>MIT licensed. Audit the source, fork it, self-host it. Security through transparency, not obscurity.</p>
        </article>
        <article class="trust-card">
          <div class="trust-icon" style="background:var(--red-glow);border-color:rgba(239,68,68,0.3);">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>
          </div>
          <h3>Emergency kill switch</h3>
          <p>One command revokes every grant instantly. Compromised skill? Shut it down in seconds, not hours.</p>
        </article>
        <article class="trust-card">
          <div class="trust-icon" style="background:rgba(234,179,8,0.12);border-color:rgba(234,179,8,0.3);">
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--yellow)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 5-3.5 8.5-7 9-3.5-.5-7-4-7-9V6z"/><path d="M12 8v4m0 4h.01"/></svg>
          </div>
          <h3>Security advisory monitoring</h3>
          <p>Clauth polls public advisory feeds and auto-revokes affected credentials before you even hear about the breach.</p>
        </article>
      </div>
    </section>

    <!-- Deep Dive Tabs -->
    <section class="content-section" id="deep-dive">
      <h2 class="section-title">Under the hood</h2>
      <p class="section-sub">Explore the architecture, see a request flow in action, or compare the before and after.</p>

      <nav class="tabs" id="tabs" aria-label="Deep dive views">
        <button class="tab active" type="button" data-tab="comparison">Before / After</button>
        <button class="tab" type="button" data-tab="architecture">Architecture</button>
        <button class="tab" type="button" data-tab="flow">Request Flow</button>
        <button class="tab" type="button" data-tab="verify">Identity Verification</button>
      </nav>

      <!-- Progressive enhancement: default content is present even if JS is blocked. -->
      <section id="view" class="view">
        <section class="compare-grid">
          <article class="compare-card" style="border-color:rgba(239,68,68,0.36);">
            <header style="background:rgba(239,68,68,0.1);color:var(--red);"><span style="display:inline-flex;color:var(--red);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg></span>OpenClaw Today</header>
            <div class="compare-body">
              <div class="compare-row"><h5>Lose Your Identity</h5><p style="color:var(--red);">A malicious skill steals your OAuth tokens and impersonates you across every connected platform</p></div>
              <div class="compare-row"><h5>Lose Your Funds</h5><p style="color:var(--red);">Payment credentials sitting in plaintext — one bad install drains your accounts</p></div>
              <div class="compare-row"><h5>Credit Card Stolen</h5><p style="color:var(--red);">Stored card details are readable by any skill with file access. No encryption, no barrier.</p></div>
              <div class="compare-row"><h5>API Bill From the Dark Web</h5><p style="color:var(--red);">Your cloud API keys get exfiltrated and sold — strangers run up thousands on your tab</p></div>
              <div class="compare-row"><h5>No Access Control</h5><p style="color:var(--red);">Every skill has god-mode access to every credential you own</p></div>
              <div class="compare-row"><h5>No Detection</h5><p style="color:var(--red);">Zero anomaly monitoring — you find out when the bill arrives or the damage is done</p></div>
              <div class="compare-row"><h5>No Audit Trail</h5><p style="color:var(--red);">No record of what was accessed, when, or by whom</p></div>
              <div class="compare-row"><h5>No Recovery Plan</h5><p style="color:var(--red);">When it happens, you manually rotate every key and hope you got them all</p></div>
            </div>
          </article>
          <article class="compare-card" style="border-color:rgba(34,197,94,0.36);">
            <header style="background:rgba(34,197,94,0.1);color:var(--green);"><span style="display:inline-flex;color:var(--green);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></span>With Clauth</header>
            <div class="compare-body">
              <div class="compare-row"><h5>Secret Storage</h5><p style="color:var(--green);">AES-256-GCM encrypted vault</p></div>
              <div class="compare-row"><h5>Skill Access</h5><p style="color:var(--green);">Skills receive scoped handles, never tokens</p></div>
              <div class="compare-row"><h5>Scope Control</h5><p style="color:var(--green);">Granular provider:action grants</p></div>
              <div class="compare-row"><h5>Anomaly Detection</h5><p style="color:var(--green);">Per-skill baselines with critical blocking</p></div>
              <div class="compare-row"><h5>Audit Log</h5><p style="color:var(--green);">Hash-chained append-only event stream</p></div>
              <div class="compare-row"><h5>Breach Response</h5><p style="color:var(--green);">Emergency revoke and advisory-driven revocations</p></div>
              <div class="compare-row"><h5>Identity Verification</h5><p style="color:var(--green);">Multiple private verification options</p></div>
              <div class="compare-row"><h5>Operational Friction</h5><p style="color:var(--green);">Near-zero during normal operation</p></div>
            </div>
          </article>
        </section>
        <section class="attack">
          <h3><span style="display:inline-flex;color:var(--accent);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2m10-10h-2M4 12H2"/></svg></span>Attack Scenario: Malicious Skill Installation</h3>
          <div class="attack-grid">
            <div>
              <h4 style="color:var(--red);">Without Clauth</h4>
              <p>Skill reads plaintext credential files, exfiltrates keys, and pivots across all connected providers before the user notices.</p>
            </div>
            <div>
              <h4 style="color:var(--green);">With Clauth</h4>
              <p>Skill has no secret file access. Unauthorized scope request is denied, logged, and surfaced as an anomaly with immediate revoke options.</p>
            </div>
          </div>
        </section>
      </section>

      <p class="muted-note deep-dive-fallback" id="deepDiveFallback">
        If the interactive deep dive doesn't load, scripts may be blocked. The default view above is still accurate.
      </p>
    </section>

    <!-- Docs & Resources -->
    <section class="content-section" id="docs">
      <h2 class="section-title">Documentation</h2>
      <p class="section-sub">Everything you need to get started, integrate your skills, and harden your setup.</p>
      <div class="docs-grid">
        <a class="doc-card" href="/docs/quick-start">
          <div class="doc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>
          </div>
          <h3>Quick Start</h3>
          <p>Install, store your first credential, and grant scoped access to a skill in under a minute.</p>
        </a>
        <a class="doc-card" href="/docs/real-world-testing">
          <div class="doc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
          </div>
          <h3>Real-World Testing</h3>
          <p>End-to-end runbook to validate provider calls, denial paths, revocation behavior, and audit integrity.</p>
        </a>
        <a class="doc-card" href="/docs/sdk">
          <div class="doc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/></svg>
          </div>
          <h3>SDK Reference</h3>
          <p>ClauthClient API for skill developers — brokered fetch, identity verification, and health checks.</p>
        </a>
        <a class="doc-card" href="/docs/api">
          <div class="doc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 7h.01M7 17h.01"/></svg>
          </div>
          <h3>API Endpoints</h3>
          <p>Full reference for the daemon HTTP API — proxy, admin, identity broker, and status routes.</p>
        </a>
        <a class="doc-card" href="/docs/security">
          <div class="doc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 5-3.5 8.5-7 9-3.5-.5-7-4-7-9V6z"/></svg>
          </div>
          <h3>Security Model</h3>
          <p>Vault encryption, scope enforcement, behavioral anomaly detection, and audit integrity.</p>
        </a>
        <a class="doc-card" href="/docs/configuration">
          <div class="doc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h5l10-10-5-5L4 15v5z"/></svg>
          </div>
          <h3>Configuration</h3>
          <p>Transport modes, hardening options, alert routing, advisory feeds, and OAuth provider setup.</p>
        </a>
        <a class="doc-card" href="/docs/identity-broker">
          <div class="doc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3m-3 0h3v3"/></svg>
          </div>
          <h3>Identity Broker</h3>
          <p>Private identity verification without public posting — OAuth, email, and signed challenge flows.</p>
        </a>
      </div>
    </section>

    <!-- Footer -->
    <footer class="site-footer">
      <div class="footer-inner">
        <div class="footer-brand">
          <img src="/logo.png" alt="Clauth" width="28" height="28" />
          <span>Clauth</span>
        </div>
        <p class="footer-tagline">Your credentials. Your machine. Your rules.</p>
        <div class="footer-links">
          <span class="footer-link">MIT Licensed</span>
          <span class="footer-sep">&middot;</span>
          <span class="footer-link">Open Source</span>
          <span class="footer-sep">&middot;</span>
          <span class="footer-link">Zero Dependencies</span>
        </div>
      </div>
    </footer>
  </main>

  <script src="landing.js" defer></script>
</body>
</html>`;
}

export function renderLandingClientJs(): string {
  // `String.raw` keeps backslashes intact so the emitted JS is valid without
  // double-escaping regexes and string escapes.
  return String.raw`(() => {
    // Used to hide the "scripts blocked" note once the client JS is running.
    document.documentElement.classList.add('js');
    const fallback = document.getElementById('deepDiveFallback');
    if (fallback) fallback.remove();

    const tabsNode = document.getElementById('tabs');
    const viewNode = document.getElementById('view');
    if (!tabsNode || !viewNode) {
      return;
    }

    const COLORS = {
      bgCard: '#111827',
      bgCardHover: '#1a2332',
      border: '#1e293b',
      borderActive: '#f97316',
      text: '#e2e8f0',
      textMuted: '#64748b',
      textDim: '#475569',
      accent: '#f97316',
      accentGlow: 'rgba(249, 115, 22, 0.14)',
      green: '#22c55e',
      red: '#ef4444',
      blue: '#3b82f6',
      purple: '#a855f7',
      yellow: '#eab308'
    };

    const ICONS = {
      bolt: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>',
      proxy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 7h.01M7 17h.01"/></svg>',
      shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 5-3.5 8.5-7 9-3.5-.5-7-4-7-9V6z"/></svg>',
      lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
      oauth: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3m-3 0h3v3"/></svg>',
      email: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/></svg>',
      dns: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>',
      sign: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h5l10-10-5-5L4 15v5z"/></svg>',
      qr: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z"/><path d="M16 14h2m2 0h0m-6 6h6v-4"/></svg>',
      legacy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12h4l10-4v8l-10-4H4z"/><path d="M8 16v4"/></svg>',
      check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>',
      close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg>',
      target: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2m10-10h-2M4 12H2"/></svg>'
    };

    const TABS = [
      { id: 'comparison', label: 'Before / After' },
      { id: 'architecture', label: 'Architecture' },
      { id: 'flow', label: 'Request Flow' },
      { id: 'verify', label: 'Identity Verification' }
    ];

    const LAYERS = [
      {
        id: 'skills',
        label: 'Skills and Agents',
        subtitle: 'Untrusted code. Never sees raw credentials.',
        color: COLORS.purple,
        glow: 'rgba(168, 85, 247, 0.12)',
        icon: 'bolt',
        items: [
          { name: 'Twitter Skill', scope: 'twitter:read, twitter:post' },
          { name: 'Slack Skill', scope: 'slack:messages' },
          { name: 'Smart Home Skill', scope: 'hue:lights, nest:thermo' },
          { name: 'Unapproved Skill', scope: 'denied: no scopes granted' }
        ]
      },
      {
        id: 'proxy',
        label: 'Credential Proxy',
        subtitle: 'Intercepts every outbound request.',
        color: COLORS.accent,
        glow: COLORS.accentGlow,
        icon: 'proxy',
        items: [
          { name: 'Scope Enforcer', desc: 'Checks granted scope before forwarding' },
          { name: 'Token Injector', desc: 'Injects credentials only at request-time' },
          { name: 'Rate Governor', desc: 'Per-skill request ceilings' },
          { name: 'Audit Pipeline', desc: 'Immutable event chain' }
        ]
      },
      {
        id: 'detection',
        label: 'Behavioral Firewall',
        subtitle: 'Silent baseline learning with anomaly blocking.',
        color: COLORS.red,
        glow: 'rgba(239, 68, 68, 0.12)',
        icon: 'shield',
        items: [
          { name: 'Baseline Profiler', desc: 'Learns normal endpoint and volume patterns' },
          { name: 'Anomaly Engine', desc: 'Spikes, new endpoints, off-hours, scope creep' },
          { name: 'Kill Switch', desc: 'Revokes grants on emergency or advisories' },
          { name: 'Alert Router', desc: 'Routes alerts to configured channels' }
        ]
      },
      {
        id: 'vault',
        label: 'Encrypted Vault',
        subtitle: 'AES-256-GCM secrets at rest.',
        color: COLORS.green,
        glow: 'rgba(34, 197, 94, 0.12)',
        icon: 'lock',
        items: [
          { name: 'OAuth Tokens', desc: 'Encrypted refresh and access tokens' },
          { name: 'API Keys', desc: 'Stored encrypted, rotated safely' },
          { name: 'Session Handles', desc: 'Ephemeral references per skill' },
          { name: 'Platform Credentials', desc: 'Messaging and provider auth artifacts' }
        ]
      }
    ];

    const FLOW_STEPS = [
      {
        title: '1. Skill submits brokered request',
        desc: 'Skill sends provider, endpoint, method, and scope. No raw secret material included.',
        highlight: 'skills'
      },
      {
        title: '2. Scope authorization',
        desc: 'Proxy checks per-skill grants. Missing scope means immediate deny and audit record.',
        highlight: 'proxy'
      },
      {
        title: '3. Behavioral evaluation',
        desc: 'Firewall compares request against baseline and blocks critical anomalies.',
        highlight: 'detection'
      },
      {
        title: '4. In-memory credential resolution',
        desc: 'Vault decrypts token in daemon memory and injects auth header into outbound call.',
        highlight: 'vault'
      },
      {
        title: '5. Brokered execution and logging',
        desc: 'Provider response returns to skill. Audit chain stores outcome, status code, and context.',
        highlight: 'proxy'
      }
    ];

    const VERIFY_METHODS = [
      { name: 'Signed Challenge', icon: 'sign', desc: 'Prove account ownership using a stored credential (no public posting)', friction: 'None', security: 'High' },
      { name: 'OAuth Flow', icon: 'oauth', desc: 'Standard OAuth2 authorization with HMAC-signed state', friction: 'Low', security: 'High' },
      { name: 'Email Challenge', icon: 'email', desc: 'One-time code delivered out-of-band (webhook) and verified in constant time', friction: 'Low', security: 'Medium' },
      { name: 'DNS TXT Record', icon: 'dns', desc: 'Coming soon: domain ownership proof for enterprise contexts', friction: 'Medium', security: 'High', comingSoon: true },
      { name: 'QR Device Pair', icon: 'qr', desc: 'Coming soon: out-of-band confirmation from a trusted device', friction: 'Low', security: 'High', comingSoon: true }
    ];

    const BEFORE_ROWS = [
      { label: 'Lose Your Identity', value: 'A malicious skill steals your OAuth tokens and impersonates you across every connected platform', tone: 'bad' },
      { label: 'Lose Your Funds', value: 'Payment credentials sitting in plaintext — one bad install drains your accounts', tone: 'bad' },
      { label: 'Credit Card Stolen', value: 'Stored card details are readable by any skill with file access. No encryption, no barrier.', tone: 'bad' },
      { label: 'API Bill From the Dark Web', value: 'Your cloud API keys get exfiltrated and sold — strangers run up thousands on your tab', tone: 'bad' },
      { label: 'No Access Control', value: 'Every skill has god-mode access to every credential you own', tone: 'bad' },
      { label: 'No Detection', value: 'Zero anomaly monitoring — you find out when the bill arrives or the damage is done', tone: 'bad' },
      { label: 'No Audit Trail', value: 'No record of what was accessed, when, or by whom', tone: 'bad' },
      { label: 'No Recovery Plan', value: 'When it happens, you manually rotate every key and hope you got them all', tone: 'bad' }
    ];

    const AFTER_ROWS = [
      { label: 'Secret Storage', value: 'AES-256-GCM encrypted vault', tone: 'good' },
      { label: 'Skill Access', value: 'Skills receive scoped handles, never tokens', tone: 'good' },
      { label: 'Scope Control', value: 'Granular provider:action grants', tone: 'good' },
      { label: 'Anomaly Detection', value: 'Per-skill baselines with critical blocking', tone: 'good' },
      { label: 'Audit Log', value: 'Hash-chained append-only event stream', tone: 'good' },
      { label: 'Breach Response', value: 'Emergency revoke and advisory-driven revocations', tone: 'good' },
      { label: 'Identity Verification', value: 'Multiple private verification options', tone: 'good' },
      { label: 'Operational Friction', value: 'Near-zero during normal operation', tone: 'good' }
    ];

    const state = {
      view: 'comparison',
      activeLayer: null,
      activeStep: null,
      animStep: 0,
      playing: false,
      timer: null
    };

    function normalizeCopyText(text) {
      return text
        .split('\n')
        .map(function (line) {
          return line.replace(/^\$\s?/, '');
        })
        .join('\n')
        .trimEnd();
    }

    async function copyToClipboard(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return;
      }

      // Fallback for older browsers.
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      textarea.style.pointerEvents = 'none';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }

    function installCopyButtons() {
      document.querySelectorAll('pre.code-block').forEach(function (pre) {
        if (pre.querySelector('button.copy-btn')) {
          return;
        }

        const btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.type = 'button';
        btn.textContent = 'Copy';
        btn.addEventListener('click', async function (event) {
          event.preventDefault();
          event.stopPropagation();

          const clone = pre.cloneNode(true);
          const existing = clone.querySelector('button.copy-btn');
          if (existing) {
            existing.remove();
          }
          const raw = clone.innerText || clone.textContent || '';
          const cleaned = normalizeCopyText(raw);

          const prevLabel = btn.textContent;
          btn.textContent = 'Copying...';
          try {
            await copyToClipboard(cleaned);
            btn.textContent = 'Copied';
          } catch {
            btn.textContent = 'Failed';
          }
          setTimeout(function () {
            btn.textContent = prevLabel;
          }, 1200);
        });

        pre.appendChild(btn);
      });
    }

    function icon(name, color) {
      const svg = ICONS[name] || '';
      return '<span style="display:inline-flex;color:' + color + ';">' + svg + '</span>';
    }

    function setView(viewId) {
      state.view = viewId;
      state.activeStep = null;
      state.activeLayer = null;
      stopFlow();
      renderTabs();
      renderView();
    }

    function renderTabs() {
      tabsNode.innerHTML = TABS.map(function (tab) {
        const active = state.view === tab.id ? ' active' : '';
        return '<button class="tab' + active + '" data-tab="' + tab.id + '">' + tab.label + '</button>';
      }).join('');

      tabsNode.querySelectorAll('button[data-tab]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          setView(btn.getAttribute('data-tab'));
        });
      });
    }

    function renderArchitecture() {
      const highlighted = state.activeStep !== null ? FLOW_STEPS[state.activeStep].highlight : null;

      const cards = LAYERS.map(function (layer, idx) {
        const active = state.activeLayer === layer.id || highlighted === layer.id;
        const cardStyle = active
          ? ' style="border-color:' + layer.color + ';background:' + layer.glow + ';box-shadow:0 0 28px ' + layer.glow + ';"'
          : '';

        const items = layer.items.map(function (item) {
          const body = item.scope
            ? '<p style="color:' + layer.color + ';font-family:var(--mono);">' + item.scope + '</p>'
            : '<p>' + item.desc + '</p>';

          return '<div class="layer-item"><h4>' + item.name + '</h4>' + body + '</div>';
        }).join('');

        const itemsStyle = active
          ? 'max-height:600px;opacity:1;margin-top:12px;'
          : 'max-height:0;opacity:0;overflow:hidden;margin-top:0;';

        const card = '' +
          '<article class="layer-card' + (active ? ' active' : '') + '" data-layer="' + layer.id + '"' + cardStyle + '>' +
            '<div class="layer-head">' + icon(layer.icon, layer.color) + '<span class="layer-label" style="color:' + layer.color + ';">' + layer.label + '</span></div>' +
            '<p class="layer-subtitle">' + layer.subtitle + '</p>' +
            '<div class="layer-items" style="transition:max-height 280ms ease,opacity 220ms ease,margin-top 220ms ease;' + itemsStyle + '">' + items + '</div>' +
          '</article>';

        if (idx >= LAYERS.length - 1) {
          return card;
        }

        return card + '<div class="flow-arrow">' + icon('proxy', '#516179') + '</div>';
      }).join('');

      viewNode.innerHTML = '' +
        '<p class="muted-note">Click any layer to inspect responsibilities. Requests flow top to bottom.</p>' +
        '<section class="stack">' + cards + '</section>' +
        '<section class="principle">' +
          '<h3>' + icon('lock', 'var(--accent)') + 'Core Principle: Zero-Knowledge Skills</h3>' +
          '<p>Skills request actions through scoped handles, not secret values. The proxy resolves credentials only inside the daemon, runs enforcement and anomaly checks, and returns only provider responses.</p>' +
        '</section>';

      viewNode.querySelectorAll('[data-layer]').forEach(function (node) {
        node.addEventListener('click', function () {
          const id = node.getAttribute('data-layer');
          state.activeLayer = state.activeLayer === id ? null : id;
          renderArchitecture();
        });
      });
    }

    function renderFlow() {
      const currentStep = state.playing ? state.animStep : state.activeStep;
      const activeLayer = currentStep !== null && currentStep !== undefined ? FLOW_STEPS[currentStep].highlight : null;

      const stepColumn = FLOW_STEPS.map(function (step, index) {
        const active = currentStep === index;
        return '' +
          '<article class="flow-step' + (active ? ' active' : '') + '" data-step="' + index + '">' +
            '<h4 style="color:' + (active ? 'var(--accent)' : 'var(--text)') + ';">' + step.title + '</h4>' +
            '<p style="color:' + (active ? 'var(--text)' : 'var(--text-muted)') + ';">' + step.desc + '</p>' +
          '</article>';
      }).join('');

      const layerColumn = LAYERS.map(function (layer, idx) {
        const isHighlighted = activeLayer === layer.id;
        const block = '' +
          '<article class="layer-card" style="padding:12px 14px;' +
            'border-color:' + (isHighlighted ? layer.color : 'var(--border)') + ';' +
            'background:' + (isHighlighted ? layer.glow : 'var(--bg-card)') + ';' +
            'box-shadow:' + (isHighlighted ? ('0 0 22px ' + layer.glow) : 'none') + ';">' +
            '<div class="layer-head" style="margin-bottom:0;">' + icon(layer.icon, layer.color) +
              '<span class="layer-label" style="font-size:13px;color:' + (isHighlighted ? layer.color : 'var(--text-muted)') + ';">' + layer.label + '</span>' +
            '</div>' +
          '</article>';

        if (idx >= LAYERS.length - 1) {
          return block;
        }

        return block + '<div class="flow-arrow">' + icon('proxy', isHighlighted ? layer.color : 'var(--text-dim)') + '</div>';
      }).join('');

      viewNode.innerHTML = '' +
        '<div class="play-row">' +
          '<span class="note">Click steps for details or play full sequence.</span>' +
          '<button class="play-btn" id="playBtn">' + (state.playing ? 'Stop Flow' : 'Play Flow') + '</button>' +
        '</div>' +
        '<section class="flow-grid">' +
          '<div class="stack">' + stepColumn + '</div>' +
          '<div class="stack">' + layerColumn + '</div>' +
        '</section>';

      document.getElementById('playBtn').addEventListener('click', function () {
        if (state.playing) {
          stopFlow();
          renderFlow();
          return;
        }
        state.playing = true;
        state.animStep = 0;
        state.activeStep = null;
        renderFlow();

        state.timer = setInterval(function () {
          if (state.animStep >= FLOW_STEPS.length - 1) {
            stopFlow();
            renderFlow();
            return;
          }
          state.animStep += 1;
          renderFlow();
        }, 2400);
      });

      viewNode.querySelectorAll('[data-step]').forEach(function (node) {
        node.addEventListener('click', function () {
          stopFlow();
          const idx = Number(node.getAttribute('data-step'));
          state.activeStep = state.activeStep === idx ? null : idx;
          renderFlow();
        });
      });
    }

    function stopFlow() {
      state.playing = false;
      if (state.timer) {
        clearInterval(state.timer);
        state.timer = null;
      }
    }

    function frictionBar(level) {
      const index = { None: 0, Low: 1, Medium: 2, High: 3 }[level] || 0;
      const tone = ['#22c55e', '#22c55e', '#eab308', '#ef4444'][index];
      let bars = '';
      for (let i = 0; i < 4; i += 1) {
        bars += '<span style="background:' + (i <= index ? tone : 'rgba(255,255,255,0.08)') + ';"></span>';
      }
      return '<div class="bar">' + bars + '<em style="color:' + tone + ';">' + level + '</em></div>';
    }

    function securityBar(level) {
      const index = { Low: 1, Medium: 2, High: 3 }[level] || 0;
      let bars = '';
      for (let i = 1; i <= 3; i += 1) {
        bars += '<span style="background:' + (i <= index ? '#22c55e' : 'rgba(255,255,255,0.08)') + ';"></span>';
      }
      return '<div class="bar">' + bars + '<em style="color:#22c55e;">' + level + '</em></div>';
    }

    function renderVerify() {
      const rows = VERIFY_METHODS.map(function (method) {
        const muted = Boolean(method.comingSoon || method.legacy);
        const extraClass = method.comingSoon ? ' coming' : (method.legacy ? ' legacy' : '');
        const badge = method.comingSoon ? ' <span class="badge">Coming soon</span>' : '';
        return '' +
          '<article class="verify-item' + extraClass + '">' +
            '<div class="icon-wrap">' + icon(method.icon, '#9db1ca') + '</div>' +
            '<div>' +
              '<h4 style="color:' + (muted ? 'var(--text-muted)' : 'var(--text)') + ';">' + method.name + badge + '</h4>' +
              '<p>' + method.desc + '</p>' +
            '</div>' +
            '<div class="meta">' +
              '<div class="mini-label">Friction</div>' + frictionBar(method.friction) +
            '</div>' +
            '<div class="meta">' +
              '<div class="mini-label">Security</div>' + securityBar(method.security) +
            '</div>' +
          '</article>';
      }).join('');

      viewNode.innerHTML = '' +
        '<section class="callout"><strong>Current challenge:</strong> OpenClaw verification often depends on public posting. Clauth provides private alternatives with lower friction and stronger identity assurance.</section>' +
        '<section class="verify-list">' + rows + '</section>';
    }

    function compareRows(rows, tone, iconName) {
      return rows.map(function (row) {
        let color = 'var(--text)';
        if (row.tone === 'bad') color = 'var(--red)';
        if (row.tone === 'warn') color = 'var(--yellow)';
        if (row.tone === 'good') color = 'var(--green)';

        return '' +
          '<div class="compare-row">' +
            '<h5>' + row.label + '</h5>' +
            '<p style="color:' + color + ';">' + row.value + '</p>' +
          '</div>';
      }).join('');
    }

    function renderComparison() {
      viewNode.innerHTML = '' +
        '<section class="compare-grid">' +
          '<article class="compare-card" style="border-color:rgba(239,68,68,0.36);">' +
            '<header style="background:rgba(239,68,68,0.1);color:var(--red);">' + icon('close', 'var(--red)') + 'OpenClaw Today</header>' +
            '<div class="compare-body">' + compareRows(BEFORE_ROWS, 'bad', 'close') + '</div>' +
          '</article>' +
          '<article class="compare-card" style="border-color:rgba(34,197,94,0.36);">' +
            '<header style="background:rgba(34,197,94,0.1);color:var(--green);">' + icon('check', 'var(--green)') + 'With Clauth</header>' +
            '<div class="compare-body">' + compareRows(AFTER_ROWS, 'good', 'check') + '</div>' +
          '</article>' +
        '</section>' +
        '<section class="attack">' +
          '<h3>' + icon('target', 'var(--accent)') + 'Attack Scenario: Malicious Skill Installation</h3>' +
          '<div class="attack-grid">' +
            '<div>' +
              '<h4 style="color:var(--red);">Without Clauth</h4>' +
              '<p>Skill reads plaintext credential files, exfiltrates keys, and pivots across all connected providers before the user notices.</p>' +
            '</div>' +
            '<div>' +
              '<h4 style="color:var(--green);">With Clauth</h4>' +
              '<p>Skill has no secret file access. Unauthorized scope request is denied, logged, and surfaced as an anomaly with immediate revoke options.</p>' +
            '</div>' +
          '</div>' +
        '</section>';
    }

    function renderView() {
      if (state.view === 'architecture') {
        renderArchitecture();
        installCopyButtons();
        return;
      }
      if (state.view === 'flow') {
        renderFlow();
        installCopyButtons();
        return;
      }
      if (state.view === 'verify') {
        renderVerify();
        installCopyButtons();
        return;
      }
      renderComparison();
      installCopyButtons();
    }

    renderTabs();
    renderView();
    installCopyButtons();
  })();
`;
}
