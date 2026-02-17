export function renderDashboardHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clauth Control Room</title>
  <link rel="icon" type="image/png" href="/favicon.png" />
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
  <style>
    :root {
      --bg: #0a0e17;
      --bg-card: #111827;
      --border: #1e293b;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent: #f97316;
      --accent-glow: rgba(249, 115, 22, 0.16);
      --green: #22c55e;
      --red: #ef4444;
      --mono: "JetBrains Mono", "Iosevka", "SFMono-Regular", Menlo, Consolas, monospace;
      --sans: "Space Grotesk", "Segoe UI", "Avenir Next", sans-serif;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(1200px 600px at 5% -20%, rgba(59, 130, 246, 0.14), transparent),
        radial-gradient(1000px 520px at 96% -15%, rgba(249, 115, 22, 0.14), transparent),
        var(--bg);
      min-height: 100vh;
    }

    .shell {
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 18px 60px;
      display: grid;
      gap: 14px;
    }

    .hero {
      background: linear-gradient(135deg, rgba(249, 115, 22, 0.18), rgba(249, 115, 22, 0.04) 60%);
      border: 1px solid rgba(249, 115, 22, 0.3);
      border-radius: 16px;
      color: var(--text);
      padding: 20px 20px 16px;
      box-shadow: 0 16px 30px rgba(0, 0, 0, 0.3);
      animation: lift-in 420ms ease-out both;
    }

    .hero h1 {
      margin: 0;
      font-size: clamp(1.4rem, 1.1rem + 1.6vw, 2rem);
      letter-spacing: -0.02em;
      font-family: var(--mono);
      font-weight: 800;
      background: linear-gradient(135deg, #fdba74, #f97316);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .hero p {
      margin: 8px 0 0;
      color: var(--text-muted);
      font-size: 0.92rem;
    }

    .grid {
      display: grid;
      gap: 14px;
      grid-template-columns: repeat(12, 1fr);
    }

    .panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px;
      box-shadow: 0 5px 14px rgba(0, 0, 0, 0.2);
      animation: lift-in 420ms ease-out both;
    }

    .panel h2 {
      margin: 0 0 9px;
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-dim);
      font-family: var(--mono);
    }

    .span-4 { grid-column: span 4; }
    .span-6 { grid-column: span 6; }
    .span-8 { grid-column: span 8; }
    .span-12 { grid-column: span 12; }

    .kvs {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 6px 10px;
      margin: 0;
      font-size: 0.9rem;
    }

    .kvs dt { font-weight: 700; color: var(--accent); font-size: 0.82rem; }
    .kvs dd { margin: 0; font-family: var(--mono); font-size: 0.84rem; color: var(--text); }

    .row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
    }

    input, button {
      border-radius: 10px;
      border: 1px solid var(--border);
      font: inherit;
      padding: 8px 10px;
      min-height: 38px;
    }

    input {
      width: 100%;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text);
    }

    input::placeholder { color: var(--text-dim); }

    button {
      cursor: pointer;
      background: linear-gradient(160deg, #f97316, #d45516);
      color: #fef3e8;
      border: 1px solid rgba(249, 115, 22, 0.5);
      font-weight: 700;
      font-size: 0.85rem;
      transition: transform 120ms ease, box-shadow 120ms ease;
    }

    button:hover { transform: translateY(-1px); box-shadow: 0 6px 16px rgba(249, 115, 22, 0.25); }
    button.secondary { background: rgba(255, 255, 255, 0.06); border-color: var(--border); color: var(--text-muted); }
    button.secondary:hover { border-color: #3b4f6b; color: var(--text); box-shadow: none; }
    button.warn { background: linear-gradient(160deg, #dc2626, #b91c1c); border-color: rgba(239, 68, 68, 0.5); color: #fee2e2; }
    button.warn:hover { box-shadow: 0 6px 16px rgba(239, 68, 68, 0.25); }

    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }

    .chip {
      border-radius: 999px;
      border: 1px solid rgba(249, 115, 22, 0.3);
      background: rgba(249, 115, 22, 0.1);
      color: #fdba74;
      padding: 4px 10px;
      font-size: 0.76rem;
      font-family: var(--mono);
    }

    .ok { color: var(--green); }
    .danger { color: var(--red); }

    pre {
      margin: 0;
      border-radius: 11px;
      border: 1px solid var(--border);
      background: rgba(0, 0, 0, 0.3);
      padding: 11px;
      overflow: auto;
      font-family: var(--mono);
      font-size: 0.78rem;
      line-height: 1.42;
      max-height: 320px;
      color: var(--text-muted);
    }

    .tiny {
      margin-top: 6px;
      font-size: 0.72rem;
      color: var(--text-dim);
      line-height: 1.35;
    }

    .stack { display: grid; gap: 8px; }

    @keyframes lift-in {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @media (max-width: 860px) {
      .span-4, .span-6, .span-8 { grid-column: span 12; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="hero">
      <h1>Clauth Control Room</h1>
      <p>Credential proxy + behavioral firewall. Local-first. Brokered execution only.</p>
      <div class="chips" id="chips"></div>
    </header>

    <section class="grid">
      <article class="panel span-4">
        <h2>Daemon Status</h2>
        <dl class="kvs" id="status"></dl>
      </article>

      <article class="panel span-4">
        <h2>Capabilities</h2>
        <dl class="kvs" id="caps"></dl>
      </article>

      <article class="panel span-4">
        <h2>Admin Session</h2>
        <div class="stack">
          <input id="adminToken" type="password" placeholder="x-clauth-admin-token" />
          <div class="row">
            <button class="secondary" id="refreshAll">Refresh</button>
            <button class="warn" id="emergency">Emergency Revoke</button>
          </div>
        </div>
        <p class="tiny">Admin token stays only in this page memory.</p>
      </article>

      <article class="panel span-6">
        <h2>Skill Token Issue</h2>
        <div class="stack">
          <input id="issueSkill" placeholder="skill id (e.g. skill.github.sync)" />
          <div class="row">
            <button id="issueBtn">Issue / Rotate Token</button>
            <button class="secondary" id="listBtn">List Tokens</button>
          </div>
        </div>
      </article>

      <article class="panel span-6">
        <h2>Skill Token Revoke</h2>
        <div class="stack">
          <input id="revokeSkill" placeholder="skill id" />
          <button class="warn" id="revokeBtn">Revoke Token</button>
        </div>
      </article>

      <article class="panel span-12">
        <h2>Output</h2>
        <pre id="output">Loading...</pre>
      </article>
    </section>
  </div>

  <script>
    const output = document.getElementById('output');
    const statusNode = document.getElementById('status');
    const capsNode = document.getElementById('caps');
    const chipsNode = document.getElementById('chips');

    const adminToken = document.getElementById('adminToken');
    const refreshBtn = document.getElementById('refreshAll');
    const emergencyBtn = document.getElementById('emergency');

    const issueSkill = document.getElementById('issueSkill');
    const issueBtn = document.getElementById('issueBtn');
    const listBtn = document.getElementById('listBtn');

    const revokeSkill = document.getElementById('revokeSkill');
    const revokeBtn = document.getElementById('revokeBtn');

    function write(value) {
      if (typeof value === 'string') {
        output.textContent = value;
        return;
      }
      output.textContent = JSON.stringify(value, null, 2);
    }

    function renderKv(node, obj) {
      node.innerHTML = '';
      Object.entries(obj).forEach(([key, value]) => {
        const dt = document.createElement('dt');
        dt.textContent = key;
        const dd = document.createElement('dd');
        dd.textContent = String(value);
        node.appendChild(dt);
        node.appendChild(dd);
      });
    }

    function renderChips(status, caps) {
      chipsNode.innerHTML = '';
      const items = [
        ['transport', status.transport],
        ['skillTokenRequired', caps.requireSkillToken],
        ['endpointPolicy', caps.endpointPolicyEnforced],
        ['vaultUnlocked', status.vaultUnlocked]
      ];
      items.forEach(([label, value]) => {
        const chip = document.createElement('span');
        chip.className = 'chip';
        chip.textContent = label + '=' + value;
        chipsNode.appendChild(chip);
      });
    }

    async function callJson(path, options = {}) {
      const response = await fetch(path, {
        ...options,
        headers: {
          'content-type': 'application/json',
          ...(options.headers || {})
        }
      });

      const text = await response.text();
      let body;
      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = text;
      }

      if (!response.ok) {
        throw new Error(typeof body === 'object' ? JSON.stringify(body, null, 2) : String(body));
      }

      return body;
    }

    async function refresh() {
      try {
        const [status, caps] = await Promise.all([
          callJson('/clauth/v1/status'),
          callJson('/clauth/v1/capabilities')
        ]);

        renderKv(statusNode, {
          daemon: status.daemon,
          activeGrants: status.activeGrants,
          activeSkillTokens: status.activeSkillTokens,
          auditValid: status.auditIntegrity?.valid
        });

        renderKv(capsNode, {
          version: caps.version,
          transport: caps.transport,
          brokeredExecution: caps.brokeredExecution,
          endpointPolicy: caps.endpointPolicyEnforced
        });

        renderChips(status, caps);
        write({ status, capabilities: caps });
      } catch (error) {
        write(error.message || String(error));
      }
    }

    async function withAdmin(path, body) {
      const token = adminToken.value.trim();
      if (!token) {
        throw new Error('Missing admin token');
      }

      return callJson(path, {
        method: 'POST',
        headers: {
          'x-clauth-admin-token': token
        },
        body: body ? JSON.stringify(body) : undefined
      });
    }

    refreshBtn.addEventListener('click', refresh);

    issueBtn.addEventListener('click', async () => {
      try {
        const skillId = issueSkill.value.trim();
        if (!skillId) throw new Error('Skill id required');
        const body = await withAdmin('/clauth/v1/admin/skill-token/issue', { skillId });
        write(body);
      } catch (error) {
        write(error.message || String(error));
      }
    });

    listBtn.addEventListener('click', async () => {
      try {
        const token = adminToken.value.trim();
        if (!token) throw new Error('Missing admin token');
        const body = await callJson('/clauth/v1/admin/skill-token/list', {
          method: 'GET',
          headers: {
            'x-clauth-admin-token': token
          }
        });
        write(body);
      } catch (error) {
        write(error.message || String(error));
      }
    });

    revokeBtn.addEventListener('click', async () => {
      try {
        const skillId = revokeSkill.value.trim();
        if (!skillId) throw new Error('Skill id required');
        const body = await withAdmin('/clauth/v1/admin/skill-token/revoke', { skillId });
        write(body);
      } catch (error) {
        write(error.message || String(error));
      }
    });

    emergencyBtn.addEventListener('click', async () => {
      try {
        const body = await withAdmin('/clauth/v1/emergency-revoke');
        write(body);
      } catch (error) {
        write(error.message || String(error));
      }
    });

    refresh();
  </script>
</body>
</html>`;
}
