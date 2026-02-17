import { promises as fs } from "node:fs";
import path from "node:path";
import { renderLandingClientJs, renderLandingHtml } from "./landing.js";

const ROOT = path.resolve(import.meta.dirname!, "..");
const STATIC_DIR = path.join(ROOT, ".vercel", "output", "static");
const CONFIG_PATH = path.join(ROOT, ".vercel", "output", "config.json");

const DOC_PAGES: { file: string; url: string; label: string }[] = [
  { file: "setup-guide.md", url: "docs/quick-start", label: "Quick Start" },
  { file: "real-world-testing.md", url: "docs/real-world-testing", label: "Real-World Testing" },
  { file: "agent-integration.md", url: "docs/sdk", label: "SDK Reference" },
  { file: "api-reference.md", url: "docs/api", label: "API Endpoints" },
  { file: "security-model.md", url: "docs/security", label: "Security Model" },
  { file: "configuration.md", url: "docs/configuration", label: "Configuration" },
  { file: "identity-broker.md", url: "docs/identity-broker", label: "Identity Broker" }
];

function markdownToHtml(md: string): string {
  let html = md
    // Code blocks (fenced)
    .replace(/```(\w*)\n([\s\S]*?)```/g, (_m, _lang, code) =>
      `<pre><code>${code.replace(/</g, "&lt;").replace(/>/g, "&gt;").trimEnd()}</code></pre>`)
    // Inline code
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Headers
    .replace(/^#### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    // Bold and italic
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    // Horizontal rules
    .replace(/^---$/gm, '<hr>')
    // Links
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
    // Tables
    .replace(/^\|(.+)\|$/gm, (match) => {
      const cells = match.split('|').filter(c => c.trim()).map(c => c.trim());
      if (cells.every(c => /^[-:]+$/.test(c))) return '<!-- table separator -->';
      const tag = 'td';
      return '<tr>' + cells.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>';
    });

  // Wrap table rows
  html = html.replace(/((?:<tr>.*<\/tr>\n?)+)/g, '<table>$1</table>');
  html = html.replace(/<!-- table separator -->\n?/g, '');

  // Paragraphs — wrap lines that aren't already in tags
  html = html.replace(/^(?!<[a-z]|$)(.+)$/gm, '<p>$1</p>');

  // Lists (simple)
  html = html.replace(/(<p>- .+<\/p>\n?)+/g, (match) => {
    const items = match.replace(/<\/?p>/g, '').trim().split('\n')
      .map(line => `<li>${line.replace(/^- /, '')}</li>`).join('\n');
    return `<ul>${items}</ul>`;
  });

  // Numbered lists
  html = html.replace(/(<p>\d+\. .+<\/p>\n?)+/g, (match) => {
    const items = match.replace(/<\/?p>/g, '').trim().split('\n')
      .map(line => `<li>${line.replace(/^\d+\. /, '')}</li>`).join('\n');
    return `<ol>${items}</ol>`;
  });

  return html;
}

function wrapDocHtml(title: string, body: string, currentUrl: string): string {
  const sidebarLinks = DOC_PAGES.map(p => {
    const href = `/${p.url}`;
    const active = p.url === currentUrl;
    return `<a href="${href}" class="sidebar-link${active ? " active" : ""}">${p.label}</a>`;
  }).join("\n      ");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title} - Clauth</title>
  <link rel="icon" type="image/png" href="/favicon.png" />
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
  <style>
    :root {
      --bg: #0a0e17;
      --bg-card: #111827;
      --border: #1e293b;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent: #f97316;
      --green: #22c55e;
      --mono: "JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace;
      --sans: "Space Grotesk", "Segoe UI", "Avenir Next", sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      padding: 0;
    }
    .doc-nav {
      border-bottom: 1px solid var(--border);
      padding: 14px 24px;
      display: flex;
      align-items: center;
      gap: 14px;
      background: rgba(17, 24, 39, 0.8);
      backdrop-filter: blur(12px);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .doc-nav img { border-radius: 4px; }
    .doc-nav a {
      color: var(--text-muted);
      text-decoration: none;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 600;
    }
    .doc-nav a:hover { color: var(--text); }
    .doc-nav .brand { color: var(--text); font-size: 15px; }
    .doc-nav .sep { color: var(--text-dim); }
    .doc-layout {
      display: flex;
      max-width: 1060px;
      margin: 0 auto;
    }
    .doc-sidebar {
      width: 220px;
      flex-shrink: 0;
      padding: 32px 0 40px 24px;
      position: sticky;
      top: 53px;
      height: calc(100vh - 53px);
      overflow-y: auto;
      border-right: 1px solid var(--border);
    }
    .sidebar-heading {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-dim);
      margin-bottom: 12px;
      padding: 0 12px;
    }
    .sidebar-link {
      display: block;
      padding: 7px 12px;
      font-family: var(--sans);
      font-size: 13px;
      font-weight: 500;
      color: var(--text-muted);
      text-decoration: none;
      border-radius: 6px;
      margin-bottom: 2px;
      transition: background 0.15s, color 0.15s;
    }
    .sidebar-link:hover {
      background: rgba(255, 255, 255, 0.04);
      color: var(--text);
      text-decoration: none;
    }
    .sidebar-link.active {
      background: rgba(249, 115, 22, 0.1);
      color: var(--accent);
      font-weight: 600;
    }
    .doc-shell {
      flex: 1;
      min-width: 0;
      padding: 40px 40px 80px;
    }
    h1 { font-size: 32px; font-weight: 800; margin-bottom: 24px; letter-spacing: -0.02em; }
    h2 { font-size: 22px; font-weight: 700; margin: 36px 0 14px; padding-top: 20px; border-top: 1px solid var(--border); }
    h3 { font-size: 17px; font-weight: 700; margin: 24px 0 10px; color: var(--accent); }
    h4 { font-size: 14px; font-weight: 700; margin: 18px 0 8px; }
    p { font-size: 15px; line-height: 1.7; color: var(--text-muted); margin-bottom: 12px; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    strong { color: var(--text); }
    code {
      font-family: var(--mono);
      font-size: 13px;
      background: rgba(249, 115, 22, 0.1);
      border: 1px solid rgba(249, 115, 22, 0.2);
      border-radius: 4px;
      padding: 1px 5px;
      color: #fdba74;
    }
    pre {
      margin: 14px 0 18px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: rgba(0, 0, 0, 0.35);
      padding: 16px 18px;
      overflow-x: auto;
      line-height: 1.55;
      position: relative;
    }
    pre code {
      background: none;
      border: none;
      padding: 0;
      font-size: 13px;
      color: var(--text);
    }
    .copy-btn {
      position: absolute;
      top: 10px;
      right: 10px;
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
    .copy-btn:active { transform: translateY(1px); }
    ul, ol { margin: 10px 0 16px 22px; }
    li { font-size: 14px; line-height: 1.7; color: var(--text-muted); margin-bottom: 6px; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0 18px;
      font-size: 13px;
    }
    td {
      padding: 8px 12px;
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-family: var(--mono);
      font-size: 12px;
    }
    tr:first-child td { font-weight: 700; color: var(--text); background: rgba(255,255,255,0.03); }
    hr { border: none; border-top: 1px solid var(--border); margin: 28px 0; }
    @media (max-width: 768px) {
      .doc-sidebar { display: none; }
      .doc-shell { padding: 28px 18px 60px; }
      .doc-nav { padding: 12px 16px; }
    }
  </style>
</head>
<body>
  <nav class="doc-nav">
    <a href="/"><img src="/logo.png" alt="Clauth" width="24" height="24" /></a>
    <a href="/" class="brand">Clauth</a>
    <span class="sep">/</span>
    <a href="/docs/quick-start">Docs</a>
  </nav>
  <div class="doc-layout">
    <aside class="doc-sidebar">
      <div class="sidebar-heading">Documentation</div>
      ${sidebarLinks}
    </aside>
    <main class="doc-shell">
      ${body}
    </main>
  </div>
  <script>
    function copyToClipboard(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }

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
      return Promise.resolve();
    }

    function installCopyButtons() {
      document.querySelectorAll('pre').forEach(function (pre) {
        const code = pre.querySelector('code');
        if (!code) return;
        if (pre.querySelector('button.copy-btn')) return;

        const btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.type = 'button';
        btn.textContent = 'Copy';
        btn.addEventListener('click', function (event) {
          event.preventDefault();
          event.stopPropagation();

          const clone = pre.cloneNode(true);
          const existing = clone.querySelector('button.copy-btn');
          if (existing) existing.remove();
          const text = (clone.innerText || clone.textContent || '').trimEnd();

          const prev = btn.textContent;
          btn.textContent = 'Copying...';
          copyToClipboard(text)
            .then(function () { btn.textContent = 'Copied'; })
            .catch(function () { btn.textContent = 'Failed'; })
            .finally(function () {
              setTimeout(function () { btn.textContent = prev; }, 1200);
            });
        });

        pre.appendChild(btn);
      });
    }

    installCopyButtons();
  </script>
</body>
</html>`;
}

async function build(): Promise<void> {
  await fs.mkdir(STATIC_DIR, { recursive: true });

  // Vercel Build Output API config
  await fs.writeFile(CONFIG_PATH, JSON.stringify({ version: 3 }), "utf8");

  // Landing page
  await fs.writeFile(path.join(STATIC_DIR, "index.html"), renderLandingHtml(), "utf8");
  await fs.writeFile(path.join(STATIC_DIR, "landing.js"), renderLandingClientJs(), "utf8");

  // Build doc pages
  const docsDir = path.join(ROOT, "docs");
  let docCount = 0;
  for (const page of DOC_PAGES) {
    const md = await fs.readFile(path.join(docsDir, page.file), "utf8");
    const title = md.match(/^# (.+)$/m)?.[1] ?? page.label;
    const body = markdownToHtml(md);
    const html = wrapDocHtml(title, body, page.url);

    const outDir = path.join(STATIC_DIR, page.url);
    await fs.mkdir(outDir, { recursive: true });
    await fs.writeFile(path.join(outDir, "index.html"), html, "utf8");
    docCount++;
  }

  // Copy static assets from public/
  const publicDir = path.join(ROOT, "public");
  const publicFiles = await fs.readdir(publicDir);
  for (const file of publicFiles) {
    await fs.copyFile(path.join(publicDir, file), path.join(STATIC_DIR, file));
  }

  // Copy install script
  const siteDir = path.join(ROOT, "site");
  await fs.copyFile(path.join(siteDir, "install.sh"), path.join(STATIC_DIR, "install.sh"));

  const totalFiles = publicFiles.length + docCount + 3;
  console.log(`Site built to ${STATIC_DIR} (${totalFiles} files, ${docCount} docs)`);
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
