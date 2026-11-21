// Rendu des reponses de l'agent IA : Markdown simple (titres, listes, tableaux, gras,
// code, citations) + liens vers NVD (CVE) et vers le graphe (noeuds et chemins).
//
// Securite : le texte du modele est d'ABORD entierement echappe (aucun HTML venant
// du modele n'est jamais interprete). Seules les balises generees ici sont ajoutees.

function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// nodeIds : noms des noeuds du graphe de l'analyse affichee (pour les rendre cliquables)
function renderAgentMarkdown(text, nodeIds = []) {
  const tokens = [];  // fragments HTML proteges des transformations Markdown
  const keep = html => `\u0000${tokens.push(html) - 1}\u0000`;
  let s = escapeHtml(text);

  // 1. Identifiants de CVE -> fiche NVD
  s = s.replace(/\bCVE-\d{4}-\d{4,}\b/g, id =>
    keep(`<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener">${id}</a>`));

  // 2. Chemins (a -> b -> c) puis noeuds isoles -> mise en evidence dans le graphe
  const ids = [...new Set(nodeIds)].filter(n => n && n !== "unknown");
  const canonical = new Map(ids.map(n => [escapeHtml(n).toLowerCase(), escapeHtml(n)]));
  const idOf = text => canonical.get(text.toLowerCase()) || text;  // "Kali" -> "kali"
  const names = [...canonical.keys()].sort((a, b) => b.length - a.length).map(escapeRegex);
  if (names.length) {
    const N = names.join("|");
    const ARROW = "\\s*(?:→|-&gt;|=&gt;|⟶)\\s*";
    const pathRe = new RegExp(`(?<![\\w-])(?:${N})(?:${ARROW}(?:${N}))+(?![\\w-])`, "gi");
    s = s.replace(pathRe, m => {
      const parts = m.split(new RegExp(ARROW)).map(idOf);
      return keep(`<a href="#graph" class="path-link" data-path="${parts.join(",")}"
                    title="Afficher ce chemin dans le graphe">${m}</a>`);
    });
    s = s.replace(new RegExp(`(?<![\\w-])(?:${N})(?![\\w-])`, "gi"), m =>
      keep(`<a href="#graph" class="node-link" data-node="${idOf(m)}" title="Voir ce noeud dans le graphe">${m}</a>`));
  }

  // 3. Mise en forme en ligne
  const inline = str => str
    .replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/__([^_]+)__/g, "<strong>$1</strong>")
    .replace(/(^|[^*\w])\*([^*\n]+)\*(?!\*)/g, "$1<em>$2</em>");

  // 4. Blocs : titres, separateurs, tableaux, listes, citations, paragraphes
  const lines = s.split(/\r?\n/);
  const out = [];
  let list = null, para = [];
  const flushPara = () => { if (para.length) { out.push(`<p>${para.map(inline).join("<br>")}</p>`); para = []; } };
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  const isTableSep = l => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l || "");
  const cells = l => l.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map(c => inline(c.trim()));

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let m;
    if (!line.trim()) { flushPara(); closeList(); continue; }
    if ((m = line.match(/^\s*(#{1,6})\s+(.*)$/))) {
      flushPara(); closeList();
      const level = Math.min(6, m[1].length + 2);
      out.push(`<h${level}>${inline(m[2])}</h${level}>`);
    } else if (/^\s*([-*_])(?:\s*\1){2,}\s*$/.test(line)) {
      flushPara(); closeList(); out.push("<hr>");
    } else if (line.trim().startsWith("|") && isTableSep(lines[i + 1])) {
      flushPara(); closeList();
      const head = cells(line); i += 1;
      const rows = [];
      while (i + 1 < lines.length && lines[i + 1].trim().startsWith("|")) rows.push(cells(lines[++i]));
      out.push(`<div class="md-table"><table><thead><tr>${head.map(c => `<th>${c}</th>`).join("")}</tr></thead>`
             + `<tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`);
    } else if ((m = line.match(/^\s*[-*+•]\s+(.*)$/)) || (m = line.match(/^\s*(\d+)[.)]\s+(.*)$/))) {
      flushPara();
      const ordered = /^\s*\d/.test(line);
      const type = ordered ? "ol" : "ul";
      // une liste numerotee coupee par des puces reprend a son vrai numero (1, puis 2...)
      if (list !== type) { closeList(); out.push(ordered ? `<ol start="${Number(m[1])}">` : "<ul>"); list = type; }
      out.push(`<li>${inline(ordered ? m[2] : m[1])}</li>`);
    } else if ((m = line.match(/^\s*&gt;\s?(.*)$/))) {
      flushPara(); closeList(); out.push(`<blockquote>${inline(m[1])}</blockquote>`);
    } else {
      closeList(); para.push(line.trim());
    }
  }
  flushPara(); closeList();

  return out.join("").replace(/\u0000(\d+)\u0000/g, (_, n) => tokens[Number(n)]);
}
