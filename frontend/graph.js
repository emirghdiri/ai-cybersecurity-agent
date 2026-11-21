// Graphe d'attaque (Cytoscape.js), style neon, qui montre la topologie reelle du labo :
//   - Kali dans le reseau externe ;
//   - la VM cible, qui contient les services de l'hote et les conteneurs Docker ;
//   - chaque reseau Docker prive (relations "via": "docker:<reseau>") dans son propre cadre.
// Tout vient de GET /graph, /risk-analysis et /vulnerabilities : rien n'est code en dur.

let cy = null;
let lastGraphData = null;

// ===================== 1. Icones et types de machines =====================
const RISK_COLORS = { critical: "#ff3b3b", high: "#ff9800", medium: "#ffd600", low: "#00e676" };
const NEON = "#29b6f6";

// Icones dessinees en SVG (aucune image externe a telecharger).
function svgIcon(body) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" fill="none"
               stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}
const ICONS = {
  attacker: svgIcon(`<rect x="4" y="8" width="40" height="30" rx="4" stroke="#ff5252"/>
    <path d="M12 18l7 5-7 5M23 29h11" stroke="#ff5252"/><path d="M16 44h16M24 38v6" stroke="#ff5252"/>`),
  server: svgIcon(`<g stroke="${NEON}"><rect x="6" y="5" width="36" height="11" rx="2"/>
    <rect x="6" y="19" width="36" height="11" rx="2"/><rect x="6" y="33" width="36" height="11" rx="2"/></g>
    <g stroke="#00e676"><path d="M33 10.5h.1M37 10.5h.1M33 24.5h.1M37 24.5h.1M33 38.5h.1M37 38.5h.1"/></g>
    <g stroke="${NEON}"><path d="M11 10.5h12M11 24.5h12M11 38.5h12"/></g>`),
  database: svgIcon(`<g stroke="${NEON}"><ellipse cx="24" cy="9" rx="16" ry="5"/>
    <path d="M8 9v30c0 2.8 7.2 5 16 5s16-2.2 16-5V9"/><path d="M8 19c0 2.8 7.2 5 16 5s16-2.2 16-5"/>
    <path d="M8 29c0 2.8 7.2 5 16 5s16-2.2 16-5"/></g>`),
  unknown: svgIcon(`<circle cx="24" cy="24" r="18" stroke="#90a4ae"/>
    <path d="M18.5 18.5a5.5 5.5 0 1 1 7.5 5.1c-1.3.6-2 1.7-2 3.1V29M24 35h.1" stroke="#90a4ae"/>`),
};
// Logos des logiciels (optionnels) : si le fichier existe dans frontend/icons/,
// il remplace l'icone generique. Ordre important : le premier mot-cle trouve gagne.
const BRAND_ICONS = [
  ["kali", "kali.svg"], ["phpmyadmin", "phpmyadmin.svg"], ["mysql", "mysql.svg"],
  ["mariadb", "mariadb.svg"], ["postgres", "postgresql.svg"], ["redis", "redis.svg"],
  ["mongo", "mongodb.svg"], ["werkzeug", "flask.svg"], ["flask", "flask.svg"], ["nginx", "nginx.svg"],
  ["httpd", "apache.svg"], ["apache", "apache.svg"], ["ssh", "openssh.svg"],
];
const iconAvailable = {};  // fichier -> true/false (on ne teste chaque fichier qu'une fois)

function imageExists(src) {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => resolve(true);
    img.onerror = () => resolve(false);
    img.src = src;
  });
}

async function brandIcon(node) {
  const text = `${node.id} ${node.name || ""}`.toLowerCase();
  const match = BRAND_ICONS.find(([keyword]) => text.includes(keyword));
  if (!match) return null;
  const src = `icons/${match[1]}`;
  if (!(src in iconAvailable)) iconAvailable[src] = await imageExists(src);
  return iconAvailable[src] ? src : null;
}

const TYPE_LABELS = { attacker: "Attaquant", server: "Serveur", database: "Base de données", unknown: "Service inconnu" };

function nodeType(node) {
  if (node.role === "attacker") return "attacker";
  if (node.name === "unknown") return "unknown";
  // Le nom du logiciel (ex. "phpmyadmin") prime sur le nom du conteneur (ex. "db-admin").
  const text = node.name || node.id;
  if (/database|db|mysql|mariadb|postgres|mongo|redis/i.test(text)) return "database";
  return "server";
}

// ===================== 2. Topologie : VM, Docker, reseaux prives =====================
const STEP_X = 270;        // largeur d'une carte + espace
const ROW_Y = [250, 480];  // ligne des services exposes, ligne des services internes

// Range chaque noeud dans un groupe : attaquant, service de l'hote, conteneur, reseau prive.
function groupOf(graph) {
  const groups = {};
  for (const e of graph.edges) {
    if (String(e.via).startsWith("docker:")) {
      const net = `net:${e.via.slice(7)}`;
      groups[e.source] ??= net;
      groups[e.target] ??= net;
    }
  }
  for (const n of graph.nodes) {
    if (groups[n.id]) continue;
    if (n.role === "attacker") groups[n.id] = "internet";
    else if (n.name && n.id === n.name) groups[n.id] = "host-services";  // processus de la VM
    else groups[n.id] = "docker";                                        // conteneur Docker
  }
  return groups;
}

// Positions fixes : exposes en haut, internes en dessous, un groupe a cote de l'autre.
function layoutPositions(nodes, groups) {
  const nets = [...new Set(Object.values(groups).filter(g => g.startsWith("net:")))];
  const positions = {};
  let x = 0;
  for (const g of ["host-services", "docker", ...nets]) {
    const members = nodes.filter(n => groups[n.id] === g);
    if (!members.length) continue;
    const rows = [members.filter(n => n.exposed_externally), members.filter(n => !n.exposed_externally)];
    const width = Math.max(rows[0].length, rows[1].length);
    rows.forEach((row, r) => row.forEach((n, i) => {
      const offset = ((width - row.length) * STEP_X) / 2;
      positions[n.id] = { x: x + offset + i * STEP_X, y: ROW_Y[r] };
    }));
    x += width * STEP_X + 90;
  }
  positions.kali = { x: (x - 90 - STEP_X) / 2, y: 0 };
  return positions;
}

function groupLabel(group) {
  if (group === "internet") return "Réseau externe (attaquant)";
  if (group === "host-services") return "Services de l'hôte (hors Docker)";
  if (group === "docker") return "Conteneurs Docker";
  return `Réseau Docker privé : ${group.slice(4)}`;
}

// Pour chaque arete (source->cible), le chemin le plus risque qui la traverse.
function edgeRisk(risks) {
  const result = {};
  for (const r of risks) {
    for (let i = 0; i < r.path.length - 1; i++) {
      const key = `${r.path[i]}->${r.path[i + 1]}`;
      if (!result[key] || r.risk_score > result[key].score) {
        result[key] = { score: r.risk_score, cls: severityClass(r.severity) };
      }
    }
  }
  return result;
}

async function buildElements(graph, risks, vulns, showIsolated) {
  const risky = edgeRisk(risks);
  const connected = new Set(graph.edges.flatMap(e => [e.source, e.target]));
  const nodes = graph.nodes.filter(n => showIsolated || connected.has(n.id));
  const ids = new Set(nodes.map(n => n.id));
  const groups = groupOf(graph);
  const positions = layoutPositions(nodes, groups);
  const icons = await Promise.all(nodes.map(brandIcon));
  const host = (vulns.hosts || [])[0] || {};

  // Ports internes atteints par les pivots (ex. 6379 vers le cache).
  const inPorts = {};
  for (const e of graph.edges) if (e.port) (inPorts[e.target] ??= new Set()).add(e.port);

  const parents = [
    { data: { id: "host", label: `Machine cible : VM ${host.hostname || "?"}  (${host.ip || "?"})`, kind: "host" } },
    ...[...new Set(nodes.map(n => groups[n.id]))].map(g => ({ data: {
      id: g, label: groupLabel(g), kind: g.startsWith("net:") ? "private" : "zone",
      parent: g === "internet" ? undefined : "host" } })),
  ];

  const nodeElements = nodes.map((n, i) => {
    const type = nodeType(n);
    const version = (n.version || "").split(" ")[0];  // "9.6p1 Ubuntu 3..." -> "9.6p1"
    let software = n.name && n.name !== "unknown" ? `${n.name} ${version}`.trim() : TYPE_LABELS[type];
    if (!n.name && /cache/i.test(n.id)) software = "Cache de données";
    let access = "";
    if (type !== "attacker") {
      access = n.exposed_externally
        ? `exposé · port ${n.port}`
        : `non exposé${inPorts[n.id] ? " · port " + [...inPorts[n.id]].join(", ") : ""}`;
    }
    return { data: { id: n.id, parent: groups[n.id], type, icon: icons[i] || ICONS[type],
                     label: [n.id, software, access].filter(Boolean).join("\n"),
                     exposed: n.exposed_externally ? "yes" : "no" },
             position: positions[n.id] };
  });

  const edgeElements = graph.edges
    .filter(e => ids.has(e.source) && ids.has(e.target))
    .map(e => {
      const id = `${e.source}->${e.target}`;
      const role = e.source === "kali" ? (risky[id] ? "Accès initial" : "Découverte") : "Mouvement latéral";
      return { data: { id, source: e.source, target: e.target, risk: risky[id]?.cls || "none",
                       label: e.port ? `${role} :${e.port}` : role,
                       kind: e.source === "kali" ? "entry" : "internal" } };
    });

  return [...parents, ...nodeElements, ...edgeElements];
}

// ===================== 3. Dessin du graphe =====================
function graphStyle() {
  return [
    // Cadres : machine cible, zones et reseaux Docker prives
    { selector: ":parent", style: {
        label: "data(label)", "text-valign": "top", "text-halign": "center", "text-margin-y": -6,
        color: "#9cc9ef", "font-size": 13, "font-weight": 700, padding: 28, shape: "round-rectangle",
        "background-color": "#0a2038", "background-opacity": 0.45, "border-width": 1, "border-color": "#2b5c8a" } },
    { selector: "node[kind = 'host']", style: {
        "background-color": "#061426", "background-opacity": 0.6, "border-width": 2, "border-color": NEON,
        color: "#e3f2fd", "font-size": 15, padding: 40 } },
    { selector: "node[kind = 'private']", style: {
        "border-style": "dashed", "border-width": 2, "border-color": "#ab47bc", color: "#e1bee7",
        "background-color": "#2a0f3d", "background-opacity": 0.35 } },
    // Machines / services
    { selector: "node:childless", style: {
        shape: "round-rectangle", width: 240, height: 92, "background-color": "#0b1e33",
        "border-width": 2, "border-color": NEON,
        "underlay-color": NEON, "underlay-padding": 6, "underlay-opacity": 0.18, "underlay-shape": "round-rectangle",
        "background-image": "data(icon)", "background-width": 44, "background-height": 44,
        "background-position-x": 16, "background-position-y": "50%", "background-clip": "none",
        label: "data(label)", "text-wrap": "wrap", "text-valign": "center", "text-halign": "center",
        "text-margin-x": 26, "text-max-width": 185, color: "#e3f2fd", "font-size": 13, "font-weight": 600 } },
    { selector: "node[type = 'attacker']", style: { "border-color": "#ff5252", "underlay-color": "#ff5252" } },
    { selector: "node[type = 'unknown']", style: { "border-color": "#546e7a", "underlay-opacity": 0, color: "#90a4ae" } },
    { selector: "node:childless[exposed = 'no'][type != 'attacker']", style: { "border-style": "dashed" } },
    // Relations
    { selector: "edge", style: {
        width: 2, "line-color": "#7fa7c9", "target-arrow-color": "#7fa7c9",
        "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 1.3,
        label: "data(label)", "font-size": 11, "font-weight": 600, color: "#e3f2fd",
        "text-background-color": "#0b1e33", "text-background-opacity": 1,
        "text-background-shape": "roundrectangle", "text-background-padding": 4,
        "text-border-color": "#7fa7c9", "text-border-width": 1, "text-border-opacity": 1 } },
    // Aretes internes (mouvement lateral) : pas d'etiquette, elles se croiseraient ;
    // le port est deja ecrit sur la carte de la cible et la legende explique la fleche.
    { selector: "edge[kind = 'internal']", style: { label: "" } },
    ...Object.entries(RISK_COLORS).map(([cls, color]) => ({
      selector: `edge[risk = '${cls}']`,
      style: { width: 4, "line-color": color, "target-arrow-color": color, "text-border-color": color,
               "underlay-color": color, "underlay-padding": 5, "underlay-opacity": 0.25 },
    })),
    { selector: ".faded", style: { opacity: 0.12 } },
    { selector: "edge.highlight", style: { width: 7 } },
  ];
}

async function renderGraph({ graph, risks, vulns }) {
  lastGraphData = { graph, risks, vulns };
  const showIsolated = document.getElementById("show-isolated").checked;
  const elements = await buildElements(graph, risks, vulns, showIsolated);

  if (cy) cy.destroy();
  cy = cytoscape({
    container: document.getElementById("cy"),
    elements,
    style: graphStyle(),
    layout: { name: "preset", fit: true, padding: 30 },
  });
  // Clic sur le fond du graphe : on retire la mise en evidence.
  cy.on("tap", event => {
    if (event.target === cy) {
      cy.elements().removeClass("faded highlight");
      showGraphAsk(null);
    }
  });
  // Clic sur un service : mise en evidence + proposition de demander a l'agent.
  cy.on("tap", "node", event => {
    const node = event.target;
    if (node.isParent() || node.data("type") === "attacker" || node.id() === "kali") return;
    highlightNode(node.id());
    showGraphAsk(node.id());
  });

  document.getElementById("graph-legend").innerHTML = `
    <div><img src="${ICONS.attacker}"> Attaquant</div>
    <div><img src="${ICONS.server}"> Serveur</div>
    <div><img src="${ICONS.database}"> Base de données / cache</div>
    <div><span style="width:22px;height:14px;border:2px solid ${NEON};border-radius:3px"></span> Machine cible (VM)</div>
    <div><span style="width:22px;height:14px;border:2px dashed #ab47bc;border-radius:3px"></span> Réseau Docker privé</div>
    <div><span class="dash"></span> Service non exposé</div>
    <div><b style="color:#ff3b3b">→</b> dans le réseau privé = mouvement latéral (pivot)</div>
    ${Object.entries(RISK_COLORS).map(([cls, c]) =>
      `<div><span class="dot" style="background:${c}"></span>${cls.toUpperCase()}</div>`).join("")}`;
}

// Appelee depuis la liste des chemins : met un chemin en evidence, estompe le reste.
function highlightPath(path) {
  if (!cy) return;
  cy.elements().not(":parent").removeClass("highlight").addClass("faded");
  path.forEach((nodeId, i) => {
    cy.getElementById(nodeId).removeClass("faded");
    if (i < path.length - 1) {
      cy.getElementById(`${nodeId}->${path[i + 1]}`).removeClass("faded").addClass("highlight");
    }
  });
}

// Met en evidence un noeud et ses relations directes (appelee depuis le chat).
function highlightNode(nodeId) {
  if (!cy) return false;
  const node = cy.getElementById(nodeId);
  if (node.empty()) return false;
  cy.elements().not(":parent").removeClass("highlight").addClass("faded");
  node.closedNeighborhood().removeClass("faded");
  node.connectedEdges().addClass("highlight");
  return true;
}

// Bouton "Demander a l'agent" sous le graphe pour le service selectionne.
function showGraphAsk(nodeId) {
  const box = document.getElementById("graph-ask");
  box.innerHTML = "";
  if (!nodeId) return;
  const button = document.createElement("button");
  button.className = "ask-btn";
  button.textContent = `Demander à l'agent d'analyser ${nodeId}`;
  button.addEventListener("click", () => askAgent(
    `Analyse le service ${nodeId} : son rôle dans les chemins d'attaque, ses vulnérabilités `
    + `les plus graves (et si elles sont exploitées), et les mesures pour le protéger.`));
  box.append(button);
}

document.getElementById("show-isolated").addEventListener("change", () => {
  if (lastGraphData) renderGraph(lastGraphData);
});

registerView(renderGraph);