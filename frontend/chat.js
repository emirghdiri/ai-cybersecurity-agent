// Agent IA : panneau de discussion (bulle en bas a droite, agrandissable).
// Les questions partent vers POST /chat -> agent/sentinelpath_agent.py ;
// l'agent ne calcule rien : il appelle les outils de l'API puis explique les resultats.
// Chaque reponse affiche ses SOURCES : les outils appeles et les donnees exactes recues,
// pour verifier que chaque chiffre vient d'un outil ("les outils calculent, l'agent explique").

const chatHistory = [];  // questions/reponses precedentes, renvoyees a l'agent
let latestRisks = [];
let graphNodeIds = [];   // noms des noeuds : rendus cliquables dans les reponses

const TOOL_LABELS = {
  list_analyses: "Historique des analyses",
  get_vulnerabilities: "Vulnérabilités (NVD, CISA KEV)",
  get_attack_graph: "Graphe d'attaque",
  get_attack_paths: "Chemins d'attaque",
  get_risk_analysis: "Analyse de risque",
  compare_analyses: "Comparaison d'analyses",
  run_new_analysis: "Nouvelle collecte live",
};

// Icone de la bulle : petit robot dessine en SVG.
const BOT_ICON = "data:image/svg+xml;utf8," + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" fill="none" stroke="#29b6f6"
        stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">
     <rect x="8" y="14" width="32" height="24" rx="7"/><path d="M24 8v6M20 46l4-8 4 8"/>
     <circle cx="24" cy="6" r="2.5"/><circle cx="18" cy="26" r="2.5" fill="#29b6f6"/>
     <circle cx="30" cy="26" r="2.5" fill="#29b6f6"/><path d="M19 32h10M4 24v6M44 24v6"/></svg>`);

// --------------------------------------------------------------------------- //
// Appel de l'agent et affichage d'une reponse (utilises aussi par le resume)
// --------------------------------------------------------------------------- //
async function callAgent(question) {
  const reply = await api("/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, analysis_id: currentId, history: chatHistory.slice(-12) }),
  });
  chatHistory.push({ role: "user", content: question }, { role: "assistant", content: reply.answer });
  // L'agent a lance une nouvelle collecte : on affiche la nouvelle analyse.
  if ((reply.tools || []).some(t => t.tool === "run_new_analysis" && t.ok)) {
    currentId = null;
    refresh();
  }
  return reply;
}

function formatArgs(args) {
  return Object.entries(args || {}).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ");
}

function prettyResult(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}

// Bloc "Sources" : outils appeles + donnees exactes transmises au modele.
function sourcesElement(tools) {
  if (!tools || !tools.length) {
    const none = document.createElement("div");
    none.className = "sources none";
    none.textContent = "Réponse sans appel d'outil : aucune donnée de l'infrastructure utilisée.";
    return none;
  }
  const details = document.createElement("details");
  details.className = "sources";
  const summary = document.createElement("summary");
  summary.textContent = `Sources : ${tools.length} outil${tools.length > 1 ? "s" : ""} appelé${tools.length > 1 ? "s" : ""} – `
    + tools.map(t => TOOL_LABELS[t.tool] || t.tool).join(" · ");
  details.append(summary);

  for (const t of tools) {
    const item = document.createElement("details");
    item.className = `source-item ${t.ok ? "" : "failed"}`;
    const head = document.createElement("summary");
    head.textContent = `${t.ok ? "✔" : "✖"} ${t.tool}(${formatArgs(t.args)})`;
    const pre = document.createElement("pre");
    pre.textContent = prettyResult(t.result);  // texte brut : jamais interprete comme du HTML
    item.append(head, pre);
    details.append(item);
  }
  return details;
}

function showAgentAnswer(container, reply) {
  container.innerHTML = `<div class="md">${renderAgentMarkdown(reply.answer, graphNodeIds)}</div>`;
  container.append(sourcesElement(reply.tools));
}

// --------------------------------------------------------------------------- //
// Panneau de discussion
// --------------------------------------------------------------------------- //
function addMessage(text, cls) {
  const log = document.getElementById("chat-log");
  const message = document.createElement("div");
  message.className = `message ${cls}`;
  message.textContent = text;  // texte brut : jamais interprete comme du HTML
  log.append(message);
  log.scrollTop = log.scrollHeight;
  return message;
}

function simulatedAnswer() {
  if (!latestRisks.length) return "Aucun chemin d'attaque analysé pour le moment.";
  const top = latestRisks[0];
  return `(réponse simulée à partir des résultats calculés) Le chemin le plus risqué est `
       + `${top.path.join(" → ")} avec un score de ${top.risk_score} (${top.severity}). `
       + top.description;
}

async function sendQuestion(question) {
  const button = document.querySelector("#chat-form button[type=submit]");
  document.getElementById("chat-suggestions").hidden = true;
  addMessage(question, "user");
  const waiting = addMessage("L'agent choisit ses outils et interroge l'API…", "agent thinking");
  button.disabled = true;
  try {
    const reply = await callAgent(question);
    waiting.remove();
    const message = addMessage("", "agent");
    showAgentAnswer(message, reply);
    const log = document.getElementById("chat-log");
    log.scrollTop = message.offsetTop - 8;  // debut de la reponse, pas la fin
  } catch (error) {
    waiting.remove();
    addMessage(`Agent IA indisponible : ${error.message}`, "agent simulated");
    addMessage(simulatedAnswer(), "agent simulated");
  } finally {
    button.disabled = false;
    document.getElementById("chat-input").focus();
  }
}

function toggleChat(open) {
  const panel = document.getElementById("chat-panel");
  panel.hidden = !open;
  if (open) document.getElementById("chat-input").focus();
}

// Pose une question a l'agent depuis n'importe quelle vue (chemins, CVE, graphe).
function askAgent(question) {
  toggleChat(true);
  sendQuestion(question);
}

// Suggestions adaptees a l'analyse affichee.
function renderSuggestions(risks, vulns) {
  const box = document.getElementById("chat-suggestions");
  const exploited = cveRows(vulns).some(r => r.kev);
  const list = [
    risks.length ? `Explique le chemin ${risks[0].path.join(" → ")}` : "Quels services sont exposés ?",
    exploited ? "Quelles failles sont activement exploitées ?" : "Quelles sont les CVE critiques ?",
    "Que dois-je corriger en priorité ?",
    "Qu'est-ce qui a changé depuis l'analyse précédente ?",
  ];
  box.innerHTML = "";
  for (const text of list) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.textContent = text;
    chip.addEventListener("click", () => sendQuestion(text));
    box.append(chip);
  }
}

registerView(({ risks, vulns, graph, summary }) => {
  latestRisks = risks;
  graphNodeIds = (graph.nodes || []).map(n => n.id);
  document.getElementById("chat-context").textContent =
    `Analyse #${summary.id} – ${summary.analysis_date.replace("T", " ")}`;
  renderSuggestions(risks, vulns);
});

// Liens des reponses (chat et resume) : noeud ou chemin -> mise en evidence dans le graphe.
document.addEventListener("click", event => {
  const link = event.target.closest(".node-link, .path-link");
  if (!link) return;
  event.preventDefault();
  // le panneau agrandi cacherait le graphe : on le reduit
  const panel = document.getElementById("chat-panel");
  if (panel.classList.contains("expanded")) {
    panel.classList.remove("expanded");
    document.getElementById("chat-expand").textContent = "Agrandir";
  }
  const ok = link.classList.contains("path-link")
    ? (highlightPath(link.dataset.path.split(",")), true)
    : highlightNode(link.dataset.node);
  if (ok !== false) document.getElementById("graph").scrollIntoView({ behavior: "smooth" });
});

// Mise en place : icone, message d'accueil, ouverture/fermeture/agrandissement.
const toggleButton = document.getElementById("chat-toggle");
toggleButton.style.backgroundImage = `url("${BOT_ICON}")`;
toggleButton.addEventListener("click", () => toggleChat(document.getElementById("chat-panel").hidden));
document.getElementById("chat-close").addEventListener("click", () => toggleChat(false));
document.getElementById("chat-expand").addEventListener("click", event => {
  const expanded = document.getElementById("chat-panel").classList.toggle("expanded");
  event.target.textContent = expanded ? "Réduire" : "Agrandir";
});

const welcome = addMessage("", "agent");
welcome.innerHTML = renderAgentMarkdown(
  "Bonjour ! Je suis l'**agent IA de SentinelPath**. Je ne calcule rien moi-même : "
  + "j'interroge les **outils d'analyse** (vulnérabilités, graphe, chemins, risque) puis je "
  + "vous explique leurs résultats. Chaque réponse indique ses **sources**.\n\n"
  + "Je peux aussi **relancer un scan** de l'infrastructure si vous me le demandez.");

document.getElementById("chat-form").addEventListener("submit", event => {
  event.preventDefault();
  const input = document.getElementById("chat-input");
  const question = input.value.trim();
  if (!question) return;
  input.value = "";
  sendQuestion(question);
});
