// Outils communs a toutes les vues du tableau de bord.
// Le frontend est servi par FastAPI : les appels fetch() vont au meme serveur.

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const views = [];      // fonctions d'affichage enregistrees par les autres fichiers
let currentId = null;  // analyse affichee (null = la plus recente)

function registerView(renderFn) {
  views.push(renderFn);
}

// Echappe le texte avant de l'inserer dans la page : les descriptions de CVE
// viennent d'une source externe (NVD), on ne les interprete jamais comme du HTML.
function esc(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}

function severityClass(severity) {
  return SEVERITIES.includes(severity) ? severity.toLowerCase() : "unknown";
}

async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof body.detail === "string" ? body.detail : `Erreur HTTP ${response.status}`;
    throw new Error(detail);
  }
  return body;
}

function withId(path) {
  return currentId ? `${path}?analysis_id=${currentId}` : path;
}

function setStatus(message, isError = false) {
  const status = document.getElementById("status");
  status.textContent = message;
  status.className = isError ? "error" : "";
}

// Une ligne par CVE, avec le service concerne (utilise par le dashboard et le tableau).
function cveRows(vulnReport) {
  const rows = [];
  for (const host of vulnReport.hosts || []) {
    for (const svc of host.services || []) {
      for (const cve of svc.vulnerabilities || []) {
        rows.push({ service: svc.name, port: svc.port, version: svc.version, ...cve });
      }
    }
  }
  return rows;
}

async function loadHistory() {
  const history = await api("/analyses");
  const select = document.getElementById("analysis-select");
  select.innerHTML = history
    .map(a => `<option value="${a.id}">#${a.id} – ${esc(a.analysis_date.replace("T", " "))}</option>`)
    .join("");
  if (history.length && !history.some(a => a.id === currentId)) currentId = history[0].id;
  select.value = currentId;
  return history;
}

async function refresh() {
  setStatus("Chargement…");
  try {
    const history = await loadHistory();
    if (!history.length) {
      setStatus("Aucune analyse enregistrée : cliquez sur « Lancer une analyse ».");
      return;
    }
    const [vulns, graph, risks] = await Promise.all([
      api(withId("/vulnerabilities")),
      api(withId("/graph")),
      api(withId("/risk-analysis")).catch(() => []),  // analyses anciennes : pas de risque
    ]);
    const summary = history.find(a => a.id === currentId);
    const data = { vulns, graph, risks, summary };
    for (const render of views) render(data);
    setStatus("");
  } catch (error) {
    setStatus(error.message, true);
  }
}

document.getElementById("analysis-select").addEventListener("change", event => {
  currentId = Number(event.target.value);
  refresh();
});

document.getElementById("analyze-btn").addEventListener("click", async event => {
  const button = event.target;
  button.disabled = true;
  setStatus("Analyse en cours (interrogation de NVD, jusqu'à une minute)…");
  try {
    const result = await api("/analyze", { method: "POST" });
    currentId = result.id;
    await refresh();
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
});