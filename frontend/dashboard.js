// Vue d'ensemble : chiffres-cles + repartition des CVE par gravite.

function renderDashboard({ vulns, risks, summary }) {
  const rows = cveRows(vulns);
  const services = (vulns.hosts || []).flatMap(h => h.services || []);
  const maxRisk = risks.length ? Math.max(...risks.map(r => r.risk_score)) : null;

  const cards = [
    { label: "Services détectés", value: services.length },
    { label: "CVE trouvées", value: rows.length },
    { label: "CVE critiques", value: rows.filter(r => r.severity === "CRITICAL").length, cls: "critical" },
    { label: "Chemins d'attaque", value: risks.length },
    { label: "Risque maximal", value: maxRisk ?? "–", cls: maxRisk >= 9 ? "critical" : "" },
  ];
  document.getElementById("cards").innerHTML = cards
    .map(c => `<div class="card ${c.cls || ""}"><span class="value">${esc(c.value)}</span>
               <span class="label">${esc(c.label)}</span></div>`)
    .join("");

  const total = rows.length || 1;
  document.getElementById("severity-bars").innerHTML = SEVERITIES.map(sev => {
    const count = rows.filter(r => r.severity === sev).length;
    const width = Math.round((count / total) * 100);
    return `<div class="bar-row">
              <span class="badge ${severityClass(sev)}">${sev}</span>
              <div class="bar"><div class="fill ${severityClass(sev)}" style="width:${width}%"></div></div>
              <span class="bar-count">${count}</span>
            </div>`;
  }).join("") + `<p class="hint">Analyse #${esc(summary.id)} du ${esc(summary.analysis_date.replace("T", " "))}
                 (scan du ${esc((summary.scan_date || "?").replace("T", " "))})</p>`;
}

registerView(renderDashboard);

// Resume redige par l'agent IA, a la demande (pour ne pas consommer le quota Groq),
// garde en memoire par analyse pour ne pas le regenerer a chaque rafraichissement.
const SUMMARY_QUESTION =
  "Fais un résumé exécutif de cette analyse pour un responsable sécurité, en 5 points courts "
  + "maximum : situation générale (services exposés, nombre de CVE), chemin d'attaque le plus "
  + "dangereux, failles activement exploitées à corriger en priorité, et la première action "
  + "recommandée. Pas de tableau.";
const summaries = new Map();

function renderSummaryBox(analysisId) {
  const box = document.getElementById("agent-summary");
  const cached = summaries.get(analysisId);
  box.innerHTML = `
    <div class="agent-summary-head">
      <span class="agent-badge">Agent IA</span>
      <strong>Résumé de l'analyse #${esc(analysisId)}</strong>
      <button type="button" id="summary-btn">${cached ? "Régénérer" : "Générer le résumé"}</button>
    </div>
    <div id="summary-body" class="hint">${cached ? "" :
      "L'agent lit les résultats calculés (vulnérabilités, chemins, risque) et les résume."}</div>`;
  if (cached) showAgentAnswer(document.getElementById("summary-body"), cached);
  document.getElementById("summary-btn").addEventListener("click", async () => {
    const button = document.getElementById("summary-btn");
    const body = document.getElementById("summary-body");
    button.disabled = true;
    body.className = "thinking";
    body.textContent = "L'agent interroge les outils et rédige le résumé…";
    try {
      const reply = await callAgent(SUMMARY_QUESTION);
      summaries.set(analysisId, reply);
      body.className = "";
      showAgentAnswer(body, reply);
      button.textContent = "Régénérer";
    } catch (error) {
      body.className = "hint error";
      body.textContent = `Agent IA indisponible : ${error.message}`;
    } finally {
      button.disabled = false;
    }
  });
}

registerView(({ summary }) => renderSummaryBox(summary.id));