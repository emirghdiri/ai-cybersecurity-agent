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