// Tableau des vulnerabilites, filtrable par gravite, trie par CVSS decroissant.

let vulnRows = [];

function renderVulnTable() {
  const filter = document.getElementById("severity-filter").value;
  const rows = vulnRows
    .filter(r => filter === "ALL" || (filter === "KEV" ? r.kev : r.severity === filter))
    .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));

  document.getElementById("vuln-count").textContent = `${rows.length} CVE affichée(s)`;
  document.getElementById("vuln-table").innerHTML = `
    <thead><tr>
      <th>Gravité</th><th>CVSS</th><th>CVE</th><th>Service</th><th>Port</th><th>Description</th>
    </tr></thead>
    <tbody>${rows.map(r => `
      <tr>
        <td><span class="badge ${severityClass(r.severity)}">${esc(r.severity || "N/A")}</span></td>
        <td>${esc(r.cvss ?? "–")}</td>
        <td><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(r.id)}" target="_blank"
               rel="noopener">${esc(r.id)}</a>
            ${r.kev ? `<span class="badge kev" title="Catalogue CISA KEV : exploitée par de vrais attaquants">exploitée</span>` : ""}
            <button type="button" class="ask-btn small" data-cve="${esc(r.id)}"
                    data-target="${esc(r.container || r.service)}" title="Demander à l'agent comment corriger">Corriger ?</button></td>
        <td>${r.container ? `<strong>${esc(r.container)}</strong><br>` : ""}${esc(r.service)} ${esc(r.version || "")}</td>
        <td>${esc(r.port)}${r.exposed === false ? ` <span class="hint">(interne)</span>` : ""}</td>
        <td class="desc">${esc(r.description)}</td>
      </tr>`).join("")}
    </tbody>`;
}

registerView(({ vulns }) => {
  vulnRows = cveRows(vulns);
  renderVulnTable();
});

document.getElementById("severity-filter").addEventListener("change", renderVulnTable);

// "Corriger ?" : une seule ecoute pour tout le tableau (delegation d'evenement)
document.getElementById("vuln-table").addEventListener("click", event => {
  const button = event.target.closest(".ask-btn[data-cve]");
  if (!button) return;
  askAgent(`Comment corriger ${button.dataset.cve} sur ${button.dataset.target} ? Indique la `
         + `version corrigée ou les liens de correctif disponibles, et si cette faille est `
         + `exploitée dans la nature.`);
});