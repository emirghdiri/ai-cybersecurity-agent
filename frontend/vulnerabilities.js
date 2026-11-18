// Tableau des vulnerabilites, filtrable par gravite, trie par CVSS decroissant.

let vulnRows = [];

function renderVulnTable() {
  const filter = document.getElementById("severity-filter").value;
  const rows = vulnRows
    .filter(r => filter === "ALL" || r.severity === filter)
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
               rel="noopener">${esc(r.id)}</a></td>
        <td>${esc(r.service)} ${esc(r.version || "")}</td>
        <td>${esc(r.port)}</td>
        <td class="desc">${esc(r.description)}</td>
      </tr>`).join("")}
    </tbody>`;
}

registerView(({ vulns }) => {
  vulnRows = cveRows(vulns);
  renderVulnTable();
});

document.getElementById("severity-filter").addEventListener("change", renderVulnTable);