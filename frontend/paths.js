// Chemins d'attaque classes par score de risque (fournis tries par le backend).

registerView(({ risks }) => {
  const list = document.getElementById("path-list");
  if (!risks.length) {
    list.innerHTML = `<p class="hint">Pas de score de risque pour cette analyse
                      (relancez une analyse pour l'obtenir).</p>`;
    return;
  }
  list.innerHTML = risks.map((r, i) => `
    <div class="path-card ${severityClass(r.severity)}" data-index="${i}">
      <div class="path-head">
        <span class="badge ${severityClass(r.severity)}">${esc(r.severity)}</span>
        <strong>Risque ${esc(r.risk_score)}</strong>
        <span class="hint">cible : ${esc(r.target)} (${esc(r.reason)}) – CVE principale : ${esc(r.worst_cve || "aucune")}</span>
      </div>
      <div class="path-nodes">${r.path.map(n => `<span class="node">${esc(n)}</span>`).join(" → ")}</div>
      <p>${esc(r.description)}</p>
    </div>`).join("");

  list.querySelectorAll(".path-card").forEach(card => {
    card.addEventListener("click", () => {
      const risk = risks[Number(card.dataset.index)];
      list.querySelectorAll(".path-card").forEach(c => c.classList.remove("selected"));
      card.classList.add("selected");
      if (typeof highlightPath === "function") {
        highlightPath(risk.path);
        document.getElementById("graph").scrollIntoView({ behavior: "smooth" });
      }
    });
  });
});