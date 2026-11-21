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
        ${(r.exploited_cves || []).length ? `<span class="badge kev" title="Le chemin traverse des CVE du catalogue CISA KEV (+${esc(r.kev_bonus)} au score)">${new Set(r.exploited_cves.map(e => e.id)).size} CVE exploitée(s)</span>` : ""}
      </div>
      <div class="path-nodes">${r.path.map(n => `<span class="node">${esc(n)}</span>`).join(" → ")}</div>
      <p>${esc(r.description)}</p>
      <button type="button" class="ask-btn" data-ask="${i}">Expliquer ce chemin avec l'agent</button>
    </div>`).join("");

  list.querySelectorAll(".ask-btn").forEach(button => {
    button.addEventListener("click", event => {
      event.stopPropagation();  // ne pas declencher la mise en evidence de la carte
      const r = risks[Number(button.dataset.ask)];
      askAgent(`Explique-moi le chemin d'attaque ${r.path.join(" → ")} (score de risque `
             + `${r.risk_score}) : comment l'attaquant progresse étape par étape, quelles failles `
             + `il exploite, et comment bloquer ce chemin en priorité.`);
    });
  });

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