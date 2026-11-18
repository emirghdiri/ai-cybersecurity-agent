// Agent IA : bulle flottante en bas a droite qui ouvre un panneau de discussion.
// Les questions partent vers POST /chat -> agent/sentinelpath_agent.py ;
// l'agent ne calcule rien : il interroge l'API puis explique les resultats.
// Si l'agent est indisponible, on affiche la raison et une reponse SIMULEE
// construite uniquement a partir des resultats deja calcules.

const chatHistory = [];  // questions/reponses precedentes, renvoyees a l'agent
let latestRisks = [];
const SUGGESTIONS = [
  "Quel est le chemin d'attaque le plus dangereux ?",
  "Quelles sont les CVE critiques ?",
  "Que dois-je corriger en priorité ?",
];

// Icone de la bulle : petit robot dessine en SVG.
const BOT_ICON = "data:image/svg+xml;utf8," + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" fill="none" stroke="#29b6f6"
        stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">
     <rect x="8" y="14" width="32" height="24" rx="7"/><path d="M24 8v6M20 46l4-8 4 8"/>
     <circle cx="24" cy="6" r="2.5"/><circle cx="18" cy="26" r="2.5" fill="#29b6f6"/>
     <circle cx="30" cy="26" r="2.5" fill="#29b6f6"/><path d="M19 32h10M4 24v6M44 24v6"/></svg>`);

registerView(({ risks, summary }) => {
  latestRisks = risks;
  document.getElementById("chat-context").textContent =
    `Analyse #${summary.id} – ${summary.analysis_date.replace("T", " ")}`;
});

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
  const button = document.querySelector("#chat-form button");
  document.getElementById("chat-suggestions").hidden = true;
  addMessage(question, "user");
  const waiting = addMessage("Réflexion en cours (interrogation de l'API)…", "agent simulated");
  button.disabled = true;
  try {
    const reply = await api("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, analysis_id: currentId, history: chatHistory.slice(-12) }),
    });
    waiting.remove();
    addMessage(reply.answer, "agent");
    chatHistory.push({ role: "user", content: question }, { role: "assistant", content: reply.answer });
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

// Mise en place : icone, message d'accueil, suggestions, ouverture/fermeture.
const toggleButton = document.getElementById("chat-toggle");
toggleButton.style.backgroundImage = `url("${BOT_ICON}")`;
toggleButton.addEventListener("click", () => toggleChat(document.getElementById("chat-panel").hidden));
document.getElementById("chat-close").addEventListener("click", () => toggleChat(false));

addMessage("Bonjour ! Je suis l'agent IA de SentinelPath. Posez-moi une question sur l'analyse "
         + "affichée : j'interroge les résultats calculés et je vous les explique.", "agent");

const suggestions = document.getElementById("chat-suggestions");
for (const text of SUGGESTIONS) {
  const chip = document.createElement("button");
  chip.type = "button";
  chip.textContent = text;
  chip.addEventListener("click", () => sendQuestion(text));
  suggestions.append(chip);
}

document.getElementById("chat-form").addEventListener("submit", event => {
  event.preventDefault();
  const input = document.getElementById("chat-input");
  const question = input.value.trim();
  if (!question) return;
  input.value = "";
  sendQuestion(question);
});