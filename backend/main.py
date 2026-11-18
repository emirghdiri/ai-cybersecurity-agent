import json
import os
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.database import get_analysis, init_db, list_analyses, save_analysis
from backend.pipeline import COLLECTOR_FILE, run_pipeline

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
MAX_IMPORT_SIZE = 1_000_000  # 1 Mo : largement suffisant pour un collector_output.json

app = FastAPI(
    title="SentinelPath API",
    description="API de l'agent d'analyse de vulnérabilités et de chemins d'attaque",
    version="0.5.0",
)

init_db()  # cree la table SQLite au demarrage si elle n'existe pas


def load_analysis(analysis_id: int | None = None):
    """Lit une analyse dans SQLite (la plus récente par défaut), avec des erreurs claires."""
    result = get_analysis(analysis_id)
    if result is None:
        if analysis_id is None:
            detail = "Aucune analyse enregistrée : lancez d'abord POST /analyze."
        else:
            detail = f"Aucune analyse avec l'id {analysis_id} (voir GET /analyses)."
        raise HTTPException(status_code=404, detail=detail)
    return result


def validate_collector(data):
    """Vérifie la structure minimale attendue par la chaîne d'analyse."""
    if not isinstance(data, dict):
        return ["la racine du fichier doit être un objet JSON { ... }"]
    errors = []
    hosts = data.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        errors.append("'hosts' doit être une liste non vide")
    else:
        for i, host in enumerate(hosts):
            services = host.get("services") if isinstance(host, dict) else None
            if not isinstance(services, list):
                errors.append(f"hosts[{i}].services doit être une liste")
                continue
            for j, svc in enumerate(services):
                if not isinstance(svc, dict) or "name" not in svc or "port" not in svc:
                    errors.append(f"hosts[{i}].services[{j}] doit contenir 'name' et 'port'")
    relations = data.get("relations")
    if not isinstance(relations, list):
        errors.append("'relations' doit être une liste")
    else:
        for k, rel in enumerate(relations):
            if not isinstance(rel, dict) or "source" not in rel or "target" not in rel:
                errors.append(f"relations[{k}] doit contenir 'source' et 'target'")
    return errors[:10]  # inutile de renvoyer des centaines d'erreurs


@app.get("/health")
def health():
    """Vérifie que l'API tourne."""
    return {"status": "ok", "service": "sentinelpath-api"}


@app.post("/analyze")
def analyze():
    """Lance toute la chaîne : vulnérabilités -> graphe -> chemins d'attaque."""
    if not COLLECTOR_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="Aucune donnée de collecte : placez collector_output.json "
                   "dans backend/data/ ou importez-le (POST /import).",
        )
    try:
        result = run_pipeline(COLLECTOR_FILE)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        raise HTTPException(
            status_code=422,
            detail=f"collector_output.json a un format inattendu : {e!r}",
        )
    result["id"] = save_analysis(result)
    return result

@app.post("/import")
async def import_collector(file: UploadFile = File(...)):
    """Plan B : importe manuellement un collector_output.json (si le scan réseau échoue)."""
    content = await file.read(MAX_IMPORT_SIZE + 1)
    if len(content) > MAX_IMPORT_SIZE:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux (max 1 Mo).")
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail="Le fichier n'est pas un JSON valide.")

    errors = validate_collector(data)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Structure de collector_output.json invalide.", "errors": errors},
        )

    COLLECTOR_FILE.parent.mkdir(exist_ok=True)
    with open(COLLECTOR_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return {
        "status": "imported",
        "filename": file.filename,
        "hosts": len(data["hosts"]),
        "services": sum(len(h["services"]) for h in data["hosts"]),
        "relations": len(data["relations"]),
        "next_step": "Lancez POST /analyze pour analyser ces données.",
    }


@app.get("/analyses")
def analyses():
    """Historique de toutes les analyses (chiffres-clés seulement)."""
    return list_analyses()


@app.get("/analysis")
def analysis(analysis_id: int | None = None):
    """Résultat complet d'une analyse (la plus récente par défaut)."""
    return load_analysis(analysis_id)


@app.get("/vulnerabilities")
def vulnerabilities(analysis_id: int | None = None):
    """Vulnérabilités (CVE/CVSS) d'une analyse (la plus récente par défaut)."""
    return load_analysis(analysis_id)["vulnerabilities"]


@app.get("/graph")
def graph(analysis_id: int | None = None):
    """Graphe d'attaque (noeuds + arêtes) d'une analyse (la plus récente par défaut)."""
    return load_analysis(analysis_id)["attack_graph"]


@app.get("/attack-paths")
def attack_paths(analysis_id: int | None = None):
    """Chemins d'attaque d'une analyse (la plus récente par défaut)."""
    return load_analysis(analysis_id)["attack_paths"]


@app.get("/risk-analysis")
def risk_analysis(analysis_id: int | None = None):
    """Chemins d'attaque classés par score de risque (le plus critique en premier)."""
    result = load_analysis(analysis_id)
    if "risk_analysis" not in result:
        raise HTTPException(
            status_code=404,
            detail=f"L'analyse {result['id']} date d'avant le Risk Analyzer : "
                   "relancez POST /analyze.",
        )
    return result["risk_analysis"]


# Tableau de bord web : les fichiers de frontend/ sont servis par la meme API,
# donc pas de probleme CORS et une seule commande a lancer pour la demo.
app.mount("/app", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


@app.get("/", include_in_schema=False)
def home():
    """Redirige la racine vers le tableau de bord."""
    return RedirectResponse(url="/app/")

# --------------------------------------------------------------------------- #
# Agent IA (module d'Amir : agent/sentinelpath_agent.py)
# --------------------------------------------------------------------------- #
class ChatTurn(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(max_length=8000)


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    analysis_id: int | None = None
    history: list[ChatTurn] = Field(default_factory=list, max_length=12)


@app.post("/chat")
def chat(request: ChatRequest):
    """Pose une question a l'agent IA, qui interroge lui-meme cette API puis explique."""
    try:
        import sentinelpath_agent as agent  # dossier agent/ deja ajoute par pipeline.py
        from groq import APIConnectionError, APIStatusError, Groq, RateLimitError
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Agent IA indisponible : module manquant ({e.name}). "
                   "Installez-le : python -m pip install groq",
        )
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Agent IA indisponible : la variable d'environnement GROQ_API_KEY n'est pas définie.",
        )

    question = request.question
    if request.analysis_id:
        question = f"(L'utilisateur consulte l'analyse #{request.analysis_id}.) {question}"
    history = [turn.model_dump() for turn in request.history]

    try:
        answer = agent.ask(Groq(api_key=api_key), history, question)
    except RateLimitError:
        raise HTTPException(status_code=429, detail="Limite de requêtes Groq atteinte : réessayez dans une minute.")
    except APIConnectionError:
        raise HTTPException(status_code=503, detail="Impossible de joindre l'API Groq (connexion Internet ?).")
    except APIStatusError as e:
        raise HTTPException(status_code=502, detail=f"Erreur de l'API Groq (HTTP {e.status_code}).")
    return {"answer": answer}