import json
import os
import threading
import time
from pathlib import Path

from html import escape
from urllib.parse import quote

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import auth
from backend.database import get_analysis, init_db, list_analyses, save_analysis
from backend.live_collector import (
    CollectorConfigError,
    LiveCollectorError,
    load_config,
    run_live_collection,
)
from backend.pipeline import COLLECTOR_FILE, run_pipeline

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
MAX_IMPORT_SIZE = 1_000_000  # 1 Mo : largement suffisant pour un collector_output.json

app = FastAPI(
    title="SentinelPath API",
    description="API de l'agent d'analyse de vulnérabilités et de chemins d'attaque",
    version="0.5.0",
)

init_db()  # cree la table SQLite au demarrage si elle n'existe pas


# --------------------------------------------------------------------------- #
# Authentification (voir backend/auth.py) et en-tetes de securite
# --------------------------------------------------------------------------- #
PUBLIC_PATHS = {"/login", "/health"}


def is_anonymous_internet_request(request):
    """
    Sans mot de passe (SENTINELPATH_AUTH=disabled), seuls deux cas sont acceptes :
      - acces direct depuis ce PC (http://127.0.0.1:8000) : pas d'en-tete de proxy ;
      - acces via "tailscale serve" (HTTPS prive) : Tailscale ajoute l'identite du membre
        du reseau (Tailscale-User-Login).
    Une requete relayee SANS identite vient d'internet (ex. Tailscale Funnel) : refusee.
    """
    forwarded = "x-forwarded-for" in request.headers
    return forwarded and not request.headers.get("tailscale-user-login")


def wants_html(request):
    return request.method == "GET" and "text/html" in request.headers.get("accept", "")


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if auth.auth_disabled() and is_anonymous_internet_request(request):
        return JSONResponse(
            {"detail": "Accès depuis internet refusé : SentinelPath fonctionne sans mot de passe, "
                       "il n'est accessible que depuis ce PC ou le réseau Tailscale."},
            status_code=403)
    if not auth.auth_disabled() and path not in PUBLIC_PATHS:
        if not auth.configured_hash():
            message = ("Authentification non configurée : définissez SENTINELPATH_PASSWORD_HASH "
                       "(python -m backend.auth). Accès refusé par sécurité.")
            return JSONResponse({"detail": message}, status_code=503)
        if not (auth.read_session(request.cookies.get(auth.SESSION_COOKIE, ""))
                or auth.is_agent_request(request.headers.get("authorization"))):
            if wants_html(request):
                return RedirectResponse(f"/login?next={quote(path)}", status_code=303)
            return JSONResponse({"detail": "Authentification requise."}, status_code=401)

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


def safe_next(target):
    """Redirection apres connexion : chemin interne uniquement (pas de //site-externe)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/app/"


LOGIN_PAGE = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelPath – Connexion</title>
<style>
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #050d1a;
         font-family: "Segoe UI", Arial, sans-serif; color: #d9e8ff; }}
  form {{ width: min(360px, calc(100vw - 32px)); padding: 28px; background: #0b1a2e;
          border: 1px solid #29b6f6; border-radius: 14px; box-shadow: 0 0 30px rgba(41,182,246,.3); }}
  h1 {{ margin: 0 0 4px; color: #fff; }} h1 span {{ color: #29b6f6; }}
  p.sub {{ margin: 0 0 20px; color: #7f9bb8; font-size: 14px; }}
  label {{ display: block; margin: 12px 0 4px; font-size: 14px; }}
  input {{ width: 100%; box-sizing: border-box; padding: 9px; border: 1px solid #15406b;
           border-radius: 6px; background: #08162a; color: #d9e8ff; font-size: 15px; }}
  button {{ width: 100%; margin-top: 20px; padding: 10px; background: transparent; color: #29b6f6;
            border: 1px solid #29b6f6; border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer; }}
  button:hover {{ background: rgba(41,182,246,.12); }}
  .error {{ margin-top: 14px; color: #ff8a80; font-size: 14px; }}
</style></head><body>
<form method="post" action="/login">
  <h1>Sentinel<span>Path</span></h1>
  <p class="sub">Analyse de vulnérabilités et de chemins d'attaque</p>
  <input type="hidden" name="next" value="{next}">
  <label for="username">Identifiant</label>
  <input id="username" name="username" autocomplete="username" required autofocus>
  <label for="password">Mot de passe</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Se connecter</button>
  {error}
</form></body></html>"""


def login_page(next_path="/app/", error=None, status_code=200):
    html = LOGIN_PAGE.format(
        next=escape(safe_next(next_path)),
        error=f'<p class="error">{escape(error)}</p>' if error else "",
    )
    return HTMLResponse(html, status_code=status_code)


@app.get("/login", include_in_schema=False)
def login_form(next: str = "/app/"):
    return login_page(next)


@app.post("/login", include_in_schema=False)
def login(username: str = Form(...), password: str = Form(...), next: str = Form("/app/")):
    if auth.auth_disabled():
        return RedirectResponse(safe_next(next), status_code=303)
    ok, error = auth.check_credentials(username, password)
    if not ok:
        return login_page(next, error, status_code=401)
    response = RedirectResponse(safe_next(next), status_code=303)
    response.set_cookie(auth.SESSION_COOKIE, auth.create_session(username),
                        max_age=auth.SESSION_SECONDS, httponly=True, secure=True,
                        samesite="lax", path="/")
    return response


@app.post("/logout", include_in_schema=False)
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return response


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


# Etat de la collecte en cours, lu par le frontend (GET /collect-status) pour afficher
# la progression, que la collecte vienne du bouton ou de l'agent IA (launch_analysis).
# Une seule collecte a la fois : deux scans simultanes solliciteraient deux fois les VMs.
COLLECT_LOCK = threading.Lock()
COLLECT_STATE = {"running": False, "step": None, "started": None}
STEP_LABELS = {
    "[1/4]": "scan Nmap depuis Kali (étape 1/5)",
    "[2/4]": "inventaire sur Ubuntu (étape 2/5)",
    "[3/4]": "récupération de l'inventaire (étape 3/5)",
    "[4/4]": "fusion inventaire + scan Nmap (étape 4/5)",
}


def set_collect_step(message):
    COLLECT_STATE["step"] = STEP_LABELS.get(message[:5], message)


@app.get("/collect-status")
def collect_status():
    """Collecte live en cours ? (etape et duree, pour afficher la progression)."""
    started = COLLECT_STATE["started"]
    return {
        "running": COLLECT_STATE["running"],
        "step": COLLECT_STATE["step"],
        "elapsed_seconds": round(time.monotonic() - started) if started else None,
    }


@app.post("/collect-and-analyze")
def collect_and_analyze():
    """
    Collecte live par SSH (scan Nmap depuis Kali + inventaire et fusion sur Ubuntu),
    enregistre collector_output.json comme POST /import, puis lance l'analyse complète.
    Peut prendre plusieurs minutes (scan de tous les ports avec détection de versions).
    """
    try:
        config = load_config()
    except CollectorConfigError as e:
        raise HTTPException(status_code=503, detail=f"Collecte live non configurée : {e}")

    if not COLLECT_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail=f"Une collecte est déjà en cours ({COLLECT_STATE['step'] or 'démarrage'}) : "
                   "attendez qu'elle se termine.",
        )
    COLLECT_STATE.update(running=True, step="démarrage", started=time.monotonic())
    try:
        return _collect_and_analyze(config)
    finally:
        COLLECT_STATE.update(running=False, step=None, started=None)
        COLLECT_LOCK.release()


def _collect_and_analyze(config):
    try:
        data, steps = run_live_collection(config, log=set_collect_step)
    except LiveCollectorError as e:
        raise HTTPException(
            status_code=504 if e.timeout else 502,
            detail=f"Échec de la collecte à l'étape « {e.step} » : {e.message}",
        )

    errors = validate_collector(data)
    if errors:
        raise HTTPException(
            status_code=502,
            detail="La collecte a produit un collector_output.json invalide : " + "; ".join(errors),
        )

    COLLECTOR_FILE.parent.mkdir(exist_ok=True)
    with open(COLLECTOR_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    COLLECT_STATE["step"] = "analyse des vulnérabilités et des chemins d'attaque (étape 5/5)"
    try:
        result = run_pipeline(COLLECTOR_FILE)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=422, detail=f"Analyse impossible : format inattendu ({e!r}).")
    analysis_id = save_analysis(result)

    return {
        "analysis_id": analysis_id,
        "scan_date": data.get("scan_date"),
        "services": sum(len(h["services"]) for h in data["hosts"]),
        "exposed_services": sum(
            1 for h in data["hosts"] for s in h["services"] if s.get("exposed_externally")
        ),
        "relations": len(data["relations"]),
        "steps": steps,
    }

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
class NoCacheStaticFiles(StaticFiles):
    """
    Fichiers du frontend avec "Cache-Control: no-cache" : le navigateur revalide
    chaque fichier (requete conditionnelle, reponse 304 si inchange) au lieu de
    garder une ancienne version de app.js apres une mise a jour du site.
    """

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


app.mount("/app", NoCacheStaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


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

    trace = []  # outils appeles par l'agent : affiches comme "sources" dans le frontend
    try:
        answer = agent.ask(Groq(api_key=api_key), history, question, trace=trace)
    except RateLimitError:
        raise HTTPException(status_code=429, detail="Limite de requêtes Groq atteinte : réessayez dans une minute.")
    except APIConnectionError:
        raise HTTPException(status_code=503, detail="Impossible de joindre l'API Groq (connexion Internet ?).")
    except APIStatusError as e:
        raise HTTPException(status_code=502, detail=f"Erreur de l'API Groq (HTTP {e.status_code}).")
    return {"answer": answer, "tools": trace}