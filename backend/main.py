import json
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

from backend.pipeline import ANALYSIS_FILE, COLLECTOR_FILE, run_pipeline

MAX_IMPORT_SIZE = 1_000_000  # 1 Mo : largement suffisant pour un collector_output.json

app = FastAPI(
    title="SentinelPath API",
    description="API de l'agent d'analyse de vulnérabilités et de chemins d'attaque",
    version="0.2.0",
)


def load_json(path: Path):
    """Lit un fichier JSON de résultats, avec des erreurs HTTP claires."""
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"{path.name} introuvable : lancez d'abord une analyse (POST /analyze).",
        )
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail=f"{path.name} est corrompu (JSON invalide).",
        )


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
        return run_pipeline(COLLECTOR_FILE)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        raise HTTPException(
            status_code=422,
            detail=f"collector_output.json a un format inattendu : {e!r}",
        )


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


@app.get("/analysis")
def analysis():
    """Renvoie le résultat complet de la dernière analyse."""
    return load_json(ANALYSIS_FILE)


@app.get("/vulnerabilities")
def vulnerabilities():
    """Renvoie les vulnérabilités (CVE/CVSS) de la dernière analyse."""
    return load_json(ANALYSIS_FILE)["vulnerabilities"]


@app.get("/graph")
def graph():
    """Renvoie le graphe d'attaque (noeuds + arêtes) de la dernière analyse."""
    return load_json(ANALYSIS_FILE)["attack_graph"]


@app.get("/attack-paths")
def attack_paths():
    """Renvoie les chemins d'attaque vers chaque cible d'intérêt."""
    return load_json(ANALYSIS_FILE)["attack_paths"]