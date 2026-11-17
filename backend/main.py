import json
from pathlib import Path

from fastapi import FastAPI, HTTPException

# Racine du dépôt (le dossier qui contient backend/, vulnerability/, ...)
BASE_DIR = Path(__file__).resolve().parent.parent
VULN_REPORT = BASE_DIR / "vulnerability" / "vulnerability_report.json"

app = FastAPI(
    title="SentinelPath API",
    description="API de l'agent d'analyse de vulnérabilités et de chemins d'attaque",
    version="0.1.0",
)


def load_json(path: Path):
    """Lit un fichier JSON de résultats, avec des erreurs HTTP claires."""
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"{path.name} introuvable : lancez d'abord l'analyse "
                   "(python vulnerability/analyze_infra.py).",
        )
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail=f"{path.name} est corrompu (JSON invalide).",
        )


@app.get("/health")
def health():
    """Vérifie que l'API tourne."""
    return {"status": "ok", "service": "sentinelpath-api"}


@app.get("/vulnerabilities")
def vulnerabilities():
    """Renvoie le rapport de vulnérabilités produit par analyze_infra.py."""
    return load_json(VULN_REPORT)