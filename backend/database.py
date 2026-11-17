"""
Stockage des analyses dans SQLite (historique).

Une ligne par analyse : quelques chiffres-cles en colonnes (pour lister et
comparer rapidement) + le resultat complet en JSON (pour tout renvoyer tel quel).
sqlite3 fait partie de Python : aucune dependance a installer.
"""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent / "data" / "sentinelpath.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_date   TEXT NOT NULL,
    scan_date       TEXT,
    services_count  INTEGER NOT NULL,
    cve_count       INTEGER NOT NULL,
    critical_count  INTEGER NOT NULL,
    paths_count     INTEGER NOT NULL,
    result_json     TEXT NOT NULL
)
"""


@contextmanager
def get_connection():
    """Ouvre la base, valide les changements (commit) puis ferme la connexion."""
    DB_FILE.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # acces aux colonnes par leur nom
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Cree la table si elle n'existe pas encore."""
    with get_connection() as conn:
        conn.execute(SCHEMA)


def summarize(result):
    """Calcule les chiffres-cles d'un resultat d'analyse (simple comptage)."""
    services = [s for h in result["vulnerabilities"]["hosts"] for s in h["services"]]
    cves = [v for s in services for v in s["vulnerabilities"]]
    return {
        "services_count": len(services),
        "cve_count": len(cves),
        "critical_count": sum(1 for v in cves if v.get("severity") == "CRITICAL"),
        "paths_count": sum(t["path_count"] for t in result["attack_paths"]),
    }


def save_analysis(result):
    """Enregistre une analyse et renvoie son identifiant."""
    summary = summarize(result)
    with get_connection() as conn:
        cursor = conn.execute(
            """INSERT INTO analyses (analysis_date, scan_date, services_count,
                   cve_count, critical_count, paths_count, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                result["analysis_date"],
                result.get("scan_date"),
                summary["services_count"],
                summary["cve_count"],
                summary["critical_count"],
                summary["paths_count"],
                json.dumps(result, ensure_ascii=False),
            ),
        )
        return cursor.lastrowid


def list_analyses():
    """Historique des analyses (sans le JSON complet), de la plus recente a la plus ancienne."""
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT id, analysis_date, scan_date, services_count, cve_count,
                      critical_count, paths_count
               FROM analyses ORDER BY id DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


def get_analysis(analysis_id=None):
    """Renvoie une analyse complete (la plus recente si aucun id), ou None."""
    with get_connection() as conn:
        if analysis_id is None:
            row = conn.execute(
                "SELECT id, result_json FROM analyses ORDER BY id DESC LIMIT 1"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, result_json FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
    if row is None:
        return None
    result = json.loads(row["result_json"])
    result["id"] = row["id"]
    return result