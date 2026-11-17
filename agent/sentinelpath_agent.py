"""
SentinelPath - Agent IA (ligne de commande).

Principe : "les outils calculent, l'agent IA explique".
L'agent ne calcule et n'invente rien : il appelle l'API FastAPI de SentinelPath
(seule source de verite) via de vraies requetes HTTP, puis reformule les
resultats en francais.

Prerequis :
  - le backend tourne :  python -m uvicorn backend.main:app --reload
  - au moins une analyse existe (POST /analyze)
  - la variable d'environnement GROQ_API_KEY est definie

Variables d'environnement optionnelles :
  - SENTINELPATH_API_URL  (defaut : http://127.0.0.1:8000)
  - GROQ_MODEL            (defaut : openai/gpt-oss-20b)

Usage :
  python agent/sentinelpath_agent.py
  python agent/sentinelpath_agent.py --debug     # affiche aussi les arguments des outils
"""
import argparse
import inspect
import json
import os
import sys
from collections import Counter

import requests
from groq import Groq, APIConnectionError, APIStatusError, RateLimitError

API_URL = os.environ.get("SENTINELPATH_API_URL", "http://127.0.0.1:8000").rstrip("/")
MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")

HTTP_TIMEOUT = 30           # secondes
MAX_TOOL_ROUNDS = 6         # appels d'outils max par question (evite les boucles infinies)
MAX_TOOL_OUTPUT = 12_000    # caracteres max renvoyes au modele par outil (limite de tokens)
MAX_HISTORY_TURNS = 6       # questions/reponses gardees en memoire de conversation
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

DEBUG = False


# =========================================================================== #
# Acces au backend (seule source de verite)
# =========================================================================== #
class BackendError(Exception):
    """Erreur lisible a renvoyer au modele (backend arrete, analyse absente...)."""


def api_get(route, analysis_id=None):
    """GET sur le backend, avec des erreurs claires plutot qu'une exception brute."""
    params = {"analysis_id": analysis_id} if analysis_id is not None else None
    try:
        r = requests.get(f"{API_URL}{route}", params=params, timeout=HTTP_TIMEOUT)
    except requests.ConnectionError:
        raise BackendError(
            f"Backend injoignable sur {API_URL}. "
            "Lancez-le avec : python -m uvicorn backend.main:app --reload"
        )
    except requests.Timeout:
        raise BackendError(f"Le backend n'a pas repondu en {HTTP_TIMEOUT} s ({route}).")

    if r.status_code != 200:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise BackendError(f"{route} a repondu HTTP {r.status_code} : {detail}")
    return r.json()


# =========================================================================== #
# Outils exposes au LLM
# Chaque outil appelle UNE route du backend. Les seuls traitements faits ici
# sont deterministes (comptage, tri, filtrage) pour reduire la taille des
# donnees envoyees au modele : aucune donnee n'est inventee.
# =========================================================================== #
def list_analyses():
    """GET /analyses : historique des analyses avec leurs chiffres-cles."""
    return api_get("/analyses")


def get_vulnerabilities(analysis_id=None, severity=None, service=None, limit=3):
    """GET /vulnerabilities, resume : totaux par severite + CVE les plus graves par service."""
    data = api_get("/vulnerabilities", analysis_id)

    severity = severity.upper() if isinstance(severity, str) and severity.strip() else None
    service = service.lower().strip() if isinstance(service, str) and service.strip() else None
    try:
        limit = max(1, min(int(limit), 15))
    except (TypeError, ValueError):
        limit = 3

    total = Counter()
    services_out = []
    for host in data.get("hosts", []):
        for svc in host.get("services", []):
            vulns = svc.get("vulnerabilities", [])
            counts = Counter(v.get("severity") or "N/A" for v in vulns)
            total.update(counts)

            label = f"{svc.get('name', '')} {svc.get('port', '')}".lower()
            if service and service not in label:
                continue

            selected = [v for v in vulns if not severity or v.get("severity") == severity]
            selected.sort(key=lambda v: v.get("cvss") or 0, reverse=True)

            services_out.append({
                "host": host.get("hostname"),
                "port": svc.get("port"),
                "service": svc.get("name"),
                "version": svc.get("version"),
                "status": svc.get("status"),
                "cve_count": len(vulns),
                "by_severity": {s: counts[s] for s in SEVERITIES if counts[s]},
                "matching_cves": len(selected),
                "top_cves": [
                    {
                        "id": v.get("id"),
                        "cvss": v.get("cvss"),
                        "severity": v.get("severity"),
                        "description": (v.get("description") or "")[:220],
                        "patch_refs": (v.get("patch_refs") or [])[:2],
                    }
                    for v in selected[:limit]
                ],
            })

    return {
        "scan_date": data.get("scan_date"),
        "total_cves": sum(total.values()),
        "total_by_severity": {s: total[s] for s in SEVERITIES if total[s]},
        "filters": {"severity": severity, "service": service, "top_cves_per_service": limit},
        "services": services_out,
    }


def get_attack_graph(analysis_id=None):
    """GET /graph : noeuds (services, exposition) et aretes (relations reseau)."""
    return api_get("/graph", analysis_id)


def get_attack_paths(analysis_id=None):
    """GET /attack-paths : chemins d'attaque depuis l'attaquant vers chaque cible."""
    return api_get("/attack-paths", analysis_id)


def get_risk_analysis(analysis_id=None, limit=10):
    """GET /risk-analysis : chemins classes par score de risque (le plus critique d'abord)."""
    data = api_get("/risk-analysis", analysis_id)
    try:
        limit = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        limit = 10
    return {"total_paths": len(data), "paths_by_risk": data[:limit]}


AVAILABLE_FUNCTIONS = {
    "list_analyses": list_analyses,
    "get_vulnerabilities": get_vulnerabilities,
    "get_attack_graph": get_attack_graph,
    "get_attack_paths": get_attack_paths,
    "get_risk_analysis": get_risk_analysis,
}

ANALYSIS_ID_PARAM = {
    "type": "integer",
    "description": "Identifiant d'une analyse precise (voir list_analyses). "
                   "Ne pas renseigner pour utiliser la plus recente.",
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_analyses",
            "description": (
                "Historique de toutes les analyses enregistrees, de la plus recente a la plus "
                "ancienne, avec leurs chiffres-cles : id, date, nombre de services, nombre total "
                "de CVE, nombre de CVE critiques, nombre de chemins d'attaque, score de risque "
                "maximal. A utiliser pour : 'combien d'analyses', 'compare avec l'analyse "
                "precedente', 'evolution du risque', ou pour trouver un analysis_id."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_vulnerabilities",
            "description": (
                "Vulnerabilites connues (CVE de la base NVD, score CVSS, severite) de chaque "
                "service detecte : totaux par severite (CRITICAL, HIGH, MEDIUM, LOW), et pour "
                "chaque service les CVE les plus graves avec description et liens de correctif. "
                "A utiliser pour : 'combien de vulnerabilites critiques', 'quelles failles sur "
                "apache', 'quel service est le plus vulnerable', 'quelle CVE corriger en premier'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "analysis_id": ANALYSIS_ID_PARAM,
                    "severity": {
                        "type": "string",
                        "enum": SEVERITIES,
                        "description": "Ne lister que les CVE de cette severite.",
                    },
                    "service": {
                        "type": "string",
                        "description": "Ne garder qu'un service (nom ou port, ex. 'apache', 'mysql', '5000').",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Nombre de CVE detaillees par service (defaut 3, max 15).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_attack_graph",
            "description": (
                "Graphe d'attaque de l'infrastructure : les noeuds (attaquant 'kali', services et "
                "conteneurs, avec port, version et exposition a l'exterieur) et les aretes "
                "(qui peut atteindre qui, par quel port, via le reseau externe ou un reseau Docker "
                "interne). A utiliser pour : 'quels services sont exposes', 'comment est organise "
                "le reseau', 'qui peut acceder a la base de donnees'."
            ),
            "parameters": {
                "type": "object",
                "properties": {"analysis_id": ANALYSIS_ID_PARAM},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_attack_paths",
            "description": (
                "Tous les chemins d'attaque possibles depuis l'attaquant vers chaque cible "
                "d'interet, avec la raison du choix de la cible ('not_exposed' = actif interne "
                "non expose comme une base de donnees, 'pivot' = point d'entree expose relie au "
                "reseau interne) et une description etape par etape. Faits structurels seulement, "
                "sans score. A utiliser pour : 'quels chemins mènent a la base', 'comment un "
                "attaquant peut atteindre X', 'combien de chemins d'attaque'."
            ),
            "parameters": {
                "type": "object",
                "properties": {"analysis_id": ANALYSIS_ID_PARAM},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_risk_analysis",
            "description": (
                "Chemins d'attaque classes du plus dangereux au moins dangereux, avec pour chacun "
                "le score de risque (0-10), la severite, la CVE la plus grave a exploiter, le noeud "
                "ou elle se trouve, une explication, et le detail par service traverse. A utiliser "
                "pour : 'quel est le chemin le plus dangereux', 'que dois-je corriger en priorite', "
                "'quel est le niveau de risque', 'comment proteger ma base de donnees'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "analysis_id": ANALYSIS_ID_PARAM,
                    "limit": {
                        "type": "integer",
                        "description": "Nombre de chemins renvoyes (defaut 10).",
                    },
                },
                "required": [],
            },
        },
    },
]

SYSTEM_PROMPT = """Tu es l'agent IA de SentinelPath, un outil d'analyse de vulnerabilites et de chemins d'attaque.

Principe absolu : les outils calculent, toi tu expliques.
- Pour toute question sur l'infrastructure (services, CVE, chemins, risque, historique), appelle TOUJOURS au moins un outil avant de repondre. Ne reponds jamais de memoire.
- N'invente JAMAIS une CVE, un score CVSS, un score de risque, une version, un service ou un chemin d'attaque. Utilise uniquement les valeurs renvoyees par les outils, recopiees exactement.
- Si un outil renvoie une erreur ou si l'information n'existe pas dans les donnees, dis-le clairement et indique quoi faire (par exemple lancer le backend ou une analyse). N'essaie pas de deviner.
- Pour les recommandations de securite, appuie-toi sur les faits renvoyes (CVE concernees, versions, chemins, liens de correctif) et propose des mesures concretes et reconnues (mise a jour vers une version corrigee, reduction de l'exposition, segmentation reseau, controle d'acces...). Precise que ce sont des recommandations generales a valider.
- Cite les identifiants exacts (CVE, noms des services/conteneurs, scores) pour que l'utilisateur puisse verifier.

Style : reponds en francais, de facon claire et structuree, concise (listes courtes plutot que longs paragraphes). Commence par la reponse directe a la question."""


# =========================================================================== #
# Boucle agent : question -> outils -> reponse
# =========================================================================== #
def parse_tool_args(func, raw_arguments):
    """
    Arguments JSON du modele -> dict utilisable par la fonction.
    gpt-oss renvoie parfois des arguments parasites comme {"": ""} : on ne garde
    que les parametres que la fonction accepte reellement, sans valeur vide.
    """
    try:
        args = json.loads(raw_arguments) if raw_arguments and raw_arguments.strip() else {}
    except json.JSONDecodeError:
        return {}
    if not isinstance(args, dict):
        return {}
    accepted = inspect.signature(func).parameters
    return {k: v for k, v in args.items() if k in accepted and v not in (None, "")}


def run_tool(name, raw_arguments):
    """Execute un outil et renvoie son resultat sous forme de texte JSON pour le modele."""
    func = AVAILABLE_FUNCTIONS.get(name)
    if func is None:
        return json.dumps({"error": f"Outil inconnu : {name}"})

    args = parse_tool_args(func, raw_arguments)
    shown = ", ".join(f"{k}={v!r}" for k, v in args.items()) if DEBUG else ""
    print(f"  [outil] {name}({shown})")

    try:
        result = func(**args)
    except BackendError as e:
        print(f"  [!] {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)

    text = json.dumps(result, ensure_ascii=False)
    if len(text) > MAX_TOOL_OUTPUT:
        text = text[:MAX_TOOL_OUTPUT] + (
            ' ... [TRONQUE : resultat trop long. Utilise des filtres (service, severity, limit) '
            'pour obtenir le reste. Ne suppose rien sur la partie manquante.]'
        )
    return text


def assistant_message_to_dict(msg):
    """Convertit la reponse du SDK en message 'assistant' reinjectable dans la conversation."""
    out = {"role": "assistant", "content": msg.content or ""}
    if msg.tool_calls:
        out["tool_calls"] = [
            {
                "id": c.id,
                "type": "function",
                "function": {"name": c.function.name, "arguments": c.function.arguments or "{}"},
            }
            for c in msg.tool_calls
        ]
    return out


def ask(client, history, question):
    """Traite une question : le modele appelle les outils necessaires puis repond."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, *history,
                {"role": "user", "content": question}]

    for _ in range(MAX_TOOL_ROUNDS):
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            temperature=0.2,  # reponses factuelles et stables
        )
        msg = response.choices[0].message
        if not msg.tool_calls:
            return msg.content or "(reponse vide du modele)"

        messages.append(assistant_message_to_dict(msg))
        for call in msg.tool_calls:
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": run_tool(call.function.name, call.function.arguments),
            })

    return ("Je n'ai pas pu terminer : trop d'appels d'outils pour cette question. "
            "Essayez de la reformuler plus precisement.")


# =========================================================================== #
# Programme principal
# =========================================================================== #
def check_setup():
    """Verifie la cle Groq et le backend avant de demarrer la conversation."""
    if not os.environ.get("GROQ_API_KEY"):
        sys.exit(
            "Erreur : la variable d'environnement GROQ_API_KEY n'est pas definie.\n"
            "Definissez-la dans votre terminal (elle ne doit jamais etre ecrite dans le code)."
        )
    try:
        api_get("/health")
    except BackendError as e:
        sys.exit(f"Erreur : {e}")
    try:
        analyses = api_get("/analyses")
    except BackendError as e:
        sys.exit(f"Erreur : {e}")
    if not analyses:
        print("[!] Aucune analyse enregistree : lancez d'abord POST /analyze "
              f"(par exemple depuis {API_URL}/docs).")
    else:
        last = analyses[0]
        print(f"Backend OK ({API_URL}) - {len(analyses)} analyse(s), derniere : "
              f"#{last['id']} du {last['analysis_date']}")


def main():
    global DEBUG
    parser = argparse.ArgumentParser(description="Agent IA SentinelPath (ligne de commande)")
    parser.add_argument("--debug", action="store_true", help="affiche les arguments des outils")
    DEBUG = parser.parse_args().debug

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # accents corrects dans PowerShell

    check_setup()
    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    history = []

    print(f"\nSentinelPath Agent ({MODEL}) - posez vos questions en francais.")
    print("Commandes : 'reset' pour oublier la conversation, 'quitter' pour sortir.\n")

    while True:
        try:
            question = input("Vous > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAu revoir.")
            break

        if not question:
            continue
        if question.lower() in {"quitter", "exit", "quit", "q"}:
            print("Au revoir.")
            break
        if question.lower() == "reset":
            history.clear()
            print("Conversation reinitialisee.\n")
            continue

        try:
            answer = ask(client, history, question)
        except RateLimitError:
            print("[!] Limite de requetes Groq atteinte (compte gratuit). "
                  "Attendez une minute puis reessayez.\n")
            continue
        except APIConnectionError:
            print("[!] Impossible de joindre l'API Groq (connexion Internet ?).\n")
            continue
        except APIStatusError as e:
            print(f"[!] Erreur de l'API Groq (HTTP {e.status_code}) : {e.message}\n")
            continue

        print(f"\nAgent > {answer}\n")

        # On ne garde que les questions/reponses (pas les gros resultats d'outils)
        # pour economiser les tokens : l'agent rappellera les outils si besoin.
        history += [{"role": "user", "content": question},
                    {"role": "assistant", "content": answer}]
        history[:] = history[-2 * MAX_HISTORY_TURNS:]


if __name__ == "__main__":
    main()
