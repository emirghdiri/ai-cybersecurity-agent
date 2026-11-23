"""
Authentification de SentinelPath (bibliotheque standard uniquement).

Indispensable des que le site est accessible depuis internet (ex. Tailscale Funnel) :
sans elle, n'importe qui pourrait lancer des scans sur les VMs, utiliser le quota Groq
et lire les vulnerabilites du labo.

Principe :
  - un compte unique ; le mot de passe n'est jamais stocke en clair, seulement son
    empreinte PBKDF2-SHA256 (600 000 iterations, sel aleatoire) ;
  - apres connexion, un cookie de session signe (HMAC-SHA256), HttpOnly, Secure,
    SameSite=Lax, valable 8 h ;
  - sans mot de passe configure : acces libre depuis ce PC et le reseau Tailscale
    uniquement, internet refuse (SENTINELPATH_AUTH=required pour tout fermer) ;
  - anti-force brute : apres 5 echecs en 5 minutes, connexion bloquee 60 s.

Variables d'environnement :
  SENTINELPATH_USER            identifiant (defaut : admin)
  SENTINELPATH_PASSWORD_HASH   empreinte generee par : python -m backend.auth
  SENTINELPATH_SECRET          cle de signature des sessions (sinon aleatoire : les
                               sessions sont alors perdues a chaque redemarrage)
  SENTINELPATH_AUTH=disabled   desactive l'authentification (PC + reseau Tailscale)
  SENTINELPATH_AUTH=required   exige un mot de passe (tout est refuse s'il manque)
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

ITERATIONS = 600_000
SESSION_COOKIE = "sentinelpath_session"
SESSION_SECONDS = 8 * 3600
MAX_FAILURES, FAILURE_WINDOW, LOCK_SECONDS = 5, 300, 60

_SECRET = (os.environ.get("SENTINELPATH_SECRET") or secrets.token_hex(32)).encode()
# Partage avec l'agent IA du meme processus (route /chat), qui en deduit son jeton d'API.
os.environ.setdefault("SENTINELPATH_SECRET", _SECRET.decode())
AGENT_TOKEN_CONTEXT = b"sentinelpath-agent-api"
_failures = []          # horodatages des echecs recents
_locked_until = 0.0
_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def auth_disabled():
    """
    Mode sans mot de passe : explicite (SENTINELPATH_AUTH=disabled) ou implicite quand
    aucun mot de passe n'est configure. Dans ce mode, main.py n'accepte que ce PC et le
    reseau Tailscale (toute requete anonyme venue d'internet est refusee).
    """
    mode = os.environ.get("SENTINELPATH_AUTH", "").lower()
    return mode == "disabled" or (mode != "required" and not configured_hash())


def configured_user():
    return os.environ.get("SENTINELPATH_USER", "admin")


def configured_hash():
    return os.environ.get("SENTINELPATH_PASSWORD_HASH", "").strip()


# --------------------------------------------------------------------------- #
# Mots de passe
# --------------------------------------------------------------------------- #
def hash_password(password, salt=None, iterations=ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        algo, iterations, salt_hex, digest_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex),
                                     int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def check_credentials(username, password):
    """Verifie identifiant + mot de passe, avec blocage apres trop d'echecs."""
    global _locked_until
    now = time.monotonic()
    with _lock:
        if now < _locked_until:
            return False, f"Trop de tentatives : reessayez dans {int(_locked_until - now) + 1} s."
    stored = configured_hash()
    ok = (bool(stored)
          and hmac.compare_digest(username.encode(), configured_user().encode())
          and verify_password(password, stored))
    with _lock:
        if ok:
            _failures.clear()
            return True, None
        _failures[:] = [t for t in _failures if now - t < FAILURE_WINDOW] + [now]
        if len(_failures) >= MAX_FAILURES:
            _locked_until = now + LOCK_SECONDS
            _failures.clear()
    return False, "Identifiant ou mot de passe incorrect."


# --------------------------------------------------------------------------- #
# Sessions (cookie signe)
# --------------------------------------------------------------------------- #
def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def create_session(username):
    payload = _b64(json.dumps({"u": username, "exp": int(time.time()) + SESSION_SECONDS}).encode())
    signature = _b64(hmac.new(_SECRET, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def read_session(token):
    """Renvoie l'utilisateur si le cookie est authentique et non expire, sinon None."""
    try:
        payload, signature = token.split(".")
        expected = _b64(hmac.new(_SECRET, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        data = json.loads(_unb64(payload))
        if data.get("exp", 0) < time.time() or data.get("u") != configured_user():
            return None
        return data["u"]
    except (ValueError, AttributeError, json.JSONDecodeError):
        return None


def agent_token():
    """
    Jeton de l'agent IA pour interroger l'API (Authorization: Bearer ...) : l'agent appelle
    l'API par HTTP et n'a pas de cookie de session. Derive de la cle secrete du serveur,
    il n'est jamais envoye au navigateur.
    """
    return hmac.new(_SECRET, AGENT_TOKEN_CONTEXT, hashlib.sha256).hexdigest()


def is_agent_request(authorization_header):
    expected = f"Bearer {agent_token()}"
    return hmac.compare_digest((authorization_header or "").encode(), expected.encode())


# --------------------------------------------------------------------------- #
# Outil en ligne de commande : generer l'empreinte d'un mot de passe
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    print("Generation de l'empreinte du mot de passe SentinelPath (rien n'est enregistre).")
    first = getpass.getpass("Mot de passe (12 caracteres minimum) : ")
    if len(first) < 12:
        raise SystemExit("Mot de passe trop court : 12 caracteres minimum.")
    if getpass.getpass("Confirmez : ") != first:
        raise SystemExit("Les deux saisies ne correspondent pas.")
    print("\nDefinissez ces variables (PowerShell), puis relancez le serveur :\n")
    print(f'  setx SENTINELPATH_PASSWORD_HASH "{hash_password(first)}"')
    print(f'  setx SENTINELPATH_SECRET "{secrets.token_hex(32)}"')
    print("\n(setx les enregistre pour les prochains terminaux : rouvrez VS Code apres.)")
