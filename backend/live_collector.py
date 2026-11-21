"""
Collecte "live" de l'infrastructure par SSH (paramiko), sans import manuel :

  1. Kali   : sudo nmap -sV -T4 -p- -oX <fichier> <IP Ubuntu>   (vue externe)
  2. Kali   -> PC -> Ubuntu : transfert du XML par SFTP (dans collector/)
  3. Ubuntu : python3 collector/local_inventory.py                (vue interne)
              python3 collector/merge.py                          (fusion)
  4. Ubuntu -> PC : recuperation de collector_output.json par SFTP

Configuration (variables d'environnement, JAMAIS dans le code) :
  KALI_SSH_HOST, KALI_SSH_USER, KALI_SSH_PASSWORD   (ou KALI_SSH_KEY = chemin de cle privee)
  UBUNTU_SSH_HOST, UBUNTU_SSH_USER, UBUNTU_SSH_PASSWORD (ou UBUNTU_SSH_KEY)
Optionnelles :
  UBUNTU_PROJECT_DIR  dossier du projet sur Ubuntu   (defaut : /home/<user>/ai-cybersecurity-agent)
  NMAP_TARGET         IP scannee                     (defaut : UBUNTU_SSH_HOST)
  KALI_NMAP_OUTPUT    fichier XML sur Kali           (defaut : /home/<user>/sentinelpath_nmap.xml)
  NMAP_TIMEOUT        duree max du scan en secondes  (defaut : 1800)
  SSH_ACCEPT_NEW_HOSTS=1  accepte une VM jamais vue (deconseille : voir check des cles d'hote)

Securite :
  - Les cles d'hote SSH sont verifiees (~/.ssh/known_hosts) : une VM inconnue ou dont
    la cle a change est refusee, pour ne jamais envoyer un mot de passe a un imposteur.
  - Le scan est lance avec "sudo -n" : si sudo demande un mot de passe, on echoue
    proprement au lieu de bloquer. La regle sudoers doit autoriser UNIQUEMENT la
    ligne de commande exacte renvoyee par nmap_command() (voir guide_sudoers()).
"""
import json
import os
import shlex
import socket
import tempfile
import time
from pathlib import Path

try:
    import paramiko
except ImportError:  # l'API demarre quand meme : seule cette route sera indisponible
    paramiko = None

SSH_CONNECT_TIMEOUT = 10     # secondes pour etablir la connexion
COMMAND_TIMEOUT = 300        # secondes pour inventaire + fusion sur Ubuntu
DEFAULT_NMAP_TIMEOUT = 1800  # un scan -p- -sV peut prendre plusieurs minutes
MAX_COLLECTOR_SIZE = 1_000_000


class CollectorConfigError(Exception):
    """Configuration absente ou invalide (variables d'environnement)."""


class LiveCollectorError(Exception):
    """Echec d'une etape de la collecte, avec un message clair pour le frontend."""

    def __init__(self, step, message, timeout=False):
        super().__init__(f"[{step}] {message}")
        self.step = step
        self.message = message
        self.timeout = timeout


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def _machine_config(prefix):
    host = os.environ.get(f"{prefix}_SSH_HOST", "").strip()
    user = os.environ.get(f"{prefix}_SSH_USER", "").strip()
    password = os.environ.get(f"{prefix}_SSH_PASSWORD") or None
    key = os.environ.get(f"{prefix}_SSH_KEY") or None

    missing = [name for name, value in ((f"{prefix}_SSH_HOST", host),
                                        (f"{prefix}_SSH_USER", user)) if not value]
    if not password and not key:
        missing.append(f"{prefix}_SSH_PASSWORD (ou {prefix}_SSH_KEY)")
    if missing:
        raise CollectorConfigError("Variables d'environnement manquantes : " + ", ".join(missing))
    if key and not Path(key).expanduser().is_file():
        raise CollectorConfigError(f"{prefix}_SSH_KEY : fichier introuvable ({key}).")
    return {"name": prefix.capitalize(), "host": host, "user": user,
            "password": password, "key": key}


def load_config():
    """Lit et valide toute la configuration ; leve CollectorConfigError si incomplete."""
    if paramiko is None:
        raise CollectorConfigError("Module paramiko manquant : python -m pip install paramiko")
    machines, problems = {}, []
    for prefix in ("KALI", "UBUNTU"):  # signaler les deux machines d'un coup
        try:
            machines[prefix] = _machine_config(prefix)
        except CollectorConfigError as e:
            problems.append(str(e))
    if problems:
        raise CollectorConfigError(" | ".join(problems))
    kali, ubuntu = machines["KALI"], machines["UBUNTU"]

    target = os.environ.get("NMAP_TARGET", ubuntu["host"]).strip()
    try:
        socket.inet_aton(target)  # IP v4 uniquement : evite toute injection dans la commande
    except OSError:
        raise CollectorConfigError(f"NMAP_TARGET doit etre une adresse IPv4 (recu : {target!r}).")

    try:
        nmap_timeout = int(os.environ.get("NMAP_TIMEOUT", DEFAULT_NMAP_TIMEOUT))
    except ValueError:
        raise CollectorConfigError("NMAP_TIMEOUT doit etre un nombre de secondes.")

    return {
        "kali": kali,
        "ubuntu": ubuntu,
        "target": target,
        "kali_output": os.environ.get("KALI_NMAP_OUTPUT",
                                      f"/home/{kali['user']}/sentinelpath_nmap.xml"),
        "project_dir": os.environ.get("UBUNTU_PROJECT_DIR",
                                      f"/home/{ubuntu['user']}/ai-cybersecurity-agent"),
        "nmap_timeout": nmap_timeout,
    }


def nmap_command(config):
    """
    Ligne de commande EXACTE du scan. La regle sudoers doit reprendre exactement
    ces arguments (sans le "sudo -n") : toute autre utilisation de nmap reste interdite.
    """
    return ["/usr/bin/nmap", "-sV", "-T4", "-p-", "-oX", config["kali_output"], config["target"]]


def guide_sudoers(config):
    """Ligne a ajouter sur Kali (sudo visudo -f /etc/sudoers.d/sentinelpath-nmap)."""
    return f"{config['kali']['user']} ALL=(root) NOPASSWD: {' '.join(nmap_command(config))}"


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #
def connect(machine):
    """Connexion SSH avec verification de la cle d'hote et erreurs lisibles."""
    step = f"connexion SSH a {machine['name']} ({machine['host']})"
    client = paramiko.SSHClient()
    client.load_system_host_keys()  # ~/.ssh/known_hosts de l'utilisateur Windows
    if os.environ.get("SSH_ACCEPT_NEW_HOSTS") == "1":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    try:
        client.connect(
            hostname=machine["host"],
            username=machine["user"],
            password=machine["password"],
            key_filename=str(Path(machine["key"]).expanduser()) if machine["key"] else None,
            timeout=SSH_CONNECT_TIMEOUT,
            banner_timeout=SSH_CONNECT_TIMEOUT,
            auth_timeout=SSH_CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.BadHostKeyException:
        raise LiveCollectorError(step, "la cle d'hote SSH a CHANGE depuis la derniere connexion. "
                                 "Possible usurpation : verifiez la VM avant de supprimer "
                                 "l'ancienne cle (ssh-keygen -R <ip>).")
    except paramiko.SSHException as e:
        if "not found in known_hosts" in str(e):
            raise LiveCollectorError(step, "VM inconnue (absente de known_hosts). Connectez-vous "
                                     f"une fois depuis ce PC : ssh {machine['user']}@{machine['host']} "
                                     "puis acceptez l'empreinte.")
        if isinstance(e, paramiko.AuthenticationException):
            raise LiveCollectorError(step, "authentification refusee (utilisateur ou mot de "
                                     "passe/cle incorrect).")
        raise LiveCollectorError(step, f"erreur SSH : {e}")
    except (socket.timeout, TimeoutError):
        raise LiveCollectorError(step, "delai depasse : la VM est-elle demarree et sur le "
                                 "meme reseau ?", timeout=True)
    except OSError as e:
        raise LiveCollectorError(step, f"VM injoignable ({e.strerror or e}). Verifiez qu'elle "
                                 "est demarree, son IP, et que SSH (port 22) est actif.")
    return client


def run(client, machine, command, timeout, step):
    """Execute une commande distante ; renvoie stdout, leve une erreur claire sinon."""
    channel = client.get_transport().open_session()
    channel.exec_command(command)
    out, err = bytearray(), bytearray()
    deadline = time.monotonic() + timeout

    while True:
        # Lire au fil de l'eau, sinon une sortie volumineuse bloque la commande distante
        while channel.recv_ready():
            out += channel.recv(65536)
        while channel.recv_stderr_ready():
            err += channel.recv_stderr(65536)
        if channel.exit_status_ready() and not channel.recv_ready() \
                and not channel.recv_stderr_ready():
            break
        if time.monotonic() > deadline:
            channel.close()
            raise LiveCollectorError(step, f"delai de {timeout} s depasse sur {machine['name']}.",
                                     timeout=True)
        time.sleep(0.5)

    code = channel.recv_exit_status()
    stdout = out.decode("utf-8", "replace")
    stderr = err.decode("utf-8", "replace").strip()
    if code != 0:
        detail = stderr[-500:] or stdout.strip()[-500:] or "aucun message"
        raise LiveCollectorError(step, f"echec (code {code}) : {detail}")
    return stdout


# --------------------------------------------------------------------------- #
# Collecte complete
# --------------------------------------------------------------------------- #
def run_live_collection(config=None, log=print):
    """
    Enchaine scan Nmap (Kali) -> inventaire + fusion (Ubuntu).
    Renvoie le contenu de collector_output.json (dict) et un resume des etapes.
    """
    config = config or load_config()
    kali, ubuntu = config["kali"], config["ubuntu"]
    project = config["project_dir"]
    remote_xml = f"{project}/collector/nmap_scan.xml"
    remote_output = f"{project}/collector_output.json"
    steps = []

    with tempfile.TemporaryDirectory(prefix="sentinelpath_") as tmp:
        local_xml = Path(tmp) / "nmap_scan.xml"
        local_json = Path(tmp) / "collector_output.json"

        # 1. Scan Nmap depuis Kali
        log(f"[1/4] Scan Nmap de {config['target']} depuis Kali...")
        t0 = time.monotonic()
        client = connect(kali)
        try:
            cmd = "sudo -n " + " ".join(shlex.quote(a) for a in nmap_command(config))
            try:
                run(client, kali, cmd, config["nmap_timeout"], "scan Nmap sur Kali")
            except LiveCollectorError as e:
                if "password is required" in e.message or "mot de passe" in e.message:
                    raise LiveCollectorError(e.step, "sudo demande un mot de passe : ajoutez la "
                                             "regle sudoers sur Kali -> " + guide_sudoers(config))
                raise
            with client.open_sftp() as sftp:
                sftp.get(config["kali_output"], str(local_xml))
        except (OSError, paramiko.SSHException) as e:
            raise LiveCollectorError("recuperation du XML Nmap sur Kali", str(e))
        finally:
            client.close()
        if "<nmaprun" not in local_xml.read_text(encoding="utf-8", errors="replace")[:2000]:
            raise LiveCollectorError("scan Nmap sur Kali", "le fichier recupere n'est pas un XML Nmap.")
        steps.append({"step": "nmap", "seconds": round(time.monotonic() - t0, 1)})

        # 2-3. Envoi du XML sur Ubuntu, inventaire local puis fusion
        log("[2/4] Envoi du scan sur Ubuntu...")
        t0 = time.monotonic()
        client = connect(ubuntu)
        try:
            with client.open_sftp() as sftp:
                try:
                    sftp.stat(f"{project}/collector/merge.py")
                except FileNotFoundError:
                    raise LiveCollectorError("verification du projet sur Ubuntu",
                                             f"{project}/collector/merge.py introuvable : "
                                             "definissez UBUNTU_PROJECT_DIR ou clonez le depot.")
                sftp.put(str(local_xml), remote_xml)

            log("[3/4] Inventaire local et fusion sur Ubuntu...")
            q = shlex.quote
            run(client, ubuntu,
                f"cd {q(project)} && python3 collector/local_inventory.py -o local_inventory.json "
                f"&& python3 collector/merge.py --inventory local_inventory.json "
                f"--nmap collector/nmap_scan.xml -o collector_output.json",
                COMMAND_TIMEOUT, "inventaire et fusion sur Ubuntu")

            log("[4/4] Recuperation de collector_output.json...")
            with client.open_sftp() as sftp:
                if sftp.stat(remote_output).st_size > MAX_COLLECTOR_SIZE:
                    raise LiveCollectorError("recuperation du resultat",
                                             "collector_output.json depasse 1 Mo.")
                sftp.get(remote_output, str(local_json))
        except (OSError, paramiko.SSHException) as e:
            raise LiveCollectorError("transfert SFTP avec Ubuntu", str(e))
        finally:
            client.close()
        steps.append({"step": "inventory+merge", "seconds": round(time.monotonic() - t0, 1)})

        try:
            data = json.loads(local_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise LiveCollectorError("lecture du resultat", f"collector_output.json invalide : {e}")

    return data, steps


if __name__ == "__main__":
    # Test en ligne de commande, sans le backend : python -m backend.live_collector
    import sys
    try:
        cfg = load_config()
        print("Regle sudoers attendue sur Kali :\n  " + guide_sudoers(cfg) + "\n")
        result, timing = run_live_collection(cfg)
    except (CollectorConfigError, LiveCollectorError) as e:
        sys.exit(f"Erreur : {e}")
    services = sum(len(h["services"]) for h in result["hosts"])
    print(f"OK : {services} service(s), {len(result['relations'])} relation(s) - {timing}")
