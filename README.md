# Agent Intelligent de Cybersécurité pour l'Analyse des Vulnérabilités et des Chemins d'Attaque

Projet **AI Cybersecurity Agent** : un agent qui collecte l'état d'une infrastructure, identifie les vulnérabilités connues (CVE) des services exposés et reconstruit les chemins d'attaque possibles entre les composants.

## Structure du projet

| Dossier          | Rôle |
|------------------|------|
| `collector/`     | Collecte de l'infrastructure : hôtes, OS, services, versions et relations réseau entre composants. |
| `vulnerability/` | Analyse des vulnérabilités : correspondance des services/versions avec les CVE via la base NVD. |
| `agent/`         | Agent IA orchestrateur : pilote les modules d'analyse et construit les chemins d'attaque. |
| `backend/`       | API FastAPI qui expose les résultats d'analyse. |
| `frontend/`      | Interface web de visualisation des vulnérabilités et des chemins d'attaque. |
| `samples/`       | Exemples de fichiers d'entrée/sortie (ex. `collector_output_sample.json`). |

## Flux de données

```
Infrastructure
      │
      ▼
collector_output.json      (produit par collector/)
      │
      ▼
Modules d'analyse          (vulnerability/ + agent/)
      │
      ▼
analysis_result.json
      │
      ▼
Backend (FastAPI)
      │
      ▼
Frontend (interface web)
```

1. **Infrastructure → `collector_output.json`** : le collecteur inventorie les hôtes, leurs services (port, nom, version) et les relations entre composants. Voir `samples/collector_output_sample.json`.
2. **`collector_output.json` → modules d'analyse** : chaque service est confronté aux CVE de la NVD ; l'agent combine vulnérabilités et relations pour déduire les chemins d'attaque.
3. **Modules d'analyse → `analysis_result.json`** : résultat consolidé (vulnérabilités, scores, chemins d'attaque).
4. **`analysis_result.json` → Backend** : l'API FastAPI expose ces résultats.
5. **Backend → Frontend** : l'interface web les affiche.

## Travailler à deux (règles de contribution)

### Répartition

| Membre | Dossiers |
|--------|----------|
| emirghdiri | `collector/`, `agent/` |
| arijcheikhrouhou | `vulnerability/`, `backend/` |
| Les deux | `frontend/` |

Chacun travaille dans ses dossiers : cela évite presque tous les conflits.

### Règles

1. **On ne travaille jamais directement sur `main`.** `main` contient uniquement du code qui marche.
2. **Une branche par tâche**, avec un nom clair : `collector-docker`, `vulnerability-nvd`, `backend-api`…
3. **On passe par une Pull Request** pour entrer dans `main`. L'autre membre relit, puis clique sur *Merge*.
4. **On ne commite jamais** de résultats de scan réels (`local_inventory.json`, `analysis_result.json`), ni de mots de passe ou de clés API : le dépôt est public.

### Cycle de travail

```bash
git checkout main
git pull                              # 1. récupérer la dernière version
git checkout -b nom-de-la-tache       # 2. créer sa branche
# ... coder ...
git add -A
git commit -m "Ce que j'ai fait"      # 3. enregistrer
git push -u origin nom-de-la-tache    # 4. envoyer la branche sur GitHub
```

5. Sur GitHub : **Compare & pull request** → **Create pull request**.
6. L'autre membre relit → **Merge pull request**.
7. Chacun revient sur `main` et fait `git pull`.
