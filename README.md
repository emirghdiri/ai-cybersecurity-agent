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
