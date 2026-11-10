# Travailler à deux (règles de contribution)

## Répartition

| Membre | Dossiers |
|--------|----------|
| emirghdiri | `collector/`, `agent/` |
| arijcheikhrouhou | `vulnerability/`, `backend/` |
| Les deux | `frontend/` |

Chacun travaille dans ses dossiers : cela évite presque tous les conflits.

## Règles

1. **On ne travaille jamais directement sur `main`.** `main` contient uniquement du code qui marche.
2. **Chacun travaille sur sa branche** (`emir-dev`, `vuln-analyzer-dev`) et pousse régulièrement.
3. **On passe par une Pull Request** pour entrer dans `main`. L'autre membre relit, puis clique sur *Merge*.
4. **On ne commite jamais** de résultats de scan réels (`local_inventory.json`, `nmap_scan.xml`, `collector_output.json`, `analysis_result.json`), ni de mots de passe ou de clés API : le dépôt est public.

## Cycle de travail

```bash
git checkout ma-branche
git pull                              # 1. récupérer la dernière version
# ... coder ...
git add -A
git commit -m "Ce que j'ai fait"      # 2. enregistrer
git push                              # 3. envoyer la branche sur GitHub
```

4. Sur GitHub : **Compare & pull request** → **Create pull request**.
5. L'autre membre relit → **Merge pull request**.
