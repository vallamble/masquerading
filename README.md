# sanitizer

Service HTTP de **sanitization signifiante** pour un POC Securiti × SharePoint : il
pseudonymise de façon cohérente (mêmes personnes → mêmes pseudonymes, IBAN/AVS/cartes de
format valide, images réécrites par OCR) les fichiers déposés dans `Documents/Inbound` d'un
SharePoint et écrit le résultat dans `Documents/Output`. Données de test 100 % fictives.

Déclenché par les Workflows Securiti (nœud HTTP Request, exécuté dans le cloud Securiti) :
scan SDI sur `Inbound` → policy File Insights → workflow → ce service → scan de vérification.

## Endpoints

| Méthode | Chemin | Corps | Rôle |
|---|---|---|---|
| GET | `/healthz` | — | état + profondeur de file |
| POST | `/sanitize` | `{"file_path":"…"}` **ou** `{"alert":{…}}` | pseudonymise un fichier (202, asynchrone) |
| POST | `/scan-completed` | `{"scan_id":"…"}` (ou `{"scan":{…}}`) | re-traite tout `Inbound` (202) |

`POST /sanitize` accepte soit un `file_path` direct, soit le payload brut d'alerte Securiti
(`alert`) dont il extrait le chemin ; le payload reçu est loggé (utile pour capturer le schéma).
Les POST exigent le header `X-Api-Key: $SERVICE_API_KEY`.

## Variables d'environnement

| Variable | Rôle | Défaut |
|---|---|---|
| `SERVICE_API_KEY` | clé attendue dans `X-Api-Key` | — (obligatoire) |
| `GRAPH_TENANT_ID` / `GRAPH_CLIENT_ID` / `GRAPH_CLIENT_SECRET` | app Entra (Sites.Selected) | — |
| `SP_HOSTNAME` | hôte SharePoint | — |
| `SP_SITE_PATH` | chemin du site (`""` = site racine) | — |
| `SP_LIBRARY` | bibliothèque de documents | `Documents` |
| `DATA_DIR` | dossier d'état (mapping + pseudonymes générés) | `/data` |
| `INBOUND_PREFIX` / `OUTPUT_PREFIX` | dossiers source/cible | `Inbound` / `Output` |

État persistant : `${DATA_DIR}/mapping_by_value.csv` (table de pseudonymes ; graine copiée
au 1er démarrage si absente) et `${DATA_DIR}/generated.json` (valeurs inconnues, dérivation
déterministe). Le service démarre **sans** credentials Graph (répond 202 et logge), l'appel
Graph n'échoue que dans le worker au moment du traitement.

## Image

`ghcr.io/vallamble/sanitizer:latest` (et `:sha-<court>`), multi-arch `linux/amd64,linux/arm64`,
construite par GitHub Actions (`.github/workflows/build.yml`) sur `python:3.11-slim` +
`tesseract-ocr` (fra/deu) + `fonts-dejavu-core`. Écoute `0.0.0.0:8080`.

## Déploiement (Docker / Portainer sur navi)

`deploy/docker-compose.yml` : mappe `127.0.0.1:8080:8080` (cloudflared cible localhost:8080),
volume externe `sanitizer_data` monté sur `/data`, healthcheck `curl /healthz`,
`restart: unless-stopped`. Copier `deploy/.env.example` → `.env` et remplir.

```bash
docker pull ghcr.io/vallamble/sanitizer:latest
cd deploy && cp .env.example .env   # puis renseigner les secrets
docker compose up -d
```

## Test rapide

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS -XPOST http://localhost:8080/sanitize \
  -H "X-Api-Key: $SERVICE_API_KEY" -H 'Content-Type: application/json' \
  -d '{"file_path":"Inbound/Dossier_patients_Q3_2026_FICTIF.pdf"}'
```
