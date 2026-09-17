"""Service de masquerading (masquage signifiant) — POC Securiti × SharePoint.

Reçoit les déclenchements des Workflows Securiti (nœud HTTP Request, exécuté
depuis le cloud Securiti) et pseudonymise les fichiers de Documents/Inbound
vers Documents/Output, de façon cohérente (Eduard→Franz partout, IBAN valides,
images réécrites par OCR). Le traitement est asynchrone (202 + worker) : le
PDF de 305 pages + OCR prend plusieurs minutes, bien au-delà du timeout d'un
nœud HTTP Request.

Endpoints :
  POST /sanitize        {"file_path": "Inbound/x.docx"}  — un fichier
  POST /scan-completed  {"scan_id": "..."}               — tout Inbound
  GET  /healthz
  GET  /mapping         table de correspondance original→pseudonyme (HTML, ?format=json)

Auth : header X-Api-Key == $SERVICE_API_KEY (les POST seulement).
État : /data (PVC) — table de pseudonymes persistante (mapping_by_value.csv
copiée au premier démarrage + generated.json pour les valeurs HMAC inconnues).
"""
import csv
import html
import json
import logging
import os
import queue
import shutil
import tempfile
import threading

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

import sanitize_reference as sr
from graph import GraphClient, secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("masquerading")

DATA_DIR = os.environ.get("DATA_DIR", "/data")
MAPPING = os.path.join(DATA_DIR, "mapping_by_value.csv")
GENERATED = os.path.join(DATA_DIR, "generated.json")
SEED_MAPPING = os.environ.get("SEED_MAPPING", "/app/seed/mapping_by_value.csv")
INBOUND = os.environ.get("INBOUND_PREFIX", "Inbound")
OUTPUT = os.environ.get("OUTPUT_PREFIX", "Output")
API_KEY = secret("SERVICE_API_KEY", default="")   # env, SERVICE_API_KEY_FILE ou /run/secrets/SERVICE_API_KEY

app = FastAPI(title="masquerading", version="0.1.0")
jobs: "queue.Queue[dict]" = queue.Queue()
state = {"processed": 0, "errors": 0, "last": None}


def _pseudonymizer():
    if not os.path.exists(MAPPING):
        os.makedirs(DATA_DIR, exist_ok=True)
        shutil.copy(SEED_MAPPING, MAPPING)
    pz = sr.Pseudonymizer(MAPPING)
    if os.path.exists(GENERATED):
        with open(GENERATED, encoding="utf-8") as f:
            pz.generated.update(json.load(f))
    return pz


def _persist_generated(pz):
    with open(GENERATED, "w", encoding="utf-8") as f:
        json.dump(pz.generated, f, ensure_ascii=False, indent=1)


# Formats acceptés par l'API (toute autre extension est ignorée et journalisée).
HANDLERS = {
    ".docx": sr.sanitize_docx, ".xlsx": sr.sanitize_xlsx, ".pdf": sr.sanitize_pdf, ".rtf": sr.sanitize_rtf,
    ".png": sr.sanitize_image_file, ".jpg": sr.sanitize_image_file, ".jpeg": sr.sanitize_image_file,
}
SUPPORTED_FORMATS = sorted(HANDLERS)


def _sanitize_one(gc: GraphClient, pz, rel_path: str):
    """rel_path est relatif à INBOUND (ex. 'images/x.png')."""
    ext = os.path.splitext(rel_path)[1].lower()
    handler = HANDLERS.get(ext)
    if handler is None:
        log.info("ignoré (extension non gérée): %s", rel_path)
        return {"skipped": ext}
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "in" + ext)
        dst = os.path.join(td, "out" + ext)
        gc.download(f"{INBOUND}/{rel_path}", src)
        summary = handler(src, dst, pz, strict=False)
        gc.upload(f"{OUTPUT}/{rel_path}", dst)
    _persist_generated(pz)
    log.info("traité %s -> %s : %s", rel_path, OUTPUT, summary)
    return summary


def worker():
    # init paresseuse : /healthz doit répondre même sans credentials Graph posés,
    # et une erreur d'env ne doit pas tuer le thread au boot.
    gc = pz = None
    while True:
        job = jobs.get()
        try:
            if gc is None:
                gc = GraphClient()
                pz = _pseudonymizer()
            if job["kind"] == "file":
                rel = job["path"]
                if rel.startswith(INBOUND + "/"):
                    rel = rel[len(INBOUND) + 1:]
                _sanitize_one(gc, pz, rel)
                state["processed"] += 1
            elif job["kind"] == "all":
                for rel, _item in gc.list_folder(INBOUND):
                    try:
                        _sanitize_one(gc, pz, rel)
                        state["processed"] += 1
                    except Exception:
                        log.exception("échec sur %s", rel)
                        state["errors"] += 1
            state["last"] = job
        except Exception:
            log.exception("échec du job %s", job)
            state["errors"] += 1
        finally:
            jobs.task_done()


threading.Thread(target=worker, daemon=True).start()


def _auth(x_api_key):
    if not API_KEY or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="X-Api-Key invalide")


# Champs candidats pour retrouver le chemin d'un fichier dans un payload d'alerte
# Securiti (le schéma du Policy Alert n'est pas documenté — T1). On sonde du plus
# précis au plus large. Le chemin renvoyé est ramené à un chemin relatif à INBOUND.
_PATH_KEYS = ("file_path", "resource_path", "resourcePath", "prefix_path",
              "object_path", "path", "full_path", "file_name", "displayName")


def _extract_path(obj):
    """Trouve récursivement un chemin de fichier plausible dans un dict/list."""
    if isinstance(obj, str):
        return obj if "/" in obj or "." in obj else None
    if isinstance(obj, dict):
        for k in _PATH_KEYS:
            if obj.get(k):
                return obj[k]
        for v in obj.values():
            p = _extract_path(v)
            if p:
                return p
    elif isinstance(obj, list):
        for v in obj:
            p = _extract_path(v)
            if p:
                return p
    return None


def _to_inbound_rel(path):
    """Ramène un chemin absolu SharePoint/Graph à un chemin relatif à INBOUND."""
    marker = f"/{INBOUND}/"
    if marker in path:
        return path.split(marker, 1)[1]
    if path.startswith(INBOUND + "/"):
        return path[len(INBOUND) + 1:]
    return path.rsplit("/", 1)[-1]  # dernier recours : le nom de fichier


class SanitizeReq(BaseModel):
    # file_path direct (test manuel) OU alert = payload brut du Policy Alert Securiti.
    file_path: str | None = None
    alert: dict | list | None = None

    model_config = {"extra": "allow"}


class ScanReq(BaseModel):
    scan_id: str | None = None
    scan: dict | list | None = None

    model_config = {"extra": "allow"}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": os.environ.get("GIT_SHA", "dev"), "queue": jobs.qsize(),
            "formats": SUPPORTED_FORMATS, **state}


def _load_mapping():
    """Lit la table de pseudonymes (CSV persistant + generated.json runtime).
    Retourne une liste de (data_type, original, pseudonyme, source)."""
    rows = []
    seen = set()
    path = MAPPING if os.path.exists(MAPPING) else SEED_MAPPING
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                orig = r.get("original_value", "")
                rows.append((r.get("data_type", ""), orig, r.get("replacement_value", ""), "table"))
                seen.add(orig)
    if os.path.exists(GENERATED):
        try:
            with open(GENERATED, encoding="utf-8") as f:
                for k, v in json.load(f).items():
                    if k not in seen:
                        rows.append(("generated (HMAC)", k, v, "runtime"))
        except Exception:
            pass
    return rows


@app.get("/mapping", response_class=HTMLResponse)
def mapping(format: str = "html"):
    """Publie la table de correspondance masquage original → pseudonyme (lab, sans auth)."""
    rows = _load_mapping()
    if format == "json":
        return JSONResponse([
            {"data_type": dt, "original_value": o, "replacement_value": p, "source": s}
            for dt, o, p, s in rows
        ])
    body = "\n".join(
        f"<tr><td>{html.escape(dt)}</td><td>{html.escape(o)}</td>"
        f"<td class='p'>{html.escape(p)}</td><td class='s'>{html.escape(s)}</td></tr>"
        for dt, o, p, s in rows
    )
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Masquerading — mapping table</title>
<style>
 body{{font:14px/1.4 system-ui,sans-serif;margin:2rem;color:#1a1a2e}}
 h1{{font-size:1.2rem}} .n{{color:#667;margin-bottom:1rem}}
 input{{padding:.4rem .6rem;margin-bottom:1rem;width:20rem;border:1px solid #ccd;border-radius:6px}}
 table{{border-collapse:collapse;width:100%}} th,td{{padding:.35rem .6rem;border-bottom:1px solid #eef;text-align:left;font-variant-numeric:tabular-nums}}
 th{{position:sticky;top:0;background:#f5f6ff}} td.p{{color:#0a7d34;font-weight:600}} td.s{{color:#889;font-size:.85em}}
 tr:hover{{background:#fafbff}}
</style></head><body>
<h1>Masquerading — mapping table (meaningful masking)</h1>
<div class="n">{len(rows)} entries · 100% synthetic data (lab) · original → consistent pseudonym</div>
<input id="q" placeholder="Filter… (name, IBAN, type)" oninput="f()">
<table><thead><tr><th>Type</th><th>Original value</th><th>Pseudonym</th><th>Source</th></tr></thead>
<tbody id="t">{body}</tbody></table>
<script>
 function f(){{var v=document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('#t tr').forEach(function(r){{r.style.display=r.innerText.toLowerCase().includes(v)?'':'none'}});}}
</script></body></html>"""
    return HTMLResponse(page)


@app.post("/sanitize", status_code=202)
def sanitize(req: SanitizeReq, x_api_key: str = Header(default="")):
    _auth(x_api_key)
    # Log du payload brut : capture le schéma d'alerte (T1) au premier tir réel.
    log.info("POST /sanitize payload: %s", req.model_dump())
    path = req.file_path
    if not path and req.alert is not None:
        path = _extract_path(req.alert)
    if not path:
        path = _extract_path(req.model_dump())
    if not path:
        raise HTTPException(status_code=422, detail="aucun chemin de fichier trouvé dans le payload")
    rel = _to_inbound_rel(path)
    jobs.put({"kind": "file", "path": rel})
    return {"queued": rel, "queue": jobs.qsize()}


@app.post("/scan-completed", status_code=202)
def scan_completed(req: ScanReq, x_api_key: str = Header(default="")):
    _auth(x_api_key)
    jobs.put({"kind": "all", "scan_id": req.scan_id})
    return {"queued": "all", "queue": jobs.qsize()}
