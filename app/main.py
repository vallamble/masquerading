"""Masquerading service (meaningful masking) — Securiti × SharePoint POC.

Receives the triggers from Securiti Workflows (HTTP Request node, executed
from the Securiti cloud) and pseudonymizes the files of Documents/Inbound
into Documents/Output, consistently (Eduard→Franz everywhere, valid IBANs,
images rewritten via OCR). Processing is asynchronous (202 + worker): the
305-page PDF + OCR takes several minutes, far beyond the timeout of an
HTTP Request node.

Endpoints:
  POST /sanitize        {"file_path": "Inbound/x.docx"}  — one file
  POST /scan-completed  {"scan_id": "..."}               — all of Inbound
  GET  /healthz
  GET  /mapping         original→pseudonym mapping table (HTML, ?format=json)

Auth: header X-Api-Key == $SERVICE_API_KEY (POST requests only).
State: /data (PVC) — persistent pseudonym table (mapping_by_value.csv
copied on first start + generated.json for the unknown HMAC-derived values).
"""
import csv
import hmac
import html
import json
import logging
import os
import queue
import shutil
import tempfile
import threading
import time

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
API_KEY = secret("SERVICE_API_KEY", default="")   # env, SERVICE_API_KEY_FILE or /run/secrets/SERVICE_API_KEY

app = FastAPI(title="masquerading", version="0.1.0")
jobs: "queue.Queue[dict]" = queue.Queue()
state = {"processed": 0, "errors": 0, "last": None}


def _merge_seed_into_mapping():
    """The persisted table (/data) is completed with the seed rows it does not have yet: a value added to the
    seed in the code (e.g. FIRST_NAME Anne) applies after redeployment without touching the volume."""
    if not os.path.exists(MAPPING):
        os.makedirs(DATA_DIR, exist_ok=True)
        shutil.copy(SEED_MAPPING, MAPPING)
        return
    with open(MAPPING, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f)); have = {(r["data_type"], r["original_value"]) for r in rows}
    with open(SEED_MAPPING, encoding="utf-8", newline="") as f:
        new = [r for r in csv.DictReader(f) if (r["data_type"], r["original_value"]) not in have]
    if new:
        with open(MAPPING, "a", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["data_type", "original_value", "replacement_value"])
            for r in new:
                w.writerow({k: r[k] for k in w.fieldnames})
        log.info("pseudonym table: %d seed row(s) added", len(new))


def _pseudonymizer():
    _merge_seed_into_mapping()
    pz = sr.Pseudonymizer(MAPPING)
    if os.path.exists(GENERATED):
        with open(GENERATED, encoding="utf-8") as f:
            pz.generated.update(json.load(f))
    return pz


def _persist_generated(pz):
    with open(GENERATED, "w", encoding="utf-8") as f:
        json.dump(pz.generated, f, ensure_ascii=False, indent=1)


# Formats accepted by the API (any other extension is ignored and logged).
HANDLERS = {
    ".docx": sr.sanitize_docx, ".xlsx": sr.sanitize_xlsx, ".pdf": sr.sanitize_pdf, ".rtf": sr.sanitize_rtf,
    ".png": sr.sanitize_image_file, ".jpg": sr.sanitize_image_file, ".jpeg": sr.sanitize_image_file,
}
SUPPORTED_FORMATS = sorted(HANDLERS)


def _stored_size(gc: GraphClient, path: str, uploaded: int, tries: int = 6, pause: float = 2.5):
    """Size of drive:/<path> as stored by SharePoint. The rewrite of a DOCX/XLSX is asynchronous: we re-read
    until the size differs from the one uploaded (or ~15 s), then consider it stable."""
    size = None
    for _ in range(tries):
        time.sleep(pause)
        try:
            size = gc.item(path).get("size")
        except Exception:
            continue
        if size is not None and size != uploaded:
            return size
    return size


def _sanitize_one(gc: GraphClient, pz, rel_path: str):
    """rel_path is relative to INBOUND (e.g. 'images/x.png')."""
    ext = os.path.splitext(rel_path)[1].lower()
    handler = HANDLERS.get(ext)
    if handler is None:
        log.info("ignored (unsupported extension): %s", rel_path)
        return {"skipped": ext}
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "in" + ext)
        dst = os.path.join(td, "out" + ext)
        gc.download(f"{INBOUND}/{rel_path}", src)
        summary = handler(src, dst, pz, strict=False)
        match = os.environ.get("MATCH_INPUT_SIZE", "1") == "1"   # requirement 7: same file size (neutral padding)
        raw = dst + ".raw"
        if match:
            shutil.copyfile(dst, raw)
            summary["size_match"] = sr.match_input_size(src, dst)
        gc.upload(f"{OUTPUT}/{rel_path}", dst)
        # SharePoint rewrites the DOCX/XLSX it stores (library metadata: +901 B on our DOCX, +8.5 KB on
        # the XLSX), ASYNCHRONOUSLY: the upload response still reports our size. We re-read the stored size
        # a few seconds later and, if it differs from the input, re-pad to (input − delta) and re-upload
        # (three attempts at most). Log: size_match.sharepoint.
        si = os.path.getsize(src)
        if match and summary["size_match"].get("method") and ext in (".docx", ".xlsx"):
            stored = _stored_size(gc, f"{OUTPUT}/{rel_path}", os.path.getsize(dst))
            for _attempt in range(3):
                if stored is None or stored <= si:          # SharePoint only ever adds bytes; unknown or smaller: stop
                    break
                target = si - (stored - si)
                prev = dst + ".prev"; shutil.copyfile(dst, prev)
                shutil.copyfile(raw, dst)
                sm2 = sr.match_input_size(src, dst, target=target)
                if not sm2.get("method"):                    # could not pad to the new target: keep the previous version
                    shutil.copyfile(prev, dst); break
                gc.upload(f"{OUTPUT}/{rel_path}", dst)
                new_stored = _stored_size(gc, f"{OUTPUT}/{rel_path}", os.path.getsize(dst))
                summary["size_match"].setdefault("sharepoint", []).append(
                    {"stored_before": stored, "target": target, "stored_after": new_stored,
                     "method": sm2.get("method") or sm2.get("unmatched")})
                stored = new_stored
    _persist_generated(pz)
    log.info("processed %s -> %s : %s", rel_path, OUTPUT, summary)
    return summary


def worker():
    # lazy init: /healthz must respond even without Graph credentials set,
    # and an env error must not kill the thread at boot.
    gc = pz = None
    while True:
        job = jobs.get()
        try:
            if gc is None or pz is None:
                gc = gc or GraphClient()
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
                        log.exception("failed on %s", rel)
                        state["errors"] += 1
            state["last"] = job
        except Exception:
            log.exception("job failed %s", job)
            state["errors"] += 1
        finally:
            jobs.task_done()


threading.Thread(target=worker, daemon=True).start()


def _auth(x_api_key):
    """Mandatory API key, compared in constant time (no leak through the response time)."""
    if not API_KEY or not hmac.compare_digest(x_api_key or "", API_KEY):
        raise HTTPException(status_code=401, detail="invalid X-Api-Key")


def _safe_rel(rel):
    """Accepted path relative to Inbound: non-empty segments, no ".." nor absolute path, supported extension.
    Prevents a forged path from making the service read/write a file outside the Inbound/Output folder."""
    rel = (rel or "").replace("\\", "/").strip("/")
    parts = rel.split("/")
    if not rel or any(p in ("", ".", "..") for p in parts):
        raise HTTPException(status_code=422, detail="invalid file path")
    if os.path.splitext(rel)[1].lower() not in HANDLERS:
        raise HTTPException(status_code=422, detail="unsupported extension: %s" % os.path.splitext(rel)[1])
    return rel


# Candidate fields to find the path of a file in a Securiti alert payload
# (the Policy Alert schema is not documented — T1). Probed from the most
# specific to the broadest. The returned path is reduced to a path relative to INBOUND.
_PATH_KEYS = ("file_path", "resource_path", "resourcePath", "prefix_path",
              "object_path", "path", "full_path", "file_name", "displayName")


def _extract_path(obj):
    """Recursively finds a plausible file path in a dict/list."""
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
    """Reduces an absolute SharePoint/Graph path to a path relative to INBOUND."""
    marker = f"/{INBOUND}/"
    if marker in path:
        return path.split(marker, 1)[1]
    if path.startswith(INBOUND + "/"):
        return path[len(INBOUND) + 1:]
    return path.rsplit("/", 1)[-1]  # last resort: the file name


class SanitizeReq(BaseModel):
    # direct file_path (manual test) OR alert = raw payload of the Securiti Policy Alert.
    file_path: str | None = None
    alert: dict | list | None = None

    model_config = {"extra": "allow"}


class ScanReq(BaseModel):
    scan_id: str | None = None
    scan: dict | list | None = None

    model_config = {"extra": "allow"}


@app.get("/healthz")
def healthz():
    pub = dict(state)
    if isinstance(pub.get("last"), dict):          # no file name on a public endpoint (may name a patient)
        pub["last"] = {k: v for k, v in pub["last"].items() if k != "path"}
    return {"status": "ok", "version": os.environ.get("GIT_SHA", "dev"), "queue": jobs.qsize(),
            "formats": SUPPORTED_FORMATS, **pub}


def _load_mapping():
    """Reads the pseudonym table (persistent CSV + runtime generated.json).
    Returns a list of (data_type, original, pseudonym, source)."""
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
def mapping(format: str = "html", x_api_key: str = Header(default="")):
    """Original → pseudonym mapping table: it enables RE-IDENTIFICATION, hence a mandatory API key
    (X-Api-Key header); MAPPING_PUBLIC=1 makes it public for a lab demo, never in production."""
    if os.environ.get("MAPPING_PUBLIC", "0") != "1":
        _auth(x_api_key)
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
    # Log WITHOUT the payload content (a Securiti alert may carry personal values): keys + path.
    log.info("POST /sanitize keys=%s", sorted(req.model_dump(exclude_none=True).keys()))
    path = req.file_path
    if not path and req.alert is not None:
        path = _extract_path(req.alert)
    if not path:
        path = _extract_path(req.model_dump())
    if not path:
        raise HTTPException(status_code=422, detail="no file path found in the payload")
    rel = _safe_rel(_to_inbound_rel(path))
    log.info("POST /sanitize -> %s", rel)
    jobs.put({"kind": "file", "path": rel})
    return {"queued": rel, "queue": jobs.qsize()}


@app.post("/scan-completed", status_code=202)
def scan_completed(req: ScanReq, x_api_key: str = Header(default="")):
    _auth(x_api_key)
    jobs.put({"kind": "all", "scan_id": req.scan_id})
    return {"queued": "all", "queue": jobs.qsize()}
