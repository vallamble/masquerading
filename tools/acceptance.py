# -*- coding: utf-8 -*-
"""
acceptance.py — end-to-end acceptance of the eight customer requirements against what is REALLY in SharePoint.

Run after `reset_demo.py` (or with --no-upload after any reprocessing). It downloads Output, evaluates both datasets
with tools/validate.sh, then adds the checks the evaluator does not cover: stored sizes Inbound vs Output, fonts and
third-party text extraction of the 305-page PDF, signature zones really blank, italic fields, prescriber first name,
and the API security surface (key required, traversal refused, no file names on /healthz).

Env: same as tools/e2e_gap.py (GRAPH_*, SP_*, SERVICE_API_KEY, SERVICE_URL, INBOUND_PREFIX, OUTPUT_PREFIX).

    python tools/acceptance.py --ds <…/02_Phase2_dataset> --download tools/runs/acceptance
"""
import argparse
import json
import os
import subprocess
import sys

import requests

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "app"))
from graph import GraphClient  # noqa: E402


def local_files(root):
    out = []
    for r, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith((".", "_")))
        for n in sorted(names):
            if not n.startswith((".", "~$", "_")):
                out.append(os.path.relpath(os.path.join(r, n), root).replace(os.sep, "/"))
    return out


def ink_fraction(path, box):
    """Share of dark pixels inside `box` of an image: ~0 when a signature zone has been covered."""
    from PIL import Image
    import numpy as np
    a = np.asarray(Image.open(path).convert("RGB")).astype(int)
    x0, y0, x1, y1 = box
    sub = a[y0:y1, x0:x1]
    dark = (sub.min(axis=2) < 100).sum()
    return dark / max(1, sub.shape[0] * sub.shape[1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ds", required=True)
    ap.add_argument("--download", default="tools/runs/acceptance")
    a = ap.parse_args()
    url = os.environ.get("SERVICE_URL", "https://masquerading.lamble.fr").rstrip("/")
    key = os.environ["SERVICE_API_KEY"]
    inbound, output = os.environ.get("INBOUND_PREFIX", "Inbound"), os.environ.get("OUTPUT_PREFIX", "Output")
    gc = GraphClient()
    results = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail)); print(("  OK  " if ok else "  FAIL") + "  %-60s %s" % (name, detail))

    # --- 0. tree and download -------------------------------------------------------------------------------------
    inb = dict(gc.list_folder(inbound)); out = dict(gc.list_folder(output))
    base_files = local_files(os.path.join(a.ds, "inbound")); gap_files = local_files(os.path.join(a.ds, "inbound_gap"))
    expected = set(base_files) | set(gap_files)
    print("== tree")
    check("Inbound holds exactly the two datasets, flat", set(inb) == expected, "%d files, top level %s" % (len(inb), sorted({r.split('/')[0] if '/' in r else '.' for r in inb})))
    check("Output mirrors Inbound", set(out) == set(inb), "%d files" % len(out))
    for rel in sorted(expected & set(out)):
        tag = "base" if rel in base_files else "gap"
        dst = os.path.join(a.download, tag, "out", rel); os.makedirs(os.path.dirname(dst), exist_ok=True)
        gc.download(f"{output}/{rel}", dst)
    # --- 1. evaluator (requirements 1, 3, 4, 5, 6, 8 + layout of 7) --------------------------------------------------
    print("== evaluator")
    verdicts = {}
    for tag, gap in (("base", ""), ("gap", "GAP=1")):
        cmd = f'DS="{a.ds}" {gap} SKIP_SANITIZE=1 RUN_DIR={os.path.join(a.download, tag)} bash tools/validate.sh'
        res = subprocess.run(cmd, shell=True, cwd=REPO, capture_output=True, text=True)
        rep = json.load(open(os.path.join(a.download, tag, "evaluation_output.json")))
        ov = rep["overall"]; verdicts[tag] = rep
        check("R1/R3/R4/R6/R8 %s dataset: 0 leaks" % tag, ov["leaked"] == 0, "%d / %d values, verdict %s" % (ov["leaked"], ov["to_pseudonymize"], "OK" if "VERDICT : OK" in res.stdout else "FAIL"))
        dec = sum(d.get("decoys_modified", 0) for d in rep["documents"].values() if "status" not in d)
        check("R1 %s dataset: decoys untouched" % tag, dec == 0, "%d modified" % dec)
    d = verdicts["base"]["documents"]["Dossier_patients_Q3_2026_FICTIF.pdf"]["integrity"]["output"]
    check("R7 layout: 305 pages / 4 images kept", d.get("pages") == 305 and d.get("images") == 4, str(d))
    sig = verdicts["gap"].get("signatures", {}).get("summary", verdicts["gap"].get("signatures", {}))
    check("R5 handwritten signatures (raster, vector, PNG) at 0 % residual ink", sig.get("ok"), json.dumps(sig))
    emb = verdicts["gap"].get("embedded", {})
    check("R8 embedded objects found, none unsupported (0 leaks inside them)",
          all(v.get("found") and not v.get("unsupported") for v in emb.values()) and len(emb) == 2,
          json.dumps({k: v.get("found") for k, v in emb.items()}))
    coh = verdicts["gap"]["coherence"].get("Coherence_FICTIF.docx", {}) if isinstance(verdicts["gap"].get("coherence"), dict) else {}
    check("R3 same pseudonym on header/footer/image/paragraph/table",
          coh.get("leaks_in_multi_surface_values", coh.get("leaks", 0)) == 0 and coh.get("values_multi_surface", 0) >= 5,
          "%s values on several surfaces, %s leaks" % (coh.get("values_multi_surface"), coh.get("leaks_in_multi_surface_values", coh.get("leaks", 0))))
    # --- 2. requirement 7: stored sizes -----------------------------------------------------------------------------
    print("== sizes as stored by SharePoint")
    same = [r for r in inb if inb[r].get("size") == out.get(r, {}).get("size")]
    diff = {r: (inb[r].get("size"), out.get(r, {}).get("size")) for r in inb if r not in same}
    check("R7 size: identical Inbound/Output as stored", len(same) == len(inb), "%d/%d identical %s" % (len(same), len(inb), diff))
    # --- 3. typography and text extraction of the 305-page PDF -----------------------------------------------------
    print("== PDF fidelity")
    import pymupdf as fitz, pdfplumber
    pdf = os.path.join(a.download, "base", "out", "Dossier_patients_Q3_2026_FICTIF.pdf")
    fonts = sorted({f[3].split("+")[-1] for pg in fitz.open(pdf) for f in pg.get_fonts(full=True)})
    check("R7 original typeface reused (no Helvetica in a DejaVu document)", not any("Helvetica" in f for f in fonts), ", ".join(fonts))
    t = pdfplumber.open(pdf).pages[2].extract_text() or ""
    check("R7 pseudonyms extractable by third-party tools (pdfplumber)", "Vincent Bise" in t, repr(t[t.find("Vincent"):t.find("Vincent") + 14]))
    tc = fitz.open(os.path.join(a.download, "gap", "out", "Template_C_FICTIF.pdf"))[0].get_text()
    check("R1 prescriber first name masked (Anne -> Aurore)", "Aurore Rotzetter" in tc and "Anne" not in tc, [l for l in tc.splitlines() if "Rotzetter" in l])
    # --- 4. images: signature zones blank, italic kept ------------------------------------------------------------
    print("== images")
    adm = os.path.join(a.download, "base", "out", "images", "formulaire_admission_PAT-2026-26898.jpg")
    ordo = os.path.join(a.download, "base", "out", "images", "ordonnance_PAT-2026-88557.png")
    check("R5 admission form: 'Signature du patient' scribble covered", ink_fraction(adm, (450, 1552, 990, 1652)) < 0.002, "ink %.4f" % ink_fraction(adm, (450, 1552, 990, 1652)))
    check("R5 prescription: bottom-right scribble covered", ink_fraction(ordo, (804, 630, 1152, 818)) < 0.002, "ink %.4f" % ink_fraction(ordo, (804, 630, 1152, 818)))
    check("R2 admission form: footer text under the signature intact", ink_fraction(adm, (590, 1660, 1060, 1690)) > 0.03, "ink %.4f" % ink_fraction(adm, (590, 1660, 1060, 1690)))
    import sanitize_reference as sr
    from PIL import Image
    img = Image.open(adm).convert("RGB")
    sl = sr._ink_slant(img, (440, 250, 700, 300), (253, 253, 250))
    check("R2 handwritten (italic) field rewritten in italic", sl is not None and sl >= 0.10, "slant %.2f" % (sl or 0))
    # --- 5. security surface -------------------------------------------------------------------------------------
    print("== API security")
    h = requests.get(f"{url}/healthz", timeout=30).json()
    check("healthz public without file names", "path" not in json.dumps(h.get("last") or {}), json.dumps(h)[:100])
    check("/mapping refused without key", requests.get(f"{url}/mapping", timeout=30).status_code == 401)
    check("/mapping served with key", requests.get(f"{url}/mapping", headers={"X-Api-Key": key}, timeout=30).status_code == 200)
    check("POST /sanitize refused without key", requests.post(f"{url}/sanitize", json={"file_path": "x.pdf"}, timeout=30).status_code == 401)
    r = requests.post(f"{url}/sanitize", headers={"X-Api-Key": key}, json={"file_path": "Inbound/../Output/x.pdf"}, timeout=30)
    check("path traversal refused (422)", r.status_code == 422, r.text[:80])
    r = requests.post(f"{url}/sanitize", headers={"X-Api-Key": key}, json={"file_path": "Inbound/x.exe"}, timeout=30)
    check("unsupported extension refused (422)", r.status_code == 422, r.text[:80])
    ok = sum(1 for _, o, _ in results if o)
    print("\n== %d / %d checks passed" % (ok, len(results)))
    sys.exit(0 if ok == len(results) else 2)


if __name__ == "__main__":
    main()
