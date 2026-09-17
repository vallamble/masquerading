# -*- coding: utf-8 -*-
"""
evaluate_output.py — Evaluates an Output folder (sanitized files) against the ground truth.

Measures (per document and per data_type):
  - LEAKS: original values to pseudonymize still present (text layer; Tesseract OCR for standalone images,
    images embedded in DOCX (word/media) and images embedded in PDF (pypdf))
  - EXPECTED SUBSTITUTIONS present (if the sanitizer uses the mapping_by_value.csv table)
  - PRESERVED PHI (diagnoses/medications) still readable (default profile) — or masked with --strict
  - MEANINGFULNESS: every string in IBAN / AHV / card format found in the output is valid
    (mod-97 / EAN-13 / Luhn) and no placeholder (XXXX, ****, [REDACTED]) appears
  - INTEGRITY: PDF page count, DOCX paragraphs, XLSX dimensions, image count, text length ratio
Usage: python3 evaluate_output.py --inbound ../inbound --output <Output dir> --ground-truth ../ground_truth [--strict]
Output: Markdown + JSON report in --report-dir (default: the Output folder)
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from synth_core import iban_is_valid, ahv_is_valid, luhn_is_valid

norm = lambda s: re.sub(r"\s+", "", s or "").casefold()
collapse = lambda s: re.sub(r"\s+", " ", s or "").casefold()
PLACEHOLDER_RE = re.compile(r"X{4,}|\*{4,}|\[(?:REDACTED|MASQU[ÉE]|SUPPRIM[ÉE])\]|#{4,}|_{5,}", re.I)
WORD_TYPES = {"FIRST_NAME", "LAST_NAME", "STREET_ADDRESS", "POSTAL_CITY", "EMAIL", "MEDICATION", "DIAGNOSIS_LABEL", "DIAGNOSIS_ICD"}


def contains(hay_raw, value, dtype, is_ocr=False):
    """Presence of a value: word boundaries for textual types (avoids Valentin ⊂ Valentine),
    whitespace-insensitive for numeric identifiers (IBAN with/without spaces...). OCR is more tolerant."""
    if dtype in WORD_TYPES and not is_ocr:
        pat = r"(?<![\w])" + re.escape(collapse(value)) + r"(?![\w])"
        return re.search(pat, collapse(hay_raw)) is not None
    return norm(value) in norm(hay_raw)


def ocr_text(img_bytes_or_path):
    txt = ""
    path = img_bytes_or_path
    tmp = None
    if isinstance(img_bytes_or_path, (bytes, bytearray)):
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False); tmp.write(img_bytes_or_path); tmp.close(); path = tmp.name
    # OCR on a 2x upscaled image: Tesseract confuses O/0 below ~30 px ("CH6O"), which was hiding leaks
    try:
        from PIL import Image
        im = Image.open(path).convert("RGB")
        if im.width * im.height <= 3_000_000:
            im = im.resize((im.width * 2, im.height * 2), Image.LANCZOS)
        up = tempfile.NamedTemporaryFile(suffix=".png", delete=False); im.save(up.name); up.close()
        if tmp:
            os.unlink(tmp.name)
        tmp = up; path = up.name
    except Exception:
        pass
    for psm in ("6", "11"):
        try:
            txt += subprocess.run(["tesseract", path, "stdout", "--psm", psm], capture_output=True, text=True, timeout=180).stdout + "\n"
        except Exception:
            pass
    if tmp:
        os.unlink(tmp.name)
    return txt


SOFFICE_CANDIDATES = [os.environ.get("SOFFICE", ""), "/usr/bin/soffice", "/usr/lib/libreoffice/program/soffice",
                      os.path.expanduser("~/Applications/LibreOffice.app/Contents/MacOS/soffice"),
                      "/Applications/LibreOffice.app/Contents/MacOS/soffice"]


def soffice_bin():
    for c in SOFFICE_CANDIDATES:
        if c and os.path.exists(c):
            return c
    return None


def soffice_convert(src, fmt, outdir):
    """Headless LibreOffice conversion with an isolated user profile (two simultaneous conversions do not block
    each other)."""
    exe = soffice_bin()
    if not exe:
        raise RuntimeError("LibreOffice (soffice) introuvable — nécessaire pour l'évaluation RTF")
    prof = tempfile.mkdtemp(prefix="lo_eval_")
    subprocess.run([exe, "--headless", "--norestore", "-env:UserInstallation=file://%s" % prof, "--convert-to", fmt,
                    "--outdir", outdir, src], capture_output=True, text=True, timeout=180)
    import shutil; shutil.rmtree(prof, ignore_errors=True)
    out = os.path.join(outdir, os.path.splitext(os.path.basename(src))[0] + "." + fmt)
    if not os.path.exists(out):
        raise RuntimeError("conversion LibreOffice %s -> %s échouée" % (src, fmt))
    return out


def docx_full_text(path):
    """DOCX text: paragraphs, tables, headers and footers of each section (+ locs)."""
    from docx import Document
    d = Document(path)
    parts, locs = [], {}
    for i, p in enumerate(d.paragraphs):
        parts.append(p.text); locs["paragraph:%d" % i] = p.text
    for ti, t in enumerate(d.tables):
        for ri, row in enumerate(t.rows):
            for ci, c in enumerate(row.cells):
                parts.append(c.text); locs["table%d!r%d,c%d" % (ti, ri, ci)] = c.text
    for si, sec in enumerate(d.sections):
        for kind, hf in (("header", sec.header), ("footer", sec.footer)):
            txt = "\n".join(p.text for p in hf.paragraphs) + "\n" + "\n".join(c.text for t in hf.tables for r in t.rows for c in r.cells)
            parts.append(txt); locs["%s:%d" % (kind, si)] = txt
    return "\n".join(parts), locs, {"paragraphs": len(d.paragraphs), "tables": len(d.tables), "sections": len(d.sections)}


def ocr_pdf_page(page, dpi=300):
    """Render of the page (/Rotate rotation applied) -> OCR. Used for pages WITHOUT a text layer (scans)."""
    pix = page.get_pixmap(dpi=dpi)
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False); tmp.close()
    pix.save(tmp.name)
    txt = ""
    for psm in ("6", "11"):
        try:
            txt += subprocess.run(["tesseract", tmp.name, "stdout", "--psm", psm], capture_output=True, text=True, timeout=300).stdout + "\n"
        except Exception:
            pass
    os.unlink(tmp.name)
    return txt


def ink_ratio_pdf(path, page_no, box, dpi=200):
    import fitz, numpy as np
    doc = fitz.open(path); page = doc[page_no - 1]
    pix = page.get_pixmap(dpi=dpi, clip=fitz.Rect(*box))
    a = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)[:, :, :3]
    return float((a.min(axis=2) < 128).mean())


def ink_ratio_img(path, box):
    import numpy as np
    from PIL import Image
    im = Image.open(path).convert("RGB").crop(tuple(int(v) for v in box))
    a = np.asarray(im)
    return float((a.min(axis=2) < 128).mean()) if a.size else 0.0


def extract_embedded(path, depth=0):
    """Embedded objects: DOCX word/embeddings/*, XLSX xl/embeddings/*, PDF attachments. Returns
    [(name, text, image_texts, stats)], evaluating recursively (max depth 3)."""
    out = []
    if depth > 3:
        return out
    ext = os.path.splitext(path)[1].lower()
    tmpd = tempfile.mkdtemp(prefix="emb_eval_")
    members = []
    if ext in (".docx", ".xlsx"):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.startswith(("word/embeddings/", "xl/embeddings/")):
                    dst = os.path.join(tmpd, os.path.basename(n)); open(dst, "wb").write(z.read(n)); members.append((n, dst))
    elif ext == ".pdf":
        try:
            import fitz
            doc = fitz.open(path)
            for i in range(doc.embfile_count()):
                info = doc.embfile_info(i); fn = info.get("filename") or info.get("name") or "embfile%d" % i
                dst = os.path.join(tmpd, os.path.basename(fn)); open(dst, "wb").write(doc.embfile_get(i)); members.append(("embfile:" + fn, dst))
        except Exception as e:  # noqa
            out.append(("embfile_error", repr(e), [], {}))
    for name, dst in members:
        try:
            ex = extract(dst, depth + 1)
            out.append((name, ex["text"], ex["image_texts"], ex["stats"]))
            out += [("%s > %s" % (name, n2), t2, i2, s2) for n2, t2, i2, s2 in ex.get("embedded", [])]
        except Exception as e:  # noqa
            out.append((name, "", [], {"error": repr(e)}))
    return out


def extract(path, depth=0):
    """Returns a dict: pages(list[str]) for PDF, text(str), image_texts(list[str]), stats(dict),
    locs: text addressable by location ('sheet!cell', 'paragraph:i', 'table0!r,c') for the finest-grained check."""
    ext = os.path.splitext(path)[1].lower()
    res = {"pages": None, "text": "", "image_texts": [], "stats": {}, "locs": {}, "page_ocr": {}, "embedded": []}
    if ext == ".rtf":
        # RTF: LibreOffice -> DOCX -> python-docx (headers/footers/tables included; the txt export loses them)
        tmpd = tempfile.mkdtemp(prefix="rtf_eval_")
        docx_path = soffice_convert(path, "docx", tmpd)
        res["text"], res["locs"], st = docx_full_text(docx_path)
        res["stats"].update(st)
        return res
    if ext == ".pdf":
        import pdfplumber
        from pypdf import PdfReader
        with pdfplumber.open(path) as pdf:
            res["pages"] = [p.extract_text() or "" for p in pdf.pages]
        res["text"] = "\n".join(res["pages"])
        # pages without a text layer (scans): 300 dpi render -> OCR (the /Rotate rotation is applied by the render)
        try:
            import fitz
            doc = fitz.open(path)
            for i, pg in enumerate(doc):
                if not res["pages"][i].strip() and pg.get_images():
                    res["page_ocr"][i + 1] = ocr_pdf_page(pg)
            res["stats"]["scanned_pages"] = sorted(res["page_ocr"])
        except Exception as e:  # noqa
            res["stats"]["scan_ocr_error"] = repr(e)
        n_img = 0
        try:
            rd = PdfReader(path)
            for pg in rd.pages:
                for im in pg.images:
                    n_img += 1
                    res["image_texts"].append(ocr_text(im.data))
        except Exception as e:  # noqa
            res["stats"]["image_extract_error"] = repr(e)
        res["stats"].update({"pages": len(res["pages"]), "images": n_img})
    elif ext == ".docx":
        from docx import Document
        d = Document(path)
        # full text = paragraphs + tables + headers/footers of each section (a PII "in the footer only"
        # was invisible to the evaluator before 17.09)
        res["text"], res["locs"], _st = docx_full_text(path)
        n_img = 0
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.startswith("word/media/") and n.lower().endswith((".png", ".jpg", ".jpeg")):
                    n_img += 1; res["image_texts"].append(ocr_text(z.read(n)))
        res["stats"].update({"paragraphs": len(d.paragraphs), "tables": len(d.tables), "images": n_img})
    elif ext == ".xlsx":
        from openpyxl import load_workbook
        wb = load_workbook(path, data_only=True)
        parts, dims = [], {}
        for ws in wb.worksheets:
            dims[ws.title] = "%dx%d" % (ws.max_row, ws.max_column)
            for row in ws.iter_rows():
                for c in row:
                    if c.value is not None:
                        parts.append(str(c.value))
                        res["locs"]["%s!%s" % (ws.title, c.coordinate)] = str(c.value)
        res["text"] = "\n".join(parts)
        res["stats"].update({"sheets": dims})
    elif ext in (".png", ".jpg", ".jpeg"):
        res["image_texts"].append(ocr_text(path))
        from PIL import Image
        with Image.open(path) as im:
            res["stats"].update({"size": im.size})
    if ext in (".docx", ".xlsx", ".pdf"):
        res["embedded"] = extract_embedded(path, depth)
        if res["embedded"]:
            res["stats"]["embedded"] = [n for n, *_ in res["embedded"]]
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inbound", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--ground-truth", required=True, help="dossier ground_truth/")
    ap.add_argument("--strict", action="store_true", help="le PHI (diagnostics/médications) doit AUSSI être masqué")
    ap.add_argument("--report-dir")
    ap.add_argument("--gt-csv", help="fichier ground truth (défaut : <ground-truth>/ground_truth.csv)")
    ap.add_argument("--decoys", help="fichier de leurres (défaut : <ground-truth>/decoys.csv)")
    ap.add_argument("--signatures", help="boîtes de signatures (signatures_gap.csv) : encre résiduelle après masquage")
    a = ap.parse_args()
    rows = list(csv.DictReader(open(a.gt_csv or os.path.join(a.ground_truth, "ground_truth.csv"), encoding="utf-8")))
    docs = sorted({r["document"] for r in rows})
    # decoys: invalid by construction, they must remain intact (over-masking measure)
    decoy_doc, decoy_values = {}, set()
    dec_path = a.decoys or os.path.join(a.ground_truth, "decoys.csv")
    if os.path.exists(dec_path):
        for r in csv.DictReader(open(dec_path, encoding="utf-8")):
            v = (r.get("value") or "").strip()
            if v:
                decoy_doc.setdefault(r.get("document", ""), []).append(v)
                decoy_values.add(v)
    report = {"documents": {}, "by_type": {}, "signifiance": {}, "leaks": [], "size_delta": {}}
    agg = {}

    def bump(t, k, n=1):
        agg.setdefault(t, {"to_pseudonymize": 0, "leaked": 0, "replacement_present": 0, "keep_expected": 0, "keep_present": 0,
                           "image_to_pseudonymize": 0, "image_leaked": 0})
        agg[t][k] += n

    for doc in docs:
        out_path = os.path.join(a.output, doc)
        in_path = os.path.join(a.inbound, doc)
        drows = [r for r in rows if r["document"] == doc]
        if not os.path.exists(out_path):
            report["documents"][doc] = {"status": "ABSENT de Output (non traité)", "gt_rows": len(drows)}
            for r in drows:
                if r["expected_action"] == "PSEUDONYMIZE":
                    bump(r["data_type"], "to_pseudonymize"); bump(r["data_type"], "leaked")
                    if r["location_type"] == "image":
                        bump(r["data_type"], "image_to_pseudonymize"); bump(r["data_type"], "image_leaked")
            continue
        ex = extract(out_path)
        ex_in = extract(in_path) if os.path.exists(in_path) else None
        # size delta ("same file size" requirement: we measure it, we do not promise it)
        if os.path.exists(in_path):
            si, so = os.path.getsize(in_path), os.path.getsize(out_path)
            report["size_delta"][doc] = {"in": si, "out": so, "pct": round(100.0 * (so - si) / max(1, si), 1)}
        img_txt = " ".join(ex["image_texts"])
        emb_txt = " ".join(t + " " + " ".join(i) for _, t, i, _ in ex.get("embedded", []))
        d = {"leaks": 0, "replacements_present": 0, "to_pseudonymize": 0, "keep_expected": 0, "keep_present": 0,
             "image_to_pseudonymize": 0, "image_leaks": 0, "leak_examples": []}

        def scope_text(r):
            """Text of the finest known scope for the GT row (PDF page, XLSX cell(s), DOCX paragraph)."""
            if r["location_type"] == "image":
                if ex["pages"] is not None and r["page"] and int(r["page"]) in ex.get("page_ocr", {}):
                    return ex["page_ocr"][int(r["page"])] + " " + img_txt, True     # scanned page: OCR of the render
                return img_txt, True
            if r["location_type"].startswith("embedded"):
                return emb_txt, False
            if ex["pages"] and r["page"]:
                pg = int(r["page"])
                return (ex["pages"][pg - 1] if 1 <= pg <= len(ex["pages"]) else ex["text"]), False
            if r["location_type"] == "cell" and r["sheet"] and r["cell"]:
                cells = r["cell"].split(":")
                return " ".join(ex["locs"].get("%s!%s" % (r["sheet"], c), "") for c in cells), False
            if r["location_type"] == "paragraph" and r["paragraph"] != "":
                return ex["locs"].get("paragraph:%s" % r["paragraph"], ex["text"]), False
            if r["location_type"] == "table_cell" and r["cell"]:
                return ex["locs"].get(r["cell"], ex["text"]), False
            return ex["text"], False

        for r in drows:
            t = r["data_type"]
            is_img = r["location_type"] == "image"
            must_hide = r["expected_action"] == "PSEUDONYMIZE" or a.strict   # KEEP: to be masked only in strict mode
            hay, is_ocr = scope_text(r)
            if must_hide:
                d["to_pseudonymize"] += 1; bump(t, "to_pseudonymize")
                if is_img:
                    d["image_to_pseudonymize"] += 1; bump(t, "image_to_pseudonymize")
                leaked = contains(hay, r["value"], t, is_ocr)   # any residual original value within its scope = a leak
                if leaked:
                    d["leaks"] += 1; bump(t, "leaked")
                    if is_img:
                        d["image_leaks"] += 1; bump(t, "image_leaked")
                    if len(d["leak_examples"]) < 15:
                        d["leak_examples"].append("%s p.%s %s '%s' (%s)" % (r["gt_id"], r["page"], t, r["value"], r["variant"]))
                    report["leaks"].append({"document": doc, "gt_id": r["gt_id"], "page": r["page"], "type": t, "value": r["value"],
                                            "variant": r["variant"], "location_type": r["location_type"]})
                target = r["strict_replacement"] if (a.strict and r["expected_action"] == "KEEP") else r["expected_replacement"]
                if contains(hay, target, t, is_ocr):
                    d["replacements_present"] += 1; bump(t, "replacement_present")
            else:
                d["keep_expected"] += 1; bump(t, "keep_expected")
                if contains(hay, r["value"], t, is_ocr):
                    d["keep_present"] += 1; bump(t, "keep_present")
        # meaningfulness: valid formats in the output.
        # Two measurement fixes (15.09): (1) PDF extraction sometimes glues an alphabetic token to the end
        # of an IBAN ("AT61 … 7252 CHF") → retry without that token before declaring the IBAN invalid;
        # (2) the dataset decoys are invalid BY CONSTRUCTION and must stay so → they are excluded from the
        # denominator, otherwise the metric punishes the expected behaviour.
        full = ex["text"] + " " + " ".join(ex["image_texts"]) + " " + emb_txt + " " + " ".join(ex.get("page_ocr", {}).values())
        iban_re = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")

        def iban_ok(x):
            if iban_is_valid(x):
                return True
            toks = x.split()
            return len(toks) > 2 and toks[-1].isalpha() and iban_is_valid(" ".join(toks[:-1]))

        dec_norm = {norm(x) for x in decoy_values}
        ibans = [x for x in iban_re.findall(full) if norm(x) not in dec_norm]
        ahvs = [x for x in re.findall(r"\b756\.\d{4}\.\d{4}\.\d{2}\b", full) if norm(x) not in dec_norm]
        no_iban = iban_re.sub(" ", full)   # avoid IBAN fragments being counted as "card"
        cards = [x for x in re.findall(r"\b(?:\d{4}[ ]?){3}\d{4}\b|\b\d{4}[ ]?\d{6}[ ]?\d{5}\b", no_iban)
                 if norm(x) not in dec_norm]
        d["format_validity"] = {
            "iban_like": len(ibans), "iban_valid": sum(iban_ok(x) for x in ibans),
            "ahv_like": len(ahvs), "ahv_valid": sum(ahv_is_valid(x) for x in ahvs),
            "card_like": len(cards), "card_luhn_valid": sum(luhn_is_valid(x) for x in cards),
            "placeholders_XXXX_etc": len(PLACEHOLDER_RE.findall(ex["text"])),
            "note": "leurres exclus du dénominateur ; IBAN avec jeton alphabétique collé (artefact d'extraction) comptés valides",
        }
        # over-masking: a modified decoy is a false positive of the sanitizer (precision measure)
        touched = [x for x in decoy_doc.get(doc, []) if x and norm(x) not in norm(full)]
        d["decoys_total"] = len(decoy_doc.get(doc, []))
        d["decoys_modified"] = len(touched)
        d["decoys_modified_examples"] = touched[:10]
        # integrity
        integ = {"output": ex["stats"]}
        if ex_in:
            integ["inbound"] = ex_in["stats"]
            integ["text_length_ratio"] = round(len(ex["text"]) / max(1, len(ex_in["text"])), 3)
            if ex["pages"] is not None and ex_in["pages"] is not None:
                integ["pages_equal"] = len(ex["pages"]) == len(ex_in["pages"])
        d["integrity"] = integ
        d["leak_rate"] = round(d["leaks"] / d["to_pseudonymize"], 4) if d["to_pseudonymize"] else None
        d["replacement_rate"] = round(d["replacements_present"] / d["to_pseudonymize"], 4) if d["to_pseudonymize"] else None
        d["keep_rate"] = round(d["keep_present"] / d["keep_expected"], 4) if d["keep_expected"] else None
        report["documents"][doc] = d

    # signatures: residual ink in each box (target < 2 % of the input ink); graphic decoys intact (± 5 %)
    if a.signatures and os.path.exists(a.signatures):
        sig_rows, ok_all = [], True
        for r in csv.DictReader(open(a.signatures, encoding="utf-8")):
            box = (float(r["x0"]), float(r["y0"]), float(r["x1"]), float(r["y1"]))
            ip, op = os.path.join(a.inbound, r["file"]), os.path.join(a.output, r["file"])
            if not os.path.exists(op):
                sig_rows.append(dict(r, status="ABSENT")); ok_all = False; continue
            vec_resid = None
            if r["file"].lower().endswith(".pdf"):
                i_ink, o_ink = ink_ratio_pdf(ip, int(r["page"]), box), ink_ratio_pdf(op, int(r["page"]), box)
                # RESIDUAL vector/text/image content under the overlay (invisible in the render, present in the stream):
                # a curved path or a non-white image inside the signature box = recoverable shape of the initials
                if r["kind"].startswith("signature"):
                    import fitz
                    pg = fitz.open(op)[int(r["page"]) - 1]; bx = fitz.Rect(*box)
                    curves = sum(1 for dr in pg.get_drawings() if any(it[0] == "c" for it in dr["items"]) and fitz.Rect(dr["rect"]).intersects(bx))
                    imgs = 0
                    for im in pg.get_images(full=True):
                        for ir in pg.get_image_rects(im[0]):
                            if ir.intersects(bx):
                                pix = fitz.Pixmap(pg.parent, im[0])
                                if pix.n - pix.alpha >= 1 and pix.samples and (min(pix.samples) < 200):
                                    imgs += 1
                    vec_resid = {"curves": curves, "dark_images": imgs}
            else:
                i_ink, o_ink = ink_ratio_img(ip, box), ink_ratio_img(op, box)
            resid = o_ink / i_ink if i_ink else 0.0
            if r["kind"].startswith("signature"):
                ok = resid < 0.02 and (vec_resid is None or (vec_resid["curves"] == 0 and vec_resid["dark_images"] == 0))
            else:
                ok = abs(o_ink - i_ink) <= 0.05 * max(i_ink, 1e-9)
            ok_all = ok_all and ok
            sig_rows.append(dict(r, ink_in=round(i_ink, 4), ink_out=round(o_ink, 4), residual=round(resid, 4), vector_residual=vec_resid, ok=ok))
        report["signatures"] = {"rows": sig_rows, "summary": {
            "ok": ok_all, "signatures": sum(1 for x in sig_rows if x["kind"].startswith("signature")),
            "signatures_ok": sum(1 for x in sig_rows if x["kind"].startswith("signature") and x.get("ok")),
            "decoys": sum(1 for x in sig_rows if x["kind"].startswith("decoy")),
            "decoys_intact": sum(1 for x in sig_rows if x["kind"].startswith("decoy") and x.get("ok")),
            "residual_max": max([x.get("residual", 0) for x in sig_rows if x["kind"].startswith("signature")] or [0])}}
    # multi-surface coherence (#3): for each (document, value) present in ≥ 2 location types, the expected pseudonym
    # must be present on EACH surface (paragraph, table, header/footer, image, embedded)
    coh = {}
    for doc in docs:
        out_path = os.path.join(a.output, doc)
        if not os.path.exists(out_path):
            continue
        groups = {}
        for r in rows:
            if r["document"] == doc and r["expected_action"] == "PSEUDONYMIZE":
                groups.setdefault(r["value"], set()).add(r["section"] or r["location_type"])
        multi = {v: s_ for v, s_ in groups.items() if len(s_) >= 2}
        if multi:
            d = report["documents"][doc]
            miss = [l for l in report["leaks"] if l["document"] == doc and l["value"] in multi]
            coh[doc] = {"values_multi_surface": len(multi), "surfaces": {v: sorted(s_) for v, s_ in list(multi.items())[:6]},
                        "leaks_in_multi_surface_values": len(miss), "replacement_rate": d.get("replacement_rate")}
    if coh:
        report["coherence"] = coh
    # embedded objects: found (by the evaluator) vs processed (sanitizer log, if it exists)
    emb = {}
    for doc in docs:
        op = os.path.join(a.output, doc)
        if os.path.exists(op) and op.lower().endswith((".docx", ".xlsx", ".pdf")):
            found = [n for n, *_ in extract_embedded(op)]
            if found:
                emb[doc] = {"found": found}
    slog = os.path.join(a.output, "sanitization_log.json")
    if emb and os.path.exists(slog):
        try:
            sl = json.load(open(slog, encoding="utf-8"))["files"]
            for doc in emb:
                e = sl.get(doc, {}).get("embedded", {})
                emb[doc].update({"processed": e.get("processed", []), "unsupported": e.get("unsupported", [])})
        except Exception as e:  # noqa
            emb["log_error"] = repr(e)
    if emb:
        report["embedded"] = emb

    for t, s in agg.items():
        s["leak_rate"] = round(s["leaked"] / s["to_pseudonymize"], 4) if s["to_pseudonymize"] else None
        s["replacement_rate"] = round(s["replacement_present"] / s["to_pseudonymize"], 4) if s["to_pseudonymize"] else None
        s["image_leak_rate"] = round(s["image_leaked"] / s["image_to_pseudonymize"], 4) if s["image_to_pseudonymize"] else None
        report["by_type"][t] = s
    tot_p = sum(s["to_pseudonymize"] for s in agg.values()); tot_l = sum(s["leaked"] for s in agg.values())
    tot_r = sum(s["replacement_present"] for s in agg.values())
    report["overall"] = {"to_pseudonymize": tot_p, "leaked": tot_l, "leak_rate": round(tot_l / tot_p, 4) if tot_p else None,
                         "replacement_rate": round(tot_r / tot_p, 4) if tot_p else None}

    rd = a.report_dir or a.output
    os.makedirs(rd, exist_ok=True)
    json.dump(report, open(os.path.join(rd, "evaluation_output.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    md = ["# Évaluation de la sortie assainie", "", "Mode : %s" % ("STRICT (PHI masqué)" if a.strict else "par défaut (PHI conservé, identifiants pseudonymisés)"), "",
          "## Global", "", "| Occurrences à pseudonymiser | Fuites | Taux de fuite | Substitutions attendues présentes |", "|---|---|---|---|",
          "| %d | %d | %s | %s |" % (tot_p, tot_l, report["overall"]["leak_rate"], report["overall"]["replacement_rate"]), "",
          "## Par type de donnée", "", "| Type | À pseudonymiser | Fuites | Taux de fuite | Subst. présentes | dont images : à traiter / fuites |", "|---|---|---|---|---|---|"]
    for t, s in sorted(report["by_type"].items()):
        md.append("| %s | %d | %d | %s | %s | %d / %d |" % (t, s["to_pseudonymize"], s["leaked"], s["leak_rate"], s["replacement_rate"], s["image_to_pseudonymize"], s["image_leaked"]))
    md += ["", "## Par document", ""]
    for doc, d in report["documents"].items():
        if "status" in d:
            md.append("- **%s** : %s (%d occurrences)" % (doc, d["status"], d["gt_rows"])); continue
        md.append("- **%s** : fuites %d/%d (taux %s), substitutions présentes %s, PHI conservé %s/%s ; leurres modifiés %d/%d ; formats : IBAN valides %d/%d, AVS %d/%d, cartes Luhn %d/%d, placeholders %d ; intégrité : %s" % (
            doc, d["leaks"], d["to_pseudonymize"], d["leak_rate"], d["replacement_rate"], d["keep_present"], d["keep_expected"],
            d.get("decoys_modified", 0), d.get("decoys_total", 0),
            d["format_validity"]["iban_valid"], d["format_validity"]["iban_like"], d["format_validity"]["ahv_valid"], d["format_validity"]["ahv_like"],
            d["format_validity"]["card_luhn_valid"], d["format_validity"]["card_like"], d["format_validity"]["placeholders_XXXX_etc"],
            json.dumps(d["integrity"], ensure_ascii=False)))
        for e in d["leak_examples"]:
            md.append("    - fuite : %s" % e)
        for e in d.get("decoys_modified_examples", []):
            md.append("    - leurre modifié (faux positif) : %s" % e)
    if report.get("signatures"):
        md += ["", "## Signatures (encre résiduelle, contenu résiduel sous le recouvrement) et leurres graphiques", "", "| Fichier | Page | Type | Encre entrée | Encre sortie | Résiduel | Résiduel vectoriel/image | OK |", "|---|---|---|---|---|---|---|---|"]
        for x in report["signatures"]["rows"]:
            md.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (x["file"], x["page"], x["kind"], x.get("ink_in"), x.get("ink_out"), x.get("residual"), json.dumps(x.get("vector_residual")), x.get("ok", x.get("status"))))
    if report.get("coherence"):
        md += ["", "## Cohérence multi-surfaces (même pseudonyme dans le texte, les tableaux, les en-têtes/pieds, les images)", ""]
        for doc, c in report["coherence"].items():
            md.append("- **%s** : %d valeurs présentes sur ≥ 2 surfaces, fuites parmi elles %d, taux de substitution %s ; ex. %s" % (
                doc, c["values_multi_surface"], c["leaks_in_multi_surface_values"], c["replacement_rate"], json.dumps(c["surfaces"], ensure_ascii=False)[:300]))
    if report.get("embedded"):
        md += ["", "## Objets imbriqués", ""]
        for doc, e in report["embedded"].items():
            md.append("- **%s** : trouvés %s ; traités %s ; non traités %s" % (doc, e.get("found"), e.get("processed", "?"), e.get("unsupported", "?")))
    md += ["", "## Delta de taille par fichier", "", "| Fichier | Entrée (o) | Sortie (o) | Delta |", "|---|---|---|---|"]
    for doc, v in report["size_delta"].items():
        md.append("| %s | %d | %d | %+.1f %% |" % (doc, v["in"], v["out"], v["pct"]))
    open(os.path.join(rd, "evaluation_output.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
