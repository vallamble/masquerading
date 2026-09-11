# -*- coding: utf-8 -*-
"""
sanitize_reference.py — Implémentation de RÉFÉRENCE du service de sanitization (option B de l'étude Phase 1).

Rôle : prouver la faisabilité de la pseudonymisation « signifiante » et cohérente hors Securiti, et servir de socle
au service (Azure Function / conteneur) appelé par le workflow Securiti (HTTP Request) ou par Power Automate.

  Entrées
    --inbound   dossier des fichiers à assainir (PDF, DOCX, XLSX, PNG/JPG)
    --output    dossier de sortie (copies assainies + sanitization_log.json)
    --mapping   table valeur -> substitution (ground_truth/mapping_by_value.csv) ; les valeurs inconnues détectées par
                motif (IBAN, AVS, carte, e-mail, téléphone, n° patient, n° carte d'assuré) reçoivent une substitution
                DÉTERMINISTE (HMAC) au format valide (IBAN mod-97, AVS EAN-13, carte de test, etc.)
    --evidence  (optionnel) export d'evidences Securiti (CSV) : ajoute ses valeurs détectées à la liste à substituer
    --strict    remplace aussi diagnostics/médications par leur généralisation (colonne strict_replacement du ground truth)

  Formats
    DOCX : paragraphes + tableaux + en-têtes/pieds ; images incorporées (word/media) passées à l'OCR-rédaction
    XLSX : toutes les cellules texte (formules conservées)
    PNG/JPG : OCR Tesseract (TSV, boîtes de mots) -> recouvrement de la zone + écriture du pseudonyme
    PDF  : PyMuPDF (fitz) si disponible : redaction des spans + réinsertion du pseudonyme, images incorporées
           extraites -> OCR-rédaction -> remplacées. Sans PyMuPDF : fichier ignoré (message).

Limites connues (référence, pas production) : pas de NER pour des noms hors mapping (prévoir Presidio/spaCy dans le
service), formatage du paragraphe DOCX ramené au style du premier run quand une valeur est modifiée, valeurs
coupées sur deux lignes dans les images non traitées.
"""
import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from synth_core import (iban_is_valid, iban_check_digits, ahv_is_valid, ean13_check_digit, luhn_is_valid,
                        TEST_CARDS_PSEUDO, iban_format)

SECRET = b"demo-secret-change-me"   # clé HMAC du déterminisme (à stocker dans Key Vault en production)
KEEP_TYPES = {"DIAGNOSIS_ICD", "DIAGNOSIS_LABEL", "MEDICATION"}


def norm(s):
    return re.sub(r"\s+", "", s or "")


def hnum(value, n):
    """Entier déterministe à n chiffres dérivé de la valeur (HMAC-SHA256)."""
    h = hmac.new(SECRET, norm(value).upper().encode(), hashlib.sha256).hexdigest()
    return str(int(h, 16) % (10 ** n)).zfill(n)


# ---------------------------------------------------------------------------
class Pseudonymizer:
    """Table de pseudonymes + détection par motif + génération déterministe pour les inconnues."""

    PATTERNS = [
        ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")),
        ("AHV_NUMBER", re.compile(r"\b756\.\d{4}\.\d{4}\.\d{2}\b")),
        ("INSURANCE_CARD_NUMBER", re.compile(r"\b80756(?:[ ]?\d{5}){3}\b")),
        ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[ ]?){3}\d{4}\b|\b\d{4}[ ]?\d{6}[ ]?\d{5}\b")),
        ("PATIENT_ID", re.compile(r"\bPAT-\d{4}-\d{5}\b")),
        ("EMAIL", re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)),
        ("PHONE", re.compile(r"(?:\+41 \d{2} \d{3} \d{2} \d{2}|\b0\d{2} \d{3} \d{2} \d{2}\b|\+33 \d \d{2} \d{2} \d{2} \d{2})")),
    ]

    def __init__(self, mapping_csv, strict_csv=None, evidence_values=None):
        self.map = {}          # clé normalisée -> (data_type, substitution)
        self.exact = {}        # valeur exacte -> substitution
        with open(mapping_csv, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                self.exact[r["original_value"]] = (r["data_type"], r["replacement_value"])
                self.map[norm(r["original_value"]).casefold()] = (r["data_type"], r["replacement_value"])
        self.strict = {}
        if strict_csv:
            with open(strict_csv, encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    if r["expected_action"] == "KEEP":
                        self.strict[r["value"]] = (r["data_type"], r["strict_replacement"])
        self.extra_values = set(evidence_values or [])
        # motif « dictionnaire » : toutes les valeurs connues, les plus longues d'abord, frontières de mot
        keys = sorted(set(list(self.exact) + list(self.strict) + list(self.extra_values)), key=len, reverse=True)
        keys = [k for k in keys if len(k) >= 3]
        self.dict_re = re.compile("|".join(r"(?<![\w@.])" + re.escape(k) + r"(?![\w@])" for k in keys)) if keys else None
        self.generated = {}

    # --- génération déterministe pour valeurs hors table ---------------------
    def generate(self, dtype, value):
        key = norm(value).upper()
        if key in self.generated:
            return self.generated[key]
        if dtype == "IBAN":
            cc = key[:2]
            bban_len = len(key) - 4
            digits = hnum(value, bban_len)
            if cc == "CH":
                digits = "8" + digits[1:]
            rep = iban_format(cc + iban_check_digits(cc, digits) + digits)
            if " " not in value:
                rep = rep.replace(" ", "")
        elif dtype == "AHV_NUMBER":
            d12 = "756" + hnum(value, 9)
            d13 = d12 + ean13_check_digit(d12)
            rep = "%s.%s.%s.%s" % (d13[0:3], d13[3:7], d13[7:11], d13[11:13])
        elif dtype == "CREDIT_CARD":
            rep = TEST_CARDS_PSEUDO[int(hnum(value, 4)) % len(TEST_CARDS_PSEUDO)][1]
        elif dtype == "INSURANCE_CARD_NUMBER":
            s = "80756" + hnum(value, 15)
            rep = " ".join(s[i:i + 5] for i in range(0, 20, 5))
        elif dtype == "PATIENT_ID":
            rep = "PAT-%s-%s" % (value[4:8], hnum(value, 5))
        elif dtype == "EMAIL":
            rep = "contact.%s@example.org" % hnum(value, 6)
        elif dtype == "PHONE":
            rep = "+41 79 000 %s %s" % (hnum(value, 2), hnum(value + "b", 2))
        else:
            rep = "[%s]" % dtype
        self.generated[key] = rep
        return rep

    # --- détection -------------------------------------------------------------
    def detect(self, text, strict=False):
        """Retourne des spans (start, end, dtype, original, replacement) non chevauchants."""
        spans = []
        if self.dict_re:
            for m in self.dict_re.finditer(text):
                v = m.group(0)
                if v in self.exact:
                    dtype, rep = self.exact[v]
                elif v in self.strict:
                    if not strict:
                        continue
                    dtype, rep = self.strict[v]
                else:
                    dtype, rep = self.map.get(norm(v).casefold(), ("UNKNOWN", None))
                    if rep is None:
                        dtype = self.guess_type(v)
                        rep = self.generate(dtype, v)
                spans.append((m.start(), m.end(), dtype, v, rep))
        for dtype, pat in self.PATTERNS:
            for m in pat.finditer(text):
                v = m.group(0)
                if dtype == "IBAN" and not iban_is_valid(v):
                    continue
                if dtype == "AHV_NUMBER" and not ahv_is_valid(v):
                    continue
                if dtype == "CREDIT_CARD" and not luhn_is_valid(v):
                    continue
                known = self.map.get(norm(v).casefold())
                rep = known[1] if known else self.generate(dtype, v)
                if known and " " not in v and " " in rep:
                    rep = rep.replace(" ", "")
                spans.append((m.start(), m.end(), dtype, v, rep))
        # conserver le plus long en cas de chevauchement
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        out, last_end = [], -1
        for s in spans:
            if s[0] >= last_end:
                out.append(s); last_end = s[1]
        return out

    def guess_type(self, v):
        for dtype, pat in self.PATTERNS:
            if pat.fullmatch(v):
                return dtype
        return "UNKNOWN"

    def replace(self, text, strict=False):
        spans = self.detect(text, strict)
        if not spans:
            return text, []
        out, i, log = [], 0, []
        for s, e, dtype, v, rep in spans:
            out.append(text[i:s])
            r = rep.upper() if (v.isupper() and dtype in ("FIRST_NAME", "LAST_NAME")) else rep
            out.append(r); i = e
            log.append({"type": dtype, "original": v, "replacement": r})
        out.append(text[i:])
        return "".join(out), log


# ---------------------------------------------------------------------------
# Images : OCR Tesseract (TSV) -> boîtes -> recouvrement + pseudonyme
# ---------------------------------------------------------------------------
def tesseract_tsv(img_path, psm):
    try:
        out = subprocess.run(["tesseract", img_path, "stdout", "--psm", str(psm), "tsv"], capture_output=True, text=True, timeout=180).stdout
    except Exception:
        return []
    rows = list(csv.DictReader(io.StringIO(out), delimiter="\t", quoting=csv.QUOTE_NONE))
    return [r for r in rows if r.get("level") == "5" and r.get("text", "").strip()]


def _find_font():
    """Police TrueType : $SANITIZE_FONT sinon premier candidat existant (Linux/conteneur, puis macOS)."""
    candidates = [os.environ.get("SANITIZE_FONT", "")] + [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    raise RuntimeError("Aucune police TrueType trouvée ; définir SANITIZE_FONT "
                       "(conteneur : installer fonts-dejavu-core)")


def sanitize_image_bytes(data, ext, pz: Pseudonymizer, strict=False):
    """Retourne (nouveaux octets, log). Recouvre chaque valeur détectée par OCR et écrit le pseudonyme."""
    from PIL import Image, ImageDraw, ImageFont
    img = Image.open(io.BytesIO(data)).convert("RGB")
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
        img.save(tf.name); tmp = tf.name
    words = []
    seen = set()
    for psm in (11, 6):
        for w in tesseract_tsv(tmp, psm):
            key = (psm, w["block_num"], w["par_num"], w["line_num"], w["word_num"])
            if key in seen:
                continue
            seen.add(key)
            words.append({"psm": psm, "line": (psm, w["block_num"], w["par_num"], w["line_num"]), "x": int(w["left"]), "y": int(w["top"]),
                          "w": int(w["width"]), "h": int(w["height"]), "text": w["text"]})
    os.unlink(tmp)
    lines = {}
    for w in words:
        lines.setdefault(w["line"], []).append(w)
    draw = ImageDraw.Draw(img)
    log, done_boxes = [], []
    font_path = _find_font()
    for key, ws in lines.items():
        ws.sort(key=lambda w: w["x"])
        text = " ".join(w["text"] for w in ws)
        # offsets des mots dans la ligne reconstruite
        offs, pos = [], 0
        for w in ws:
            offs.append((pos, pos + len(w["text"]))); pos += len(w["text"]) + 1
        for s, e, dtype, v, rep in pz.detect(text, strict):
            idx = [i for i, (a, b) in enumerate(offs) if a < e and b > s]
            if not idx:
                continue
            x0 = min(ws[i]["x"] for i in idx); y0 = min(ws[i]["y"] for i in idx)
            x1 = max(ws[i]["x"] + ws[i]["w"] for i in idx); y1 = max(ws[i]["y"] + ws[i]["h"] for i in idx)
            box = (x0, y0, x1, y1)
            if any(abs(box[0] - b[0]) < 4 and abs(box[1] - b[1]) < 4 for b in done_boxes):
                continue   # déjà traité par l'autre passe OCR
            done_boxes.append(box)
            # couleur de fond : médiane d'une bordure autour de la boîte
            pad = 3
            border = [img.getpixel((min(max(x, 0), img.width - 1), min(max(y, 0), img.height - 1)))
                      for x in range(x0 - pad, x1 + pad, 4) for y in (y0 - pad, y1 + pad)]
            bg = tuple(sorted(c[i] for c in border)[len(border) // 2] for i in range(3)) if border else (255, 255, 255)
            draw.rectangle([x0 - pad, y0 - pad, x1 + pad, y1 + pad], fill=bg)
            r = rep.upper() if (v.isupper() and dtype in ("FIRST_NAME", "LAST_NAME")) else rep
            size = max(10, int((y1 - y0) * 0.95))
            font = ImageFont.truetype(font_path, size)
            while size > 8 and draw.textlength(r, font=font) > (x1 - x0) * 1.15:
                size -= 1; font = ImageFont.truetype(font_path, size)
            ink = (20, 40, 140) if key[0] == 11 and "handwriting" in dtype else (15, 15, 15)
            draw.text((x0, y0 - 1), r, font=font, fill=ink)
            log.append({"type": dtype, "original": v, "replacement": r, "box": box})
    buf = io.BytesIO()
    fmt = "JPEG" if ext.lower() in (".jpg", ".jpeg") else "PNG"
    img.save(buf, fmt, quality=92) if fmt == "JPEG" else img.save(buf, fmt)
    return buf.getvalue(), log


# ---------------------------------------------------------------------------
def sanitize_docx(src, dst, pz, strict):
    from docx import Document
    d = Document(src)
    log = []

    def fix_paragraph(p):
        full = p.text
        new, l = pz.replace(full, strict)
        if l:
            runs = p.runs
            if runs:
                runs[0].text = new
                for r in runs[1:]:
                    r.text = ""
            log.extend(l)

    for p in d.paragraphs:
        fix_paragraph(p)
    for t in d.tables:
        for row in t.rows:
            for c in row.cells:
                for p in c.paragraphs:
                    fix_paragraph(p)
    for s in d.sections:
        for p in list(s.header.paragraphs) + list(s.footer.paragraphs):
            fix_paragraph(p)
    tmp = dst + ".tmp.docx"
    d.save(tmp)
    # images incorporées
    img_log = []
    with zipfile.ZipFile(tmp) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename.startswith("word/media/") and item.filename.lower().endswith((".png", ".jpg", ".jpeg")):
                data, l = sanitize_image_bytes(data, os.path.splitext(item.filename)[1], pz, strict)
                img_log.append({"media": item.filename, "replacements": l})
            zout.writestr(item, data)
    os.unlink(tmp)
    return {"text_replacements": log, "images": img_log}


def sanitize_xlsx(src, dst, pz, strict):
    from openpyxl import load_workbook
    wb = load_workbook(src)
    log = []
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            cells = list(row)
            # valeurs réparties sur deux cellules adjacentes (ex. NPA | Localité) : on teste la paire
            for i in range(len(cells) - 1):
                a, b = cells[i], cells[i + 1]
                if isinstance(a.value, (str, int)) and isinstance(b.value, str):
                    pair = "%s %s" % (a.value, b.value)
                    hit = pz.map.get(norm(pair).casefold())
                    if hit and hit[0] == "POSTAL_CITY" and " " in hit[1]:
                        npa, city = hit[1].split(" ", 1)
                        a.value = int(npa) if isinstance(a.value, int) else npa
                        b.value = city
                        log.append({"type": "POSTAL_CITY", "original": pair, "replacement": hit[1],
                                    "cell": "%s!%s:%s" % (ws.title, a.coordinate, b.coordinate)})
            for c in cells:
                if isinstance(c.value, str) and not c.value.startswith("="):
                    new, l = pz.replace(c.value, strict)
                    if l:
                        c.value = new
                        for e in l:
                            e["cell"] = "%s!%s" % (ws.title, c.coordinate)
                        log.extend(l)
    wb.save(dst)
    return {"text_replacements": log}


def sanitize_pdf(src, dst, pz, strict):
    try:
        import fitz  # PyMuPDF
    except ImportError:
        return {"skipped": "PyMuPDF (fitz) non disponible dans cet environnement — installer `pip install pymupdf` pour la branche PDF"}
    doc = fitz.open(src)
    log, img_log = [], []
    for page in doc:
        text = page.get_text("text")
        spans = pz.detect(text, strict)
        uniq = {}
        for s, e, dtype, v, rep in spans:
            uniq.setdefault(v, (dtype, rep))
        rects = []
        for v, (dtype, rep) in uniq.items():
            for r in page.search_for(v):
                rects.append((r, v, dtype, rep))
        for r, v, dtype, rep in rects:
            page.add_redact_annot(r, fill=(1, 1, 1))
        if rects:
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
            for r, v, dtype, rep in rects:
                rr = rep.upper() if (v.isupper() and dtype in ("FIRST_NAME", "LAST_NAME")) else rep
                fs = max(5.0, r.height * 0.78)
                box = fitz.Rect(r.x0, r.y0 - 1, r.x1 + 2, r.y1 + 1)
                while fs > 4 and page.insert_textbox(box, rr, fontsize=fs, fontname="helv", color=(0, 0, 0)) < 0:
                    fs -= 0.5
                log.append({"page": page.number + 1, "type": dtype, "original": v, "replacement": rr})
        for img in page.get_images(full=True):
            xref = img[0]
            info = doc.extract_image(xref)
            data, l = sanitize_image_bytes(info["image"], "." + info["ext"], pz, strict)
            if l:
                page.replace_image(xref, stream=data)
                img_log.append({"page": page.number + 1, "xref": xref, "replacements": l})
    doc.save(dst, garbage=3, deflate=True)
    return {"text_replacements": log, "images": img_log}


def sanitize_image_file(src, dst, pz, strict):
    with open(src, "rb") as f:
        data = f.read()
    new, l = sanitize_image_bytes(data, os.path.splitext(src)[1], pz, strict)
    with open(dst, "wb") as f:
        f.write(new)
    return {"images": [{"media": os.path.basename(src), "replacements": l}]}


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inbound", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--mapping", required=True, help="ground_truth/mapping_by_value.csv (ou table de pseudonymes du client)")
    ap.add_argument("--strict-source", help="ground_truth.csv pour les généralisations (mode --strict)")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--evidence", help="export d'evidences Securiti (CSV)")
    ap.add_argument("--evidence-value-col", default="Detection")
    ap.add_argument("--only", help="motif de nom de fichier à traiter (sous-chaîne)")
    a = ap.parse_args()
    ev_values = set()
    if a.evidence:
        with open(a.evidence, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                v = (r.get(a.evidence_value_col) or "").strip()
                if len(v) >= 3:
                    ev_values.add(v)
    pz = Pseudonymizer(a.mapping, a.strict_source if a.strict else None, ev_values)
    os.makedirs(a.output, exist_ok=True)
    report = {"inbound": a.inbound, "output": a.output, "strict": a.strict, "files": {}}
    for root, _, fns in os.walk(a.inbound):
        for fn in sorted(fns):
            if a.only and a.only not in fn:
                continue
            src = os.path.join(root, fn)
            rel = os.path.relpath(src, a.inbound)
            dst = os.path.join(a.output, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            ext = os.path.splitext(fn)[1].lower()
            t0 = time.time()
            try:
                if ext == ".docx":
                    res = sanitize_docx(src, dst, pz, a.strict)
                elif ext == ".xlsx":
                    res = sanitize_xlsx(src, dst, pz, a.strict)
                elif ext == ".pdf":
                    res = sanitize_pdf(src, dst, pz, a.strict)
                elif ext in (".png", ".jpg", ".jpeg"):
                    res = sanitize_image_file(src, dst, pz, a.strict)
                else:
                    shutil.copy2(src, dst); res = {"copied": True}
            except Exception as e:  # noqa
                res = {"error": repr(e)}
            res["seconds"] = round(time.time() - t0, 2)
            n_txt = len(res.get("text_replacements", []))
            n_img = sum(len(i["replacements"]) for i in res.get("images", []))
            res["summary"] = {"text_replacements": n_txt, "image_replacements": n_img}
            report["files"][rel] = res
            print("%-45s %s" % (rel, json.dumps(res.get("summary") if "skipped" not in res and "error" not in res else res, ensure_ascii=False)))
    report["generated_pseudonyms_for_unknown_values"] = pz.generated
    with open(os.path.join(a.output, "sanitization_log.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
