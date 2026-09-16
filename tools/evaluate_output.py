# -*- coding: utf-8 -*-
"""
evaluate_output.py — Évalue un dossier Output (fichiers assainis) contre le ground truth.

Mesures (par document et par data_type) :
  - FUITES : valeurs originales à pseudonymiser encore présentes (couche texte ; OCR Tesseract pour les images
    autonomes, les images incorporées DOCX (word/media) et les images incorporées PDF (pypdf))
  - SUBSTITUTIONS ATTENDUES présentes (si le sanitizer utilise la table mapping_by_value.csv)
  - PHI CONSERVÉ (diagnostics/médications) toujours lisible (profil par défaut) — ou masqué si --strict
  - SIGNIFIANCE : toutes les chaînes au format IBAN / AVS / carte trouvées dans la sortie sont valides
    (mod-97 / EAN-13 / Luhn) et aucun placeholder (XXXX, ****, [REDACTED]) n'apparaît
  - INTÉGRITÉ : nombre de pages PDF, paragraphes DOCX, dimensions XLSX, nombre d'images, ratio de longueur du texte
Usage : python3 evaluate_output.py --inbound ../inbound --output <dossier Output> --ground-truth ../ground_truth [--strict]
Sortie : rapport Markdown + JSON dans --report-dir (défaut : le dossier Output)
"""
import argparse
import csv
import io
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
    """Présence d'une valeur : frontières de mot pour les types textuels (évite Valentin ⊂ Valentine),
    insensible aux espaces pour les identifiants numériques (IBAN avec/sans espaces...). L'OCR est plus tolérant."""
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
    # OCR sur image agrandie 2x : Tesseract confond O/0 sous ~30 px (« CH6O »), ce qui masquait des fuites
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


def extract(path):
    """Retourne dict : pages(list[str]) pour PDF, text(str), image_texts(list[str]), stats(dict),
    locs : texte adressable par emplacement ('sheet!cell', 'paragraph:i', 'table0!r,c') pour un contrôle au plus fin."""
    ext = os.path.splitext(path)[1].lower()
    res = {"pages": None, "text": "", "image_texts": [], "stats": {}, "locs": {}}
    if ext == ".pdf":
        import pdfplumber
        from pypdf import PdfReader
        with pdfplumber.open(path) as pdf:
            res["pages"] = [p.extract_text() or "" for p in pdf.pages]
        res["text"] = "\n".join(res["pages"])
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
        parts = [p.text for p in d.paragraphs]
        for i, p in enumerate(d.paragraphs):
            res["locs"]["paragraph:%d" % i] = p.text
        for ti, t in enumerate(d.tables):
            for ri, row in enumerate(t.rows):
                for ci, c in enumerate(row.cells):
                    parts.append(c.text)
                    res["locs"]["table%d!r%d,c%d" % (ti, ri, ci)] = c.text
        res["text"] = "\n".join(parts)
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
    # leurres : invalides par construction, ils doivent rester intacts (mesure du sur-masquage)
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
        # delta de taille (exigence « même taille de fichier » : on la mesure, on ne la promet pas)
        if os.path.exists(in_path):
            si, so = os.path.getsize(in_path), os.path.getsize(out_path)
            report["size_delta"][doc] = {"in": si, "out": so, "pct": round(100.0 * (so - si) / max(1, si), 1)}
        img_txt = " ".join(ex["image_texts"])
        d = {"leaks": 0, "replacements_present": 0, "to_pseudonymize": 0, "keep_expected": 0, "keep_present": 0,
             "image_to_pseudonymize": 0, "image_leaks": 0, "leak_examples": []}

        def scope_text(r):
            """Texte du périmètre le plus fin connu pour la ligne GT (page PDF, cellule(s) XLSX, paragraphe DOCX)."""
            if r["location_type"] == "image":
                return img_txt, True
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
            must_hide = r["expected_action"] == "PSEUDONYMIZE" or a.strict   # KEEP : à masquer seulement en mode strict
            hay, is_ocr = scope_text(r)
            if must_hide:
                d["to_pseudonymize"] += 1; bump(t, "to_pseudonymize")
                if is_img:
                    d["image_to_pseudonymize"] += 1; bump(t, "image_to_pseudonymize")
                leaked = contains(hay, r["value"], t, is_ocr)   # toute valeur originale résiduelle dans son périmètre = fuite
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
        # signifiance : formats valides dans la sortie.
        # Deux corrections de mesure (15.09) : (1) l'extraction PDF colle parfois un jeton alphabétique à la fin
        # d'un IBAN (« AT61 … 7252 CHF ») → on retente sans ce jeton avant de déclarer l'IBAN invalide ;
        # (2) les leurres du dataset sont invalides PAR CONSTRUCTION et doivent le rester → ils sont exclus du
        # dénominateur, sinon la métrique punit le comportement attendu.
        full = ex["text"] + " " + " ".join(ex["image_texts"])
        iban_re = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")

        def iban_ok(x):
            if iban_is_valid(x):
                return True
            toks = x.split()
            return len(toks) > 2 and toks[-1].isalpha() and iban_is_valid(" ".join(toks[:-1]))

        dec_norm = {norm(x) for x in decoy_values}
        ibans = [x for x in iban_re.findall(full) if norm(x) not in dec_norm]
        ahvs = [x for x in re.findall(r"\b756\.\d{4}\.\d{4}\.\d{2}\b", full) if norm(x) not in dec_norm]
        no_iban = iban_re.sub(" ", full)   # éviter que des fragments d'IBAN soient comptés comme « carte »
        cards = [x for x in re.findall(r"\b(?:\d{4}[ ]?){3}\d{4}\b|\b\d{4}[ ]?\d{6}[ ]?\d{5}\b", no_iban)
                 if norm(x) not in dec_norm]
        d["format_validity"] = {
            "iban_like": len(ibans), "iban_valid": sum(iban_ok(x) for x in ibans),
            "ahv_like": len(ahvs), "ahv_valid": sum(ahv_is_valid(x) for x in ahvs),
            "card_like": len(cards), "card_luhn_valid": sum(luhn_is_valid(x) for x in cards),
            "placeholders_XXXX_etc": len(PLACEHOLDER_RE.findall(ex["text"])),
            "note": "leurres exclus du dénominateur ; IBAN avec jeton alphabétique collé (artefact d'extraction) comptés valides",
        }
        # sur-masquage : un leurre modifié est un faux positif du sanitizer (mesure de précision)
        touched = [x for x in decoy_doc.get(doc, []) if x and norm(x) not in norm(full)]
        d["decoys_total"] = len(decoy_doc.get(doc, []))
        d["decoys_modified"] = len(touched)
        d["decoys_modified_examples"] = touched[:10]
        # intégrité
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
    open(os.path.join(rd, "evaluation_output.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
