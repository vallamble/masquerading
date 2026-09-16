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
                if dtype == "CREDIT_CARD":
                    if not luhn_is_valid(v):
                        continue
                    # Un corps d'IBAN n'est pas un numéro de carte : 16 chiffres consécutifs pris dans un IBAN
                    # passent Luhn par hasard (~1 fois sur 10). Sans ce garde-fou, le sanitizer remplaçait deux
                    # leurres « IBAN à checksum invalide » de la page 179 par des numéros de carte de test.
                    before = text[max(0, m.start() - 8):m.start()]
                    if re.search(r"[A-Z]{2}\d{2}\s?$", before) or re.search(r"\d\s?$", before):
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


_FONT_FAMILIES = [
    # (nom, candidats Linux/conteneur ..., candidats macOS ...)
    ("sans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/System/Library/Fonts/Supplemental/Arial.ttf", "/Library/Fonts/Arial.ttf"),
    ("sans-bold", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf"),
    ("mono", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Supplemental/Courier New.ttf"),
    ("serif", "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf", "/System/Library/Fonts/Supplemental/Times New Roman.ttf"),
    ("condensed", "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf", "/System/Library/Fonts/Supplemental/Arial Narrow.ttf"),
]


def _font_candidates():
    """Familles TrueType disponibles : {nom: chemin}. $SANITIZE_FONT force la famille « sans »."""
    out = {}
    forced = os.environ.get("SANITIZE_FONT", "")
    if forced and os.path.exists(forced):
        out["sans"] = forced
    for fam in _FONT_FAMILIES:
        if fam[0] in out:
            continue
        for p in fam[1:]:
            if os.path.exists(p):
                out[fam[0]] = p; break
    if not out:
        raise RuntimeError("Aucune police TrueType trouvée ; définir SANITIZE_FONT "
                           "(conteneur : installer fonts-dejavu-core)")
    return out


def _fit_font(draw, ImageFont, path, original, box_w, box_h):
    """Taille pour laquelle le texte ORIGINAL rendu a la hauteur de sa boîte OCR (tient compte des jambages/accents
    de l'original, donc taille homogène sur une ligne). Retourne (font, erreur relative de largeur, offset_y)."""
    lo, hi = 6, max(8, int(box_h * 2.2))
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        f = ImageFont.truetype(path, mid)
        bb = f.getbbox(original)
        h = bb[3] - bb[1]
        if h <= box_h:
            best = (f, bb); lo = mid + 1
        else:
            hi = mid - 1
    if best is None:
        f = ImageFont.truetype(path, 6); best = (f, f.getbbox(original))
    f, bb = best
    w_err = abs(draw.textlength(original, font=f) - box_w) / max(box_w, 1)
    return f, w_err, bb[1]


# Confusions OCR fréquentes dans les jetons numériques (substitutions à longueur constante)
_OCR_DIGIT_FIX = str.maketrans({"O": "0", "o": "0", "Q": "0", "D": "0", "I": "1", "l": "1", "|": "1", "S": "5", "Z": "2", "B": "8"})
_NUMERIC_TOKEN = re.compile(r"^[A-Z]{0,2}[0-9OoQDIl|SZB.\-]{2,}$")
_IBAN_LOOSE = re.compile(r"\b[A-Z]{2}[0-9OoQDIlSZB]{2}(?:[ ]?[A-Z0-9]{2,4}){3,8}\b")
_IBAN_COUNTRIES = {"CH", "LI", "DE", "AT", "FR", "IT", "ES", "PT", "NL", "BE", "LU", "GB", "IE", "DK", "SE", "NO", "FI", "PL", "CZ", "MC"}


def _ocr_normalize_line(text):
    """Corrige O→0, I→1, S→5… dans les jetons majoritairement numériques (IBAN, AVS, cartes, n° patient).
    Longueur conservée : les offsets de mots restent valables."""
    toks = text.split(" ")
    out = []
    for t in toks:
        if _NUMERIC_TOKEN.match(t) and sum(c.isdigit() for c in t) >= max(2, len(t) // 3):
            head = t[:2] if t[:2].isalpha() and t[:2].isupper() else ""
            out.append(head + t[len(head):].translate(_OCR_DIGIT_FIX))
        else:
            out.append(t)
    return " ".join(out)


def _levenshtein(a, b, cap=3):
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
        if min(prev) > cap:
            return cap + 1
    return prev[-1]


def sanitize_image_bytes(data, ext, pz: Pseudonymizer, strict=False, ocr_scale=None,
                         cover_unread=os.environ.get("COVER_UNREAD_INK", "0") == "1"):
    """Retourne (nouveaux octets, log). Recouvre chaque valeur détectée par OCR et écrit le pseudonyme.

    Robustesse OCR : (1) l'OCR tourne sur une image agrandie 2× (Tesseract lit mal les chiffres < 30 px : « CH6O »
    au lieu de « CH60 ») ; (2) confusions O/0, I/1, S/5… corrigées dans les jetons numériques avant détection ;
    (3) « fail-closed » : une chaîne à forme d'IBAN dont le checksum reste faux est rapprochée de la table de
    pseudonymes (distance ≤ 2) ou recouverte par un IBAN généré — jamais laissée en clair.
    Rendu : la taille de police est ajustée pour que le texte ORIGINAL remplisse sa boîte (homogène sur la ligne) ;
    la famille (sans / mono / serif / gras / condensé) est celle dont la largeur rendue colle le mieux à l'original.
    """
    from PIL import Image, ImageDraw, ImageFont
    img = Image.open(io.BytesIO(data)).convert("RGB")
    # Deux échelles : 2x lit mieux les petits chiffres (texte imprimé), 1x lit mieux les écritures irrégulières
    # (manuscrit simulé) que l'agrandissement lisse. Les boîtes sont ramenées à l'échelle d'origine.
    if ocr_scale is None:
        scales = (2, 1) if img.width * img.height <= 3_000_000 else (1,)
    else:
        scales = (ocr_scale,)
    words = []
    seen = set()
    for sc in scales:
        ocr_img = img.resize((img.width * sc, img.height * sc), Image.LANCZOS) if sc != 1 else img
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            ocr_img.save(tf.name); tmp = tf.name
        for psm in (11, 6):
            for w in tesseract_tsv(tmp, psm):
                key = (sc, psm, w["block_num"], w["par_num"], w["line_num"], w["word_num"])
                if key in seen:
                    continue
                seen.add(key)
                words.append({"psm": psm, "line": (sc, psm, w["block_num"], w["par_num"], w["line_num"]),
                              "x": int(w["left"]) // sc, "y": int(w["top"]) // sc,
                              "w": -(-int(w["width"]) // sc), "h": -(-int(w["height"]) // sc),
                              "conf": float(w.get("conf", "0") or 0), "text": w["text"].strip()})
        os.unlink(tmp)
    lines = {}
    for w in words:
        if w["text"]:
            lines.setdefault(w["line"], []).append(w)
    draw = ImageDraw.Draw(img)
    log, done_boxes, candidates = [], [], []
    fonts = _font_candidates()
    iban_keys = [(norm(k).upper(), rep) for k, (t, rep) in pz.exact.items() if t == "IBAN"]
    name_keys = [(k.casefold(), t, rep) for k, (t, rep) in pz.exact.items()
                 if t in ("FIRST_NAME", "LAST_NAME", "STREET_ADDRESS", "POSTAL_CITY") and len(k) >= 5]

    def fuzzy_iban(v):
        """(substitution, méthode, distance) : table de pseudonymes à distance ≤ 2, sinon IBAN généré (jamais en clair)."""
        c = norm(v).upper()
        hits = sorted(((_levenshtein(c, k), rep) for k, rep in iban_keys), key=lambda t: t[0])
        if hits and hits[0][0] <= 2 and (len(hits) == 1 or hits[1][0] > hits[0][0]):
            return hits[0][1], "fuzzy_mapping(d=%d)" % hits[0][0], hits[0][0]
        return pz.generate("IBAN", c[:2] + "00" + c[4:]), "generated_fail_closed", 99

    for key, ws in lines.items():
        ws.sort(key=lambda w: w["x"])
        text = " ".join(w["text"] for w in ws)
        offs, pos = [], 0
        for w in ws:
            offs.append((pos, pos + len(w["text"]))); pos += len(w["text"]) + 1
        fixed = _ocr_normalize_line(text)
        spans = pz.detect(text, strict)
        covered = [(s, e) for s, e, *_ in spans]
        for sp in pz.detect(fixed, strict):
            if not any(a < sp[1] and b > sp[0] for a, b in covered):
                spans.append(sp + ("ocr_normalized",)); covered.append((sp[0], sp[1]))
        # fail-closed : forme d'IBAN sans checksum valide (pays connu, corps majoritairement numérique)
        for m in _IBAN_LOOSE.finditer(fixed):
            if any(a < m.end() and b > m.start() for a, b in covered):
                continue
            body = norm(m.group(0))[4:]
            if m.group(0)[:2] not in _IBAN_COUNTRIES or sum(c.isdigit() for c in body) < 0.6 * len(body):
                continue
            # l'OCR coupe parfois le dernier groupe (« … 5296 » + « 6 ») : étendre aux 1–2 jetons suivants si cela
            # rapproche de la table de pseudonymes
            cands = [(m.start(), m.end())]
            tail = fixed[m.end():]
            for ext in re.finditer(r"[ ]?[A-Z0-9]{1,4}", tail):
                if ext.start() > 1 or len(cands) > 2:
                    break
                cands.append((m.start(), m.end() + ext.end()))
                if not ext.group(0).startswith(" "):
                    break
            best = None
            for a, b in cands:
                rep, how, dist = fuzzy_iban(fixed[a:b])
                if best is None or dist < best[0]:
                    best = (dist, a, b, rep, how)
            _, a, b, rep, how = best
            spans.append((a, b, "IBAN", text[a:b], rep, how)); covered.append((a, b))
        # fail-closed : mot mal lu par l'OCR (« Pjerre-Alain », confiance basse) proche d'un nom de la table
        for i, w in enumerate(ws):
            a, b = offs[i]
            if any(x < b and y > a for x, y in covered) or len(w["text"]) < 5 or w["conf"] >= 85:
                continue
            tok = w["text"].strip(".,;:()")
            cap = 2 if len(tok) >= 9 else 1
            hits = sorted(((_levenshtein(tok.casefold(), k, cap), dtype, rep) for k, dtype, rep in name_keys
                           if abs(len(k) - len(tok)) <= cap), key=lambda t: t[0])
            if hits and hits[0][0] <= cap and (len(hits) == 1 or hits[1][0] > hits[0][0]):
                spans.append((a, b, hits[0][1], w["text"], hits[0][2], "fuzzy_mapping(d=%d)" % hits[0][0]))
                covered.append((a, b))
        for sp in spans:
            s, e, dtype, v, rep = sp[:5]
            how = sp[5] if len(sp) > 5 else "exact"
            idx = [i for i, (a, b) in enumerate(offs) if a < e and b > s]
            if not idx:
                continue
            x0 = min(ws[i]["x"] for i in idx); y0 = min(ws[i]["y"] for i in idx)
            x1 = max(ws[i]["x"] + ws[i]["w"] for i in idx); y1 = max(ws[i]["y"] + ws[i]["h"] for i in idx)
            candidates.append(((x0, y0, x1, y1), dtype, v, rep, how, min(ws[i]["conf"] for i in idx)))

    # Ordre de traitement : correspondances exactes d'abord, puis normalisées, puis approchées ; à qualité égale la
    # boîte la plus large (ex. l'IBAN complet lu par psm 6 gagne sur la version tronquée lue par psm 11).
    rank = {"exact": 0, "ocr_normalized": 1}
    candidates.sort(key=lambda c: (rank.get(c[4], 2), -(c[0][2] - c[0][0])))

    def overlaps(b, d):
        ix = max(0, min(b[2], d[2]) - max(b[0], d[0])); iy = max(0, min(b[3], d[3]) - max(b[1], d[1]))
        return ix * iy > 0.5 * (b[2] - b[0]) * (b[3] - b[1])

    for box, dtype, v, rep, how, conf_min in candidates:
        x0, y0, x1, y1 = box
        if any(overlaps(box, d) for d in done_boxes):
            continue   # déjà traité par une autre passe OCR
        done_boxes.append(box)
        if True:
            # couleur de fond : médiane d'une bordure autour de la boîte ; couleur d'encre : pixel le plus sombre
            pad = 3
            border = [img.getpixel((min(max(x, 0), img.width - 1), min(max(y, 0), img.height - 1)))
                      for x in range(x0 - pad, x1 + pad, 4) for y in (y0 - pad, y1 + pad)]
            bg = tuple(sorted(c[i] for c in border)[len(border) // 2] for i in range(3)) if border else (255, 255, 255)
            inner = [img.getpixel((x, y)) for x in range(x0, x1, 3) for y in range(y0, y1, 2)]
            ink = min(inner, key=sum) if inner else (15, 15, 15)
            if sum(bg) - sum(ink) < 90:          # contraste trop faible (fond sombre) : encre par défaut lisible
                ink = (255, 255, 255) if sum(bg) < 384 else (15, 15, 15)
            r = rep.upper() if (v.isupper() and dtype in ("FIRST_NAME", "LAST_NAME")) else rep
            # police : famille dont la largeur rendue de l'ORIGINAL est la plus proche de la boîte, taille = hauteur boîte
            best = None
            for fam, path in fonts.items():
                f, werr, top = _fit_font(draw, ImageFont, path, v, x1 - x0, y1 - y0)
                if best is None or werr < best[1]:
                    best = (f, werr, top, fam)
            font, _, top, fam = best
            # largeur disponible : la boîte + l'espace libre (couleur de fond) à sa droite, comme le ferait l'application
            def is_bg(px):
                return sum(abs(px[i] - bg[i]) for i in range(3)) < 45
            free = x1 + pad
            while free < img.width - 1 and free - x1 < (x1 - x0) * 0.8 + 40:
                if all(is_bg(img.getpixel((free, yy))) for yy in range(y0, y1, max(1, (y1 - y0) // 4))):
                    free += 2
                else:
                    break
            avail = max(x1 - x0, free - pad - x0)
            size = font.size
            while size > 6 and draw.textlength(r, font=font) > avail:
                size -= 1; font = ImageFont.truetype(font.path, size)
            xr = x0 + int(draw.textlength(r, font=font)) + pad
            draw.rectangle([x0 - pad, y0 - pad, max(x1, xr) + pad, y1 + pad], fill=bg)
            done_boxes[-1] = (x0 - pad, y0 - pad, max(x1, xr) + pad, y1 + pad)
            draw.text((x0, y0 - top), r, font=font, fill=ink)
            log.append({"type": dtype, "original": v, "replacement": r, "box": box, "font": fam, "match": how,
                        "ocr_conf_min": conf_min})
    # score « encre non lue » (signature, écriture illisible) : toujours calculé pour router l'image en revue manuelle ;
    # le recouvrement automatique (_cover_unread_ink) est EXPÉRIMENTAL et désactivé par défaut (COVER_UNREAD_INK=1).
    try:
        unread = _cover_unread_ink(img, words, done_boxes, apply=cover_unread)
        log += unread
    except Exception as exc:   # numpy absent, etc. : ne jamais bloquer la sanitization
        log.append({"type": "UNREAD_INK", "match": "score_failed", "error": str(exc)})
    buf = io.BytesIO()
    fmt = "JPEG" if ext.lower() in (".jpg", ".jpeg") else "PNG"
    img.save(buf, fmt, quality=92) if fmt == "JPEG" else img.save(buf, fmt)
    return buf.getvalue(), log


def _cover_unread_ink(img, words, done_boxes, apply=False):
    """Fail-closed : zones d'encre que l'OCR n'a lues dans aucune passe (signature, écriture illisible) → recouvertes.
    Ce que personne ne peut lire ne peut pas être vérifié ; on préfère l'effacer que le laisser passer.
    Heuristique : composantes sombres hors des boîtes de mots lus (toute confiance), regroupées par lignes ;
    on ignore les grands aplats (bandeaux, cadres) et les traits fins (bordures de champs)."""
    import numpy as np
    from PIL import ImageDraw
    a = np.asarray(img).astype(int)
    h, w = a.shape[:2]
    page_bg = np.median(a.reshape(-1, 3), axis=0)
    diff = np.abs(a - page_bg).sum(axis=2)
    # encre = pixel nettement différent du fond ET sombre (noir, bleu foncé) : exclut bordures grises et fonds colorés clairs
    ink = (diff > 150) & (a.min(axis=2) < 100)
    # retirer tout ce que l'OCR a lu (avec marge) et ce qui a déjà été réécrit
    for wd in words:
        if wd["conf"] >= 30 and len(wd["text"]) >= 2:
            x0, y0, x1, y1 = wd["x"] - 3, wd["y"] - 3, wd["x"] + wd["w"] + 3, wd["y"] + wd["h"] + 3
            ink[max(0, y0):min(h, y1), max(0, x0):min(w, x1)] = False
    for x0, y0, x1, y1 in done_boxes:
        ink[max(0, y0 - 4):min(h, y1 + 4), max(0, x0 - 4):min(w, x1 + 4)] = False
    # composantes connexes (4-voisinage) par étiquetage simple sur image réduite
    step = 2
    small = ink[::step, ::step]
    sh, sw = small.shape
    labels = np.zeros((sh, sw), dtype=np.int32)
    boxes = {}
    cur = 0
    ys, xs = np.nonzero(small)
    for y, x in zip(ys, xs):
        if labels[y, x]:
            continue
        cur += 1
        stack = [(y, x)]; labels[y, x] = cur
        bx0 = bx1 = x; by0 = by1 = y; n = 0
        while stack:
            cy, cx = stack.pop(); n += 1
            bx0, bx1, by0, by1 = min(bx0, cx), max(bx1, cx), min(by0, cy), max(by1, cy)
            for ny, nx in ((cy - 1, cx), (cy + 1, cx), (cy, cx - 1), (cy, cx + 1)):
                if 0 <= ny < sh and 0 <= nx < sw and small[ny, nx] and not labels[ny, nx]:
                    labels[ny, nx] = cur; stack.append((ny, nx))
        boxes[cur] = (bx0 * step, by0 * step, (bx1 + 1) * step, (by1 + 1) * step, n * step * step)
    # filtrer : ni aplats (grande surface pleine), ni traits fins (bordures), ni poussière
    comps = []
    for x0, y0, x1, y1, area in boxes.values():
        bw, bh = x1 - x0, y1 - y0
        if bh < 6 or bw < 3 or bh > 0.25 * h or (bw > 0.6 * w and bh < 0.05 * h):
            continue
        if bh <= 4 or bw <= 4:
            continue
        fill = area / max(bw * bh, 1)
        if fill > 0.5 and bw * bh > 1500:      # aplat (logo, bandeau, cadre plein) : pas un trait d'écriture
            continue
        if fill < 0.04:                        # cadre creux (bordure de champ)
            continue
        comps.append([x0, y0, x1, y1])
    # regrouper les composantes voisines sur une même ligne (lettres d'un mot / mots d'une ligne)
    comps.sort(key=lambda b: (b[1], b[0]))
    merged = []
    for c in comps:
        for m in merged:
            if c[0] <= m[2] + 25 and c[2] >= m[0] - 25 and min(c[3], m[3]) - max(c[1], m[1]) > -8:
                m[0], m[1], m[2], m[3] = min(m[0], c[0]), min(m[1], c[1]), max(m[2], c[2]), max(m[3], c[3]); break
        else:
            merged.append(c)
    draw = ImageDraw.Draw(img)
    log = []
    zones = [(x0, y0, x1, y1) for x0, y0, x1, y1 in merged if (x1 - x0) >= 30 and (y1 - y0) >= 12]
    unread_px = int(sum(ink[y0:y1, x0:x1].sum() for x0, y0, x1, y1 in zones))
    log.append({"type": "UNREAD_INK", "match": "score", "zones": len(zones), "unread_ink_pixels": unread_px,
                "unread_ink_ratio": round(unread_px / max(1, int(diff.size)), 5),
                "boxes": [[int(v) for v in z] for z in zones],
                "hint": "zones d'encre qu'aucune passe OCR n'a lues ; > 0 → revue manuelle recommandée (signature, manuscrit)"})
    if apply:
        for x0, y0, x1, y1 in zones:
            bg = tuple(int(v) for v in page_bg)
            draw.rectangle([x0 - 3, y0 - 3, x1 + 3, y1 + 3], fill=bg)
            log.append({"type": "UNREAD_INK", "original": None, "replacement": None,
                        "box": [int(x0), int(y0), int(x1), int(y1)], "match": "covered_fail_closed"})
    return log


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


def _pdf_line_matches(page, pz, strict, fitz):
    """Détection par LIGNE reconstruite depuis les boîtes de mots (même principe que la branche image).

    `page.search_for(valeur)` échoue quand l'espace de la valeur n'est pas un vrai caractère espace dans le flux
    PDF (espacement par positionnement : « +41 21 000 35 16 », « 8400 Winterthur ») ou quand la valeur est coupée
    par un retour à la ligne : la valeur reste alors en clair. On reconstruit donc le texte ligne par ligne avec
    l'offset de chaque mot, on détecte sur ce texte, et on remonte aux rectangles des mots recouverts.
    Retourne [(rects, dtype, original, remplacement)] — plusieurs rects quand la valeur court sur deux lignes.
    """
    words = page.get_text("words")          # (x0, y0, x1, y1, mot, bloc, ligne, n° mot)
    lines = {}
    for w in words:
        lines.setdefault((w[5], w[6]), []).append(w)
    seq = []
    for key in sorted(lines):
        ws = sorted(lines[key], key=lambda w: w[7])
        offs, pos, parts = [], 0, []
        for w in ws:
            offs.append((pos, pos + len(w[4]), w)); parts.append(w[4]); pos += len(w[4]) + 1
        seq.append((" ".join(parts), offs))

    out, seen = [], set()

    def collect(text, offs):
        for s, e, dtype, v, rep in pz.detect(text, strict):
            hit = [w for (a, b, w) in offs if a < e and b > s]
            if not hit:
                continue
            key = (round(hit[0][0], 1), round(hit[0][1], 1), v)
            if key in seen:
                continue
            seen.add(key)
            # un rectangle par ligne traversée (une valeur coupée par un retour à la ligne en produit deux)
            by_line = {}
            for w in hit:
                by_line.setdefault((w[5], w[6]), []).append(w)
            rects = [fitz.Rect(min(w[0] for w in g), min(w[1] for w in g),
                               max(w[2] for w in g), max(w[3] for w in g)) for g in by_line.values()]
            out.append((rects, dtype, v, rep))

    for text, offs in seq:
        collect(text, offs)
    # 2e passe : valeurs coupées entre deux lignes consécutives
    for (t1, o1), (t2, o2) in zip(seq, seq[1:]):
        joined = t1 + " " + t2
        shift = len(t1) + 1
        collect(joined, list(o1) + [(a + shift, b + shift, w) for (a, b, w) in o2])
    return out


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
        for rs, dtype, v, rep in _pdf_line_matches(page, pz, strict, fitz):
            for i, r in enumerate(rs):
                rects.append((r, v, dtype, rep if i == 0 else ""))   # la suite de la valeur coupée est effacée
            uniq.pop(v, None)
        # filet de sécurité : ce que la détection par lignes n'a pas vu (valeur dans une annotation, un champ…)
        for v, (dtype, rep) in uniq.items():
            for r in page.search_for(v):
                rects.append((r, v, dtype, rep))
        for r, v, dtype, rep in rects:
            page.add_redact_annot(r, fill=(1, 1, 1))
        if rects:
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
            for r, v, dtype, rep in rects:
                if not rep:
                    continue        # 2e ligne d'une valeur coupée : la zone est effacée, rien à réécrire
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
    # garbage=4 + clean : supprime les objets devenus orphelins après replace_image (l'ancienne image comptait
    # encore dans le PDF de sortie — anomalie « 8 images au lieu de 4 »). À recouper avec `pdfimages -list`.
    doc.save(dst, garbage=4, clean=True, deflate=True)
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
            if fn.startswith(("~$", ".")):      # fichiers de verrou Office / cachés
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
