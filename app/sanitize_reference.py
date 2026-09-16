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
import collections
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
# forme d'AVS lue avec des espaces parasites ou des groupes coupés (« 756.456 1.4552.33 ») : fail-closed comme l'IBAN
_AHV_LOOSE = re.compile(r"\b756[.,]\s?(?:\d\s?){4}[.,]\s?(?:\d\s?){4}[.,]\s?\d{2}\b")
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


def _ocr_words(img, scales):
    """OCR Tesseract (TSV) aux échelles demandées × psm 11 et 6 ; boîtes ramenées à l'échelle d'origine."""
    from PIL import Image
    words, seen = [], set()
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
    return words


def _collect_candidates(words, pz, strict):
    """Lignes OCR -> détection (brute, normalisée O/0-I/1, fail-closed IBAN et noms) -> candidats
    ((x0, y0, x1, y1), dtype, original, remplacement, méthode, confiance_min) triés (exact > normalisé > approché, boîte large d'abord)."""
    lines = {}
    for w in words:
        if w["text"]:
            lines.setdefault(w["line"], []).append(w)
    candidates = []
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
        # fail-closed : forme d'AVS (756.xxxx.xxxx.xx) avec espaces parasites ou checksum faux -> table (d ≤ 2) sinon générée
        for m in _AHV_LOOSE.finditer(fixed):
            if any(a < m.end() and b > m.start() for a, b in covered):
                continue
            digits = re.sub(r"\D", "", m.group(0))
            canon = "%s.%s.%s.%s" % (digits[0:3], digits[3:7], digits[7:11], digits[11:13])
            known = pz.map.get(norm(canon).casefold())
            if known:
                rep, how = known[1], "ocr_respaced"
            else:
                hits = sorted(((_levenshtein(digits, re.sub(r"\D", "", k)), r_) for k, (t, r_) in pz.exact.items() if t == "AHV_NUMBER"),
                              key=lambda t: t[0])
                if hits and hits[0][0] <= 2 and (len(hits) == 1 or hits[1][0] > hits[0][0]):
                    rep, how = hits[0][1], "fuzzy_mapping(d=%d)" % hits[0][0]
                else:
                    rep, how = pz.generate("AHV_NUMBER", canon), "generated_fail_closed"
            spans.append((m.start(), m.end(), "AHV_NUMBER", text[m.start():m.end()], rep, how)); covered.append((m.start(), m.end()))
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
    rank = {"exact": 0, "ocr_normalized": 1}
    candidates.sort(key=lambda c: (rank.get(c[4], 2), -(c[0][2] - c[0][0])))
    return candidates


def _paint_candidates(img, candidates, fonts, extra_tag=None):
    """Recouvre chaque candidat (couleur de fond locale) et écrit le pseudonyme (police/taille ajustées à l'original).
    Retourne (boîtes traitées, log)."""
    from PIL import ImageDraw, ImageFont
    draw = ImageDraw.Draw(img)
    log, done_boxes = [], []

    def overlaps(b, d):
        ix = max(0, min(b[2], d[2]) - max(b[0], d[0])); iy = max(0, min(b[3], d[3]) - max(b[1], d[1]))
        return ix * iy > 0.5 * (b[2] - b[0]) * (b[3] - b[1])

    for box, dtype, v, rep, how, conf_min in candidates:
        x0, y0, x1, y1 = box
        if any(overlaps(box, d) for d in done_boxes):
            continue   # déjà traité par une autre passe OCR
        done_boxes.append(box)
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
        best = None
        for fam, path in fonts.items():
            f, werr, top = _fit_font(draw, ImageFont, path, v, x1 - x0, y1 - y0)
            if best is None or werr < best[1]:
                best = (f, werr, top, fam)
        font, _, top, fam = best

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
        entry = {"type": dtype, "original": v, "replacement": r, "box": box, "font": fam, "match": how, "ocr_conf_min": conf_min}
        if extra_tag:
            entry["tag"] = extra_tag
        log.append(entry)
    return done_boxes, log


def sanitize_image_bytes(data, ext, pz: Pseudonymizer, strict=False, ocr_scale=None,
                         cover_unread=os.environ.get("COVER_UNREAD_INK", "0") == "1",
                         cover_signatures=None, signature_context=False):
    """Retourne (nouveaux octets, log). Recouvre chaque valeur détectée par OCR et écrit le pseudonyme.

    Robustesse OCR : (1) l'OCR tourne sur une image agrandie 2× (Tesseract lit mal les chiffres < 30 px : « CH6O »
    au lieu de « CH60 ») ; (2) confusions O/0, I/1, S/5… corrigées dans les jetons numériques avant détection ;
    (3) « fail-closed » : une chaîne à forme d'IBAN dont le checksum reste faux est rapprochée de la table de
    pseudonymes (distance ≤ 2) ou recouverte par un IBAN généré — jamais laissée en clair.
    Rendu : la taille de police est ajustée pour que le texte ORIGINAL remplisse sa boîte (homogène sur la ligne) ;
    la famille (sans / mono / serif / gras / condensé) est celle dont la largeur rendue colle le mieux à l'original.
    Signatures manuscrites : zones d'encre non lues par l'OCR près d'un libellé « Signature » ou dans le tiers bas
    → recouvertes par défaut (COVER_SIGNATURES=1), les cadres et filets sont préservés (voir _cover_signatures).
    """
    from PIL import Image
    img = Image.open(io.BytesIO(data)).convert("RGB")
    # Deux échelles : 2x lit mieux les petits chiffres (texte imprimé), 1x lit mieux les écritures irrégulières
    # (manuscrit simulé) que l'agrandissement lisse. Les boîtes sont ramenées à l'échelle d'origine.
    if ocr_scale is None:
        scales = (2, 1) if img.width * img.height <= 3_000_000 else (1,)
    else:
        scales = (ocr_scale,)
    words = _ocr_words(img, scales)
    candidates = _collect_candidates(words, pz, strict)
    done_boxes, log = _paint_candidates(img, candidates, _font_candidates())
    # signatures manuscrites (recouvrement ciblé, activé par défaut) puis score « encre non lue » (revue manuelle) ;
    # le recouvrement générique de toute encre non lue (_cover_unread_ink, apply=) reste EXPÉRIMENTAL, OFF par défaut.
    if cover_signatures is None:
        cover_signatures = os.environ.get("COVER_SIGNATURES", "1") == "1"
    try:
        sig = _cover_signatures(img, words, done_boxes, apply=cover_signatures, force_location=signature_context)
        log += sig
        done_boxes += [tuple(e["box"]) for e in sig if e.get("match") == "covered"]
    except Exception as exc:   # noqa : ne jamais bloquer la sanitization
        log.append({"type": "SIGNATURE", "match": "detect_failed", "error": str(exc)})
    try:
        unread = _cover_unread_ink(img, words, done_boxes, apply=cover_unread)
        log += unread
    except Exception as exc:   # numpy absent, etc. : ne jamais bloquer la sanitization
        log.append({"type": "UNREAD_INK", "match": "score_failed", "error": str(exc)})
    buf = io.BytesIO()
    fmt = "JPEG" if ext.lower() in (".jpg", ".jpeg") else "PNG"
    img.save(buf, fmt, quality=92) if fmt == "JPEG" else img.save(buf, fmt)
    return buf.getvalue(), log


SIGNATURE_WORDS = {"signature", "signatures", "signé", "signe", "signed", "unterschrift", "visa", "firma", "sign", "signature:"}
SIG_NEAR_PX = 250          # distance max (px) entre un libellé « Signature » et la zone d'encre (à droite ou en dessous)


def _ink_mask(img):
    """Masque d'encre : pixel nettement différent du fond ET sombre (noir, bleu foncé) ; fond = médiane de l'image."""
    import numpy as np
    a = np.asarray(img).astype(int)
    page_bg = np.median(a.reshape(-1, 3), axis=0)
    diff = np.abs(a - page_bg).sum(axis=2)
    return (diff > 150) & (a.min(axis=2) < 100), page_bg


def _components(mask, step=2):
    """Composantes connexes (4-voisinage) sur une image réduite d'un facteur `step` : [(x0, y0, x1, y1, n_pixels)]."""
    import numpy as np
    small = mask[::step, ::step]
    sh, sw = small.shape
    labels = np.zeros((sh, sw), dtype=np.int32)
    boxes, cur = [], 0
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
        boxes.append((bx0 * step, by0 * step, (bx1 + 1) * step, (by1 + 1) * step, n * step * step))
    return boxes


def _trusted_words(words):
    """Mots OCR dont la boîte peut être retirée du masque d'encre : lus de façon STABLE par ≥ 2 passes (même texte
    normalisé, boîtes qui se recouvrent) ou avec une confiance ≥ 75. Un paraphe lu comme « DWDM » (conf. 41) dans une
    seule passe n'est pas un mot : sa boîte ne doit pas effacer l'encre de la signature."""
    cands = [w for w in words if w["conf"] >= 30 and len(w["text"]) >= 2]
    out = []
    for i, a in enumerate(cands):
        if a["conf"] >= 75:
            out.append(a); continue
        ta = norm(a["text"]).casefold()
        for j, b in enumerate(cands):
            if i == j or a["line"][:2] == b["line"][:2]:
                continue                                        # même passe (échelle, psm)
            ix = max(0, min(a["x"] + a["w"], b["x"] + b["w"]) - max(a["x"], b["x"]))
            iy = max(0, min(a["y"] + a["h"], b["y"] + b["h"]) - max(a["y"], b["y"]))
            if ix * iy > 0.5 * a["w"] * a["h"] and _levenshtein(ta, norm(b["text"]).casefold(), 2) <= 1:
                out.append(a); break
    return out


def _signature_label_boxes(words):
    out = []
    for w in words:
        t = w["text"].strip().casefold().strip(".,;:()")
        if t in SIGNATURE_WORDS or t.rstrip(":") in SIGNATURE_WORDS:
            out.append((w["x"], w["y"], w["x"] + w["w"], w["y"] + w["h"]))
    return out


def _near_label(box, labels, dist=SIG_NEAR_PX):
    x0, y0, x1, y1 = box
    for lx0, ly0, lx1, ly1 in labels:
        right = 0 <= x0 - lx1 <= dist and y0 <= ly1 + dist and y1 >= ly0 - dist        # à droite du libellé
        below = 0 <= y0 - ly1 <= dist and x0 <= lx1 + dist and x1 >= lx0 - dist        # en dessous
        if right or below:
            return True
    return False


def _cover_signatures(img, words, done_boxes, apply=True, force_location=False):
    """Détecteur de ZONE DE SIGNATURE (image ou rendu de page) et recouvrement ciblé.
    Candidats : composantes connexes d'encre sombre qu'aucune boîte de mot OCR ne couvre, regroupées par proximité.
    Filtres : (1) localisation — tiers bas de l'image OU ≤ 250 px à droite/en dessous d'un libellé « Signature/Signé/
    Signed/Unterschrift/Visa/Firma » (force_location : l'image est elle-même placée dans une zone de signature) ;
    (2) forme — largeur/hauteur entre 1,5 et 10, taux de remplissage 3–35 % ; (3) taille ≥ 40×12 px.
    Rejets explicites : encre à > 90 % sur le périmètre de la boîte (cadres), hauteur < 6 px (lignes, filets).
    Action : rectangle couleur de fond locale (+4 px), log SIGNATURE_COVERED. Sans apply : SIGNATURE_DETECTED."""
    import numpy as np
    from PIL import ImageDraw
    ink, page_bg = _ink_mask(img)
    h, w = ink.shape
    for wd in _trusted_words(words):
        x0, y0, x1, y1 = wd["x"] - 3, wd["y"] - 3, wd["x"] + wd["w"] + 3, wd["y"] + wd["h"] + 3
        ink[max(0, y0):min(h, y1), max(0, x0):min(w, x1)] = False
    for x0, y0, x1, y1 in done_boxes:
        ink[max(0, y0 - 4):min(h, y1 + 4), max(0, x0 - 4):min(w, x1 + 4)] = False
    comps = [list(c[:4]) for c in _components(ink) if c[3] - c[1] >= 3 and c[2] - c[0] >= 3]
    # regroupement par proximité (traits d'un même paraphe, soulignement) ; on garde les composantes de chaque groupe
    comps.sort(key=lambda b: (b[1], b[0]))
    merged, members = [], []
    for c in comps:
        for i, m in enumerate(merged):
            if c[0] <= m[2] + 30 and c[2] >= m[0] - 30 and c[1] <= m[3] + 20 and c[3] >= m[1] - 20:
                m[0], m[1], m[2], m[3] = min(m[0], c[0]), min(m[1], c[1]), max(m[2], c[2]), max(m[3], c[3]); members[i].append(c); break
        else:
            merged.append(list(c)); members.append([c])
    labels = _signature_label_boxes(words)
    log, zones = [], []
    for (x0, y0, x1, y1), parts in zip(merged, members):
        bw, bh = x1 - x0, y1 - y0
        why = None
        if bh < 6:
            why = "line"
        elif bw < 40 or bh < 12:
            why = "too_small"
        elif not (1.5 <= bw / bh <= 10):
            why = "aspect"
        elif not any((c[2] - c[0]) >= 0.5 * bw and (c[3] - c[1]) >= max(12, 0.3 * bh) for c in parts):
            why = "no_continuous_stroke"      # texte imprimé non lu : lettres séparées ; un paraphe est un trait continu
        else:
            sub = ink[y0:y1, x0:x1]
            total = int(sub.sum())
            fill = total / max(1, bw * bh)
            band = 3
            perim = int(sub[:band].sum() + sub[-band:].sum() + sub[band:-band, :band].sum() + sub[band:-band, -band:].sum())
            if total and perim / total > 0.9:
                why = "frame"
            elif not (0.03 <= fill <= 0.35):
                why = "fill=%.2f" % fill
            elif not (force_location or (y0 + y1) / 2 >= 2 * h / 3 or _near_label((x0, y0, x1, y1), labels)):
                why = "location"
        if why:
            if bw >= 40 and bh >= 12 and why not in ("line", "too_small"):
                log.append({"type": "SIGNATURE", "match": "rejected", "reason": why, "box": [int(x0), int(y0), int(x1), int(y1)]})
            continue
        zones.append((x0, y0, x1, y1))
    draw = ImageDraw.Draw(img)
    for x0, y0, x1, y1 in zones:
        pad = 4
        bx0, by0, bx1, by1 = max(0, x0 - pad), max(0, y0 - pad), min(w - 1, x1 + pad), min(h - 1, y1 + pad)
        border = [img.getpixel((x, y)) for x in range(bx0, bx1, 4) for y in (by0, by1)]
        bg = tuple(sorted(c[i] for c in border)[len(border) // 2] for i in range(3)) if border else tuple(int(v) for v in page_bg)
        if apply:
            draw.rectangle([bx0, by0, bx1, by1], fill=bg)
        log.append({"type": "SIGNATURE_COVERED" if apply else "SIGNATURE_DETECTED", "match": "covered" if apply else "detected",
                    "box": [int(bx0), int(by0), int(bx1), int(by1)], "original": None, "replacement": None})
    return log


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
# ---------------------------------------------------------------------------
# Objets imbriqués (OLE / package / pièces jointes) : routage récursif par extension, fail-closed sinon
# ---------------------------------------------------------------------------
MAX_EMBED_DEPTH = 3
_OLE_PREVIEW_EXT = (".emf", ".wmf")


def _route_embedded(name, data, pz, strict, depth, seen):
    """Traite un objet imbriqué (octets) : retourne (nouveaux octets ou None, entrée de log).
    .xlsx/.docx -> sanitize_xlsx/sanitize_docx (récursif, profondeur max, garde anti-boucle par empreinte) ;
    .bin (OLE compound) -> si un package Office est encapsulé, on l'extrait et on le traite, sinon EMBEDDED_UNSUPPORTED.
    Un objet non traité est toujours journalisé + marqué pour revue (jamais ignoré en silence)."""
    import hashlib as _h
    ext = os.path.splitext(name)[1].lower()
    fp = _h.sha256(data).hexdigest()[:16]
    entry = {"object": name, "bytes": len(data), "ext": ext, "depth": depth}
    if fp in seen:
        entry.update(status="skipped_loop", reason="objet déjà rencontré (garde anti-boucle)")
        return None, entry
    seen.add(fp)
    if depth > MAX_EMBED_DEPTH:
        entry.update(status="unsupported", type="EMBEDDED_UNSUPPORTED", reason="profondeur > %d" % MAX_EMBED_DEPTH, review=True)
        return None, entry
    handler = {".xlsx": sanitize_xlsx, ".xlsm": sanitize_xlsx, ".docx": sanitize_docx, ".docm": sanitize_docx}.get(ext)
    if handler is None and ext == ".bin":
        inner = _ole_extract_package(data)
        if inner:
            inner_name, inner_data = inner
            new, sub = _route_embedded(inner_name, inner_data, pz, strict, depth, seen)
            entry.update(status=sub.get("status"), ole_package=inner_name, inner=sub)
            if new is not None:
                new = _ole_replace_package(data, new)
                if new is None:
                    entry.update(status="unsupported", type="EMBEDDED_UNSUPPORTED", review=True,
                                 reason="package Office traité mais réécriture OLE impossible")
            return new, entry
        entry.update(status="unsupported", type="EMBEDDED_UNSUPPORTED", review=True,
                     reason="OLE compound sans package Office reconnu (ou olefile absent)")
        return None, entry
    if handler is None:
        entry.update(status="unsupported", type="EMBEDDED_UNSUPPORTED", review=True, reason="extension non gérée")
        return None, entry
    tmpd = tempfile.mkdtemp(prefix="emb_")
    try:
        src = os.path.join(tmpd, "in" + ext); dst = os.path.join(tmpd, "out" + ext)
        with open(src, "wb") as f:
            f.write(data)
        res = handler(src, dst, pz, strict, _depth=depth + 1, _seen=seen) if ext in (".docx", ".docm") else handler(src, dst, pz, strict)
        with open(dst, "rb") as f:
            new = f.read()
        n_txt = len(res.get("text_replacements", []))
        n_img = sum(len(i["replacements"]) for i in res.get("images", []))
        entry.update(status="processed", replacements=n_txt + n_img, embedded=res.get("embedded"))
        if res.get("review"):
            entry["review"] = res["review"]
        return new, entry
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def _ole_extract_package(data):
    """OLE compound (.bin) : renvoie (nom, octets) du package Office encapsulé (flux « Package » = OOXML zip), sinon None."""
    try:
        import olefile
    except ImportError:
        return None
    try:
        if not olefile.isOleFile(io.BytesIO(data)):
            return None
        ole = olefile.OleFileIO(io.BytesIO(data))
        for stream in (["Package"], ["package"]):
            if ole.exists("/".join(stream)):
                blob = ole.openstream(stream).read()
                if blob[:2] == b"PK":
                    with zipfile.ZipFile(io.BytesIO(blob)) as z:
                        names = z.namelist()
                    ext = ".xlsx" if any(n.startswith("xl/") for n in names) else ".docx" if any(n.startswith("word/") for n in names) else ""
                    return ("package" + ext, blob) if ext else None
        return None
    except Exception:
        return None


def _ole_replace_package(data, new_blob):
    """Réécrit le flux Package d'un OLE compound (même taille ou inférieure : olefile écrit en place ; sinon None)."""
    try:
        import olefile
        ole = olefile.OleFileIO(io.BytesIO(data), write_mode=True)
        for stream in (["Package"], ["package"]):
            if ole.exists("/".join(stream)):
                size = ole.get_size("/".join(stream))
                if len(new_blob) > size:
                    return None                         # olefile ne sait pas agrandir un flux
                ole.write_stream("/".join(stream), new_blob + b"\x00" * (size - len(new_blob)))
                ole.close()
                return ole.fp.getvalue()
    except Exception:
        return None
    return None


def _embedded_summary(entries):
    return {"found": [e["object"] for e in entries],
            "processed": [e["object"] for e in entries if e.get("status") == "processed"],
            "unsupported": [e["object"] for e in entries if e.get("status") not in ("processed",)],
            "details": entries}


def sanitize_docx(src, dst, pz, strict, _depth=0, _seen=None):
    from docx import Document
    d = Document(src)
    log = []
    seen = _seen if _seen is not None else set()

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
    # images incorporées + objets imbriqués (word/embeddings/*) + aperçus d'objets (EMF/WMF : non OCRisables -> revue)
    img_log, emb_log, review = [], [], []
    # python-docx ne réécrit que les parties reliées : un objet présent dans la source mais absent après sauvegarde
    # est signalé (perte de contenu silencieuse sinon)
    with zipfile.ZipFile(src) as zsrc, zipfile.ZipFile(tmp) as ztmp:
        dropped = [n for n in zsrc.namelist() if n.startswith("word/embeddings/") and n not in ztmp.namelist()]
    if dropped:
        review.append({"type": "EMBEDDED_DROPPED_BY_PYTHON_DOCX", "objects": dropped,
                       "hint": "objet sans relation dans document.xml.rels : absent de la sortie (pas de fuite, perte de contenu)"})
        emb_log += [{"object": n, "status": "dropped", "reason": "non relié, perdu à la sauvegarde"} for n in dropped]
    with zipfile.ZipFile(tmp) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            low = item.filename.lower()
            if item.filename.startswith("word/media/") and low.endswith((".png", ".jpg", ".jpeg")):
                data, l = sanitize_image_bytes(data, os.path.splitext(item.filename)[1], pz, strict)
                img_log.append({"media": item.filename, "replacements": l})
            elif item.filename.startswith("word/media/") and low.endswith(_OLE_PREVIEW_EXT):
                # l'aperçu Word d'un objet Excel imbriqué montre les valeurs EN CLAIR ; un métafichier n'est ni OCRisé
                # ni réécrit ici -> fail-closed : signalé pour revue (l'objet lui-même est traité ci-dessous)
                review.append({"type": "EMBEDDED_PREVIEW_UNSUPPORTED", "media": item.filename,
                               "hint": "aperçu EMF/WMF d'un objet imbriqué : valeurs potentiellement en clair, non traité"})
            elif item.filename.startswith("word/embeddings/"):
                new, e = _route_embedded(item.filename, data, pz, strict, _depth, seen)
                emb_log.append(e)
                if new is not None:
                    data = new
                    item = zipfile.ZipInfo(item.filename, date_time=item.date_time); item.compress_type = zipfile.ZIP_DEFLATED
                else:
                    review.append({"type": e.get("type", "EMBEDDED_UNSUPPORTED"), "object": item.filename, "reason": e.get("reason")})
            zout.writestr(item, data)
    os.unlink(tmp)
    res = {"text_replacements": log, "images": img_log}
    if emb_log:
        res["embedded"] = _embedded_summary(emb_log)
    if review:
        res["review"] = review
    return res


# ---------------------------------------------------------------------------
# RTF : conversion LibreOffice (RTF -> DOCX -> sanitize_docx -> RTF). Variante « native » (parser les mots de
# contrôle RTF et patcher les runs en place) = cible production, non codée ici (voir RAPPORT gap customer).
# ---------------------------------------------------------------------------
_SOFFICE_CANDIDATES = [os.environ.get("SOFFICE", ""), "/usr/bin/soffice", "/usr/lib/libreoffice/program/soffice",
                       os.path.expanduser("~/Applications/LibreOffice.app/Contents/MacOS/soffice"),
                       "/Applications/LibreOffice.app/Contents/MacOS/soffice"]


def soffice_bin():
    for c in _SOFFICE_CANDIDATES:
        if c and os.path.exists(c):
            return c
    return None


def soffice_convert(src, fmt, outdir, timeout=120):
    """`soffice --headless --convert-to <fmt>` avec un profil utilisateur ISOLÉ par appel (-env:UserInstallation) :
    deux requêtes simultanées ne se disputent pas le verrou du profil par défaut."""
    exe = soffice_bin()
    if not exe:
        raise RuntimeError("LibreOffice (soffice) introuvable : nécessaire pour le RTF (conteneur : libreoffice-writer)")
    prof = tempfile.mkdtemp(prefix="lo_%d_" % os.getpid())
    cmd = [exe, "--headless", "--norestore", "--nologo", "-env:UserInstallation=file://%s" % prof,
           "--convert-to", fmt, "--outdir", outdir, src]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    finally:
        shutil.rmtree(prof, ignore_errors=True)
    out = os.path.join(outdir, os.path.splitext(os.path.basename(src))[0] + "." + fmt)
    if not os.path.exists(out):
        raise RuntimeError("conversion LibreOffice %s -> %s échouée : %s %s" % (os.path.basename(src), fmt, r.stdout.strip(), r.stderr.strip()))
    return out


def _docx_text_parts(path):
    """Texte d'un DOCX par zone : body (paragraphes + tableaux), header, footer — pour le contrôle de fidélité RTF."""
    from docx import Document
    d = Document(path)
    body = [p.text for p in d.paragraphs] + [c.text for t in d.tables for r in t.rows for c in r.cells]
    header = [p.text for s_ in d.sections for p in s_.header.paragraphs]
    footer = [p.text for s_ in d.sections for p in s_.footer.paragraphs]
    return {"body": "\n".join(body), "header": "\n".join(header), "footer": "\n".join(footer),
            "tables": len(d.tables), "paragraphs": len(d.paragraphs)}


def sanitize_rtf(src, dst, pz, strict):
    """RTF -> DOCX (LibreOffice) -> sanitize_docx -> RTF (LibreOffice). Puis contrôle : tout le texte NON sensible du RTF
    de sortie doit être identique à l'entrée (diff des jetons hors valeurs remplacées) ; en-tête, pied de page et tableaux
    doivent survivre à l'aller-retour. Un écart est journalisé (RTF_FIDELITY_WARN) et marque le fichier pour revue."""
    tmp = tempfile.mkdtemp(prefix="rtf_")
    try:
        docx_in = soffice_convert(src, "docx", tmp)
        work = os.path.join(tmp, "work"); os.makedirs(work)
        docx_out = os.path.join(work, os.path.basename(docx_in))
        res = sanitize_docx(docx_in, docx_out, pz, strict)
        rtf_out = soffice_convert(docx_out, "rtf", work)
        shutil.move(rtf_out, dst)
        # contrôle de fidélité sur le RTF réellement écrit (re-lu via DOCX)
        back = soffice_convert(dst, "docx", os.path.join(tmp, "back"))
        a, b = _docx_text_parts(docx_in), _docx_text_parts(back)
        originals = {e["original"] for e in res.get("text_replacements", [])}
        replacements = {e["replacement"] for e in res.get("text_replacements", [])}

        def tokens(txt, drop):
            for v in sorted(drop, key=len, reverse=True):
                txt = txt.replace(v, " ")
            return collections.Counter(re.findall(r"\w+", txt))
        fid = {}
        for zone in ("body", "header", "footer"):
            ta, tb = tokens(a[zone], originals), tokens(b[zone], replacements)
            fid[zone] = {"missing": sorted((ta - tb).elements())[:20], "added": sorted((tb - ta).elements())[:20],
                         "tokens_in": sum(ta.values()), "tokens_out": sum(tb.values())}
        fid["tables_in"], fid["tables_out"] = a["tables"], b["tables"]
        fid["header_present"] = bool(b["header"].strip()) if a["header"].strip() else True
        fid["footer_present"] = bool(b["footer"].strip()) if a["footer"].strip() else True
        problems = [z for z in ("body", "header", "footer") if fid[z]["missing"] or fid[z]["added"]]
        if a["tables"] != b["tables"]:
            problems.append("tables")
        if not fid["header_present"]:
            problems.append("header_lost")
        if not fid["footer_present"]:
            problems.append("footer_lost")
        fid["ok"] = not problems
        res["rtf"] = {"via": "libreoffice", "fidelity": fid}
        if problems:
            res.setdefault("review", []).append({"type": "RTF_FIDELITY_WARN", "zones": problems,
                                                 "hint": "LibreOffice a modifié du texte non sensible ou perdu une zone : vérifier le RTF"})
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
    res = {"text_replacements": log}
    # objets imbriqués dans un classeur (xl/embeddings/*) : openpyxl ne les conserve pas tous ; on relit la SOURCE
    # et on réinjecte les objets traités dans la sortie (fail-closed : un objet non traité est signalé).
    with zipfile.ZipFile(src) as zsrc:
        emb_names = [n for n in zsrc.namelist() if n.startswith("xl/embeddings/")]
        emb_data = {n: zsrc.read(n) for n in emb_names}
    if emb_names:
        emb_log, review = [], []
        with zipfile.ZipFile(dst) as zin:
            present = set(zin.namelist())
        for n in emb_names:
            new, e = _route_embedded(n, emb_data[n], pz, strict, 0, set())
            emb_log.append(e)
            if new is None:
                review.append({"type": e.get("type", "EMBEDDED_UNSUPPORTED"), "object": n, "reason": e.get("reason")})
            emb_data[n] = new
        if any(v is not None for v in emb_data.values()) and all(n in present for n in emb_names):
            tmp = dst + ".tmp.xlsx"
            with zipfile.ZipFile(dst) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename in emb_data and emb_data[item.filename] is not None:
                        data = emb_data[item.filename]
                    zout.writestr(item, data)
            shutil.move(tmp, dst)
        elif not all(n in present for n in emb_names):
            review.append({"type": "EMBEDDED_DROPPED_BY_OPENPYXL", "objects": [n for n in emb_names if n not in present],
                           "hint": "openpyxl n'a pas conservé l'objet : absent de la sortie (pas de fuite, mais perte de contenu)"})
        res["embedded"] = _embedded_summary(emb_log)
        if review:
            res["review"] = review
    return res


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



# ---------------------------------------------------------------------------
# PDF : pages SCANNÉES (aucun mot dans la couche texte, une image couvre la page)
# ---------------------------------------------------------------------------
SCAN_DPI = int(os.environ.get("SCAN_DPI", "300"))


def _estimate_skew(gray, max_deg=3.0):
    """Angle (degrés) tel que gray.rotate(angle) redresse les lignes de texte. Profil de projection : on maximise la
    variance des sommes de lignes de l'image binarisée (les lignes de texte redressées donnent des pics nets).
    numpy + PIL seulement (pas d'OpenCV). Grossier au pas de 0,25° puis fin au pas de 0,05°."""
    import numpy as np
    from PIL import Image
    small = gray.resize((max(1, int(gray.width * 1000 / gray.height)), 1000), Image.BILINEAR) if gray.height > 1000 else gray
    a = np.asarray(small)
    thr = max(60, min(200, int(np.percentile(a, 30))))          # encre = plus sombre que le fond
    binimg = Image.fromarray(((a < thr) * 255).astype("uint8"))

    def score(angle):
        r = np.asarray(binimg.rotate(angle, resample=Image.BILINEAR, fillcolor=0))
        rows = r.sum(axis=1).astype(float)
        return rows.var()
    coarse = np.arange(-max_deg, max_deg + 0.001, 0.25)
    best = max(coarse, key=score)
    fine = np.arange(best - 0.25, best + 0.2501, 0.05)
    best = max(fine, key=score)
    return float(round(best, 2)) if abs(best) >= 0.1 else 0.0


def _prep_scan(render):
    """Prétraitement OCR d'une page scannée : niveaux de gris + normalisation de contraste (percentiles 1/99)."""
    import numpy as np
    from PIL import Image
    g = np.asarray(render.convert("L")).astype(float)
    lo, hi = np.percentile(g, 1), np.percentile(g, 99)
    if hi - lo < 30:
        return render.convert("L")
    g = np.clip((g - lo) * 255.0 / (hi - lo), 0, 255)
    return Image.fromarray(g.astype("uint8"))


def _pil_rotate_matrix(w, h, angle):
    """Matrice affine (a, b, c, d, e, f) utilisée par PIL pour img.rotate(angle) : sortie (x, y) -> entrée."""
    import math
    rad = -math.radians(angle % 360)          # PIL : angle = -radians(angle) (rotation anti-horaire à l'écran)
    a, b, d, e = round(math.cos(rad), 15), round(math.sin(rad), 15), round(-math.sin(rad), 15), round(math.cos(rad), 15)
    cx, cy = w / 2.0, h / 2.0
    c = a * (-cx) + b * (-cy) + cx
    f = d * (-cx) + e * (-cy) + cy
    return (a, b, c, d, e, f)


def _affine_apply(m, x, y):
    a, b, c, d, e, f = m
    return a * x + b * y + c, d * x + e * y + f


def _affine_from_points(src, dst):
    """Affine 2×3 qui envoie les 3 points src sur dst (résolution exacte)."""
    import numpy as np
    A = np.array([[sx, sy, 1] for sx, sy in src], dtype=float)
    bx = np.array([d[0] for d in dst], dtype=float); by = np.array([d[1] for d in dst], dtype=float)
    ax = np.linalg.solve(A, bx); ay = np.linalg.solve(A, by)
    return (ax[0], ax[1], ax[2], ay[0], ay[1], ay[2])


def _affine_invert(m):
    a, b, c, d, e, f = m
    det = a * e - b * d
    ia, ib, id_, ie = e / det, -b / det, -d / det, a / det
    return (ia, ib, -(ia * c + ib * f), id_, ie, -(id_ * c + ie * f))


def _covering_image(page, doc, min_cover=0.8):
    """Image XObject qui couvre ≥ 80 % de la page : (xref, rect, matrice) ou None (images inline BI/EI, ou rien)."""
    import fitz
    best = None
    for im in page.get_images(full=True):
        xref = im[0]
        try:
            for rect, M in page.get_image_rects(xref, transform=True):
                cover = (rect & page.mediabox).get_area() / max(1.0, page.mediabox.get_area()) if page.rotation else \
                        (rect & page.rect).get_area() / max(1.0, page.rect.get_area())
                if cover >= min_cover and (best is None or cover > best[0]):
                    best = (cover, xref, rect, M)
        except Exception:
            continue
    return best[1:] if best else None


def _transfer_patches(src_img, dst_img, boxes, T):
    """Copie dans dst_img (image brute) les zones `boxes` de src_img (rendu redressé), via l'affine T (src -> dst) :
    le rendu réécrit est reprojeté sur la géométrie d'origine (rotation, /Rotate, échelle), sans toucher au reste."""
    from PIL import Image, ImageDraw
    Tinv = _affine_invert(T)
    W, H = dst_img.size
    for (x0, y0, x1, y1) in boxes:
        pad = 2
        corners = [(x0 - pad, y0 - pad), (x1 + pad, y0 - pad), (x1 + pad, y1 + pad), (x0 - pad, y1 + pad)]
        dc = [_affine_apply(T, x, y) for x, y in corners]
        bx0, by0 = max(0, int(min(p[0] for p in dc)) - 1), max(0, int(min(p[1] for p in dc)) - 1)
        bx1, by1 = min(W, int(max(p[0] for p in dc)) + 2), min(H, int(max(p[1] for p in dc)) + 2)
        if bx1 <= bx0 or by1 <= by0:
            continue
        a, b, c, d, e, f = Tinv
        data = (a, b, a * bx0 + b * by0 + c, d, e, d * bx0 + e * by0 + f)      # (x, y) de la vignette -> source
        patch = src_img.transform((bx1 - bx0, by1 - by0), Image.AFFINE, data, resample=Image.BICUBIC)
        mask = Image.new("L", (bx1 - bx0, by1 - by0), 0)
        ImageDraw.Draw(mask).polygon([(px - bx0, py - by0) for px, py in dc], fill=255)
        dst_img.paste(patch, (bx0, by0), mask)


def _leak_suspects(words, pz, strict):
    """2e filet : sur le rendu APRÈS masquage, tout candidat qui n'est pas un pseudonyme connu est suspect.
    Un pseudonyme mal relu par l'OCR (devise collée « … 5816 1 CHF », un caractère faux) n'est pas un suspect :
    tolérance Levenshtein ≤ 1 (≤ 2 au-delà de 12 caractères) après retrait d'un jeton alphabétique final."""
    reps = {norm(rep).casefold() for (_, rep) in pz.exact.values()} | {norm(g).casefold() for g in pz.generated.values()}
    by_len = {}
    for r_ in reps:
        by_len.setdefault(len(r_), []).append(r_)

    def is_pseudonym(v):
        v2 = re.sub(r"\s+[A-Za-z]{2,4}$", "", v)              # « CHF », « EUR » collés par l'OCR
        for cand in {norm(v).casefold(), norm(v2).casefold()}:
            if cand in reps:
                return True
            cap = 2 if len(cand) > 12 else 1
            for L in range(len(cand) - cap, len(cand) + cap + 1):
                if any(_levenshtein(cand, r_, cap) <= cap for r_ in by_len.get(L, ())):
                    return True
        return False
    return [c for c in _collect_candidates(words, pz, strict) if not is_pseudonym(c[2])]


# ---------------------------------------------------------------------------
# PDF : signatures vectorielles / annotations / widgets
# ---------------------------------------------------------------------------
def _pdf_signature_labels(page):
    out = []
    for w in page.get_text("words"):
        t = w[4].strip().casefold().strip(".,;:()")
        if t in SIGNATURE_WORDS or t.rstrip(":") in SIGNATURE_WORDS:
            out.append((w[0], w[1], w[2], w[3]))
    return out


def _rect_in_signature_zone(page, r, labels, dist_pt=100):
    if (r.y0 + r.y1) / 2 >= page.rect.y0 + 2 * page.rect.height / 3:
        return True
    return _near_label((r.x0, r.y0, r.x1, r.y1), labels, dist=dist_pt)


def _cover_vector_signatures(page, fitz):
    """Tracés courbes (items 'c' de get_drawings) regroupés par proximité, filtrés comme le raster (localisation, ratio
    1,5–10, taille ≥ 30×8 pt, ni rectangle ni ligne) -> redaction (retrait des tracés couverts) + rectangle couleur de fond.
    Annotations /Ink et champs de signature (/Sig) -> supprimés puis recouverts. Log SIGNATURE_COVERED par zone."""
    log = []
    labels = _pdf_signature_labels(page)
    groups = []
    for d in page.get_drawings():
        items = d.get("items", [])
        kinds = [it[0] for it in items]
        if "c" not in kinds:
            continue                                   # rectangles, lignes, filets : pas un paraphe
        r = d["rect"]
        for g in groups:
            if r.x0 <= g["rect"].x1 + 20 and r.x1 >= g["rect"].x0 - 20 and r.y0 <= g["rect"].y1 + 15 and r.y1 >= g["rect"].y0 - 15:
                g["rect"] |= r; g["n"] += 1; g["curves"] += kinds.count("c"); break
        else:
            groups.append({"rect": fitz.Rect(r), "n": 1, "curves": kinds.count("c")})
    zones = []
    for g in groups:
        r = g["rect"]; bw, bh = r.width, r.height
        why = None
        if bh < 8 or bw < 30:
            why = "too_small"
        elif not (1.5 <= bw / max(bh, 0.1) <= 10):
            why = "aspect"
        elif g["curves"] < 2:
            why = "single_curve"
        elif not _rect_in_signature_zone(page, r, labels):
            why = "location"
        if why:
            log.append({"type": "SIGNATURE", "match": "rejected_vector", "reason": why, "box": [round(v, 1) for v in r]})
            continue
        zones.append(("vector", r))
    for annot in list(page.annots() or []):
        if annot.type[0] == fitz.PDF_ANNOT_INK:
            zones.append(("ink_annot", fitz.Rect(annot.rect))); page.delete_annot(annot)
    for wdg in list(page.widgets() or []):
        if wdg.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
            zones.append(("sig_widget", fitz.Rect(wdg.rect)))
            try:
                page.delete_widget(wdg)
            except Exception:
                pass
    if not zones:
        return log
    for kind, r in zones:
        box = fitz.Rect(r.x0 - 4, r.y0 - 4, r.x1 + 4, r.y1 + 4) & page.rect
        # couleur de fond locale : médiane du rendu autour de la boîte
        try:
            pix = page.get_pixmap(clip=fitz.Rect(box.x0 - 6, box.y0 - 6, box.x1 + 6, box.y1 + 6) & page.rect, dpi=72)
            import numpy as np
            a = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)[:, :, :3]
            edge = np.concatenate([a[0], a[-1], a[:, 0], a[:, -1]])
            bg = tuple(float(v) / 255 for v in np.median(edge, axis=0))
        except Exception:
            bg = (1, 1, 1)
        page.add_redact_annot(box, fill=bg)
        log.append({"type": "SIGNATURE_COVERED", "match": "covered_" + kind, "box": [round(v, 1) for v in box], "original": None, "replacement": None})
    # la redaction retire les tracés entièrement couverts et peint le fond ; les cadres/filets qui ne font que
    # traverser la boîte ne sont pas retirés (REMOVE_IF_COVERED, pas IF_TOUCHED)
    page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE, graphics=fitz.PDF_REDACT_LINE_ART_REMOVE_IF_COVERED)
    return log


def sanitize_scanned_page(page, doc, pz, strict, dpi=SCAN_DPI):
    """Page scannée : rendu (rotation /Rotate et orientation de l'image appliquées) -> gris + contraste -> déskew ->
    OCR -> masquage sur le rendu redressé -> reprojection des zones réécrites sur l'image brute (géométrie d'origine
    conservée) -> replace_image. Puis 2e passe OCR sur la page masquée : valeur encore lue -> LEAK_SUSPECT + recouverte.
    Sans XObject (images inline BI/EI) : le rendu masqué remplace le contenu de la page (fail-closed, journalisé)."""
    import fitz
    import numpy as np
    from PIL import Image
    fonts = _font_candidates()
    hit = _covering_image(page, doc)
    pix = page.get_pixmap(dpi=dpi)
    render = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    gray = _prep_scan(render)
    skew = _estimate_skew(gray)
    D = gray.rotate(skew, resample=Image.BICUBIC, fillcolor=255).convert("RGB")     # pour l'OCR
    Dp = render.rotate(skew, resample=Image.BICUBIC, fillcolor=(255, 255, 255))     # pour la peinture (couleurs)
    words = _ocr_words(D, (1,))
    cands = _collect_candidates(words, pz, strict)
    done, log = _paint_candidates(Dp, cands, fonts)
    try:
        sig = _cover_signatures(Dp, words, done, apply=os.environ.get("COVER_SIGNATURES", "1") == "1")
        log += sig; done += [tuple(e["box"]) for e in sig if e.get("match") == "covered"]
    except Exception as exc:  # noqa
        log.append({"type": "SIGNATURE", "match": "detect_failed", "error": str(exc)})
    info = {"page": page.number + 1, "scanned": True, "skew": skew, "dpi": dpi, "masked": len(done),
            "method": "xobject" if hit else "inline_render", "rotate": page.rotation}

    # D (rendu redressé) -> rendu -> point page (tourné) -> point page (non tourné) -> unité image -> pixel brut
    rot = _pil_rotate_matrix(render.width, render.height, skew)          # D (x, y) -> rendu (x, y)

    def apply_replacement(painted, boxes, tag):
        if not boxes:
            return
        if hit:
            xref, rect, M = hit
            raw_info = doc.extract_image(xref)
            raw = Image.open(io.BytesIO(raw_info["image"])).convert("RGB")
            Minv = ~M
            k = 72.0 / dpi

            def d2raw(x, y):
                rx, ry = _affine_apply(rot, x, y)
                pt = fitz.Point(rx * k, ry * k) * page.derotation_matrix * Minv
                return pt.x * raw.width, pt.y * raw.height
            src = [(0, 0), (1000, 0), (0, 1000)]
            T = _affine_from_points(src, [d2raw(*q) for q in src])
            _transfer_patches(painted, raw, boxes, T)
            buf = io.BytesIO()
            if raw_info["ext"].lower() in ("jpeg", "jpg"):
                raw.save(buf, "JPEG", quality=80)
            else:
                raw.save(buf, "PNG")
            page.replace_image(xref, stream=buf.getvalue())
        else:
            # pas de XObject : le rendu masqué (ramené à la géométrie du rendu) devient la page
            back = painted.rotate(-skew, resample=Image.BICUBIC, fillcolor=(255, 255, 255))
            buf = io.BytesIO(); back.save(buf, "JPEG", quality=80)
            for cx in page.get_contents():
                doc.update_stream(cx, b"")
            # le rendu est dans l'orientation d'AFFICHAGE : on l'insère dans le mediabox (non tourné) avec rotate=/Rotate
            # (vérifié empiriquement sur une page /Rotate 90 : seule cette combinaison relit droit)
            page.insert_image(page.mediabox, stream=buf.getvalue(), rotate=page.rotation)
            log.append({"type": "SCAN_INLINE_REPLACED", "match": tag,
                        "hint": "page sans XObject image : contenu remplacé par le rendu masqué (revue conseillée)"})

    apply_replacement(Dp, done, "first_pass")
    # ---- 2e filet : OCR du rendu masqué ----
    pix2 = page.get_pixmap(dpi=dpi)
    render2 = Image.frombytes("RGB", (pix2.width, pix2.height), pix2.samples)
    D2 = _prep_scan(render2).rotate(skew, resample=Image.BICUBIC, fillcolor=255).convert("RGB")
    words2 = _ocr_words(D2, (1,))
    suspects = _leak_suspects(words2, pz, strict)
    if suspects:
        Dp2 = render2.rotate(skew, resample=Image.BICUBIC, fillcolor=(255, 255, 255))
        done2, log2 = _paint_candidates(Dp2, suspects, fonts, extra_tag="LEAK_SUSPECT")
        for e in log2:
            e["type_leak"] = e["type"]; e["type"] = "LEAK_SUSPECT"
        log += log2
        apply_replacement(Dp2, done2, "second_pass")
        info["leak_suspects_covered"] = len(done2)
    info["unread_ink"] = None
    return info, log


def sanitize_pdf(src, dst, pz, strict):
    try:
        import fitz  # PyMuPDF
    except ImportError:
        return {"skipped": "PyMuPDF (fitz) non disponible dans cet environnement — installer `pip install pymupdf` pour la branche PDF"}
    doc = fitz.open(src)
    log, img_log, pages_log = [], [], []
    for page in doc:
        words_on_page = page.get_text("words")
        if not words_on_page:
            # page sans couche texte : scannée si une image la couvre (ou images inline -> rendu) ; vide sinon
            blank = not page.get_images(full=True) and not page.get_drawings()
            if not blank:
                info, l = sanitize_scanned_page(page, doc, pz, strict)
                pages_log.append(info)
                img_log.append({"page": page.number + 1, "xref": None, "scanned": True, "replacements": l})
                continue
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
        # signatures vectorielles (tracés courbes), annotations /Ink, champs /Sig -> recouvrement (COVER_SIGNATURES)
        if os.environ.get("COVER_SIGNATURES", "1") == "1":
            try:
                sl = _cover_vector_signatures(page, fitz)
                if sl:
                    img_log.append({"page": page.number + 1, "xref": None, "vector": True, "replacements": sl})
            except Exception as exc:  # noqa
                img_log.append({"page": page.number + 1, "xref": None, "vector": True,
                                "replacements": [{"type": "SIGNATURE", "match": "vector_detect_failed", "error": str(exc)}]})
        sig_labels = _pdf_signature_labels(page)
        for img in page.get_images(full=True):
            xref = img[0]
            info = doc.extract_image(xref)
            # une image placée dans une zone de signature (tiers bas, ou près d'un libellé) est peut-être LE paraphe
            ctx = False
            try:
                for r in page.get_image_rects(xref):
                    if _rect_in_signature_zone(page, r, sig_labels):
                        ctx = True
            except Exception:
                pass
            data, l = sanitize_image_bytes(info["image"], "." + info["ext"], pz, strict, signature_context=ctx)
            if l:
                page.replace_image(xref, stream=data)
                img_log.append({"page": page.number + 1, "xref": xref, "signature_context": ctx, "replacements": l})
        pages_log.append({"page": page.number + 1, "scanned": False, "masked": len([r for r in rects if r[3]])})
    # garbage=4 + clean : supprime les objets devenus orphelins après replace_image (l'ancienne image comptait
    # encore dans le PDF de sortie — anomalie « 8 images au lieu de 4 »). À recouper avec `pdfimages -list`.
    # pièces jointes (embedded files) : extraites, routées par extension, réécrites (embfile_upd) ; inconnues -> revue
    emb_log, review = [], []
    for name in list(doc.embfile_names()):
        info = doc.embfile_info(name)
        fname = info.get("filename") or info.get("name") or name
        data = doc.embfile_get(name)
        new, e = _route_embedded(fname, data, pz, strict, 0, set())
        emb_log.append(e)
        if new is not None:
            # PyMuPDF 1.28 : embfile_upd(buffer_=bytes) plante (« bytes has no m_internal ») -> suppression + réinsertion
            doc.embfile_del(name)
            doc.embfile_add(name, new, filename=info.get("filename") or fname, ufilename=info.get("ufilename") or fname,
                            desc=info.get("desc") or "")
        else:
            review.append({"type": e.get("type", "EMBEDDED_UNSUPPORTED"), "object": fname, "reason": e.get("reason")})
    doc.save(dst, garbage=4, clean=True, deflate=True)
    res = {"text_replacements": log, "images": img_log, "pages": pages_log}
    if emb_log:
        res["embedded"] = _embedded_summary(emb_log)
    if review:
        res["review"] = review
    return res


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
                elif ext == ".rtf":
                    res = sanitize_rtf(src, dst, pz, a.strict)
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
