# -*- coding: utf-8 -*-
"""
sanitize_reference.py — REFERENCE implementation of the sanitization service (option B of the Phase 1 study).

Role: prove the feasibility of "meaningful", consistent pseudonymization outside Securiti, and serve as the foundation
for the service (Azure Function / container) called by the Securiti workflow (HTTP Request) or by Power Automate.

  Inputs
    --inbound   folder of the files to sanitize (PDF, DOCX, XLSX, PNG/JPG)
    --output    output folder (sanitized copies + sanitization_log.json)
    --mapping   value -> substitution table (ground_truth/mapping_by_value.csv); unknown values detected by
                pattern (IBAN, AVS, card, e-mail, phone, patient no., insured card no.) receive a DETERMINISTIC
                (HMAC) substitution in a valid format (IBAN mod-97, AVS EAN-13, test card, etc.)
    --evidence  (optional) Securiti evidence export (CSV): adds its detected values to the list to substitute
    --strict    also replaces diagnoses/medications with their generalization (strict_replacement column of the
                ground truth)

  Formats
    DOCX : paragraphs + tables + headers/footers; embedded images (word/media) passed to OCR redaction
    XLSX : all text cells (formulas preserved)
    PNG/JPG : Tesseract OCR (TSV, word boxes) -> cover the area + write the pseudonym
    PDF  : PyMuPDF (fitz) if available: redaction of the spans + reinsertion of the pseudonym, embedded images
           extracted -> OCR redaction -> replaced. Without PyMuPDF: file skipped (message).

Known limits (reference, not production): no NER for names outside the mapping (plan for Presidio/spaCy in the
service), DOCX paragraph formatting reduced to the style of the first run when a value is modified, values
split across two lines in images not handled.
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

def _hmac_secret():
    """HMAC key behind every generated pseudonym. Read from HMAC_SECRET (value, <VAR>_FILE or /run/secrets/HMAC_SECRET),
    else SERVICE_API_KEY (already a Swarm secret), else a demo constant with a warning: the repository is public, so a
    hard-coded key would let anyone recompute generated pseudonyms by enumeration."""
    for name in ("HMAC_SECRET", "SERVICE_API_KEY"):
        val = os.environ.get(name)
        path = os.environ.get(name + "_FILE") or ("/run/secrets/" + name if os.path.exists("/run/secrets/" + name) else None)
        if not val and path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                val = f.read().strip()
        if val:
            return val.encode("utf-8")
    if os.environ.get("MASQUERADING_IN_CONTAINER") == "1":
        print("WARNING: HMAC_SECRET not set, generated pseudonyms use the demo key", file=sys.stderr)
    return b"demo-secret-change-me"


SECRET = _hmac_secret()
KEEP_TYPES = {"DIAGNOSIS_ICD", "DIAGNOSIS_LABEL", "MEDICATION"}


def norm(s):
    return re.sub(r"\s+", "", s or "")


def hnum(value, n):
    """Deterministic n-digit integer derived from the value (HMAC-SHA256)."""
    h = hmac.new(SECRET, norm(value).upper().encode(), hashlib.sha256).hexdigest()
    return str(int(h, 16) % (10 ** n)).zfill(n)


# ---------------------------------------------------------------------------
class Pseudonymizer:
    """Pseudonym table + pattern detection + deterministic generation for unknown values."""

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
        self.map = {}          # normalized key -> (data_type, substitution)
        self.exact = {}        # exact value -> substitution
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
        # "dictionary" pattern: all known values, longest first, word boundaries
        keys = sorted(set(list(self.exact) + list(self.strict) + list(self.extra_values)), key=len, reverse=True)
        keys = [k for k in keys if len(k) >= 3]
        self.dict_re = re.compile("|".join(r"(?<![\w@.])" + re.escape(k) + r"(?![\w@])" for k in keys)) if keys else None
        self.generated = {}

    # --- deterministic generation for values outside the table ---------------
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

    # --- detection -------------------------------------------------------------
    def detect(self, text, strict=False):
        """Returns non-overlapping spans (start, end, dtype, original, replacement)."""
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
                    # An IBAN body is not a card number: 16 consecutive digits taken from an IBAN pass Luhn
                    # by chance (~1 time in 10). Without this guard, the sanitizer replaced two "IBAN with
                    # invalid checksum" decoys on page 179 with test card numbers.
                    before = text[max(0, m.start() - 8):m.start()]
                    if re.search(r"[A-Z]{2}\d{2}\s?$", before) or re.search(r"\d\s?$", before):
                        continue
                known = self.map.get(norm(v).casefold())
                rep = known[1] if known else self.generate(dtype, v)
                if known and " " not in v and " " in rep:
                    rep = rep.replace(" ", "")
                spans.append((m.start(), m.end(), dtype, v, rep))
        # keep the longest one in case of overlap
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
# Images: Tesseract OCR (TSV) -> boxes -> cover + pseudonym
# ---------------------------------------------------------------------------
def tesseract_tsv(img_path, psm):
    """Tesseract word boxes (TSV). Fails CLOSED: a missing binary, a timeout or a non-zero exit raises, so the file
    errors out instead of being written back unchanged and reported as sanitized."""
    try:
        res = subprocess.run(["tesseract", img_path, "stdout", "--psm", str(psm), "tsv"], capture_output=True, text=True, timeout=180)
    except FileNotFoundError as exc:
        raise RuntimeError("tesseract binary not found: OCR unavailable, refusing to pass the image through") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("tesseract timed out after 180 s (psm %s)" % psm) from exc
    if res.returncode != 0:
        raise RuntimeError("tesseract failed (rc=%d): %s" % (res.returncode, (res.stderr or "")[-300:]))
    out = res.stdout
    rows = list(csv.DictReader(io.StringIO(out), delimiter="\t", quoting=csv.QUOTE_NONE))
    return [r for r in rows if r.get("level") == "5" and r.get("text", "").strip()]


_LO_FONTS = ("~/Applications/LibreOffice.app/Contents/Resources/fonts/truetype", "/Applications/LibreOffice.app/Contents/Resources/fonts/truetype")
_FONT_FAMILIES = [
    # (name, Linux/container candidates, DejaVu bundled with LibreOffice (macOS, same metrics as the container),
    #  macOS fallback)
    ("sans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", *(d + "/DejaVuSans.ttf" for d in _LO_FONTS),
     "/System/Library/Fonts/Supplemental/Arial.ttf", "/Library/Fonts/Arial.ttf"),
    ("sans-bold", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", *(d + "/DejaVuSans-Bold.ttf" for d in _LO_FONTS),
     "/System/Library/Fonts/Supplemental/Arial Bold.ttf"),
    ("mono", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", *(d + "/DejaVuSansMono.ttf" for d in _LO_FONTS),
     "/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Supplemental/Courier New.ttf"),
    ("serif", "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf", *(d + "/DejaVuSerif.ttf" for d in _LO_FONTS),
     "/System/Library/Fonts/Supplemental/Times New Roman.ttf"),
    ("condensed", "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf", *(d + "/DejaVuSansCondensed.ttf" for d in _LO_FONTS),
     "/System/Library/Fonts/Supplemental/Arial Narrow.ttf"),
    # slanted variants: chosen only when the original glyphs are slanted (_ink_slant), never based on width
    ("sans-oblique", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf", *(d + "/DejaVuSans-Oblique.ttf" for d in _LO_FONTS),
     "/System/Library/Fonts/Supplemental/Arial Italic.ttf"),
    ("sans-bold-oblique", "/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf", *(d + "/DejaVuSans-BoldOblique.ttf" for d in _LO_FONTS),
     "/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf"),
    ("serif-italic", "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Italic.ttf", *(d + "/DejaVuSerif-Italic.ttf" for d in _LO_FONTS),
     "/System/Library/Fonts/Supplemental/Times New Roman Italic.ttf"),
    ("condensed-oblique", "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed-Oblique.ttf", *(d + "/DejaVuSansCondensed-Oblique.ttf" for d in _LO_FONTS)),
]
_ITALIC_OF = {"sans": "sans-oblique", "sans-bold": "sans-bold-oblique", "serif": "serif-italic", "condensed": "condensed-oblique"}



def _font_candidates():
    """Available TrueType families: {name: path}. $SANITIZE_FONT forces the "sans" family."""
    out = {}
    forced = os.environ.get("SANITIZE_FONT", "")
    if forced and os.path.exists(forced):
        out["sans"] = forced
    for fam in _FONT_FAMILIES:
        if fam[0] in out:
            continue
        for p in fam[1:]:
            p = os.path.expanduser(p)
            if os.path.exists(p):
                out[fam[0]] = p; break
    if not out:
        raise RuntimeError("Aucune police TrueType trouvée ; définir SANITIZE_FONT "
                           "(conteneur : installer fonts-dejavu-core)")
    return out


def _fit_font(draw, ImageFont, path, original, box_w, box_h):
    """Size at which the rendered ORIGINAL text has the height of its OCR box (accounts for the descenders/accents
    of the original, hence a homogeneous size across a line). Returns (font, relative width error, offset_y)."""
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


# Frequent OCR confusions in numeric tokens (constant-length substitutions)
_OCR_DIGIT_FIX = str.maketrans({"O": "0", "o": "0", "Q": "0", "D": "0", "I": "1", "l": "1", "|": "1", "S": "5", "Z": "2", "B": "8"})
_NUMERIC_TOKEN = re.compile(r"^[A-Z]{0,2}[0-9OoQDIl|SZB.\-]{2,}$")
_IBAN_LOOSE = re.compile(r"\b[A-Z]{2}[0-9OoQDIlSZB]{2}(?:[ ]?[A-Z0-9]{2,4}){3,8}\b")
# AVS-shaped string read with stray spaces or split groups ("756.456 1.4552.33"): fail-closed like the IBAN
_AHV_LOOSE = re.compile(r"\b756[.,]\s?(?:\d\s?){4}[.,]\s?(?:\d\s?){4}[.,]\s?\d{2}\b")
_IBAN_COUNTRIES = {"CH", "LI", "DE", "AT", "FR", "IT", "ES", "PT", "NL", "BE", "LU", "GB", "IE", "DK", "SE", "NO", "FI", "PL", "CZ", "MC"}


def _ocr_normalize_line(text):
    """Fixes O→0, I→1, S→5… in mostly numeric tokens (IBAN, AVS, cards, patient no.).
    Length preserved: the word offsets remain valid."""
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
    """Tesseract OCR (TSV) at the requested scales × psm 11 and 6; boxes brought back to the original scale."""
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
    """OCR lines -> detection (raw, O/0-I/1 normalized, fail-closed IBAN and names) -> candidates
    ((x0, y0, x1, y1), dtype, original, replacement, method, min_confidence) sorted
    (exact > normalized > fuzzy, wide box first)."""
    lines = {}
    for w in words:
        if w["text"]:
            lines.setdefault(w["line"], []).append(w)
    candidates = []
    iban_keys = [(norm(k).upper(), rep) for k, (t, rep) in pz.exact.items() if t == "IBAN"]
    name_keys = [(k.casefold(), t, rep) for k, (t, rep) in pz.exact.items()
                 if t in ("FIRST_NAME", "LAST_NAME", "STREET_ADDRESS", "POSTAL_CITY") and len(k) >= 5]

    def fuzzy_iban(v):
        """(substitution, method, distance): pseudonym table at distance ≤ 2, else a generated IBAN (never in clear)."""
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
        # fail-closed: IBAN-shaped string without a valid checksum (known country, mostly numeric body)
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
        # fail-closed: AVS form (756.xxxx.xxxx.xx) with stray spaces or bad checksum -> table (d ≤ 2), else generated
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
        # fail-closed: word misread by the OCR ("Pjerre-Alain", low confidence) close to a name in the table
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


def _image_slope(img):
    """|tan| of the skew of the image's text lines (projection profile, cf. _estimate_skew for scanned pages).
    An image skewed by 1.4° inflates each OCR box by 2.4% of its WIDTH: on the same card, an 800 px number
    "measured" 20 px more than a 200 px name and its pseudonym came out in a larger font size. Estimating from the
    OCR boxes themselves underestimated the angle by half; this one works on the pixels."""
    import math
    try:
        return abs(math.tan(math.radians(_estimate_skew(img.convert("L")))))
    except Exception:
        return 0.0


def _size_clusters(sizes, ratio=1.10):
    """Groups nearby font sizes (px) (ratio ≤ 1.10 between sorted neighbors, or ≤ 3 px for small sizes: at 20 px,
    2 px of OCR box noise already make 10%): returns {index: median size of its cluster}.
    Words of the same style (body text, title) get the same size; two distinct styles remain distinct."""
    order = sorted(range(len(sizes)), key=lambda i: sizes[i])
    out, group = {}, []
    def flush():
        if group:
            med = sorted(sizes[i] for i in group)[len(group) // 2]
            for i in group:
                out[i] = med
    for i in order:
        if group and sizes[i] > max(sizes[group[-1]] * ratio, sizes[group[-1]] + 3):
            flush(); group = []
        group.append(i)
    flush()
    return out


def _label_components(mask):
    """Connected components (4-neighborhood) of a boolean mask: (int32 labels 1..k, [(x0, y0, x1, y1, n_pixels)])."""
    import numpy as np
    h, w = mask.shape
    labels = np.zeros((h, w), dtype=np.int32)
    boxes, cur = [], 0
    ys, xs = np.nonzero(mask)
    for y, x in zip(ys.tolist(), xs.tolist()):
        if labels[y, x]:
            continue
        cur += 1
        stack = [(y, x)]; labels[y, x] = cur
        bx0 = bx1 = x; by0 = by1 = y; n = 0
        while stack:
            cy, cx = stack.pop(); n += 1
            bx0, bx1, by0, by1 = min(bx0, cx), max(bx1, cx), min(by0, cy), max(by1, cy)
            for ny, nx in ((cy - 1, cx), (cy + 1, cx), (cy, cx - 1), (cy, cx + 1)):
                if 0 <= ny < h and 0 <= nx < w and mask[ny, nx] and not labels[ny, nx]:
                    labels[ny, nx] = cur; stack.append((ny, nx))
        boxes.append((bx0, by0, bx1 + 1, by1 + 1, n))
    return labels, boxes


def _erase_ink(img, rect, bg, keep_rules=True):
    """Erases the ink of an area by repainting only the INK PIXELS (local background color), not a solid rectangle:
    the paper texture remains and the RULES (field frame, table line) crossing the area are preserved.
    On a form skewed by 1°, the bottom border of a field enters the OCR box on one side: a solid rectangle
    cut it over half its length. Rule = thin component (≤ 4 px or 12% of the height) crossing ≥ 80% of the
    area, or long (≥ 4 × its thickness) and leaving the area. Falls back to the solid rectangle if numpy is missing."""
    from PIL import Image, ImageDraw
    x0, y0 = max(0, int(rect[0])), max(0, int(rect[1]))
    x1, y1 = min(img.width, int(rect[2]) + 1), min(img.height, int(rect[3]) + 1)
    if x1 <= x0 or y1 <= y0:
        return
    try:
        import numpy as np
        a = np.asarray(img.crop((x0, y0, x1, y1))).astype(int)
        mask = np.abs(a - np.array(bg)).sum(axis=2) > 24
        if keep_rules and mask.any():
            labels, boxes = _label_components(mask)
            h, w = mask.shape
            thin = max(4, int(0.12 * h))
            for k, (bx0, by0, bx1, by1, _n) in enumerate(boxes, 1):
                cw, ch = bx1 - bx0, by1 - by0
                touches = bx0 == 0 or by0 == 0 or bx1 == w or by1 == h
                # horizontal rule: thin and either crossing, or long (≥ 4 × its thickness) and leaving the area —
                # a skewed border only enters the box over part of its length
                horiz = ch <= thin and (cw >= 0.8 * w or (cw >= 4 * thin and touches))
                vert = cw <= thin and (ch >= 0.8 * h or (ch >= 4 * thin and touches))
                if horiz or vert:
                    mask[labels == k] = False
        d = mask.copy()                                   # 1 px dilation: anti-aliasing halos of the glyphs
        d[1:, :] |= mask[:-1, :]; d[:-1, :] |= mask[1:, :]; d[:, 1:] |= mask[:, :-1]; d[:, :-1] |= mask[:, 1:]
        out = a.copy(); out[d] = np.array(bg)
        img.paste(Image.fromarray(out.astype("uint8")), (x0, y0))
    except Exception:
        ImageDraw.Draw(img).rectangle([x0, y0, x1 - 1, y1 - 1], fill=bg)


def _tighten_box(img, box, bg):
    """Tightens the OCR box to the actual vertical extent of the ink. Tesseract sometimes inflates a cell box up to
    the rule or the neighboring line ("Bissig" h = 29 px in a 16 px table → size 28 instead of 20); since the size
    is fitted on the height, the cell came out 1.5 × too large. Rule rows (≥ 60% ink pixels) are ignored;
    we only ever shrink, never enlarge."""
    try:
        import numpy as np
        x0, y0, x1, y1 = box
        a = np.asarray(img.crop((x0, y0, x1, y1))).astype(int)
        ink = np.abs(a - np.array(bg)).sum(axis=2) > 40          # low threshold: the anti-aliased tops of the "l" count
        row = ink.sum(axis=1)
        rows = np.nonzero((row >= 1) & (row < 0.6 * max(1, x1 - x0)))[0]
        if len(rows) == 0:
            return box
        ny0, ny1 = y0 + int(rows[0]), y0 + int(rows[-1]) + 1
        ext = ny1 - ny0
        # guards: a Tesseract inflation stays < 2 × (extent ≥ 45% of the box) and the ink of a word is continuous
        # (≥ 60% of the rows of the extent contain some) — on a low-contrast scanned page, only the darkest rows
        # passed the threshold and "WIDMER" dropped to 10 px
        # only tighten a clear inflation (≥ 20% of the box): on small anti-aliased text, trimming 1-2 rows of
        # letter tops would distort the size more than the Tesseract box itself
        if ext < 4 or ext > 0.8 * (y1 - y0) or ext < 0.45 * (y1 - y0) or len(rows) < 0.6 * ext:
            return box
        return (x0, ny0, x1, ny1)
    except Exception:
        return box


def _ink_slant(img, box, bg):
    """Glyph slant (tan) in a box: the ink mask is "straightened" by a shear s and we keep the s that concentrates
    the ink the most into columns (sum of squares of the per-column histogram, maximal when the stems become
    vertical). Upright text ≈ 0, DejaVu Oblique/Italic ≈ 0.2. Used to rewrite a "handwritten" (italic) field
    in italic rather than upright. None if too little ink."""
    try:
        import numpy as np
        x0, y0, x1, y1 = box
        a = np.asarray(img.crop((x0, y0, x1, y1))).astype(int)
        ink = np.abs(a - np.array(bg)).sum(axis=2) > 60
        h, w = ink.shape
        if ink.sum() < 30 or h < 6:
            return None
        ys, xs = np.nonzero(ink)
        best, best_s = -1.0, 0.0
        for s in np.arange(-0.10, 0.46, 0.04):
            # straightening: the top of the glyphs (small y) is shifted left by s × height; no clipping
            # (clipping piled the pixels up on the edge and made the maximal shear win)
            xs2 = np.round(xs - s * ((h - 1) - ys)).astype(int)
            xs2 -= xs2.min()
            hist = np.bincount(xs2)
            score = float((hist.astype(float) ** 2).sum())
            if score > best:
                best, best_s = score, float(s)
        return best_s
    except Exception:
        return None


def _numeric_like(s):
    return sum(ch.isalpha() for ch in s) <= 2


def _paint_candidates(img, candidates, fonts, extra_tag=None, words=None):
    """Covers each candidate and writes the pseudonym while respecting the image's typography.
    1. Box height corrected for skew (box − width × |slope|). 2. Font size: the ORIGINAL text must fill this
       height; the retained size is the MEDIAN of the "run" (reliable OCR words linked to the candidate by single
       spaces on the same line) — a line is a unit of style, and "Eduard" without descender no longer comes out
       smaller than "Weber" next to it. 3. Size clusters over the image (_size_clusters): one style = one size; a
       PURELY NUMERIC cluster 10-35% above a word cluster is brought down to it (digits do not exceed the ascenders
       of the same style: the gap comes from cursive/decorative fonts or from the OCR boxes of the digits).
    4. Family (sans / bold / mono / serif / condensed) chosen PER CLUSTER. 5. Neighboring replaced words on a line
       (gap ≤ 0.8 × height = single space, not a table gutter): the next one is PUSHED to the end of the previous
       one + the original space (no more "Rémy    Kunz"); punctuation attached to the OCR word ("Weber,") is
       preserved. 6. Erasure by ink pixels (_erase_ink): rules and texture preserved. Returns (boxes, log)."""
    from PIL import ImageDraw, ImageFont
    draw = ImageDraw.Draw(img)
    log, done_boxes = [], []
    slope = _image_slope(img)
    trusted = [w for w in (words or []) if w["conf"] >= 75 and len(w["text"]) >= 2]

    def overlaps(b, d):
        ix = max(0, min(b[2], d[2]) - max(b[0], d[0])); iy = max(0, min(b[3], d[3]) - max(b[1], d[1]))
        return ix * iy > 0.5 * (b[2] - b[0]) * (b[3] - b[1])

    def vover(b, y0, y1):
        iy = min(b[3], y1) - max(b[1], y0)
        return iy / max(1, min(b[3] - b[1], y1 - y0))

    def hc_of(w, h):
        return max(4.0, h - min(w * slope, 0.5 * h))

    def run_words(box):
        """Reliable words of the same visual line, linked to the box by gaps ≤ 1.2 × height (single spaces);
        a label separated from its value by a column gap is not part of it. Excludes the candidate's own words."""
        x0, y0, x1, y1 = box
        gap = max(12, 1.2 * (y1 - y0))
        same = [w for w in trusted if vover(box, w["y"], w["y"] + w["h"]) >= 0.6]
        lo, hi, run, rest = x0, x1, [], same
        while True:
            keep, added = [], False
            for w in rest:
                wx0, wx1 = w["x"], w["x"] + w["w"]
                if wx1 >= lo - gap and wx0 <= hi + gap:
                    run.append(w); lo, hi = min(lo, wx0), max(hi, wx1); added = True
                else:
                    keep.append(w)
            rest = keep
            if not added:
                break
        return [w for w in run if not (w["x"] + w["w"] > x0 + 2 and w["x"] < x1 - 2)]

    # pass 1: corrected geometry, fit per family, colors (BEFORE any erasure)
    items = []
    for box, dtype, v, rep, how, conf_min in candidates:
        if any(overlaps(box, d) for d in done_boxes):
            continue   # already handled by another OCR pass
        done_boxes.append(box)
        x0, y0, x1, y1 = box
        pad = 3
        border = [img.getpixel((min(max(x, 0), img.width - 1), min(max(y, 0), img.height - 1)))
                  for x in range(x0 - pad, x1 + pad, 4) for y in (y0 - pad, y1 + pad)]
        bg = tuple(sorted(c[k] for c in border)[len(border) // 2] for k in range(3)) if border else (255, 255, 255)
        ocr_box = box
        box = _tighten_box(img, box, bg)                          # box inflated by Tesseract → extent of the ink
        x0, y0, x1, y1 = box
        infl = min((x1 - x0) * slope, 0.5 * (y1 - y0))          # inflation due to skew, split top/bottom
        hc = max(4.0, (y1 - y0) - infl)
        fits = {fam: _fit_font(draw, ImageFont, path, v, x1 - x0, hc) for fam, path in fonts.items()}
        inner = [img.getpixel((x, y)) for x in range(x0, x1, 3) for y in range(y0, y1, 2)]
        ink = min(inner, key=sum) if inner else (15, 15, 15)
        if sum(bg) - sum(ink) < 90:          # contrast too low (dark background): readable default ink
            ink = (255, 255, 255) if sum(bg) < 384 else (15, 15, 15)
        items.append({"box": box, "ocr_box": ocr_box, "dtype": dtype, "v": v, "rep": rep, "how": how, "conf": conf_min,
                      "infl": infl, "hc": hc, "fits": fits, "bg": bg, "ink": ink, "run": run_words(box)})
    if not items:
        return done_boxes, log

    def pick_family(idx, base):
        # a family only supersedes the base family if it reduces the cumulative width error by ≥ 25%:
        # DejaVu Sans and Serif have nearly identical advance widths, width alone separates them at random
        errs = {fam: sum(items[i]["fits"][fam][1] for i in idx) for fam in fonts if fam not in _ITALIC_OF.values()}
        best = min(errs, key=errs.get)
        return best if base not in errs or errs[best] < 0.75 * errs[base] else base
    ref_fam = pick_family(range(len(items)), "sans")          # reference family of the image
    # reference size per candidate: median of the run (the candidate + its line neighbors)
    for it in items:
        sizes = [it["fits"][ref_fam][0].size]
        for w in it["run"]:
            sizes.append(_fit_font(draw, ImageFont, fonts[ref_fam], w["text"], w["w"], hc_of(w["w"], w["h"]))[0].size)
        it["ref_size"] = sorted(sizes)[len(sizes) // 2]
    clusters = _size_clusters([it["ref_size"] for it in items])
    letter_cl = {c for i, c in clusters.items() if not _numeric_like(items[i]["v"])}
    for i, c in list(clusters.items()):
        if c not in letter_cl:
            below = [l for l in letter_cl if l < c <= 1.35 * l]
            if below:
                clusters[i] = max(below)
    # family per size cluster (one style = one family), the image reference unless clearly different
    fam_of = {}
    for cl in set(clusters.values()):
        idx = [i for i, c in clusters.items() if c == cl]
        fam_of[cl] = pick_family(idx, ref_fam)
    # slanted glyphs → oblique/italic variant of the family. Measured per WORD (not per cluster: on a form, italic
    # "handwritten" fields and upright fields have the same size), then median per INK COLOR: the same pen =
    # the same style, and a short word with diagonals ("Waeber") measures poorly on its own
    for it in items:
        it["slant"] = _ink_slant(img, it["box"], it["bg"])
    by_ink = {}
    for i, it in enumerate(items):
        by_ink.setdefault(tuple(c // 48 for c in it["ink"]), []).append(i)
    for idx in by_ink.values():
        sl = sorted(items[i]["slant"] for i in idx if items[i]["slant"] is not None)
        if len(sl) >= 2:
            for i in idx:
                items[i]["slant"] = sl[len(sl) // 2]
    for i, it in enumerate(items):
        fam = fam_of[clusters[i]]
        if it["slant"] is not None:
            it["slant"] = round(it["slant"], 2)
            if it["slant"] >= 0.10 and _ITALIC_OF.get(fam) in fonts:      # upright measures ±0.02, DejaVu oblique 0.18
                fam = _ITALIC_OF[fam]
        it["fam"] = fam
        it["size"] = max(6, int(round(clusters[i] * it["fits"][fam][0].size / max(it["fits"][ref_fam][0].size, 1))))
        it["r"] = it["rep"].upper() if (it["v"].isupper() and it["dtype"] in ("FIRST_NAME", "LAST_NAME")) else it["rep"]
        # "Weber,": the comma belongs to the OCR word, not to the value → keep it after the pseudonym
        bx = it["box"]
        for w in trusted:
            if abs(w["x"] + w["w"] - bx[2]) <= 3 and vover(bx, w["y"], w["y"] + w["h"]) >= 0.6 and w["text"][-1] in ",;:." \
                    and not it["v"].endswith(w["text"][-1]) and not it["r"].endswith(w["text"][-1]):
                it["r"] += w["text"][-1]; break

    # visual lines (vertical overlap ≥ 60%), sorted left to right
    groups = []
    for i in sorted(range(len(items)), key=lambda i: (items[i]["box"][1] + items[i]["box"][3], items[i]["box"][0])):
        b = items[i]["box"]
        for g in groups:
            gb = items[g[-1]]["box"]
            if vover(gb, b[1], b[3]) >= 0.6:
                g.append(i); break
        else:
            groups.append([i])
    pad = 3
    for g in groups:
        g.sort(key=lambda i: items[i]["box"][0])
        # 1) erase all the original boxes of the line (before writing: a long pseudonym may overflow onto the
        #    neighbor's box, which would otherwise be erased afterwards)
        for i in g:
            x0, y0, x1, y1 = items[i]["ocr_box"]                 # the whole box read by the OCR, not the tightened box
            _erase_ink(img, (x0 - pad, y0 - pad, x1 + pad, y1 + pad), items[i]["bg"])
        # 2) chains: words linked by a single space (≤ 0.8 × height, nothing else between them). A chain is
        #    laid out as a unit: pushed word by word and, if it does not fit in the free space, scaled down
        #    by a single factor (otherwise the last word alone absorbed the whole reduction: tiny "Amrein")
        chains, cur = [], [g[0]]
        for a_, b_ in zip(g, g[1:]):
            gap = items[b_]["box"][0] - items[a_]["box"][2]
            bb = items[b_]["box"]
            between = any(w["x"] >= items[a_]["box"][2] - 2 and w["x"] + w["w"] <= bb[0] + 2
                          and vover(bb, w["y"], w["y"] + w["h"]) >= 0.6 for w in trusted)
            if 0 <= gap <= max(10, 0.8 * items[b_]["hc"]) and not between:
                cur.append(b_)
            else:
                chains.append(cur); cur = [b_]
        chains.append(cur)
        for ch in chains:
            first, last = items[ch[0]], items[ch[-1]]
            lx0, ly0, lx1, ly1 = last["box"]; bg = last["bg"]
            lty0, lty1 = int(ly0 + last["infl"] / 2), int(ly1 - last["infl"] / 2)

            def is_bg(px):
                return sum(abs(px[k] - bg[k]) for k in range(3)) < 45
            free = lx1 + pad
            while free < img.width - 1 and free - lx1 < max((lx1 - lx0) * 0.8 + 40, (lx1 - lx0) * 1.5):
                if all(is_bg(img.getpixel((free, yy))) for yy in range(lty0, max(lty0 + 1, lty1), max(1, (lty1 - lty0) // 4))):
                    free += 2
                else:
                    break
            avail = max(lx1, free - pad) - first["box"][0]
            gaps = [items[b_]["box"][0] - items[a_]["box"][2] for a_, b_ in zip(ch, ch[1:])]

            def needed(f):
                tot = sum(gaps)
                for i in ch:
                    fnt = ImageFont.truetype(fonts[items[i]["fam"]], max(6, int(items[i]["size"] * f)))
                    tot += draw.textlength(items[i]["r"], font=fnt)
                return tot
            f = 1.0
            while f > 0.3 and needed(f) > avail:
                f -= 0.05
            xd = first["box"][0]
            for k, i in enumerate(ch):
                it = items[i]; x0, y0, x1, y1 = it["box"]; fam, v, r = it["fam"], it["v"], it["r"]
                size = max(6, int(it["size"] * f)); font = ImageFont.truetype(fonts[fam], size)
                ty0 = int(y0 + it["infl"] / 2)
                top = font.getbbox(v)[1]                        # top offset of the ORIGINAL's rendering → same baseline
                xr = xd + int(draw.textlength(r, font=font))
                if xr > x1:                                     # pseudonym overflows the box: erase what follows too
                    _erase_ink(img, (x1 + pad, y0 - pad, xr + pad, y1 + pad), it["bg"])
                draw.text((xd, ty0 - top), r, font=font, fill=it["ink"])
                nb = (min(x0, xd) - pad, y0 - pad, max(x1, xr) + pad, y1 + pad)
                done_boxes[done_boxes.index(it["ocr_box"])] = nb
                entry = {"type": it["dtype"], "original": v, "replacement": r, "box": it["ocr_box"], "font": fam,
                         "font_px": font.size, "skew": round(slope, 4), "match": it["how"], "ocr_conf_min": it["conf"]}
                if it["box"] != it["ocr_box"]:
                    entry["tightened_box"] = it["box"]
                if it.get("slant") is not None:
                    entry["slant"] = it["slant"]
                if xd != x0:
                    entry["x_shift"] = xd - x0
                if f < 1.0:
                    entry["chain_scale"] = round(f, 2)
                if extra_tag:
                    entry["tag"] = extra_tag
                log.append(entry)
                xd = xr + (gaps[k] if k < len(gaps) else 0)
    return done_boxes, log


def sanitize_image_bytes(data, ext, pz: Pseudonymizer, strict=False, ocr_scale=None,
                         cover_unread=os.environ.get("COVER_UNREAD_INK", "0") == "1",
                         cover_signatures=None, signature_context=False):
    """Returns (new bytes, log). Covers each value detected by OCR and writes the pseudonym.

    OCR robustness: (1) the OCR runs on an image enlarged 2× (Tesseract misreads digits < 30 px: "CH6O"
    instead of "CH60"); (2) O/0, I/1, S/5… confusions fixed in numeric tokens before detection;
    (3) "fail-closed": an IBAN-shaped string whose checksum remains wrong is matched against the pseudonym
    table (distance ≤ 2) or covered by a generated IBAN — never left in clear.
    Rendering (_paint_candidates): box height corrected for the image skew, font size fitted on the ORIGINAL text
    then homogenized by clusters over the image (one style = one size), family (sans / bold / mono / serif / condensed)
    per cluster.
    Handwritten signatures: ink areas not read by the OCR near a "Signature" label or in the bottom third
    → covered by default (COVER_SIGNATURES=1), frames and rules are preserved (see _cover_signatures).
    """
    from PIL import Image, ImageOps
    img = ImageOps.exif_transpose(Image.open(io.BytesIO(data))).convert("RGB")   # phone photos: rotate before OCR
    # Two scales: 2x reads small digits better (printed text), 1x reads irregular writing (simulated
    # handwriting) better than the smoothed enlargement. The boxes are brought back to the original scale.
    if ocr_scale is None:
        scales = (2, 1) if img.width * img.height <= 3_000_000 else (1,)
    else:
        scales = (ocr_scale,)
    words = _ocr_words(img, scales)
    candidates = _collect_candidates(words, pz, strict)
    done_boxes, log = _paint_candidates(img, candidates, _font_candidates(), words=words)
    # handwritten signatures (targeted cover, enabled by default) then "unread ink" score (manual review);
    # the generic covering of all unread ink (_cover_unread_ink, apply=) remains EXPERIMENTAL, OFF by default.
    if cover_signatures is None:
        cover_signatures = os.environ.get("COVER_SIGNATURES", "1") == "1"
    try:
        sig = _cover_signatures(img, words, done_boxes, apply=cover_signatures, force_location=signature_context)
        log += sig
        done_boxes += [tuple(e["box"]) for e in sig if e.get("match") == "covered"]
    except Exception as exc:   # noqa - never block the sanitization
        log.append({"type": "SIGNATURE", "match": "detect_failed", "error": str(exc)})
    try:
        unread = _cover_unread_ink(img, words, done_boxes, apply=cover_unread)
        log += unread
    except Exception as exc:   # numpy missing, etc.: never block the sanitization
        log.append({"type": "UNREAD_INK", "match": "score_failed", "error": str(exc)})
    if ext.lower() in (".jpg", ".jpeg"):
        out, q = _jpeg_fit(img, len(data))          # highest quality (≤ 92) that does not exceed the original
        log.append({"type": "ENCODE", "match": "jpeg_quality", "quality": q, "in": len(data), "out": len(out)})
        return out, log
    buf = io.BytesIO(); img.save(buf, "PNG")
    if len(buf.getvalue()) > len(data):
        buf = io.BytesIO(); img.save(buf, "PNG", compress_level=9)
    return buf.getvalue(), log


SIGNATURE_WORDS = {"signature", "signatures", "signé", "signe", "signed", "unterschrift", "visa", "firma", "sign", "signature:"}
SIG_NEAR_PX = 250          # max distance (px) between a "Signature" label and the ink area (to the right or below)


def _ink_mask(img):
    """Ink mask: pixel clearly different from the background AND dark (black, dark blue); background = image median."""
    import numpy as np
    a = np.asarray(img).astype(int)
    page_bg = np.median(a.reshape(-1, 3), axis=0)
    diff = np.abs(a - page_bg).sum(axis=2)
    return (diff > 150) & (a.min(axis=2) < 100), page_bg


def _components(mask, step=2):
    """Connected components (4-neighborhood) on an image downscaled by a factor `step`: [(x0, y0, x1, y1, n_pixels)]."""
    _labels, boxes = _label_components(mask[::step, ::step])
    return [(bx0 * step, by0 * step, bx1 * step, by1 * step, n * step * step) for bx0, by0, bx1, by1, n in boxes]


def _trusted_words(words):
    """OCR words whose box may be removed from the ink mask: read STABLY by ≥ 2 passes (same normalized text,
    overlapping boxes) or with a confidence ≥ 75. A signature scribble read as "DWDM" (conf. 41) in a single
    pass is not a word: its box must not erase the ink of the signature."""
    cands = [w for w in words if w["conf"] >= 30 and len(w["text"]) >= 2]
    out = []
    for i, a in enumerate(cands):
        if a["conf"] >= 75:
            out.append(a); continue
        ta = norm(a["text"]).casefold()
        for j, b in enumerate(cands):
            if i == j or a["line"][:2] == b["line"][:2]:
                continue                                        # same pass (scale, psm)
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
        right = 0 <= x0 - lx1 <= dist and y0 <= ly1 + dist and y1 >= ly0 - dist        # to the right of the label
        below = 0 <= y0 - ly1 <= dist and x0 <= lx1 + dist and x1 >= lx0 - dist        # below
        if right or below:
            return True
    return False


def _scribble_like(parts, bh):
    """Signature scribble (sawtooth, loops) as seen through the components: at least one TALL stroke (≥ 50% of the
    group height) and THIN pieces (median width/height ≤ 0.5). Unread printed text yields roughly square letters
    (ratio 0.5-1), a barcode yields solid edge-to-edge bars but a much higher fill."""
    if len(parts) < 3:
        return False
    hs = sorted(c[3] - c[1] for c in parts); ratios = sorted((c[2] - c[0]) / max(1, c[3] - c[1]) for c in parts)
    # a sawtooth fragments into short pieces: we require ONE stroke ≥ 50% of the height (the tall stroke) and
    # mostly thin pieces (median width/height ≤ 0.5) — letters have a ratio of 0.6-1
    return hs[-1] >= 0.5 * bh and ratios[len(ratios) // 2] <= 0.5


def _cover_signatures(img, words, done_boxes, apply=True, force_location=False):
    """SIGNATURE AREA detector (image or page rendering) and targeted covering.
    Candidates: connected components of dark ink covered by no OCR word box, grouped by proximity.
    Filters: (1) location — bottom third of the image OR ≤ 250 px to the right of/below a "Signature/Signé/
    Signed/Unterschrift/Visa/Firma" label (force_location: the image itself sits in a signature area);
    (2) shape — width/height between 1.5 and 10, fill rate 3–35%; (3) size ≥ 40×12 px.
    Explicit rejections: > 90% of the ink on the box perimeter (frames), height < 6 px (lines, rules).
    Action: local-background-color rectangle (+4 px), log SIGNATURE_COVERED. Without apply: SIGNATURE_DETECTED."""
    from PIL import ImageDraw
    ink, page_bg = _ink_mask(img)
    h, w = ink.shape
    for wd in _trusted_words(words):
        x0, y0, x1, y1 = wd["x"] - 3, wd["y"] - 3, wd["x"] + wd["w"] + 3, wd["y"] + wd["h"] + 3
        ink[max(0, y0):min(h, y1), max(0, x0):min(w, x1)] = False
    for x0, y0, x1, y1 in done_boxes:
        ink[max(0, y0 - 4):min(h, y1 + 4), max(0, x0 - 4):min(w, x1 + 4)] = False
    comps = [list(c[:4]) for c in _components(ink) if c[3] - c[1] >= 3 and c[2] - c[0] >= 3]
    # grouping by proximity (strokes of the same scribble, underline); the components of each group are kept
    comps.sort(key=lambda b: (b[1], b[0]))
    merged, members = [], []
    for c in comps:
        for i, m in enumerate(merged):
            if c[0] <= m[2] + 30 and c[2] >= m[0] - 30 and c[1] <= m[3] + 20 and c[3] >= m[1] - 20:
                m[0], m[1], m[2], m[3] = min(m[0], c[0]), min(m[1], c[1]), max(m[2], c[2]), max(m[3], c[3]); members[i].append(c); break
        else:
            merged.append(list(c)); members.append([c])
    # transitive closure: a sawtooth scribble read as 4 pieces formed 4 neighboring groups that were never merged
    # (each component only joined the first group encountered) → 4 "aspect / no_continuous_stroke" rejections
    changed = True
    while changed:
        changed = False
        for i in range(len(merged)):
            for j in range(i + 1, len(merged)):
                a, b = merged[i], merged[j]
                if a[0] <= b[2] + 30 and a[2] >= b[0] - 30 and a[1] <= b[3] + 20 and a[3] >= b[1] - 20:
                    merged[i] = [min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), max(a[3], b[3])]
                    members[i] += members[j]; del merged[j]; del members[j]; changed = True; break
            if changed:
                break
    labels = _signature_label_boxes(words)
    log, zones = [], []
    for (x0, y0, x1, y1), parts in zip(merged, members):
        bw, bh = x1 - x0, y1 - y0
        near = _near_label((x0, y0, x1, y1), labels)          # ≤ 250 px from a "Signature" label: strong context
        bottom = (y0 + y1) / 2 >= 2 * h / 3
        why = None
        if bh < 6:
            why = "line"
        elif bw < 40 or bh < 12:
            why = "too_small"
        elif not (1.5 <= bw / bh <= 10) and not (near or (bottom and 1.0 <= bw / bh <= 10)):
            why = "aspect"                    # near a label, or compact in the bottom third: shape does not disqualify
        elif not near and not any((c[2] - c[0]) >= 0.5 * bw and (c[3] - c[1]) >= max(12, 0.3 * bh) for c in parts) \
                and not (bottom and _scribble_like(parts, bh)):
            why = "no_continuous_stroke"      # unread printed text: separate letters; a scribble is a continuous stroke
            #                                   or, in the bottom third, a tall-thin-stroke squiggle (_scribble_like)
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
    trusted = _trusted_words(words)
    for x0, y0, x1, y1 in zones:
        pad = 6
        bx0, by0, bx1, by1 = max(0, x0 - pad), max(0, y0 - pad), min(w - 1, x1 + pad), min(h - 1, y1 + pad)
        # do not bite into read text (footer under the scribble, label above): the rectangle is trimmed
        # at the edge of the neighboring word when it lies entirely above or below the scribble's ink
        for wd in trusted:
            wx0, wy0, wx1, wy1 = wd["x"], wd["y"], wd["x"] + wd["w"], wd["y"] + wd["h"]
            if wx1 <= bx0 or wx0 >= bx1 or wy1 <= by0 or wy0 >= by1:
                continue
            if wy0 >= y1 - 2:
                by1 = min(by1, max(y1, wy0 - 1))
            elif wy1 <= y0 + 2:
                by0 = max(by0, min(y0, wy1 + 1))
        border = [img.getpixel((x, y)) for x in range(bx0, bx1, 4) for y in (by0, by1)]
        bg = tuple(sorted(c[i] for c in border)[len(border) // 2] for i in range(3)) if border else tuple(int(v) for v in page_bg)
        if apply:
            draw.rectangle([bx0, by0, bx1, by1], fill=bg)
        log.append({"type": "SIGNATURE_COVERED" if apply else "SIGNATURE_DETECTED", "match": "covered" if apply else "detected",
                    "box": [int(bx0), int(by0), int(bx1), int(by1)], "original": None, "replacement": None})
    return log


def _cover_unread_ink(img, words, done_boxes, apply=False):
    """Fail-closed: ink areas the OCR did not read in any pass (signature, illegible writing) → covered.
    What nobody can read cannot be verified; we would rather erase it than let it through.
    Heuristic: dark components outside the boxes of read words (any confidence), grouped by lines;
    large solid areas (banners, frames) and thin strokes (field borders) are ignored."""
    import numpy as np
    from PIL import ImageDraw
    a = np.asarray(img).astype(int)
    h, w = a.shape[:2]
    page_bg = np.median(a.reshape(-1, 3), axis=0)
    diff = np.abs(a - page_bg).sum(axis=2)
    # ink = pixel clearly different from the background AND dark (black, dark blue): excludes gray borders and
    # light colored backgrounds
    ink = (diff > 150) & (a.min(axis=2) < 100)
    # remove everything the OCR read (with a margin) and what has already been rewritten
    for wd in words:
        if wd["conf"] >= 30 and len(wd["text"]) >= 2:
            x0, y0, x1, y1 = wd["x"] - 3, wd["y"] - 3, wd["x"] + wd["w"] + 3, wd["y"] + wd["h"] + 3
            ink[max(0, y0):min(h, y1), max(0, x0):min(w, x1)] = False
    for x0, y0, x1, y1 in done_boxes:
        ink[max(0, y0 - 4):min(h, y1 + 4), max(0, x0 - 4):min(w, x1 + 4)] = False
    # connected components (4-neighborhood) by simple labeling on a downscaled image
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
    # filter: no solid areas (large filled surface), no thin strokes (borders), no dust
    comps = []
    for x0, y0, x1, y1, area in boxes.values():
        bw, bh = x1 - x0, y1 - y0
        if bh < 6 or bw < 3 or bh > 0.25 * h or (bw > 0.6 * w and bh < 0.05 * h):
            continue
        if bh <= 4 or bw <= 4:
            continue
        fill = area / max(bw * bh, 1)
        if fill > 0.5 and bw * bh > 1500:      # solid area (logo, banner, filled frame): not a writing stroke
            continue
        if fill < 0.04:                        # hollow frame (field border)
            continue
        comps.append([x0, y0, x1, y1])
    # group neighboring components on the same line (letters of a word / words of a line)
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
# Embedded objects (OLE / package / attachments): recursive routing by extension, fail-closed otherwise
# ---------------------------------------------------------------------------
MAX_EMBED_DEPTH = 3
_OLE_PREVIEW_EXT = (".emf", ".wmf")


def _route_embedded(name, data, pz, strict, depth, seen):
    """Processes an embedded object (bytes): returns (new bytes or None, log entry).
    .xlsx/.docx -> sanitize_xlsx/sanitize_docx (recursive, max depth, anti-loop guard by fingerprint);
    .bin (OLE compound) -> if an Office package is encapsulated, extract and process it, else EMBEDDED_UNSUPPORTED.
    An unprocessed object is always logged + flagged for review (never silently ignored)."""
    import hashlib as _h
    ext = os.path.splitext(name)[1].lower()
    fp = _h.sha256(data).hexdigest()[:16]
    entry = {"object": name, "bytes": len(data), "ext": ext, "depth": depth}
    if fp in seen:
        # same bytes as an ANCESTOR: a real loop. Flagged for review (the caller keeps the original bytes).
        entry.update(status="skipped_loop", type="EMBEDDED_LOOP", review=True, reason="objet déjà rencontré (garde anti-boucle)")
        return None, entry
    seen.add(fp)
    try:
        return _route_embedded_inner(name, data, pz, strict, depth, seen, ext, entry)
    finally:
        seen.discard(fp)      # chain semantics: two identical siblings are both sanitized


def _route_embedded_inner(name, data, pz, strict, depth, seen, ext, entry):
    if depth > MAX_EMBED_DEPTH:
        entry.update(status="unsupported", type="EMBEDDED_UNSUPPORTED", reason="profondeur > %d" % MAX_EMBED_DEPTH, review=True)
        return None, entry
    handler = {".xlsx": sanitize_xlsx, ".xlsm": sanitize_xlsx, ".docx": sanitize_docx}.get(ext)   # .docm: python-docx rejects it
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
        res = handler(src, dst, pz, strict, _depth=depth + 1, _seen=seen)
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
    """OLE compound (.bin): returns (name, bytes) of the encapsulated Office package ("Package" stream = OOXML zip),
    else None."""
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
    """Rewrites the Package stream of an OLE compound (same size or smaller: olefile writes in place; else None)."""
    try:
        import olefile
        ole = olefile.OleFileIO(io.BytesIO(data), write_mode=True)
        for stream in (["Package"], ["package"]):
            if ole.exists("/".join(stream)):
                size = ole.get_size("/".join(stream))
                if len(new_blob) > size:
                    return None                         # olefile cannot grow a stream
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
    # embedded images + embedded objects (word/embeddings/*) + object previews (EMF/WMF: not OCR-able -> review)
    img_log, emb_log, review = [], [], []
    # python-docx only rewrites related parts: an object present in the source but missing after saving
    # is reported (silent content loss otherwise)
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
                # the Word preview of an embedded Excel object shows the values IN CLEAR; a metafile is neither OCR'd
                # nor rewritten here -> fail-closed: flagged for review (the object itself is processed below)
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
# RTF: LibreOffice conversion (RTF -> DOCX -> sanitize_docx -> RTF). "Native" variant (parse the RTF control
# words and patch the runs in place) = production target, not coded here (see the gap report).
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
    """`soffice --headless --convert-to <fmt>` with a user profile ISOLATED per call (-env:UserInstallation):
    two simultaneous requests do not fight over the default profile's lock."""
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
    """Text of a DOCX per zone: body (paragraphs + tables), header, footer — for the RTF fidelity check."""
    from docx import Document
    d = Document(path)
    body = [p.text for p in d.paragraphs] + [c.text for t in d.tables for r in t.rows for c in r.cells]
    header = [p.text for s_ in d.sections for p in s_.header.paragraphs]
    footer = [p.text for s_ in d.sections for p in s_.footer.paragraphs]
    return {"body": "\n".join(body), "header": "\n".join(header), "footer": "\n".join(footer),
            "tables": len(d.tables), "paragraphs": len(d.paragraphs)}


def sanitize_rtf(src, dst, pz, strict):
    """RTF -> DOCX (LibreOffice) -> sanitize_docx -> RTF (LibreOffice). Then a check: all NON-sensitive text of the
    output RTF must be identical to the input (token diff excluding replaced values); header, footer and tables
    must survive the round trip. A discrepancy is logged (RTF_FIDELITY_WARN) and flags the file for review."""
    tmp = tempfile.mkdtemp(prefix="rtf_")
    try:
        docx_in = soffice_convert(src, "docx", tmp)
        work = os.path.join(tmp, "work"); os.makedirs(work)
        docx_out = os.path.join(work, os.path.basename(docx_in))
        res = sanitize_docx(docx_in, docx_out, pz, strict)
        rtf_out = soffice_convert(docx_out, "rtf", work)
        shutil.move(rtf_out, dst)
        # fidelity check on the RTF actually written (re-read via DOCX)
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


def sanitize_xlsx(src, dst, pz, strict, _depth=0, _seen=None):
    from openpyxl import load_workbook
    wb = load_workbook(src)
    log = []
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            cells = list(row)
            # values spread over two adjacent cells (e.g. NPA | Localité): the pair is tested
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
    # embedded objects in a workbook (xl/embeddings/*): openpyxl does not keep them all; the SOURCE is re-read
    # and the processed objects are reinjected into the output (fail-closed: an unprocessed object is reported).
    with zipfile.ZipFile(src) as zsrc:
        emb_names = [n for n in zsrc.namelist() if n.startswith("xl/embeddings/")]
        emb_data = {n: zsrc.read(n) for n in emb_names}
    if emb_names:
        emb_log, review = [], []
        with zipfile.ZipFile(dst) as zin:
            present = set(zin.namelist())
        for n in emb_names:
            new, e = _route_embedded(n, emb_data[n], pz, strict, _depth, _seen if _seen is not None else set())
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
    """Detection per LINE rebuilt from the word boxes (same principle as the image branch).

    `page.search_for(value)` fails when the space in the value is not a real space character in the PDF
    stream (spacing by positioning: "+41 21 000 35 16", "8400 Winterthur") or when the value is split by
    a line break: the value then remains in clear. So the text is rebuilt line by line with the offset of
    each word, detection runs on that text, and the rectangles of the covered words are recovered.
    Returns [(rects, dtype, original, replacement)] — several rects when the value spans two lines.
    """
    words = page.get_text("words")          # (x0, y0, x1, y1, word, block, line, word no.)
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
            # one rectangle per line crossed (a value split by a line break produces two)
            by_line = {}
            for w in hit:
                by_line.setdefault((w[5], w[6]), []).append(w)
            rects = [fitz.Rect(min(w[0] for w in g), min(w[1] for w in g),
                               max(w[2] for w in g), max(w[3] for w in g)) for g in by_line.values()]
            out.append((rects, dtype, v, rep))

    for text, offs in seq:
        collect(text, offs)
    # 2nd pass: values split between two consecutive lines
    for (t1, o1), (t2, o2) in zip(seq, seq[1:]):
        joined = t1 + " " + t2
        shift = len(t1) + 1
        collect(joined, list(o1) + [(a + shift, b + shift, w) for (a, b, w) in o2])
    return out



# ---------------------------------------------------------------------------
# PDF: SCANNED pages (no word in the text layer, an image covers the page)
# ---------------------------------------------------------------------------
SCAN_DPI = int(os.environ.get("SCAN_DPI", "300"))


def _estimate_skew(gray, max_deg=3.0):
    """Angle (degrees) such that gray.rotate(angle) straightens the text lines. Projection profile: maximize the
    variance of the row sums of the binarized image (straightened text lines give sharp peaks).
    numpy + PIL only (no OpenCV). Coarse in 0.25° steps then fine in 0.05° steps."""
    import numpy as np
    from PIL import Image
    small = gray.resize((max(1, int(gray.width * 1000 / gray.height)), 1000), Image.BILINEAR) if gray.height > 1000 else gray
    a = np.asarray(small)
    thr = max(60, min(200, int(np.percentile(a, 30))))          # ink = darker than the background
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
    """OCR preprocessing of a scanned page: grayscale + contrast normalization (percentiles 1/99)."""
    import numpy as np
    from PIL import Image
    g = np.asarray(render.convert("L")).astype(float)
    lo, hi = np.percentile(g, 1), np.percentile(g, 99)
    if hi - lo < 30:
        return render.convert("L")
    g = np.clip((g - lo) * 255.0 / (hi - lo), 0, 255)
    return Image.fromarray(g.astype("uint8"))


def _pil_rotate_matrix(w, h, angle):
    """Affine matrix (a, b, c, d, e, f) used by PIL for img.rotate(angle): output (x, y) -> input."""
    import math
    rad = -math.radians(angle % 360)          # PIL: angle = -radians(angle) (counter-clockwise rotation on screen)
    a, b, d, e = round(math.cos(rad), 15), round(math.sin(rad), 15), round(-math.sin(rad), 15), round(math.cos(rad), 15)
    cx, cy = w / 2.0, h / 2.0
    c = a * (-cx) + b * (-cy) + cx
    f = d * (-cx) + e * (-cy) + cy
    return (a, b, c, d, e, f)


def _affine_apply(m, x, y):
    a, b, c, d, e, f = m
    return a * x + b * y + c, d * x + e * y + f


def _affine_from_points(src, dst):
    """2×3 affine mapping the 3 src points onto dst (exact solve)."""
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
    """Image XObject covering ≥ 80% of the page: (xref, rect, matrix) or None (inline BI/EI images, or nothing)."""
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
    """Copies into dst_img (raw image) the `boxes` areas of src_img (deskewed rendering), via the affine T (src -> dst):
    the rewritten rendering is reprojected onto the original geometry (rotation, /Rotate, scale), without touching
    the rest."""
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
        data = (a, b, a * bx0 + b * by0 + c, d, e, d * bx0 + e * by0 + f)      # (x, y) of the patch -> source
        patch = src_img.transform((bx1 - bx0, by1 - by0), Image.AFFINE, data, resample=Image.BICUBIC)
        mask = Image.new("L", (bx1 - bx0, by1 - by0), 0)
        ImageDraw.Draw(mask).polygon([(px - bx0, py - by0) for px, py in dc], fill=255)
        dst_img.paste(patch, (bx0, by0), mask)


def _leak_suspects(words, pz, strict):
    """2nd safety net: on the rendering AFTER masking, any candidate that is not a known pseudonym is suspect.
    A pseudonym misread by the OCR (attached currency "… 5816 1 CHF", one wrong character) is not a suspect:
    Levenshtein tolerance ≤ 1 (≤ 2 beyond 12 characters) after removing a trailing alphabetic token."""
    reps = {norm(rep).casefold() for (_, rep) in pz.exact.values()} | {norm(g).casefold() for g in pz.generated.values()}
    by_len = {}
    for r_ in reps:
        by_len.setdefault(len(r_), []).append(r_)

    def is_pseudonym(v):
        v2 = re.sub(r"\s+[A-Za-z]{2,4}$", "", v)              # "CHF", "EUR" attached by the OCR
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
# PDF: vector signatures / annotations / widgets
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
    """Curved paths ('c' items of get_drawings) grouped by proximity, filtered like the raster (location, ratio
    1.5–10, size ≥ 30×8 pt, neither rectangle nor line) -> redaction (removal of the covered paths) + background-color
    rectangle. /Ink annotations and signature fields (/Sig) -> deleted then covered. Log SIGNATURE_COVERED per zone."""
    log = []
    labels = _pdf_signature_labels(page)
    groups = []
    for d in page.get_drawings():
        items = d.get("items", [])
        kinds = [it[0] for it in items]
        if "c" not in kinds:
            continue                                   # rectangles, lines, rules: not a scribble
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
        # local background color: median of the rendering around the box
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
    # ACTUAL removal of the paths: with REMOVE_IF_COVERED, PyMuPDF left 7 out of 8 paths in the stream (covered
    # by a white rectangle = recoverable by removing the rectangle, not fail-closed). REMOVE_IF_TOUCHED removes
    # them all; a frame/rule crossing the box would be removed too (logged below, PII takes priority).
    boxes = [fitz.Rect(r.x0 - 4, r.y0 - 4, r.x1 + 4, r.y1 + 4) & page.rect for _, r in zones]
    before = [(fitz.Rect(d["rect"]), tuple(it[0] for it in d.get("items", []))) for d in page.get_drawings()]
    page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE, graphics=fitz.PDF_REDACT_LINE_ART_REMOVE_IF_TOUCHED)
    after = [(fitz.Rect(d["rect"]), tuple(it[0] for it in d.get("items", []))) for d in page.get_drawings()]
    # post-check: no curved path left in the boxes (else LEAK_SUSPECT_VECTOR); non-curved paths removed = side effect
    for b in boxes:
        residual = [r for r, kinds in after if "c" in kinds and r.intersects(b)]
        if residual:
            log.append({"type": "LEAK_SUSPECT_VECTOR", "match": "curves_remaining", "box": [round(v, 1) for v in b], "count": len(residual),
                        "hint": "tracés vectoriels encore présents sous le recouvrement : revue manuelle"})
    removed_non_curve = [r for r, kinds in before if "c" not in kinds and any(r.intersects(b) for b in boxes)
                         and not any(r == r2 and kinds == k2 for r2, k2 in after)]
    if removed_non_curve:
        log.append({"type": "SIGNATURE_COVER_SIDE_EFFECT", "match": "non_curve_paths_removed", "count": len(removed_non_curve),
                    "boxes": [[round(v, 1) for v in r] for r in removed_non_curve[:5]],
                    "hint": "un cadre/filet touchant la zone de signature a été retiré avec elle"})
    return log


def sanitize_scanned_page(page, doc, pz, strict, dpi=SCAN_DPI):
    """Scanned page: rendering (/Rotate rotation and image orientation applied) -> gray + contrast -> deskew ->
    OCR -> masking on the deskewed rendering -> reprojection of the rewritten areas onto the raw image (original
    geometry preserved) -> replace_image. Then a 2nd OCR pass on the masked page: a value still read ->
    LEAK_SUSPECT + covered. Without XObject (inline BI/EI images): the masked rendering replaces the page
    content (fail-closed, logged)."""
    import fitz
    from PIL import Image
    fonts = _font_candidates()
    hit = _covering_image(page, doc)
    pix = page.get_pixmap(dpi=dpi)
    render = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    gray = _prep_scan(render)
    skew = _estimate_skew(gray)
    D = gray.rotate(skew, resample=Image.BICUBIC, fillcolor=255).convert("RGB")     # for the OCR
    Dp = render.rotate(skew, resample=Image.BICUBIC, fillcolor=(255, 255, 255))     # for painting (colors)
    words = _ocr_words(D, (1,))
    cands = _collect_candidates(words, pz, strict)
    done, log = _paint_candidates(Dp, cands, fonts, words=words)
    try:
        sig = _cover_signatures(Dp, words, done, apply=os.environ.get("COVER_SIGNATURES", "1") == "1")
        log += sig; done += [tuple(e["box"]) for e in sig if e.get("match") == "covered"]
    except Exception as exc:  # noqa
        log.append({"type": "SIGNATURE", "match": "detect_failed", "error": str(exc)})
    info = {"page": page.number + 1, "scanned": True, "skew": skew, "dpi": dpi, "masked": len(done),
            "method": "xobject" if hit else "inline_render", "rotate": page.rotation}

    # D (deskewed rendering) -> rendering -> page point (rotated) -> page point (unrotated) -> image unit -> raw pixel
    rot = _pil_rotate_matrix(render.width, render.height, skew)          # D (x, y) -> rendering (x, y)

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
            if raw_info["ext"].lower() in ("jpeg", "jpg"):
                data_out, _q = _jpeg_fit(raw, len(raw_info["image"]), q_start=88)   # ≤ size of the original stream
            else:
                buf = io.BytesIO(); raw.save(buf, "PNG"); data_out = buf.getvalue()
            page.replace_image(xref, stream=data_out)
        else:
            # no XObject: the masked rendering (brought back to the rendering geometry) becomes the page
            back = painted.rotate(-skew, resample=Image.BICUBIC, fillcolor=(255, 255, 255))
            buf = io.BytesIO(); back.save(buf, "JPEG", quality=80)
            for cx in page.get_contents():
                doc.update_stream(cx, b"")
            # the rendering is in DISPLAY orientation: it is inserted into the mediabox (unrotated) with rotate=/Rotate
            # (verified empirically on a /Rotate 90 page: only this combination reads back upright)
            page.insert_image(page.mediabox, stream=buf.getvalue(), rotate=page.rotation)
            log.append({"type": "SCAN_INLINE_REPLACED", "match": tag,
                        "hint": "page sans XObject image : contenu remplacé par le rendu masqué (revue conseillée)"})

    apply_replacement(Dp, done, "first_pass")
    # ---- 2nd safety net: OCR of the masked rendering ----
    pix2 = page.get_pixmap(dpi=dpi)
    render2 = Image.frombytes("RGB", (pix2.width, pix2.height), pix2.samples)
    D2 = _prep_scan(render2).rotate(skew, resample=Image.BICUBIC, fillcolor=255).convert("RGB")
    words2 = _ocr_words(D2, (1,))
    suspects = _leak_suspects(words2, pz, strict)
    if suspects:
        Dp2 = render2.rotate(skew, resample=Image.BICUBIC, fillcolor=(255, 255, 255))
        done2, log2 = _paint_candidates(Dp2, suspects, fonts, extra_tag="LEAK_SUSPECT", words=words2)
        for e in log2:
            e["type_leak"] = e["type"]; e["type"] = "LEAK_SUSPECT"
        log += log2
        apply_replacement(Dp2, done2, "second_pass")
        info["leak_suspects_covered"] = len(done2)
    info["unread_ink"] = None
    return info, log


def _pdf_spans(page):
    """Text spans of the page: (bbox, font size, baseline y, font name, flags, RGB color 0-1)."""
    out = []
    try:
        for b in page.get_text("dict")["blocks"]:
            for l in b.get("lines", []):
                for sp in l.get("spans", []):
                    c = sp.get("color", 0)
                    rgb = (((c >> 16) & 255) / 255.0, ((c >> 8) & 255) / 255.0, (c & 255) / 255.0)
                    out.append((sp["bbox"], sp["size"], sp["origin"][1], sp.get("font", ""), sp.get("flags", 0), rgb))
    except Exception:
        pass
    return out


_TTF_DIRS = ["/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/truetype/liberation", "/usr/share/fonts/truetype/liberation2",
             "/usr/share/fonts/truetype/crosextra"] + list(_LO_FONTS)
# client families → TrueType files (free metric equivalents: same advance widths, hence same layout);
# (name pattern, file base, regular/bold/italic/bold-italic style)
_TTF_FAMILIES = [
    (("arial", "arialmt", "liberationsans", "liberation sans"), "LiberationSans", ("-Regular", "-Bold", "-Italic", "-BoldItalic")),
    (("times new roman", "timesnewroman", "liberationserif", "liberation serif"), "LiberationSerif", ("-Regular", "-Bold", "-Italic", "-BoldItalic")),
    (("courier new", "couriernew", "liberationmono", "liberation mono"), "LiberationMono", ("-Regular", "-Bold", "-Italic", "-BoldItalic")),
    (("calibri", "carlito"), "Carlito", ("-Regular", "-Bold", "-Italic", "-BoldItalic")),
    (("cambria", "caladea"), "Caladea", ("-Regular", "-Bold", "-Italic", "-BoldItalic")),
    (("dejavusansmono", "dejavu sans mono"), "DejaVuSansMono", ("", "-Bold", "-Oblique", "-BoldOblique")),
    (("dejavuserif", "dejavu serif"), "DejaVuSerif", ("", "-Bold", "-Italic", "-BoldItalic")),
    (("dejavusans", "dejavu sans", "dejavu"), "DejaVuSans", ("", "-Bold", "-Oblique", "-BoldOblique")),
]


def _ttf_path(base, style):
    for d in _TTF_DIRS:
        path = os.path.join(os.path.expanduser(d), base + style + ".ttf")
        if os.path.exists(path):
            return path
    return None


def _pdf_font_for(fontname, flags):
    """(PyMuPDF font name, TTF file or None) most faithful to the original span.
    PyMuPDF flags: 1 superscript, 2 italic, 4 "serifed" (unreliable: DejaVuSans has it), 8 monospace, 16 bold.
    1) The original family is rewritten with a TrueType file of the same metrics (_TTF_FAMILIES): DejaVu as is,
       Arial → Liberation Sans, Times New Roman → Liberation Serif, Courier New → Liberation Mono, Calibri → Carlito,
       Cambria → Caladea (fonts-liberation / crosextra in the container, LibreOffice on macOS) — a "Keller" in
       Helvetica in the middle of a DejaVu Sans page was immediately visible. 2) Otherwise base 14 by name then flags
       (bold, italic, mono; serif by NAME only) — exact for the non-embedded Helvetica/Times/Courier."""
    name = (fontname or "").lower()
    bold = bool(flags & 16) or any(k in name for k in ("bold", "black", "heavy", "semibold"))
    italic = bool(flags & 2) or any(k in name for k in ("italic", "oblique"))
    mono = bool(flags & 8) or any(k in name for k in ("mono", "courier", "consolas", "menlo"))
    serif = any(k in name for k in ("times", "serif", "georgia", "garamond", "cambria", "book")) and "sans" not in name
    base_name = name.split("+")[-1]                       # "ABCDEF+Arial-BoldMT" → "arial-boldmt"
    for keys, base, styles in _TTF_FAMILIES:
        if any(k in base_name for k in keys):
            style = styles[3] if (bold and italic) else styles[1] if bold else styles[2] if italic else styles[0]
            path = _ttf_path(base, style) or _ttf_path(base, styles[0])
            if path:
                return "F" + hashlib.md5(path.encode()).hexdigest()[:8], path
            break
    if mono:
        return ("cobi" if bold and italic else "cobo" if bold else "coit" if italic else "cour"), None
    if serif:
        return ("tibi" if bold and italic else "tibo" if bold else "tiit" if italic else "tiro"), None
    return ("hebi" if bold and italic else "hebo" if bold else "heit" if italic else "helv"), None


def _pdf_reinsert(page, rects, words, spans, fitz):
    """Rewrites the pseudonyms in the redacted areas while respecting the page typography:
    font size, baseline, font (closest base 14) and color of the original SPAN — no more text placed 1-2 pt too
    high nor a size of 0.78 × box height. Available space = up to the next word of the line (or the margin): a
    pseudonym longer than the original keeps its size as long as there is white space to the right ("5. November 1962"
    came out as superscript). Neighboring replaced words (single space, nothing between them) = a chain pushed word
    by word and scaled down by a single factor if it does not fit ("KELLERFranz"). Returns the log entries."""
    items = []
    for r, v, dtype, rep in rects:
        if not rep:
            continue        # 2nd line of a split value: the area is erased, nothing to rewrite
        rr = rep.upper() if (v.isupper() and dtype in ("FIRST_NAME", "LAST_NAME")) else rep
        best, bo = None, 0.0
        for bbox, size, base, fname, flags, rgb in spans:
            iy = min(r.y1, bbox[3]) - max(r.y0, bbox[1]); ix = min(r.x1, bbox[2]) - max(r.x0, bbox[0])
            if iy > 0.5 * min(r.height, bbox[3] - bbox[1]) and ix > 0 and ix * iy > bo:
                best, bo = (size, base, fname, flags, rgb), ix * iy
        if best:
            size, base, fname, flags, rgb = best
            fn, ff = _pdf_font_for(fname, flags)
        else:
            size, base, fn, ff, rgb = max(5.0, r.height * 0.78), r.y1 - 0.22 * r.height, "helv", None, (0, 0, 0)
        items.append({"r": r, "v": v, "dtype": dtype, "rr": rr, "size": float(size), "base": base, "fn": fn, "ff": ff,
                      "rgb": rgb, "src_font": best[2] if best else None})
    if not items:
        return []
    log = []

    def vover(a, b):
        iy = min(a.y1, b.y1) - max(a.y0, b.y0)
        return iy / max(0.1, min(a.height, b.height))
    # visual lines then chains (gap ≤ 0.6 font size ≈ two spaces, no unreplaced word between the two)
    groups = []
    for i in sorted(range(len(items)), key=lambda i: (items[i]["r"].y0 + items[i]["r"].y1, items[i]["r"].x0)):
        for g in groups:
            if vover(items[g[-1]]["r"], items[i]["r"]) >= 0.6:
                g.append(i); break
        else:
            groups.append([i])
    replaced = [it["r"] for it in items]

    def is_replaced(w):
        wr = fitz.Rect(w[:4])
        return any(wr.intersects(r) and (wr & r).width > 0.5 * wr.width for r in replaced)
    for g in groups:
        g.sort(key=lambda i: items[i]["r"].x0)
        chains, cur = [], [g[0]]
        for a, b in zip(g, g[1:]):
            ra, rb = items[a]["r"], items[b]["r"]; gap = rb.x0 - ra.x1
            between = any(w[0] >= ra.x1 - 0.5 and w[2] <= rb.x0 + 0.5 and vover(fitz.Rect(w[:4]), rb) >= 0.6
                          and not is_replaced(w) for w in words)
            if -0.5 <= gap <= 0.6 * items[b]["size"] and not between:
                cur.append(b)
            else:
                chains.append(cur); cur = [b]
        chains.append(cur)
        for ch in chains:
            first, last = items[ch[0]], items[ch[-1]]
            nxt = [w[0] for w in words if w[0] >= last["r"].x1 - 0.5 and vover(fitz.Rect(w[:4]), last["r"]) >= 0.5
                   and not is_replaced(w)]
            limit = (min(nxt) - 0.25 * last["size"]) if nxt else (page.rect.x1 - 12)
            avail = max(last["r"].x1, limit) - first["r"].x0
            # segments: neighboring words of the SAME style (font, size, baseline, color) merged into a single
            # string with real space characters — two text objects 2.9 pt apart are glued back together by
            # tolerance-based extractors (pdfplumber: "FranzKeller"); an explicit space separates them for everyone
            segs = []
            for i in ch:
                it = items[i]
                if segs and all(items[segs[-1][-1]][k] == it[k] for k in ("fn", "ff", "rgb")) \
                        and abs(items[segs[-1][-1]]["size"] - it["size"]) < 0.1 and abs(items[segs[-1][-1]]["base"] - it["base"]) < 0.3:
                    segs[-1].append(i)
                else:
                    segs.append([i])
            seg_txt = [" ".join(items[i]["rr"] for i in sg) for sg in segs]
            seg_gap = [max(0.0, items[b[0]]["r"].x0 - items[a[-1]]["r"].x1) for a, b in zip(segs, segs[1:])]

            def tlen(it, fs, txt=None):
                txt = it["rr"] if txt is None else txt
                if it["ff"]:
                    return fitz.Font(fontfile=it["ff"]).text_length(txt, fontsize=fs)
                return fitz.get_text_length(txt, fontname=it["fn"], fontsize=fs)

            def needed(f):
                return sum(seg_gap) + sum(tlen(items[sg[0]], max(4.0, items[sg[0]]["size"] * f), txt)
                                          for sg, txt in zip(segs, seg_txt))
            f = 1.0
            while f > 0.3 and needed(f) > avail:
                f -= 0.025
            x = first["r"].x0
            for k, (sg, txt) in enumerate(zip(segs, seg_txt)):
                it = items[sg[0]]; fs = max(4.0, round(it["size"] * f, 2))
                if it["ff"]:
                    page.insert_text((x, it["base"]), txt, fontsize=fs, fontname=it["fn"], fontfile=it["ff"], color=it["rgb"])
                else:
                    page.insert_text((x, it["base"]), txt, fontsize=fs, fontname=it["fn"], color=it["rgb"])
                for j, i in enumerate(sg):
                    e = {"type": items[i]["dtype"], "original": items[i]["v"], "replacement": items[i]["rr"], "fontsize": fs,
                         "font": os.path.basename(it["ff"]) if it["ff"] else it["fn"], "source_font": items[i]["src_font"]}
                    if j == 0 and abs(x - it["r"].x0) > 0.5:
                        e["x_shift"] = round(x - it["r"].x0, 1)
                    if j > 0:
                        e["joined"] = True
                    if f < 1.0:
                        e["chain_scale"] = round(f, 3)
                    log.append(e)
                x += tlen(it, fs, txt) + (seg_gap[k] if k < len(seg_gap) else 0)
    return log


def sanitize_pdf(src, dst, pz, strict):
    try:
        import fitz  # PyMuPDF
    except ImportError:
        return {"skipped": "PyMuPDF (fitz) non disponible dans cet environnement — installer `pip install pymupdf` pour la branche PDF"}
    doc = fitz.open(src)
    log, img_log, pages_log = [], [], []
    done_xrefs = set()          # an XObject shared by many pages (logo, stamp) is OCR'd and replaced ONCE
    for page in doc:
        words_on_page = page.get_text("words")
        if not words_on_page:
            # page without text layer: scanned if an image covers it (or inline images -> rendering); blank otherwise
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
                rects.append((r, v, dtype, rep if i == 0 else ""))   # the rest of the split value is erased
            uniq.pop(v, None)
        # safety net: what the line-based detection did not see (value in an annotation, a field…)
        for v, (dtype, rep) in uniq.items():
            for r in page.search_for(v):
                rects.append((r, v, dtype, rep))
        # redaction: merge neighboring rectangles of the same line (gap ≤ 0.6 × height) to also erase the original
        # SPACE glyph between two replaced words — otherwise it remains in the middle of the rewritten pseudonym and
        # tolerance-based extractors (pdfplumber, pdfminer) read "Vincent Bi se"; PyMuPDF itself did not see it
        red = []
        for r, v, dtype, rep in sorted(rects, key=lambda t: (round(t[0].y0), t[0].x0)):
            if red and abs(red[-1].y0 - r.y0) < 0.5 * r.height and -0.5 <= r.x0 - red[-1].x1 <= 0.6 * r.height:
                red[-1] = red[-1] | r
            else:
                red.append(fitz.Rect(r))
        for r in red:
            page.add_redact_annot(r, fill=(1, 1, 1))
        if rects:
            spans_before = _pdf_spans(page)                    # original metrics: read BEFORE the redaction
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
            for e in _pdf_reinsert(page, rects, words_on_page, spans_before, fitz):
                e["page"] = page.number + 1
                log.append(e)
        # vector signatures (curved paths), /Ink annotations, /Sig fields -> covering (COVER_SIGNATURES)
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
            if xref in done_xrefs:
                continue
            done_xrefs.add(xref)
            info = doc.extract_image(xref)
            # an image placed in a signature area (bottom third, or near a label) may be THE signature scribble
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
    # garbage=4 + clean: removes the objects orphaned after replace_image (the old image still counted
    # in the output PDF — "8 images instead of 4" anomaly). To be cross-checked with `pdfimages -list`.
    # attachments (embedded files): extracted, routed by extension, rewritten (embfile_upd); unknown -> review
    emb_log, review = [], []
    for name in list(doc.embfile_names()):
        info = doc.embfile_info(name)
        fname = info.get("filename") or info.get("name") or name
        data = doc.embfile_get(name)
        new, e = _route_embedded(fname, data, pz, strict, 1, set())
        emb_log.append(e)
        if new is not None:
            # PyMuPDF 1.28: embfile_upd(buffer_=bytes) crashes ("bytes has no m_internal") -> delete + reinsert
            doc.embfile_del(name)
            doc.embfile_add(name, new, filename=info.get("filename") or fname, ufilename=info.get("ufilename") or fname,
                            desc=info.get("desc") or "")
        else:
            review.append({"type": e.get("type", "EMBEDDED_UNSUPPORTED"), "object": fname, "reason": e.get("reason")})
    if os.environ.get("PDF_SUBSET_FONTS", "1") == "1":
        try:
            doc.subset_fonts()      # reinserted TTF fonts (DejaVu) reduced to the glyphs used: 2.6 MB -> 1.7 MB
        except Exception:
            pass
    doc.save(dst, garbage=4, clean=True, deflate=True)
    res = {"text_replacements": log, "images": img_log, "pages": pages_log}
    if emb_log:
        res["embedded"] = _embedded_summary(emb_log)
    if review:
        res["review"] = review
    return res


# ---------------------------------------------------------------------------------------------------------------------
# File size identical to the input (requirement 7 "maintaining the same file size")
# ---------------------------------------------------------------------------------------------------------------------
def _jpeg_fit(img, target_len, q_start=92, q_min=55):
    """Encodes `img` as JPEG at the best quality level (≤ q_start) whose size does not exceed `target_len`;
    failing that, the smallest one (q_min). Returns (bytes, quality)."""
    best = None
    for q in range(q_start, q_min - 1, -2):
        buf = io.BytesIO(); img.save(buf, "JPEG", quality=q); data = buf.getvalue()
        best = (data, q)
        if target_len is None or len(data) <= target_len:
            break
    return best


def _pad_pdf(dst, target):
    """Adjusts the size of a PDF to `target` bytes with an unreferenced stream object (/MasqueradingPad true) filled
    with zeros, stored uncompressed to be linear; converges in a few saves (the xref offsets change length when
    crossing a power of 10). Returns the method or None if the output is already larger."""
    import fitz, shutil
    backup = dst + ".bak"; shutil.copyfile(dst, backup)
    for _ in range(8):
        size = os.path.getsize(dst); d = target - size
        if d == 0:
            os.unlink(backup); return "pdf_pad_stream"
        if d < 0 and not _pdf_pad_len(dst):
            shutil.move(backup, dst); return None
        doc = fitz.open(dst)
        xref = None
        for x in range(1, doc.xref_length()):
            try:
                if doc.xref_get_key(x, "MasqueradingPad")[1] == "true":
                    xref = x; break
            except Exception:
                pass
        cur = len(doc.xref_stream_raw(xref)) if xref else 0
        n = max(0, cur + d)
        if xref is None:
            xref = doc.get_new_xref()                       # empty object: give it a dictionary BEFORE the stream
            doc.update_object(xref, "<< /MasqueradingPad true >>")
            doc.update_stream(xref, b"\0" * max(1, n), new=True, compress=0)
        else:
            doc.update_stream(xref, b"\0" * max(1, n), compress=0)
        tmp = dst + ".pad"
        doc.save(tmp, garbage=0, deflate=False); doc.close()
        os.replace(tmp, dst)
    if os.path.getsize(dst) == target:
        os.unlink(backup); return "pdf_pad_stream"
    shutil.move(backup, dst); return None


def _pdf_pad_len(dst):
    import fitz
    doc = fitz.open(dst)
    for x in range(1, doc.xref_length()):
        try:
            if doc.xref_get_key(x, "MasqueradingPad")[1] == "true":
                return len(doc.xref_stream_raw(x))
        except Exception:
            pass
    return 0


def _pad_png(dst, target):
    """tEXt chunk ("P" + spaces) inserted before IEND: 12 bytes of header/CRC + data. If the output is larger
    than the target, re-encode with increasing compress_level."""
    import struct, zlib
    from PIL import Image
    data = open(dst, "rb").read()
    d = target - len(data)
    if d == 0:
        return "png_exact"
    if d < 14:
        img = Image.open(io.BytesIO(data))
        for lvl in range(6, 10):
            buf = io.BytesIO(); img.save(buf, "PNG", compress_level=lvl); cand = buf.getvalue()
            if target - len(cand) >= 14:
                data = cand; d = target - len(data); break
        if d < 14:
            return None
    payload = b"P\0" + b" " * (d - 12 - 2)
    chunk = struct.pack(">I", len(payload)) + b"tEXt" + payload
    chunk += struct.pack(">I", zlib.crc32(b"tEXt" + payload) & 0xFFFFFFFF)
    i = data.rfind(b"IEND") - 4
    out = data[:i] + chunk + data[i:]
    open(dst, "wb").write(out)
    return "png_text_chunk" if len(out) == target else None


def _pad_jpeg(dst, target):
    """COM segments (FF FE, 4 bytes of header + data ≤ 65,531) inserted after SOI. Output too large → re-encode
    at decreasing quality until ≥ 4 bytes of margin remain."""
    from PIL import Image
    data = open(dst, "rb").read()
    d = target - len(data)
    if d == 0:
        return "jpeg_exact"
    if d < 4:
        img = Image.open(io.BytesIO(data)).convert("RGB")
        for q in range(90, 54, -2):
            buf = io.BytesIO(); img.save(buf, "JPEG", quality=q); cand = buf.getvalue()
            if target - len(cand) >= 4:
                data = cand; d = target - len(data); break
        if d < 4:
            return None
    segs = b""
    while d > 0:
        n = min(d, 65535)
        if d - n in (1, 2, 3):          # do not leave a remainder impossible to encode
            n = d - 4
        segs += b"\xff\xfe" + (n - 2).to_bytes(2, "big") + b" " * (n - 4)
        d -= n
    out = data[:2] + segs + data[2:]
    open(dst, "wb").write(out)
    return "jpeg_com_segments" if len(out) == target else None


def _pad_media_bytes(name, data, n):
    """Adds `n` INCOMPRESSIBLE (random) bytes to an image of an Office package: private PNG chunk "maSq" (ancillary,
    ignored by readers) or JPEG COM segments. Random so that the deflated size tracks the raw size."""
    import struct, zlib
    ext = os.path.splitext(name)[1].lower()
    if ext == ".png" and n >= 12:
        payload = os.urandom(n - 12)
        chunk = struct.pack(">I", len(payload)) + b"maSq" + payload + struct.pack(">I", zlib.crc32(b"maSq" + payload) & 0xFFFFFFFF)
        i = data.rfind(b"IEND") - 4
        return data[:i] + chunk + data[i:]
    if ext in (".jpg", ".jpeg") and n >= 4:
        segs = b""; d = n
        while d > 0:
            m = min(d, 65535)
            if d - m in (1, 2, 3):
                m = d - 4
            segs += b"\xff\xfe" + (m - 2).to_bytes(2, "big") + os.urandom(m - 4); d -= m
        return data[:2] + segs + data[2:]
    return None


def _pad_zip(dst, target):
    """DOCX/XLSX: STORED (uncompressed, hence linear) padding of random bytes, either in the largest image of the
    package (private PNG chunk / COM segments), or — without an image — in a `masquerading/pad.bin` part declared in
    [Content_Types].xml (orphan part, legal in OPC). The zip archive comment is FORBIDDEN: LibreOffice then refuses
    to open the document ("source file could not be loaded"). Output too large → members recompressed at
    level 9. NB: SharePoint rewrites every uploaded DOCX/XLSX (+~10 KB of metadata) — the equality holds locally."""
    import zipfile, shutil
    PAD_PART = "masquerading/pad.bin"

    def rewrite(patch=None, extra=None, level=9):
        # always level 9: a rewrite at the default level re-inflated the members after a pass at level 9
        # (38,510 → 36,160 → 39,891 bytes) and convergence failed
        tmp = dst + ".rz"
        with zipfile.ZipFile(dst) as zi, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=level) as zo:
            for it in zi.infolist():
                if it.filename == PAD_PART:
                    continue
                data = zi.read(it.filename)
                if patch and it.filename == patch[0]:
                    zo.writestr(it.filename, patch[1], compress_type=zipfile.ZIP_STORED)
                    continue
                if extra and it.filename == "[Content_Types].xml" and PAD_PART not in data.decode("utf-8", "ignore"):
                    data = data.replace(b"</Types>", b'<Override PartName="/' + PAD_PART.encode() +
                                        b'" ContentType="application/octet-stream"/></Types>')
                zo.writestr(it, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=level)
            if extra:
                zo.writestr(PAD_PART, extra, compress_type=zipfile.ZIP_STORED)
        shutil.move(tmp, dst)
    backup = dst + ".bak"; shutil.copyfile(dst, backup)

    def give_up():
        shutil.move(backup, dst)                            # never leave a file bloated by a failed padding
        return None
    d = target - os.path.getsize(dst)
    if d < 0:
        rewrite(); d = target - os.path.getsize(dst)
        if d < 0:
            return give_up()
    if d == 0:
        os.unlink(backup); return "zip_recompressed"
    with zipfile.ZipFile(dst) as z:
        media = [it for it in z.infolist() if "/media/" in it.filename and it.filename.lower().endswith((".png", ".jpg", ".jpeg"))]
        m = max(media, key=lambda it: it.file_size) if media else None
        original = z.read(m.filename) if m else None
    # the padded image is written STORED: its former compression (file_size − compress_size) is lost → to be deducted
    stored_penalty = (m.file_size - m.compress_size) if m else 0
    n = d - 64 - stored_penalty
    if m and n < 16:                                        # not enough gap to absorb the stored image → dedicated part
        m = None; n = d - 200
    n = max(16, n)
    for _ in range(8):
        if m:
            padded = _pad_media_bytes(m.filename, original, n)
            if padded is None:
                return give_up()
            rewrite(patch=(m.filename, padded)); method = "zip_media_pad"
        else:
            rewrite(extra=os.urandom(n)); method = "zip_pad_part"
        d = target - os.path.getsize(dst)
        if d == 0:
            os.unlink(backup); return method
        n += d
        if n < 16:
            return give_up()
    return give_up()


def _pad_rtf(dst, target):
    """RTF: spaces before the final brace (ignored by readers)."""
    data = open(dst, "rb").read()
    d = target - len(data)
    if d < 0:
        return None
    i = data.rfind(b"}")
    out = data[:i] + b" " * d + data[i:]
    open(dst, "wb").write(out)
    return "rtf_spaces" if len(out) == target else None


def match_input_size(src, dst, target=None):
    """Makes the output file the SAME SIZE as the input (or `target` bytes) when the output is smaller
    (or compressible enough to become so): neutral padding specific to each format. Log: {'in', 'out_before', 'out',
    'method'}; 'unmatched' if the output remains larger than the target (e.g. re-encoded image that is heavier)."""
    ext = os.path.splitext(dst)[1].lower()
    target = os.path.getsize(src) if target is None else int(target); before = os.path.getsize(dst)
    fn = {".pdf": _pad_pdf, ".png": _pad_png, ".jpg": _pad_jpeg, ".jpeg": _pad_jpeg, ".docx": _pad_zip, ".xlsx": _pad_zip,
          ".rtf": _pad_rtf}.get(ext)
    res = {"in": target, "out_before": before}
    if fn is None:
        res["unmatched"] = "format"; return res
    try:
        method = fn(dst, target)
    except Exception as exc:  # noqa - the padding must never make the sanitization fail
        method = None; res["error"] = repr(exc)
    res["out"] = os.path.getsize(dst)
    if method:
        res["method"] = method
    else:
        res["unmatched"] = "sortie plus grosse que l'entrée" if res["out"] > target else "non convergé"
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
            if fn.startswith(("~$", ".")):      # Office lock files / hidden files
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
            if "error" not in res and "copied" not in res and os.environ.get("MATCH_INPUT_SIZE", "1") == "1":
                res["size_match"] = match_input_size(src, dst)
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
