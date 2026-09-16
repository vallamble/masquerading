# masquerading

HTTP service for **meaningful masking / pseudonymization** in a Securiti × SharePoint PoC.
It consistently pseudonymizes files dropped in a SharePoint `Documents/Inbound` folder — same
people → same pseudonyms, format-valid IBAN/AVS/cards, in-image text rewritten via OCR — and
writes the result to `Documents/Output`. All test data is 100 % fictional.

Triggered by Securiti Workflows (HTTP Request node, executed in the Securiti cloud):
SDI scan on `Inbound` → File Insights policy → workflow → this service → verification scan.

## Endpoints

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/healthz` | — | status + queue depth |
| POST | `/sanitize` | `{"file_path":"…"}` **or** `{"alert":{…}}` | pseudonymize one file (202, async) |
| POST | `/scan-completed` | `{"scan_id":"…"}` (or `{"scan":{…}}`) | re-process all of `Inbound` (202) |

`POST /sanitize` accepts either a direct `file_path` or the raw Securiti alert payload
(`alert`), from which it extracts the path; the received payload is logged (handy to capture the
schema). POST requests require the `X-Api-Key: $SERVICE_API_KEY` header.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `SERVICE_API_KEY` | key expected in `X-Api-Key` | — (required) |
| `GRAPH_TENANT_ID` / `GRAPH_CLIENT_ID` / `GRAPH_CLIENT_SECRET` | Entra app (Sites.ReadWrite.All or Sites.Selected) | — |
| `SP_HOSTNAME` | SharePoint host | — |
| `SP_SITE_PATH` | site path (`""` = tenant root site) | — |
| `SP_LIBRARY` | document library | `Documents` |
| `DATA_DIR` | state dir (mapping + generated pseudonyms) | `/data` |
| `INBOUND_PREFIX` / `OUTPUT_PREFIX` | source/target folders | `Inbound` / `Output` |
| `SANITIZE_FONT` | force the "sans" TrueType font path (optional) | auto-detected |
| `COVER_SIGNATURES` | `1` = cover handwritten signature zones (raster ink near a "Signature" label or in the bottom third, vector strokes, /Ink annotations, /Sig widgets); frames and rules are left intact. `0` = detect and log only | `1` |
| `COVER_UNREAD_INK` | `1` = auto-cover **every** ink zone OCR can't read (experimental, too aggressive on banners/frames) | `0` |
| `SCAN_DPI` | render resolution for scanned PDF pages (OCR + second pass) | `300` |
| `SOFFICE` | path to LibreOffice `soffice` (RTF conversion) | auto-detected |

Persistent state: `${DATA_DIR}/mapping_by_value.csv` (pseudonym table; seed copied on first
start if missing) and `${DATA_DIR}/generated.json` (unknown values, deterministic derivation).
The service starts **without** Graph credentials (returns 202 and logs); the Graph call only
fails inside the worker at processing time.

## Supported formats

| Format | How | Notes |
|---|---|---|
| PDF (text layer) | PyMuPDF redaction per reconstructed line + pseudonym re-inserted | headers/footers are ordinary page text |
| PDF **scanned pages** (no text layer, one full-page image) | page rendered at `SCAN_DPI`, grayscale + contrast, deskew (projection profile), OCR, patches re-projected onto the original image (geometry and `/Rotate` preserved); **second OCR pass** after masking: anything still readable is `LEAK_SUSPECT` and covered | per-page log: `scanned`, `skew`, `masked` |
| PDF **attachments** (embedded files) | extracted, routed by extension, re-attached | unknown types: `EMBEDDED_UNSUPPORTED` + review |
| DOCX | paragraphs, tables, headers/footers; `word/media/*.png|jpg` via OCR | |
| DOCX **embedded objects** (`word/embeddings/*.xlsx|docx`, `.bin` OLE holding an Office package) | recursive (depth ≤ 3, loop guard) | EMF/WMF object previews can't be OCR'd: `EMBEDDED_PREVIEW_UNSUPPORTED` + review |
| XLSX | all text cells (formulas kept); `xl/embeddings/*` | |
| **RTF** | LibreOffice headless RTF → DOCX → `sanitize_docx` → RTF, isolated user profile per call; round-trip fidelity check (non-sensitive tokens, header/footer/tables): `RTF_FIDELITY_WARN` on drift | native RTF control-word patching is the production target (not implemented) |
| PNG / JPG | OCR (two scales × two modes), fail-closed IBAN/AVS/name matching | |
| Handwritten **signatures** | see `COVER_SIGNATURES` | the typed name / "Digitally signed by …" block goes through the normal text path |

Everything the engine cannot process is **fail-closed**: logged in the per-file `review` list, never silently passed through.

## How masking works

- **Documents** (DOCX/XLSX/PDF): text is matched against the pseudonym table + deterministic
  patterns (IBAN mod-97, AVS EAN-13, Luhn cards, patient IDs, emails, phones) and replaced with
  format-valid pseudonyms — no `XXXX` placeholders.
- **Images** (PNG/JPG + images embedded in PDF/DOCX): OCR at two scales (2× LANCZOS then 1×) ×
  two page-segmentation modes, with numeric-token normalization (O/0, I/1, S/5…) so a misread
  digit can't hide an identifier. **Fail-closed**: any IBAN-shaped string whose checksum is
  doubtful is matched to the table (Levenshtein ≤ 2) or replaced by a generated IBAN — never left
  in clear. Low-confidence names/addresses are matched to the table (distance ≤ 1). Rendering
  fits the pseudonym to the box and picks a DejaVu family (sans/bold/mono/serif/condensed) by
  minimal width error. Ink zones OCR can't read at all (signatures, handwriting) are scored as
  `UNREAD_INK` in the log for manual review.

## Image

`ghcr.io/vallamble/masquerading:latest` (and `:sha-<short>`), multi-arch `linux/amd64,linux/arm64`,
built by GitHub Actions (`.github/workflows/build.yml`) on `python:3.11-slim` + `tesseract-ocr`
(fra/deu/eng) + `fonts-dejavu` (sans/bold/mono/serif/condensed) + `libreoffice-writer` (headless, no
GUI/Java, needed for RTF). Listens on `0.0.0.0:8080`.

## Deployment (Docker / Portainer, behind Traefik)

`deploy/docker-compose.yml` runs the service in Docker Swarm and exposes it through **Traefik**
(external network `traefik_public`, `websecure` entrypoint, Let's Encrypt resolver `le`,
router `Host(masquerading.lamble.fr)` → container `:8080`). No host port is published (traffic
goes through Traefik; internet access via a Cloudflare tunnel pointing at Traefik). The
`masquerading_data` volume is **external** and holds `/data`. Copy `deploy/.env.example` → `.env`
and fill it (or set the variables in the Portainer stack).

```bash
docker pull ghcr.io/vallamble/masquerading:latest
cd deploy && cp .env.example .env   # then fill in the secrets
docker stack deploy -c docker-compose.yml masquerading   # or deploy via Portainer
```

## Validation

```bash
DS=<…/02_Phase2_dataset> bash tools/validate.sh          # POC dataset: expect 0 leaks / 3 717, 0 decoys / 154, 305 pages, 4 images
DS=<…/02_Phase2_dataset> GAP=1 bash tools/validate.sh    # gap dataset (RTF, scanned PDF, embedded objects, signatures)
python tools/make_gap_dataset.py --ds <…/02_Phase2_dataset>   # regenerate the 100 % fictional gap dataset
```

## Quick test

```bash
curl -fsS https://masquerading.lamble.fr/healthz
curl -fsS -XPOST https://masquerading.lamble.fr/sanitize \
  -H "X-Api-Key: $SERVICE_API_KEY" -H 'Content-Type: application/json' \
  -d '{"file_path":"Documents/Inbound/Dossier_patients_Q3_2026_FICTIF.pdf"}'
```
