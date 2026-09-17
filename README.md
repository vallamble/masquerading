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
| GET | `/healthz` | — | status, build commit (`version`), queue depth |
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
| `MATCH_INPUT_SIZE` | `1` = make every output file byte-identical in size to its input (neutral padding, see Status) ; `0` = natural size | `1` |
| `PDF_SUBSET_FONTS` | `1` = subset the TrueType faces re-inserted in PDFs | `1` |

Every secret variable also accepts the Docker convention `<VAR>_FILE` (path to a file holding the value), and falls back
to `/run/secrets/<VAR>` if present: `deploy/docker-compose.yml` mounts the four Swarm secrets `SERVICE_API_KEY`,
`GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET` (created in Portainer → Secrets) that way, so no secret value
ever lives in the compose file or in the stack's environment variables.

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
  in clear. Low-confidence names/addresses are matched to the table (distance ≤ 1). **Rendering
  keeps the image's typography**: the page skew is measured on the pixels (projection profile) and
  removed from every OCR box height (a tilted 800 px number used to "measure" 20 px taller than a
  200 px name next to it), the font size is fitted on the original text and then homogenised per
  size cluster over the whole image (one style = one size), and the DejaVu family
  (sans/bold/mono/serif/condensed) is chosen per cluster by cumulative width error, never word by
  word. `font_px` and `skew` are logged per replacement. Ink zones OCR can't read at all
  (signatures, handwriting) are scored as `UNREAD_INK` in the log for manual review.

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

## Status (2026-09-17)

| Check | Result |
|---|---|
| POC dataset (9 files, 4 522 ground-truth rows) | **0 leaks / 3 717**, 0 decoys modified / 154, 305 pages and 4 images preserved, 1 min 19 |
| Gap dataset (RTF, scanned PDF with `/Rotate 90`, DOCX with embedded XLSX + preview, PDF with attachment, signed forms) | **0 leaks / 314**, 0 decoys / 8, 3/3 signatures at 0 % residual ink, 6/6 frames and rules intact |
| End-to-end on the deployed service (Graph upload → `POST /sanitize` → `Documents/Output/gap/`) | 6/6 files processed in < 1 min, same evaluation result as local |
| Container image | 657 MB → 1.12 GB (LibreOffice writer, headless) |
| In-image typography (Valery, 17.09: font size changed from word to word) | fixed in two passes: skew-corrected box heights, size = median of the OCR *run* (same-line neighbours), one size per style cluster, numeric-only clusters capped at the nearest letter cluster (cursive digits), OCR boxes inflated by Tesseract tightened to the ink, one family per cluster; adjacent replaced words re-flowed as a chain (single space kept, uniform shrink if the chain does not fit); erase by ink pixels so field borders and rules survive. Checked by eye on all 6 standalone images, the OLE preview, the 4 scanned pages |
| PDF text-layer typography | replacement text uses the original span's size, baseline and colour, and the **same TrueType face** when the source font is DejaVu (Sans / Serif / Mono × Bold × Oblique, from `fonts-dejavu` in the container), base-14 otherwise (was `insert_textbox` in Helvetica at 0.78 × box height: visibly different face, 1–2 pt too high, shrunk to superscript when the pseudonym was longer); embedded fonts are subset before saving; free space up to the next word is used; adjacent replaced words re-flowed (`KELLERFranz` → `KELLER Franz`) |
| PDF text extractable by third-party tools | pdfplumber/pdfminer read `Vincent Bi se`: the original *space glyph* between two replaced words survived redaction and sat inside the re-inserted pseudonym. Neighbouring redaction rectangles on a line are now merged (gap ≤ 0.6 × height) and same-style neighbours are written as one string with real spaces. Evaluator "replacements present" on the 305-page PDF: 0.84 → 1.00 with pdfplumber (PyMuPDF already read 100 %) |
| File size identical to the input (requirement 7) | `match_input_size()` after every handler: shrink first (font subsetting, JPEG quality ≤ original stream, zip level 9), then pad with a format-neutral element to the exact input size; logged per file as `size_match` (`method` or `unmatched`) |
| Client fonts in PDF | Arial → Liberation Sans, Times New Roman → Liberation Serif, Courier New → Liberation Mono, Calibri → Carlito, Cambria → Caladea (same metrics, `fonts-liberation`/`fonts-crosextra-*` in the image, LibreOffice fonts on macOS); DejaVu reused as is; unembedded Helvetica/Times/Courier stay base-14 |
| In-image italic / "handwritten" fields | glyph slant measured on the ink of each word (shear that best aligns the stems), median per ink colour (one pen = one style) → oblique/italic variant of the family (DejaVu Sans-Oblique, Serif-Italic, Condensed-Oblique) instead of upright |
| End-to-end through SharePoint and the deployed service (17.09, `bd3f1a4`) | POC dataset 9 files → `Documents/Inbound/e2e-base` → `POST /sanitize` → `Documents/Output/e2e-base` → same evaluation as local: **0 leaks / 3 717**, 305 pages / 4 images. Gap dataset 11 files → `e2e-gap`: **0 / 372**, signatures 3/3, decoys 6/6. Graph client now retries timeouts and 429/5xx (a 300 s ReadTimeout broke the first gap run) |
| Deployed build | `GET /healthz` returns `version` = short commit SHA baked at build time (`GIT_SHA`), so the running image can be checked after each Portainer *Pull and redeploy* |

Known limits, logged for review rather than processed: OLE `.bin` objects that are not Office packages, EMF/WMF previews
of embedded objects (Word-generated), a signature drawn over text (the text under it is erased too), native RTF patching
(LibreOffice round trip is used instead). Signature thresholds were tuned on synthetic strokes; check them on real
signatures before a demo.

## Customer requirements — evidence (2026-09-17, build `0723127`)

Measured with `tools/evaluate_output.py` on two 100 % fictional datasets (POC: 9 files / 3 717 values; gap: 11 files /
372 values), locally **and** end to end through SharePoint and the deployed service (same numbers). Every image and
rendered PDF page was also checked by eye; the harness is blind to typography.

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | Identify PII/PHI across varying formats and templates | met | 0 leaks / 3 717 + 0 / 372; same content in different templates (`Template_B.docx`, `Template_C.pdf`, `Lettre.rtf`) 0 leaks; format-valid pseudonyms (IBAN 150/150, AVS 83/83 in the 305-page PDF); non-sensitive decoys untouched 0 / 154 |
| 2 | Mask PII in images | met | 6 standalone images, images inside DOCX (incl. the OLE preview) and PDF: 0 leaks; pseudonyms rendered in the original size, weight, slant and colour |
| 3 | Consistent masking across free text, images, tables | met | multi-surface check: `Coherence.docx` 5 values on header + footer + image + paragraph + table, 305-page PDF 481 values on ≥ 2 surfaces, 0 leaks, identical pseudonym everywhere (deterministic mapping) |
| 4 | Headers and footers on all pages | met | `Pied_de_page.pdf` (4 pages, PII only in header/footer) 0/16, `Pied_de_page.docx` 0/5, RTF header/footer 0/36 |
| 5 | Handwritten and system-generated signatures | met | 3 signatures (raster, vector, PNG) at 0 % residual ink, 6/6 frames and rules intact; typed name + "Digitally signed by" line rewritten 0/20 |
| 6 | Data in scanned images | met | 4 scanned pages (200 dpi, skewed, one `/Rotate 90`) 0/130, second OCR pass after masking finds nothing |
| 7 | Layout unchanged, same file size (Word, PDF) | met | 305/305 pages, 4/4 images, identical paragraph/table/sheet counts, text length ratio 0.98–1.02; replacement text in the original face (or its metric-compatible twin), size, baseline and colour. **Size: byte-identical to the input** for every format we write (`MATCH_INPUT_SIZE=1`, default): the output is first made no larger than the input (PDF fonts subset, JPEG quality fitted to the original stream, zip level 9), then padded with a neutral element — unreferenced zero stream in PDF, `tEXt` chunk in PNG, `COM` segments in JPEG, a stored random pad inside the largest image or a declared `masquerading/pad.bin` part in DOCX/XLSX (never a zip archive comment: LibreOffice refuses to open the file), trailing spaces in RTF. Padded DOCX/XLSX verified to open in LibreOffice and python-docx. Caveat: SharePoint rewrites every DOCX/XLSX it stores (+~10 KB of library metadata), so compare Inbound-on-SharePoint with Output, not the local file |
| 8 | Sensitive data in nested documents | met | XLSX embedded in DOCX (`word/embeddings`) and XLSX attached to a PDF: found = processed, 0 leaks (incl. the OLE preview image). Out of scope, logged for review: non-Office OLE `.bin`, EMF/WMF previews |

Formats: PDF (text layer), DOCX, RTF, XLSX, images inside PDF, scanned images inside PDF — all covered by the two datasets above.

## Validation

```bash
DS=<…/02_Phase2_dataset> bash tools/validate.sh          # POC dataset: expect 0 leaks / 3 717, 0 decoys / 154, 305 pages, 4 images
DS=<…/02_Phase2_dataset> GAP=1 bash tools/validate.sh    # gap dataset (RTF, scanned PDF, embedded objects, signatures)
python tools/make_gap_dataset.py --ds <…/02_Phase2_dataset>   # regenerate the 100 % fictional gap dataset

# end to end through SharePoint and the deployed service (env: GRAPH_*, SP_*, SERVICE_API_KEY — see tools/e2e_gap.py)
python tools/e2e_gap.py --inbound-gap <…/inbound>     --subdir e2e-base --download tools/runs/e2e_base/out
SKIP_SANITIZE=1 RUN_DIR=tools/runs/e2e_base bash tools/validate.sh
```

## Demo state

`Documents/Inbound` holds exactly the two fictional datasets: the POC files at the root (with `images/`) and the gap
files under `gap/`. `Documents/Output` mirrors that tree with the pseudonymized files produced by the current build.
Securiti workflows do not fire in the lab tenant, so the trigger is manual: `POST /sanitize` for one file or
`POST /scan-completed` to reprocess all of Inbound. To rebuild that state from scratch (wipes both folders first):

```bash
python tools/reset_demo.py --ds <…/02_Phase2_dataset> --download tools/runs/demo --evaluate   # add --keep to redeposit without wiping
```

## Quick test

```bash
curl -fsS https://masquerading.lamble.fr/healthz
curl -fsS -XPOST https://masquerading.lamble.fr/sanitize \
  -H "X-Api-Key: $SERVICE_API_KEY" -H 'Content-Type: application/json' \
  -d '{"file_path":"Documents/Inbound/Dossier_patients_Q3_2026_FICTIF.pdf"}'
```
