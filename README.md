# masquerading

HTTP service for **meaningful masking / pseudonymization** in a Securiti × SharePoint PoC.
It consistently pseudonymizes files dropped in a SharePoint `Inbound` folder — same
people → same pseudonyms, format-valid IBAN/AVS/cards, in-image text rewritten via OCR — and
writes the result to `Output`. All test data is 100 % fictional.

Triggered by Securiti Workflows (HTTP Request node, executed in the Securiti cloud):
SDI scan on `Inbound` → File Insights policy → workflow → this service → verification scan.
On the lab tenant the scan-completion trigger reaches the service automatically after every completed job of the
console scan definition; the policy-alert path is not exposed for File Insights — see *Triggers* for what each
building block can and cannot do.

## Endpoints

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/healthz` | — | status, build commit (`version`), queue depth, counters (no file names) |
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
| `HMAC_SECRET` | key of the HMAC that derives pseudonyms for values absent from the table (`generated.json`); falls back to `SERVICE_API_KEY`, then to a demo constant with a start-up warning — set it in production so generated pseudonyms cannot be recomputed from the public code | — |
| `SECURITI_POLL_DATASOURCE` | data system id to watch (e.g. `102`); when set, the service polls the tenant's scan listing and reprocesses all of `Inbound` each time a new discovery-scan job on that data system reaches "Post-Processing Complete" (fallback trigger when Securiti workflows do not fire) | — (off) |
| `SECURITI_TENANT_URL` / `SECURITI_TENANT_ID` / `SECURITI_API_KEY` / `SECURITI_API_SECRET` | read-only API credentials for the poller (`<VAR>_FILE` / `/run/secrets` accepted) | `app.securiti.ai` / — |
| `SECURITI_POLL_INTERVAL` | polling period in seconds (min 30) | `120` |
| `MAPPING_PUBLIC` | `1` = serve `GET /mapping` (the original → pseudonym table, i.e. the re-identification key) without the API key — lab demos only, never in production | `0` |
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

## Triggers

What each Securiti building block produces, and why only one of them has ever called this service (lab tenant,
release 1.150, console audits of 2026-09-18/21):

| Building block | What it produces | Can it start a workflow? | On the lab tenant |
|---|---|---|---|
| **File Insights policy** (100) | a *count*: the scope query is re-run on the Data Command Graph on display, nothing is stored, no alert, no finding | no — the form has no Actions section (Trigger Workflow exists only for Structured Data Insights) | 12 files in scope, `SAN-main` (Policy Alert, Event Mode) 0 executions ever |
| **File Quarantine policy** | an *action on the file*: move to the same data system or to a central quarantine location, or e-mail | no — the three actions do not include Trigger Workflow; the service would have to watch the quarantine folder itself | unreachable: central destination refused (400 "datasource should be valid and in auth-complete state" on an authenticated connector) and the scope validator rejects `sharepoint_online_onprem` |
| **Discovery Scan Trigger** (`SAN-fallback`) | an *event*: "a discovery scan job has completed" on the data system | yes — **Event Mode**, provided the *scan definition itself* references the workflow (Scan Details → Responses → Trigger Workflow → Add Workflows); in Cron Mode it only lists definitions and fires once per definition | **works per job**: scan 206 job f4a67b04 completed 19:00Z, execution 989 at 19:22Z (0.6 s), service reprocessed `Inbound`, `Output` rewritten 19:22–19:25Z |

So: Securiti classifies a dropped file within one scan, and the completion of that scan now reaches the service
automatically, job after job. The per-file alert path (File Insights → Policy Alert → `SAN-main`) is still not exposed
on this tenant and stays in the support ticket, together with Access Intelligence for M365. Two prerequisites for the
automatic chain, both learned the hard way: the scan definition must be created in the console (API-created definitions
read 0 bytes) and must list the workflow in its Responses tab (the trigger node alone is not enough — Event Mode looked
"dead" for a week because of that); the console PATCH of a console-created scan is refused through the API
("all mandatory rules must be selected"), so this wiring is a console step.

Ways to start processing, from the most to the least automatic:

1. **Securiti workflow** (automatic, per job): scan definition 206 "POC Sanitization Console" → Responses → Trigger
   Workflow = `SAN-fallback` (Discovery Scan Trigger, Event Mode, Target Type Microsoft 365 SharePoint Online) →
   `POST /scan-completed`. Each completed job of 206 reprocesses `Inbound`; the scan's own schedule (manual today,
   daily possible) sets the latency. `SAN-main` (Policy Alert on policy 100) stays configured for the day the tenant
   exposes the alert path.
2. **Scan-completion poller** (fallback, built in): with `SECURITI_POLL_DATASOURCE` set, the service watches the
   tenant's scan listing every `SECURITI_POLL_INTERVAL` seconds and reprocesses `Inbound` when a new scan *job* on that
   data system completes — the same per-job event as above, observed from our side, for tenants where the
   workflow path is unavailable.
   `GET /healthz` shows `securiti_poll` (known jobs, triggered count, last check/error).
3. **Manual**: `POST /sanitize` (one file) or `POST /scan-completed` (all of `Inbound`).

## Security

- Every `POST` and `GET /mapping` require `X-Api-Key`, compared in constant time; `GET /healthz` is public and exposes no file name.
- File paths coming from the alert payload are reduced to a path relative to `Inbound`, then rejected if they contain `..`, empty segments or an unsupported extension — the service can only read `Inbound/…` and write `Output/…`.
- Request logs record the payload's keys and the resolved path, never its contents (a Securiti alert may carry personal data). Secrets come from `<VAR>_FILE` / `/run/secrets`, never from the compose file.
- The pseudonym table (`/data/mapping_by_value.csv`, `generated.json`) is the re-identification key: it lives on the service volume only; the `/mapping` page that shows it is behind the API key unless `MAPPING_PUBLIC=1`.
- Outputs are written under the same relative path in `Output`; the neutral padding used for size matching never carries data (zeros, spaces, or random bytes).

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
| End-to-end on the deployed service (Graph upload → `POST /sanitize` → `Output/gap/`) | 6/6 files processed in < 1 min, same evaluation result as local |
| Container image | 657 MB → 1.12 GB (LibreOffice writer, headless) |
| In-image typography (17.09: font size changed from word to word) | fixed in two passes: skew-corrected box heights, size = median of the OCR *run* (same-line neighbours), one size per style cluster, numeric-only clusters capped at the nearest letter cluster (cursive digits), OCR boxes inflated by Tesseract tightened to the ink, one family per cluster; adjacent replaced words re-flowed as a chain (single space kept, uniform shrink if the chain does not fit); erase by ink pixels so field borders and rules survive. Checked by eye on all 6 standalone images, the OLE preview, the 4 scanned pages |
| PDF text-layer typography | replacement text uses the original span's size, baseline and colour, and the **same TrueType face** when the source font is DejaVu (Sans / Serif / Mono × Bold × Oblique, from `fonts-dejavu` in the container), base-14 otherwise (was `insert_textbox` in Helvetica at 0.78 × box height: visibly different face, 1–2 pt too high, shrunk to superscript when the pseudonym was longer); embedded fonts are subset before saving; free space up to the next word is used; adjacent replaced words re-flowed (`KELLERFranz` → `KELLER Franz`) |
| PDF text extractable by third-party tools | pdfplumber/pdfminer read `Vincent Bi se`: the original *space glyph* between two replaced words survived redaction and sat inside the re-inserted pseudonym. Neighbouring redaction rectangles on a line are now merged (gap ≤ 0.6 × height) and same-style neighbours are written as one string with real spaces. Evaluator "replacements present" on the 305-page PDF: 0.84 → 1.00 with pdfplumber (PyMuPDF already read 100 %) |
| File size identical to the input (requirement 7) — as stored by SharePoint | after upload the service re-reads the stored size (SharePoint rewrites Office files a few seconds later) and, if it differs, re-pads the raw output to input size minus the observed delta and re-uploads (3 attempts); logged as `size_match.sharepoint`. Final run on `b5aeb41`: 19/20 identical, XLSX 25 042 → 25 040 |
| File size identical to the input (requirement 7) | `match_input_size()` after every handler: shrink first (font subsetting, JPEG quality ≤ original stream, zip level 9), then pad with a format-neutral element to the exact input size; logged per file as `size_match` (`method` or `unmatched`) |
| Original fonts in PDF | Arial → Liberation Sans, Times New Roman → Liberation Serif, Courier New → Liberation Mono, Calibri → Carlito, Cambria → Caladea (same metrics, `fonts-liberation`/`fonts-crosextra-*` in the image, LibreOffice fonts on macOS); DejaVu reused as is; unembedded Helvetica/Times/Courier stay base-14 |
| Signature detector | ink groups merged transitively (a saw-tooth scribble read as 4 pieces formed 4 groups that each failed); next to a "Signature" label the shape filters no longer apply; in the bottom third a compact group passes if it looks like a scribble (one stroke ≥ 50 % of the height, thin fragments). Cover rectangle clipped against neighbouring OCR text |
| Pseudonym table | `FIRST_NAME Anne → Aurore` added (the prescriber "Dr Anne Genoud" kept her first name); the service merges new seed rows into the persisted `/data` table at start-up, so table additions ship with the code |
| In-image italic / "handwritten" fields | glyph slant measured on the ink of each word (shear that best aligns the stems), median per ink colour (one pen = one style) → oblique/italic variant of the family (DejaVu Sans-Oblique, Serif-Italic, Condensed-Oblique) instead of upright |
| End-to-end through SharePoint and the deployed service (17.09, `bd3f1a4`) | POC dataset 9 files → `Documents/Inbound/e2e-base` → `POST /sanitize` → `Documents/Output/e2e-base` → same evaluation as local: **0 leaks / 3 717**, 305 pages / 4 images. Gap dataset 11 files → `e2e-gap`: **0 / 372**, signatures 3/3, decoys 6/6. Graph client now retries timeouts and 429/5xx (a 300 s ReadTimeout broke the first gap run) |
| Deployed build | `GET /healthz` returns `version` = short commit SHA baked at build time (`GIT_SHA`), so the running image can be checked after each Portainer *Pull and redeploy* |

Known limits found by the 2026-09-18 code review, not covered by the two datasets and left as is (documented, not fixed):
DOCX text inside text boxes, footnotes/endnotes, comments, content controls and tracked changes is not traversed;
XLSX numeric cells (a card number typed as a number), cell comments, sheet names and `xl/media` images are not scanned;
vector artwork in the bottom third of a PDF page (a footer logo made of curves) can be taken for a vector signature and
removed; `.docm` is not handled. Fixed in the same review: identical embedded objects repeated in one file are now all
sanitized (the anti-loop guard returned the original bytes for the second copy), an OCR failure now fails the file instead
of writing it back unchanged, EXIF orientation is honoured before OCR, a PDF image shared by many pages is processed once.

Known limits, logged for review rather than processed: OLE `.bin` objects that are not Office packages, EMF/WMF previews
of embedded objects (Word-generated), a signature drawn over text (the text under it is erased too), native RTF patching
(LibreOffice round trip is used instead). Signature thresholds were tuned on synthetic strokes; check them on real
signatures before a demo.

## Requirements — evidence (2026-09-17, build `0723127`)

The eight requirements below are the specification this service was built against. Measured with `tools/evaluate_output.py` on two 100 % fictional datasets (POC: 9 files / 3 717 values; gap: 11 files /
372 values), locally **and** end to end through SharePoint and the deployed service (same numbers). Every image and
rendered PDF page was also checked by eye; the harness is blind to typography.

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | Identify PII/PHI across varying formats and templates | met | 0 leaks / 3 717 + 0 / 372; same content in different templates (`Template_B.docx`, `Template_C.pdf`, `Lettre.rtf`) 0 leaks; format-valid pseudonyms (IBAN 150/150, AVS 83/83 in the 305-page PDF); non-sensitive decoys untouched 0 / 154 |
| 2 | Mask PII in images | met | 6 standalone images, images inside DOCX (incl. the OLE preview) and PDF: 0 leaks; pseudonyms rendered in the original size, weight, slant and colour |
| 3 | Consistent masking across free text, images, tables | met | multi-surface check: `Coherence.docx` 5 values on header + footer + image + paragraph + table, 305-page PDF 481 values on ≥ 2 surfaces, 0 leaks, identical pseudonym everywhere (deterministic mapping) |
| 4 | Headers and footers on all pages | met | `Pied_de_page.pdf` (4 pages, PII only in header/footer) 0/16, `Pied_de_page.docx` 0/5, RTF header/footer 0/36 |
| 5 | Handwritten and system-generated signatures | met | 3 signatures (raster, vector, PNG) at 0 % residual ink, 6/6 frames and rules intact; typed name + "Digitally signed by" line rewritten 0/20; the two scribbles of the POC images (admission form next to its "Signature du patient" label, prescription bottom-right without label) are covered too, the footer text under them left intact |
| 6 | Data in scanned images | met | 4 scanned pages (200 dpi, skewed, one `/Rotate 90`) 0/130, second OCR pass after masking finds nothing |
| 7 | Layout unchanged, same file size (Word, PDF) | met | 305/305 pages, 4/4 images, identical paragraph/table/sheet counts, text length ratio 0.98–1.02; replacement text in the original face (or its metric-compatible twin), size, baseline and colour. **Size: byte-identical to the input** for every format we write (`MATCH_INPUT_SIZE=1`, default): the output is first made no larger than the input (PDF fonts subset, JPEG quality fitted to the original stream, zip level 9), then padded with a neutral element — unreferenced zero stream in PDF, `tEXt` chunk in PNG, `COM` segments in JPEG, a stored random pad inside the largest image or a declared `masquerading/pad.bin` part in DOCX/XLSX (never a zip archive comment: LibreOffice refuses to open the file), trailing spaces in RTF. Padded DOCX/XLSX verified to open in LibreOffice and python-docx. On SharePoint, which rewrites every DOCX/XLSX it stores (+~10 KB of library metadata, asynchronously), the service re-reads the stored size and re-pads to compensate: **19/20 files have the same stored size in Output as in Inbound**, the XLSX lands within 2 bytes because SharePoint's own rewrite varies by a couple of bytes from one save to the next |
| 8 | Sensitive data in nested documents | met | XLSX embedded in DOCX (`word/embeddings`) and XLSX attached to a PDF: found = processed, 0 leaks (incl. the OLE preview image). Out of scope, logged for review: non-Office OLE `.bin`, EMF/WMF previews |

Formats: PDF (text layer), DOCX, RTF, XLSX, images inside PDF, scanned images inside PDF — all covered by the two datasets above.

## Validation

```bash
DS=<…/02_Phase2_dataset> bash tools/validate.sh          # POC dataset: expect 0 leaks / 3 717, 0 decoys / 154, 305 pages, 4 images
DS=<…/02_Phase2_dataset> GAP=1 bash tools/validate.sh    # gap dataset (RTF, scanned PDF, embedded objects, signatures)
python tools/make_gap_dataset.py --ds <…/02_Phase2_dataset>   # regenerate the 100 % fictional gap dataset

# acceptance of the eight requirements against what is really in SharePoint (tree, evaluator, stored sizes, fonts,
# third-party text extraction, signature zones, italic fields, API security) — 24 checks, exit 0 when all pass
python tools/acceptance.py --ds <…/02_Phase2_dataset> --download tools/runs/acceptance

# end to end through SharePoint and the deployed service (env: GRAPH_*, SP_*, SERVICE_API_KEY — see tools/e2e_gap.py)
python tools/e2e_gap.py --inbound-gap <…/inbound>     --subdir e2e-base --download tools/runs/e2e_base/out
SKIP_SANITIZE=1 RUN_DIR=tools/runs/e2e_base bash tools/validate.sh
```

## Demo state

`Inbound` and `Output` sit at the root of the "Documents" library (`INBOUND_PREFIX=Inbound`,
`OUTPUT_PREFIX=Output`), where they inherit the site permissions. They were first nested under a shared
`Documents/` folder: every item there carried unique permissions, which made Purview's "content shared inside
the organization" DLP condition true, and the *U.S. Financial Data — low volume* rule then restricted access to
the one PDF holding 23 card numbers (`AccessDenied type=accessremoved` for regular users, invisible in the folder
listing, while Graph still saw it). Root folders that nobody shares avoid the rule without touching Purview.
`Inbound` holds exactly the two fictional datasets, flat: the 4 POC documents and the 11 gap files at the
root, the 5 POC images under `images/`. `Output` mirrors that tree with the pseudonymized files produced by
the current build.
The Securiti trigger is the scan-completion workflow (Discovery Scan Trigger in Event Mode, referenced in the
Responses tab of the console scan definition → `POST /scan-completed`), so every completed scan reprocesses
`Inbound`; a fresh file dropped there shows up pseudonymized in `Output` after the next scan (56 min end to end
on 2026-09-21, 30 of them scan time). `POST /sanitize` for one file or `POST /scan-completed` for all of
`Inbound` remain available by hand. To rebuild the reference state from scratch (wipes both folders first):

```bash
python tools/reset_demo.py --ds <…/02_Phase2_dataset> --download tools/runs/demo --evaluate   # add --keep to redeposit without wiping
```

## Quick test

```bash
curl -fsS https://masquerading.lamble.fr/healthz
curl -fsS -XPOST https://masquerading.lamble.fr/sanitize \
  -H "X-Api-Key: $SERVICE_API_KEY" -H 'Content-Type: application/json' \
  -d '{"file_path":"Inbound/Dossier_patients_Q3_2026_FICTIF.pdf"}'
```
