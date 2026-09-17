#!/usr/bin/env bash
# Non-regression harness: the SERVICE engine (app/sanitize_reference.py) on the full POC dataset,
# evaluated with tools/evaluate_output.py. Expected: 0 leaks / 3,717, 0 decoys / 154, 305 pages, 4 images.
#
#   DS=<…/02_Phase2_dataset> bash tools/validate.sh            # existing dataset (inbound/ + ground_truth.csv)
#   DS=… GAP=1 bash tools/validate.sh                           # gap dataset (inbound_gap/ + ground_truth_gap.csv)
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DS="${DS:?définir DS=<chemin de 02_Phase2_dataset>}"
PY="${PY:-$REPO/.venv/bin/python}"
GAP="${GAP:-0}"
if [ "$GAP" = "1" ]; then
  INB="$DS/inbound_gap"; GT_CSV="$DS/ground_truth/ground_truth_gap.csv"; RUN="${RUN_DIR:-$REPO/tools/runs/gap}"
  EXTRA=(--signatures "$DS/ground_truth/signatures_gap.csv")
  [ -f "$DS/ground_truth/decoys_gap.csv" ] && EXTRA+=(--decoys "$DS/ground_truth/decoys_gap.csv")
else
  INB="$DS/inbound"; GT_CSV="$DS/ground_truth/ground_truth.csv"; RUN="${RUN_DIR:-$REPO/tools/runs/base}"
  EXTRA=()
fi
mkdir -p "$RUN"
if [ "${SKIP_SANITIZE:-0}" != "1" ]; then
  rm -rf "$RUN/out"
  echo "== 1. sanitization ($INB -> $RUN/out)"
  time "$PY" "$REPO/app/sanitize_reference.py" --inbound "$INB" --output "$RUN/out" \
       --mapping "$DS/ground_truth/mapping_by_value.csv" ${ONLY:+--only "$ONLY"} 2>&1 | tee "$RUN/sanitize.log" | tail -15
fi
echo "== 2. évaluation"
"$PY" "$REPO/tools/evaluate_output.py" --inbound "$INB" --output "$RUN/out" \
     --ground-truth "$DS/ground_truth" --gt-csv "$GT_CSV" --report-dir "$RUN" ${EXTRA[@]+"${EXTRA[@]}"} > "$RUN/eval.stdout" 2>&1
tail -n +1 "$RUN/eval.stdout" | grep -E "^\| [0-9]|^- \*\*|fuite :|leurre modifié|signature|taille|imbriqu|ABSENT" | sed 's/^/   /'
echo "== 3. verdict"
"$PY" - "$RUN/evaluation_output.json" "$GAP" <<'PYEOF'
import json, sys
rep = json.load(open(sys.argv[1])); gap = sys.argv[2] == "1"
ov = rep["overall"]; docs = rep["documents"]
dec = sum(d.get("decoys_modified", 0) for d in docs.values() if "status" not in d)
dect = sum(d.get("decoys_total", 0) for d in docs.values() if "status" not in d)
absent = [k for k, d in docs.items() if "status" in d]
print("   fuites            : %d / %d" % (ov["leaked"], ov["to_pseudonymize"]))
print("   leurres modifiés  : %d / %d" % (dec, dect))
ok = ov["leaked"] == 0 and dec == 0 and not absent
if absent: print("   ABSENTS           :", absent)
if not gap:
    d = docs.get("Dossier_patients_Q3_2026_FICTIF.pdf", {})
    pages = d.get("integrity", {}).get("output", {}).get("pages"); imgs = d.get("integrity", {}).get("output", {}).get("images")
    print("   PDF pages/images  : %s / %s (attendu 305 / 4)" % (pages, imgs))
    ok = ok and pages == 305 and imgs == 4
else:
    sig = rep.get("signatures", {})
    if sig:
        print("   signatures        : %s" % json.dumps(sig.get("summary", sig), ensure_ascii=False))
        ok = ok and sig.get("summary", {}).get("ok", False)
    emb = rep.get("embedded", {})
    if emb: print("   imbriqués         : %s" % json.dumps(emb, ensure_ascii=False))
sz = rep.get("size_delta", {})
for k, v in sz.items(): print("   taille %-40s %+.1f %%  (%d -> %d o)" % (k, v["pct"], v["in"], v["out"]))
print("   VERDICT : %s" % ("OK" if ok else "ECHEC"))
sys.exit(0 if ok else 2)
PYEOF
