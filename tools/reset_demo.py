# -*- coding: utf-8 -*-
"""
reset_demo.py — remet SharePoint au propre pour la démo, puis prouve la sortie.

  1. vide <INBOUND_PREFIX> et <OUTPUT_PREFIX> (tout : anciens résultats, dossiers e2e-*, fichiers hors dataset),
  2. dépose le dataset POC à la racine d'Inbound (sous-dossier images/ compris) et le dataset d'écart dans Inbound/gap/,
  3. POST /scan-completed : le service retraite tout Inbound vers Output (même arborescence),
  4. attend que chaque fichier soit sorti, télécharge Output dans --download/{base,gap}/out,
  5. affiche les commandes d'évaluation (tools/validate.sh SKIP_SANITIZE=1) — ou les lance avec --evaluate.

Env : voir tools/e2e_gap.py (GRAPH_*, SP_*, SERVICE_API_KEY, SERVICE_URL, INBOUND_PREFIX, OUTPUT_PREFIX).

    python tools/reset_demo.py --ds <…/02_Phase2_dataset> --download tools/runs/demo --evaluate
"""
import argparse
import os
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
from graph import GraphClient  # noqa: E402


def local_files(root):
    out = []
    for r, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith((".", "_")))
        for n in sorted(names):
            if not n.startswith((".", "~$", "_")):
                out.append(os.path.relpath(os.path.join(r, n), root).replace(os.sep, "/"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ds", required=True, help="dossier 02_Phase2_dataset (inbound/, inbound_gap/, ground_truth/)")
    ap.add_argument("--download", default="tools/runs/demo")
    ap.add_argument("--gap-subdir", default="gap")
    ap.add_argument("--timeout", type=int, default=1500)
    ap.add_argument("--evaluate", action="store_true", help="lancer tools/validate.sh sur les sorties téléchargées")
    ap.add_argument("--keep", action="store_true", help="ne pas vider Inbound/Output (dépôt + retraitement seulement)")
    ap.add_argument("--no-upload", action="store_true", help="ni vidage, ni dépôt, ni POST : attendre la fin du job en cours, télécharger, évaluer")
    a = ap.parse_args()
    url = os.environ.get("SERVICE_URL", "https://masquerading.lamble.fr").rstrip("/")
    key = os.environ["SERVICE_API_KEY"]
    inbound = os.environ.get("INBOUND_PREFIX", "Documents/Inbound")
    output = os.environ.get("OUTPUT_PREFIX", "Documents/Output")
    gc = GraphClient()
    h = requests.get(f"{url}/healthz", timeout=30).json()
    print("healthz:", h)
    if h.get("queue") and not a.no_upload:
        print("ECHEC : la file du service n'est pas vide, attendre avant de nettoyer"); sys.exit(2)

    if not a.keep and not a.no_upload:
        for folder in (inbound, output):
            items = gc.list_folder(folder)
            print("vidage", folder, ":", len(items), "fichiers")
            # supprimer les dossiers de 1er niveau puis les fichiers restants
            tops = sorted({rel.split("/")[0] for rel, _ in items})
            for t in tops:
                print("   rm", f"{folder}/{t}", "->", gc.delete(f"{folder}/{t}"))

    plan = [(os.path.join(a.ds, "inbound"), ""), (os.path.join(a.ds, "inbound_gap"), a.gap_subdir)]
    expected = {}
    for root, sub in plan:
        for rel in local_files(root):
            target = f"{sub}/{rel}" if sub else rel
            if not a.no_upload:
                gc.upload(f"{inbound}/{target}", os.path.join(root, rel))
                print("   dépôt", f"{inbound}/{target}")
            expected[target] = os.path.getsize(os.path.join(root, rel))
    if not a.no_upload:
        print("Inbound :", len(expected), "fichiers ; POST /scan-completed")
        r = requests.post(f"{url}/scan-completed", headers={"X-Api-Key": key}, json={"scan_id": "reset-demo"}, timeout=60)
        print("  ->", r.status_code, r.text[:200])

    # 1) attendre la FIN du job « all » (healthz.last = {'kind': 'all'} et file vide) : avec --keep, Output contient encore
    #    les anciennes sorties et leur simple présence ne prouve rien ; 2) puis vérifier la présence de chaque fichier
    t0 = time.time()
    while time.time() - t0 < a.timeout:
        h = requests.get(f"{url}/healthz", timeout=30).json()
        if not h.get("queue") and (h.get("last") or {}).get("kind") == "all":
            break
        print("  … service en cours : processed=%s (%ds)" % (h.get("processed"), time.time() - t0)); time.sleep(20)
    else:
        print("ECHEC : le job all n'est pas terminé dans le délai"); sys.exit(2)
    pending = set(expected)
    while pending and time.time() - t0 < a.timeout:
        time.sleep(5)
        try:
            present = dict(gc.list_folder(output))
        except requests.HTTPError:
            present = {}
        for rel in list(pending):
            if rel in present:
                so, si = present[rel].get("size", 0), expected[rel]
                print("  OK %-45s %8d -> %8d o  (%+.1f %%)" % (rel, si, so, 100.0 * (so - si) / max(1, si)))
                pending.discard(rel)
        print("  … encore %d en attente (%ds)" % (len(pending), time.time() - t0) if pending else "  tout est sorti")
    h = requests.get(f"{url}/healthz", timeout=30).json()
    print("healthz:", h)
    if pending:
        print("ECHEC : sorties manquantes", sorted(pending)); sys.exit(2)
    base_out, gap_out = os.path.join(a.download, "base", "out"), os.path.join(a.download, "gap", "out")
    for rel in expected:
        if rel.startswith(a.gap_subdir + "/"):
            dst = os.path.join(gap_out, rel[len(a.gap_subdir) + 1:])
        else:
            dst = os.path.join(base_out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        gc.download(f"{output}/{rel}", dst)
    print("téléchargé dans", a.download)
    repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    cmds = [f'DS="{a.ds}" SKIP_SANITIZE=1 RUN_DIR={os.path.join(a.download, "base")} bash tools/validate.sh',
            f'DS="{a.ds}" GAP=1 SKIP_SANITIZE=1 RUN_DIR={os.path.join(a.download, "gap")} bash tools/validate.sh']
    if a.evaluate:
        rc = 0
        for c in cmds:
            print("==", c)
            rc |= subprocess.call(c, shell=True, cwd=repo)
        sys.exit(rc)
    print("évaluer :"); [print("  ", c) for c in cmds]


if __name__ == "__main__":
    main()
