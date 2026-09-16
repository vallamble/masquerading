# -*- coding: utf-8 -*-
"""
e2e_gap.py — bout-en-bout du dataset d'écart contre le service déployé.

  1. dépose les fichiers de <inbound_gap> dans <INBOUND_PREFIX>/gap/ via Graph (mêmes credentials que la stack Portainer),
  2. POST /sanitize pour chacun (X-Api-Key),
  3. attend et vérifie leur présence dans <OUTPUT_PREFIX>/gap/ (taille, delta), télécharge la sortie dans --download.

Env requis (copier depuis la stack Portainer, ne JAMAIS les mettre dans le dépôt) :
  GRAPH_TENANT_ID GRAPH_CLIENT_ID GRAPH_CLIENT_SECRET SP_HOSTNAME SP_SITE_PATH [SP_LIBRARY]
  SERVICE_API_KEY  SERVICE_URL (défaut https://masquerading.lamble.fr)
  INBOUND_PREFIX (défaut Documents/Inbound)  OUTPUT_PREFIX (défaut Documents/Output)

    python tools/e2e_gap.py --inbound-gap <…/02_Phase2_dataset/inbound_gap> --download tools/runs/e2e_out
"""
import argparse
import os
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
from graph import GraphClient  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inbound-gap", required=True)
    ap.add_argument("--download", default=None, help="dossier local où récupérer les sorties")
    ap.add_argument("--subdir", default="gap", help="sous-dossier de dépôt dans Inbound/Output")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    url = os.environ.get("SERVICE_URL", "https://masquerading.lamble.fr").rstrip("/")
    key = os.environ["SERVICE_API_KEY"]
    inbound = os.environ.get("INBOUND_PREFIX", "Documents/Inbound")
    output = os.environ.get("OUTPUT_PREFIX", "Documents/Output")
    gc = GraphClient()
    files = sorted(f for f in os.listdir(a.inbound_gap) if not f.startswith((".", "~$", "_")))
    print("healthz:", requests.get(f"{url}/healthz", timeout=30).json())
    sizes = {}
    for fn in files:
        local = os.path.join(a.inbound_gap, fn)
        rel = f"{a.subdir}/{fn}"
        gc.upload(f"{inbound}/{rel}", local)
        sizes[fn] = os.path.getsize(local)
        r = requests.post(f"{url}/sanitize", headers={"X-Api-Key": key}, json={"file_path": f"{inbound}/{rel}"}, timeout=60)
        print("upload + POST", rel, r.status_code, r.json())
    print("attente des sorties dans", f"{output}/{a.subdir} …")
    t0 = time.time()
    pending = set(files)
    while pending and time.time() - t0 < a.timeout:
        time.sleep(15)
        try:
            present = {os.path.basename(rel): it for rel, it in gc.list_folder(f"{output}/{a.subdir}")}
        except requests.HTTPError:
            present = {}
        for fn in list(pending):
            if fn in present:
                so, si = present[fn].get("size", 0), sizes[fn]
                print("  OK %-32s %8d -> %8d o  (%+.1f %%)" % (fn, si, so, 100.0 * (so - si) / max(1, si)))
                if a.download:
                    os.makedirs(a.download, exist_ok=True)
                    gc.download(f"{output}/{a.subdir}/{fn}", os.path.join(a.download, fn))
                pending.discard(fn)
        print("  … encore %d en attente (%ds) : %s" % (len(pending), time.time() - t0, sorted(pending)) if pending else "  tout est sorti")
    print("healthz:", requests.get(f"{url}/healthz", timeout=30).json())
    if pending:
        print("ECHEC : sorties manquantes", sorted(pending)); sys.exit(2)
    print("OK : %d fichiers traités — lancer ensuite : DS=… GAP=1 SKIP_SANITIZE=1 RUN_DIR=<run> bash tools/validate.sh "
          "après avoir copié %s dans <run>/out" % (len(files), a.download or "<download>"))


if __name__ == "__main__":
    main()
