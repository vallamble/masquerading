"""Client Microsoft Graph app-only (client credentials) pour SharePoint.

Lit Inbound et écrit Output dans la bibliothèque de documents du site d'Alice.
Permissions Entra requises : Sites.Selected (write sur le site) ou Files.ReadWrite.All,
consenties par l'admin du tenant. Aucune valeur secrète ici — tout vient de l'env.
"""
import os
import time

import requests

GRAPH = "https://graph.microsoft.com/v1.0"
UPLOAD_CHUNK = 5 * 1024 * 1024  # multiple de 320 KiB requis par Graph ; 5 MiB


def secret(name, default=None, required=False):
    """Valeur de $NAME, ou contenu du fichier $NAME_FILE (secrets Docker Swarm montés dans /run/secrets/<nom>),
    ou /run/secrets/<NAME> s'il existe. Espaces et fin de ligne retirés."""
    v = os.environ.get(name)
    if not v:
        path = os.environ.get(name + "_FILE") or (f"/run/secrets/{name}" if os.path.exists(f"/run/secrets/{name}") else None)
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                v = f.read().strip()
    if not v:
        if required:
            raise KeyError(f"{name} : ni variable d'environnement, ni {name}_FILE, ni /run/secrets/{name}")
        return default
    return v.strip()


class GraphClient:
    def __init__(self):
        self.tenant = secret("GRAPH_TENANT_ID", required=True)
        self.client_id = secret("GRAPH_CLIENT_ID", required=True)
        self.client_secret = secret("GRAPH_CLIENT_SECRET", required=True)
        # ex. SP_HOSTNAME=cyberdux.sharepoint.com  SP_SITE_PATH=/sites/AliceTeam
        self.hostname = secret("SP_HOSTNAME", required=True)
        self.site_path = secret("SP_SITE_PATH", default="") or ""
        self._token = None
        self._token_exp = 0.0
        self._site_id = None
        self._drive_id = None

    # --- auth ---------------------------------------------------------------
    def token(self):
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        r = requests.post(
            f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=30,
        )
        r.raise_for_status()
        j = r.json()
        self._token = j["access_token"]
        self._token_exp = time.time() + int(j.get("expires_in", 3600))
        return self._token

    def _h(self):
        return {"Authorization": f"Bearer {self.token()}"}

    def _get(self, url, **kw):
        return self._retry(lambda: requests.get(url, headers=self._h(), timeout=60, **kw))

    @staticmethod
    def _retry(call, tries=4):
        """Graph répond parfois par un timeout ou un 429/5xx transitoire (un ReadTimeout de 300 s a cassé un bout-en-bout
        de 11 fichiers) : on rejoue jusqu'à 4 fois avec attente croissante, puis on laisse remonter l'erreur."""
        import time
        last = None
        for i in range(tries):
            try:
                r = call()
                if r.status_code in (429, 500, 502, 503, 504) and i < tries - 1:
                    time.sleep(float(r.headers.get("Retry-After", 5 * (i + 1)))); continue
                r.raise_for_status()
                return r
            except (requests.Timeout, requests.ConnectionError) as exc:
                last = exc
                if i == tries - 1:
                    raise
                time.sleep(5 * (i + 1))
        raise last

    # --- site / drive -------------------------------------------------------
    def drive_id(self):
        if self._drive_id:
            return self._drive_id
        # SP_SITE_PATH vide = site racine du tenant (GET /sites/{hostname});
        # sinon un site nommé (GET /sites/{hostname}:/sites/X).
        if self.site_path.strip("/"):
            site = self._get(f"{GRAPH}/sites/{self.hostname}:{self.site_path}").json()
        else:
            site = self._get(f"{GRAPH}/sites/{self.hostname}").json()
        self._site_id = site["id"]
        drive_name = os.environ.get("SP_LIBRARY", "Documents")
        drives = self._get(f"{GRAPH}/sites/{self._site_id}/drives").json()["value"]
        for d in drives:
            if d["name"] == drive_name:
                self._drive_id = d["id"]
                return self._drive_id
        raise RuntimeError(f"bibliothèque {drive_name!r} introuvable sur {self.site_path}")

    # --- lecture ------------------------------------------------------------
    def list_folder(self, path):
        """Liste récursivement les fichiers sous <path> (ex. 'Inbound').
        Retourne [(chemin relatif à <path>, item)]."""
        out = []

        def walk(p, rel):
            url = f"{GRAPH}/drives/{self.drive_id()}/root:/{p}:/children"
            while url:
                j = self._get(url).json()
                for it in j.get("value", []):
                    r = f"{rel}/{it['name']}" if rel else it["name"]
                    if "folder" in it:
                        walk(f"{p}/{it['name']}", r)
                    else:
                        out.append((r, it))
                url = j.get("@odata.nextLink")

        walk(path, "")
        return out

    def item(self, path):
        """Métadonnées de drive:/<path> (dont `size` telle que STOCKÉE par SharePoint)."""
        return self._get(f"{GRAPH}/drives/{self.drive_id()}/root:/{path}").json()

    def delete(self, path):
        """Supprime drive:/<path> (fichier ou dossier, récursif côté Graph). 404 = déjà absent, ignoré."""
        r = requests.delete(f"{GRAPH}/drives/{self.drive_id()}/root:/{path}", headers=self._h(), timeout=60)
        if r.status_code not in (204, 404):
            r.raise_for_status()
        return r.status_code

    def download(self, path, local):
        """Télécharge drive:/<path> vers un fichier local."""
        r = self._get(f"{GRAPH}/drives/{self.drive_id()}/root:/{path}:/content", stream=True)
        with open(local, "wb") as f:
            for chunk in r.iter_content(1024 * 256):
                f.write(chunk)

    # --- écriture -----------------------------------------------------------
    def upload(self, path, local):
        """Upload local -> drive:/<path>. Session d'upload au-delà de 4 MB."""
        size = os.path.getsize(local)
        if size <= 4 * 1024 * 1024:
            def put():
                with open(local, "rb") as f:
                    return requests.put(f"{GRAPH}/drives/{self.drive_id()}/root:/{path}:/content",
                                        headers=self._h(), data=f, timeout=300)
            return self._retry(put).json()
        j = requests.post(
            f"{GRAPH}/drives/{self.drive_id()}/root:/{path}:/createUploadSession",
            headers=self._h(),
            json={"item": {"@microsoft.graph.conflictBehavior": "replace"}},
            timeout=60,
        )
        j.raise_for_status()
        url = j.json()["uploadUrl"]
        with open(local, "rb") as f:
            pos = 0
            while pos < size:
                chunk = f.read(UPLOAD_CHUNK)
                end = pos + len(chunk) - 1
                r = requests.put(
                    url,
                    headers={"Content-Range": f"bytes {pos}-{end}/{size}"},
                    data=chunk, timeout=300,
                )
                r.raise_for_status()
                pos = end + 1
        return r.json()
