# Service de masquerading (masquage signifiant) (POC Securiti × SharePoint).
# - fonts-dejavu (core+extra) : familles sans/bold/mono/serif/condensed pour la réécriture d'images (OCR) ; python:3.11-slim
#   n'embarque aucune police.
# - tesseract fra+deu+eng (+ osd) : OCR des images, des pages scannées et du 2e filet.
# - libreoffice-writer (sans GUI, --no-install-recommends) : RTF <-> DOCX (sanitize_rtf). Java et les autres modules
#   (calc, impress, GTK) ne sont pas installés. Mesure de l'image : voir README (taille avant/après).
# - curl : healthcheck.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-fra tesseract-ocr-deu tesseract-ocr-eng \
      fonts-dejavu curl \
      libreoffice-writer libreoffice-core libreoffice-common \
    && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/
# Table de pseudonymes de départ (copiée vers /data au 1er démarrage si absente).
COPY seed/ /app/seed/

RUN useradd -u 10001 -m masquerading
USER 10001
# LibreOffice écrit un profil utilisateur : chaque conversion utilise -env:UserInstallation=file:///tmp/lo_<pid>_…
ENV SOFFICE=/usr/bin/soffice HOME=/home/masquerading

# Commit de build (CI : --build-arg GIT_SHA=<sha court>) exposé par GET /healthz → on sait quelle version tourne derrière Portainer.
ARG GIT_SHA=dev
ENV GIT_SHA=$GIT_SHA

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
