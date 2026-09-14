# Service de sanitization signifiante (POC Securiti × SharePoint).
# fonts-dejavu (core+extra) est indispensable : familles sans/bold/mono/serif/condensed : la réécriture d'images (OCR) charge
# DejaVuSans.ttf — python:3.11-slim n'embarque aucune police. curl sert au healthcheck.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-fra tesseract-ocr-deu fonts-dejavu curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/
# Table de pseudonymes de départ (copiée vers /data au 1er démarrage si absente).
COPY seed/ /app/seed/

RUN useradd -u 10001 -m sanitizer
USER 10001

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
