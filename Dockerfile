# Masquerading service (meaningful masking) (Securiti × SharePoint POC).
# - fonts-dejavu (core+extra): sans/bold/mono/serif/condensed families for rewriting images (OCR); python:3.11-slim
#   ships no font at all. fonts-liberation(2) / carlito / caladea: metric-compatible equivalents of Arial, Times New
#   Roman, Courier New, Calibri, Cambria to rewrite client PDFs with the same advance widths (see _pdf_font_for).
# - tesseract fra+deu+eng (+ osd): OCR of images, scanned pages and the 2nd safety net.
# - libreoffice-writer (no GUI, --no-install-recommends): RTF <-> DOCX (sanitize_rtf). Java and the other modules
#   (calc, impress, GTK) are not installed. Image size measurement: see README (size before/after).
# - curl: healthcheck.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-fra tesseract-ocr-deu tesseract-ocr-eng \
      fonts-dejavu fonts-liberation fonts-liberation2 fonts-crosextra-carlito fonts-crosextra-caladea curl \
      libreoffice-writer libreoffice-core libreoffice-common \
    && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/
# Initial pseudonym table (copied to /data on first start-up if absent).
COPY seed/ /app/seed/

RUN useradd -u 10001 -m masquerading
USER 10001
# LibreOffice writes a user profile: each conversion uses -env:UserInstallation=file:///tmp/lo_<pid>_…
ENV SOFFICE=/usr/bin/soffice HOME=/home/masquerading MASQUERADING_IN_CONTAINER=1

# Build commit (CI: --build-arg GIT_SHA=<short sha>) exposed by GET /healthz → tells which version is running behind
# Portainer.
ARG GIT_SHA=dev
ENV GIT_SHA=$GIT_SHA

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
