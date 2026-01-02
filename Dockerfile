FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static

# Persistent data (SQLite DB) should be mounted here
RUN mkdir -p /app/data

EXPOSE 8000

ENV PORT=8000 \
    DB_PATH=/app/data/redirects.db \
    ADMIN_USER=admin \
    ADMIN_PASS=admin

CMD ["sh", "-c", "gunicorn -w 2 -b 0.0.0.0:${PORT:-8000} app:app"]


