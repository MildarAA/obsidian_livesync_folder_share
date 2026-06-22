FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --home-dir /app app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY sync.py ./sync.py

RUN mkdir -p /data /logs && chown -R app:app /data /logs /app

USER app

ENTRYPOINT ["python", "/app/sync.py"]
