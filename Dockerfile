FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

RUN mkdir -p data

EXPOSE 10000

# Seed DB at startup, then launch the server
CMD ["sh", "-c", "python -m backend.db.seed_db && uvicorn backend.main:app --host 0.0.0.0 --port 10000"]
