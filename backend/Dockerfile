FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps (important for ML)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY . .

# Expose port (optional)
EXPOSE 10000

# Run DB seed at runtime + start server
CMD ["sh", "-c", "python -m db.seed_db && gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT"]
