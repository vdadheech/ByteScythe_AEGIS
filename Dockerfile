# Use official Python image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements from backend/ folder and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire backend package (preserves the 'backend/' structure)
# This is required because main.py imports use: from backend.api.routes, etc.
COPY backend/ ./backend/

# Copy any data files needed
COPY data/ ./data/

# Expose the port Render will use
EXPOSE 10000

# Run from repo root so 'from backend.xxx' imports resolve correctly
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "10000"]
