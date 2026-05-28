FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/uploads

COPY backend/ ./backend/
COPY frontend/ ./frontend/

EXPOSE 5000

# python -m sets sys.path to /app so 'from backend.xxx import ...' resolves correctly
CMD ["python", "-m", "backend.app"]
