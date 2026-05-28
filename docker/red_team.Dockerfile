FROM python:3.11-slim
WORKDIR /app

# Phase 2 will add: nmap, whatweb, nuclei, ffuf, sqlmap, etc.
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY red_team/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/uploads

COPY red_team/ ./

EXPOSE 8001
CMD ["python", "app.py"]
