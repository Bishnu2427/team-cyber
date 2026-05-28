FROM python:3.11-slim
WORKDIR /app

# System tools
RUN apt-get update && apt-get install -y curl nodejs npm && rm -rf /var/lib/apt/lists/*

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

COPY blue_team/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Security scanning tools
RUN pip install --no-cache-dir semgrep bandit pip-audit

RUN mkdir -p /app/uploads

COPY blue_team/ ./

EXPOSE 8002
CMD ["python", "app.py"]
