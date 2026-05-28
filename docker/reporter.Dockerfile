FROM python:3.11-slim
WORKDIR /app

COPY reporter/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/uploads

COPY reporter/ ./

EXPOSE 8004
CMD ["python", "app.py"]
