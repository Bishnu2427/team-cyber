FROM python:3.11-slim
WORKDIR /app

COPY verifier/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY verifier/ ./

EXPOSE 8003
CMD ["python", "app.py"]
