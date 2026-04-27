FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY writer.py .
COPY schema.sql .

CMD ["python", "writer.py"]
