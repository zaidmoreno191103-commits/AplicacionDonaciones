FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Usuario sin privilegios + carpeta para la base de datos
RUN useradd --create-home appuser \
    && mkdir /data \
    && chown -R appuser:appuser /app /data
USER appuser

ENV DATABASE_URL=sqlite:////data/database.db
VOLUME /data

EXPOSE 5000

CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-", "main:app"]
