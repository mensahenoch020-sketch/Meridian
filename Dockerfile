FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOST=0.0.0.0 COOKIE_SECURE=1 DB_PATH=/data/meridian.db
COPY server.py banking.py ./
COPY public ./public
RUN mkdir -p /data
EXPOSE 8000
CMD ["python", "server.py"]
