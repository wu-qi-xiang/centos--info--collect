FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY deploy/requirements-prod.txt /app/requirements-prod.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements-prod.txt

COPY . /app/
RUN mkdir -p /app/logs /app/uploads

EXPOSE 8000

CMD ["gunicorn", "PyLinux.wsgi:application", "-c", "deploy/gunicorn.conf.py"]
