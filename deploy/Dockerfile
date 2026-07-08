FROM python:3.7-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt deploy/requirements-prod.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements-prod.txt

COPY . /app/
RUN mkdir -p /app/logs /app/uploads

EXPOSE 8000

CMD ["gunicorn", "PyLinux.wsgi:application", "-c", "deploy/gunicorn.conf.py"]
