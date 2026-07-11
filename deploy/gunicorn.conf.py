import multiprocessing
import os


bind = os.environ.get('GUNICORN_BIND', '0.0.0.0:8000')
workers = int(os.environ.get('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
timeout = int(os.environ.get('GUNICORN_TIMEOUT', '120'))
accesslog = os.environ.get('GUNICORN_ACCESS_LOG', 'logs/gunicorn-access.log')
errorlog = os.environ.get('GUNICORN_ERROR_LOG', 'logs/gunicorn-error.log')
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')
capture_output = True
