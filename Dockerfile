FROM python:3.12-slim AS api

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend_api/requirements.txt /app/backend_api/requirements.txt
RUN pip install --no-cache-dir -r /app/backend_api/requirements.txt
RUN groupadd --system xssboss && useradd --system --gid xssboss --create-home xssboss
COPY --chown=xssboss:xssboss backend_api /app/backend_api
COPY --chown=xssboss:xssboss browser_workers /app/browser_workers
COPY --chown=xssboss:xssboss analysis_engine /app/analysis_engine
COPY --chown=xssboss:xssboss fuzzer /app/fuzzer
COPY --chown=xssboss:xssboss oracle_server /app/oracle_server
COPY --chown=xssboss:xssboss recon_engine /app/recon_engine
COPY --chown=xssboss:xssboss backend_api/alembic.ini /app/backend_api/alembic.ini
RUN mkdir -p /app/reports /app/screenshots /app/evidence && chown -R xssboss:xssboss /app
USER xssboss
EXPOSE 8000
CMD ["uvicorn", "backend_api.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM api AS browser
USER root
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install --with-deps chromium \
    && chown -R xssboss:xssboss /ms-playwright
USER xssboss
CMD ["celery", "-A", "browser_workers.worker:celery_app", "worker", "-Q", "browser", "--concurrency=1", "--loglevel=INFO"]

FROM node:22-alpine AS ui-build
WORKDIR /ui
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM nginx:1.29-alpine AS ui
COPY deploy/nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=ui-build /ui/dist /usr/share/nginx/html
EXPOSE 80
