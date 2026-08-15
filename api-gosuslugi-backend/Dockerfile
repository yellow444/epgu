ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim-bookworm

ARG UID=1000
ARG GID=1000
WORKDIR /app

RUN groupadd --gid ${GID} app \
 && useradd --uid ${UID} --gid ${GID} --no-create-home --shell /usr/sbin/nologin app

COPY python-epgu /python-epgu
COPY api-gosuslugi-backend/requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app api-gosuslugi-backend/app.py api-gosuslugi-backend/config.py api-gosuslugi-backend/routers.py api-gosuslugi-backend/service_profiles.json ./
COPY --chown=app:app api-gosuslugi-backend/inbound.py api-gosuslugi-backend/inbound_api.py api-gosuslugi-backend/inbound_store.py ./
COPY --chown=app:app api-gosuslugi-backend/mailbox.py api-gosuslugi-backend/certsources.py api-gosuslugi-backend/setup_api.py api-gosuslugi-backend/secret_store.py api-gosuslugi-backend/settings_store.py ./
COPY --chown=app:app api-gosuslugi-backend/xml /xml

# Каталоги журнала входящих запросов и вложений из почты. Владелец
# выставляется здесь, чтобы тома унаследовали права и запись шла не от root.
RUN mkdir --parents /var/lib/epgu-inbound /var/lib/epgu-mail \
 && chown app:app /var/lib/epgu-inbound /var/lib/epgu-mail

ENV XML_ROOT=/xml \
    PYTHONUNBUFFERED=1
USER app
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/version', timeout=3).read()"]

# Public image intentionally contains no proprietary CryptoPro binaries.
# Mount/use a separately licensed image providing pycades for signing endpoints.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
