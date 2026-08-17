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

# Копируем модули по маске, а не списком имён: перечисление уже дважды
# отставало от кода, и приложение падало при старте на ModuleNotFoundError.
# Тесты в рабочий образ не едут, для них есть Dockerfile.test.
COPY --chown=app:app api-gosuslugi-backend/*.py api-gosuslugi-backend/service_profiles.json ./
RUN rm -f test_*.py
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
