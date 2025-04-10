ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-bookworm AS base

ARG UID=1000
ARG GID=1000
ARG WORKDIR=/app

WORKDIR ${WORKDIR}

RUN groupadd --gid ${GID} app \
 && useradd --uid ${UID} --gid ${GID} --no-create-home --shell /bin/bash app \
 && mkdir --parents ${WORKDIR} \
 && chown app:app ${WORKDIR}

RUN apt update \
 && apt install --assume-yes \
    libpcsclite1:amd64 \
 && apt clean

ADD linux-amd64_deb.tgz ./
RUN linux-amd64_deb/install.sh \
 && apt install --assume-yes \
    ./linux-amd64_deb/cprocsp-pki-cades-*.deb \
    ./linux-amd64_deb/cprocsp-rdr-pcsc-*.deb \
    ./linux-amd64_deb/cprocsp-rdr-rutoken-*.deb \
    ./linux-amd64_deb/lsb-cprocsp-devel_5.0*.deb \
 && rm -rf linux-amd64_deb


FROM base AS build

RUN apt update \
 && apt install --assume-yes \
    build-essential \
    cmake \
    libboost-all-dev \
    python3-dev \
    unzip \
 && apt clean

ADD https://cryptopro.ru/sites/default/files/products/cades/pycades/pycades.zip ./pycades.zip
ARG PYTHON_VERSION
RUN unzip ./pycades.zip \
 && cd pycades_* \
 && mkdir build \
 && cd build \
 && cmake .. \
 && make -j4 \
 && cp pycades.so /usr/local/lib/python${PYTHON_VERSION}/ \
 && rm -rf /usr/src/pycades*


FROM base AS runtime

ARG PYTHON_VERSION
COPY --from=build /usr/local/lib/python${PYTHON_VERSION}/pycades.so /usr/local/lib/python${PYTHON_VERSION}/pycades.so
COPY --from=build /opt/cprocsp /opt/cprocsp

COPY requirements.txt ./
RUN pip install -U pip
RUN pip install -r requirements.txt

ADD http://certenroll.test.gosuslugi.ru/cdp/test_ca_rtk3.cer ./
RUN /opt/cprocsp/bin/amd64/certmgr -install -store mroot -f ./test_ca_rtk3.cer \
 && rm -rf ./test_ca_rtk3.cer

RUN mkdir --parents /var/opt/cprocsp/keys/app \
 && chown app:app /var/opt/cprocsp/keys/app

USER app

EXPOSE 5000
