FROM python:3.8

ENV DEBIAN_FRONTEND noninteractive
ENV PATH="${PATH}:/opt/cprocsp/bin/amd64/"
ENV PYTHONPATH "${PYTHONPATH}:/app/pycades"
RUN apt-get update 
RUN apt-get install -y wget cmake build-essential libboost-all-dev python3-dev unzip

WORKDIR /app
COPY [ "requirements.txt", "pycades.zip", "linux-amd64_deb.tgz", "./"]
# RUN wget 'https://cryptopro.ru/sites/default/files/products/cades/pycades/pycades.zip'
RUN tar zxvf linux-amd64_deb.tgz 
RUN chmod +x /app/*.*
RUN  /app/linux-amd64_deb/install.sh
RUN  apt -o Apt::Get::Assume-Yes=true install /app/linux-amd64_deb/lsb-cprocsp-devel_5.0*.deb && \ 
apt -o Apt::Get::Assume-Yes=true install  /app/linux-amd64_deb/lsb-cprocsp-base_5.0*.deb && \ 
apt -o Apt::Get::Assume-Yes=true install  /app/linux-amd64_deb/cprocsp-pki-cades*.deb
RUN unzip pycades.zip 
RUN cd pycades && \
mkdir build && \
cd build && \ 
cmake .. && \
make -j4 && \
chmod +x /app/pycades/build/pycades.so && \
cp /app/pycades/build/pycades.so /usr/local/lib
RUN rm /app/linux-amd64_deb.tgz /app/pycades.zip 
RUN set -ex 


RUN pip install -U pip
RUN pip install -r requirements.txt

EXPOSE 5000